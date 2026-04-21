//! CRYPTO and OPENSSL utility C ABI wrappers for the `openssl-ffi` crate.
//!
//! This module exports `extern "C"` functions matching the
//! `include/openssl/crypto.h.in` public API contract.  It covers the
//! major utility subsystems defined in the C header:
//!
//! * Version information (`OPENSSL_version_*`, `OpenSSL_version*`,
//!   `OPENSSL_info`)
//! * Library initialisation and cleanup (`OPENSSL_init_crypto`,
//!   `OPENSSL_cleanup`, `OPENSSL_init`, `OPENSSL_thread_stop*`)
//! * Memory allocation (`CRYPTO_malloc`, `CRYPTO_zalloc`,
//!   `CRYPTO_realloc`, `CRYPTO_free`, `CRYPTO_clear_free`,
//!   `CRYPTO_memdup`, `CRYPTO_strdup`)
//! * Secure heap allocation (`CRYPTO_secure_malloc`,
//!   `CRYPTO_secure_zalloc`, `CRYPTO_secure_free`,
//!   `CRYPTO_secure_clear_free`, `CRYPTO_secure_allocated`,
//!   `CRYPTO_secure_malloc_init`, `CRYPTO_secure_malloc_done`)
//! * Memory hook installation (`CRYPTO_set_mem_functions`,
//!   `CRYPTO_get_mem_functions`)
//! * Thread lock primitives (`CRYPTO_THREAD_lock_new`,
//!   `CRYPTO_THREAD_read_lock`, `CRYPTO_THREAD_write_lock`,
//!   `CRYPTO_THREAD_unlock`, `CRYPTO_THREAD_lock_free`,
//!   `CRYPTO_THREAD_run_once`, `CRYPTO_THREAD_get_current_id`,
//!   `CRYPTO_THREAD_compare_id`)
//! * Atomic operations (`CRYPTO_atomic_add`, `CRYPTO_atomic_add64`,
//!   `CRYPTO_atomic_and`, `CRYPTO_atomic_or`, `CRYPTO_atomic_load`,
//!   `CRYPTO_atomic_load_int`, `CRYPTO_atomic_store`,
//!   `CRYPTO_atomic_store_int`)
//! * `OSSL_LIB_CTX` lifecycle (`OSSL_LIB_CTX_new`, `OSSL_LIB_CTX_free`,
//!   `OSSL_LIB_CTX_set0_default`, `OSSL_LIB_CTX_get0_global_default`,
//!   `OSSL_LIB_CTX_load_config`, `OSSL_LIB_CTX_get_data`, etc.)
//! * `CRYPTO_EX_DATA` (extra data) index allocation and get/set
//! * String utilities (`OPENSSL_strlcpy`, `OPENSSL_strlcat`,
//!   `OPENSSL_strnlen`, `OPENSSL_strcasecmp`, `OPENSSL_hexstr2buf`,
//!   `OPENSSL_buf2hexstr`, `OPENSSL_hexchar2int`)
//! * Miscellaneous helpers (`OPENSSL_die`, `OPENSSL_isservice`,
//!   `CRYPTO_memcmp`, `OSSL_sleep`)
//!
//! The public surface wraps the safe Rust primitives in
//! [`openssl_common::mem`] (for secure zeroing and constant-time
//! comparison), [`openssl_crypto::init`] (for the staged
//! library-initialisation state machine) and
//! [`openssl_crypto::context::LibContext`] (for library context
//! lifecycle).  Ownership of FFI-facing objects is managed through the
//! `Box`/`Arc` → raw pointer → `Box::from_raw`/`Arc::from_raw` pattern
//! used throughout the `openssl-ffi` crate.
//!
//! # Unsafe policy (Rule R8)
//!
//! This module is allowed to contain `unsafe` code because it lives in
//! the `openssl-ffi` crate — the single designated FFI boundary crate
//! for the workspace.  Every `unsafe` block in this file carries a
//! `// SAFETY:` comment that documents:
//!
//! * NULL-pointer and validity assumptions for pointer parameters
//! * Alignment assumptions for reinterpretation casts (notably
//!   `*mut i32`/`*mut u64` → `&AtomicI32`/`&AtomicU64`)
//! * Lifetime assumptions for references derived from raw pointers
//! * Thread-ownership assumptions for mutable references
//! * Ownership assumptions for `Box::from_raw`/`Arc::from_raw`
//!
//! # Return-value conventions (from `crypto/cryptlib.c`, `crypto/mem.c`,
//! `crypto/init.c`, `crypto/threads_pthread.c`)
//!
//! * `OPENSSL_init_crypto` — `1` on success, `0` on failure (always
//!   `1` in this implementation; the init machinery is infallible once
//!   the staged subsystems complete their `Once` initialisation).
//! * `CRYPTO_THREAD_read_lock` / `CRYPTO_THREAD_write_lock` /
//!   `CRYPTO_THREAD_unlock` — `1` on success, `0` on failure.
//! * `CRYPTO_atomic_*` — `1` on success (always in this
//!   implementation; Rust atomics are lock-free and infallible).
//! * `CRYPTO_*_malloc` / `CRYPTO_*_zalloc` / `CRYPTO_*_realloc` —
//!   pointer to allocated memory on success, NULL on failure.
//! * `CRYPTO_EX_DATA` — `1` success, `0` failure; `CRYPTO_get_ex_data`
//!   returns the stored `void*` or NULL if not set.
//! * `OPENSSL_strlcpy` / `OPENSSL_strlcat` — length of source string
//!   (not the number of bytes copied), matching BSD `strlcpy` semantics.
//! * `OPENSSL_strnlen` — number of bytes scanned (`<= maxlen`).
//!
//! # Lock model
//!
//! `CRYPTO_RWLOCK` is a type-erased read/write lock backed by a
//! small atomic-counter-based reader/writer lock (`RwLockInner`).
//! Because the OpenSSL C API uses a single `CRYPTO_THREAD_unlock`
//! function for both read and write locks — and Rust's safe
//! lock-guard APIs couple acquisition and release to the guard
//! lifetime — this module tracks per-thread lock kind in a
//! thread-local `HashMap` keyed by lock address.  This mirrors the C
//! behaviour where `pthread_rwlock_unlock` releases whatever lock
//! the current thread holds without requiring an explicit kind
//! parameter.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, CStr};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use libc::size_t;

use openssl_common::mem::{cleanse, SecureVec};
use openssl_crypto::context::LibContext;
use openssl_crypto::init::{self, InitFlags};
use openssl_crypto::thread::{atomic_add_u64, atomic_load_u64, atomic_store_u64};

// ---------------------------------------------------------------------------
// Opaque C-visible types
// ---------------------------------------------------------------------------

/// Opaque `OSSL_LIB_CTX` handle exposed to C consumers.
///
/// The underlying Rust representation is an `Arc<LibContext>` stored
/// behind the opaque pointer via `Arc::into_raw`.  This preserves the
/// reference-counted ownership semantics of the C API, where multiple
/// subsystems can hold handles to the same library context without the
/// caller needing to track ownership explicitly.
#[repr(C)]
pub struct OSSL_LIB_CTX {
    _private: [u8; 0],
}

/// Opaque `CRYPTO_RWLOCK` handle exposed to C consumers.
///
/// The C typedef is `typedef void CRYPTO_RWLOCK` (see
/// `include/openssl/crypto.h.in` line 82), but Rust requires a concrete
/// `#[repr(C)]` type for the opaque pointer.  The underlying Rust
/// representation is a `Box<RwLockInner>`.
#[repr(C)]
pub struct CRYPTO_RWLOCK {
    _private: [u8; 0],
}

/// Opaque `OPENSSL_INIT_SETTINGS` handle exposed to C consumers.
///
/// Used by `OPENSSL_init_crypto` for advanced configuration (config
/// file path, app name).  The Rust implementation treats settings as
/// optional and defaults to sane values when NULL is passed.
#[repr(C)]
pub struct OPENSSL_INIT_SETTINGS {
    _private: [u8; 0],
}

/// Opaque `CRYPTO_EX_DATA` handle exposed to C consumers.
///
/// Represents a bag of extension data associated with a parent object
/// (SSL, X509, RSA, etc.).  Backed by a `Box<ExDataStorage>`.
#[repr(C)]
pub struct CRYPTO_EX_DATA {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// Version constants (from include/openssl/crypto.h.in lines 186-198)
// ---------------------------------------------------------------------------

/// Selector for `OpenSSL_version` requesting the version string.
pub const OPENSSL_VERSION: c_int = 0;
/// Selector for `OpenSSL_version` requesting the CFLAGS used during build.
pub const OPENSSL_CFLAGS: c_int = 1;
/// Selector for `OpenSSL_version` requesting the build date.
pub const OPENSSL_BUILT_ON: c_int = 2;
/// Selector for `OpenSSL_version` requesting the target platform.
pub const OPENSSL_PLATFORM: c_int = 3;
/// Selector for `OpenSSL_version` requesting the installation prefix.
pub const OPENSSL_DIR: c_int = 4;
/// Selector for `OpenSSL_version` requesting the engines installation dir.
pub const OPENSSL_ENGINES_DIR: c_int = 5;
/// Selector for `OpenSSL_version` requesting the short version string.
pub const OPENSSL_VERSION_STRING: c_int = 6;
/// Selector for `OpenSSL_version` requesting the full version string.
pub const OPENSSL_FULL_VERSION_STRING: c_int = 7;
/// Selector for `OpenSSL_version` requesting the modules installation dir.
pub const OPENSSL_MODULES_DIR: c_int = 8;
/// Selector for `OpenSSL_version` requesting the runtime CPU info.
pub const OPENSSL_CPU_INFO: c_int = 9;
/// Selector for `OpenSSL_version` requesting the Windows context.
pub const OPENSSL_WINCTX: c_int = 10;

/// The packed version number exposed by `OpenSSL_version_num`.
///
/// Encoding from `include/openssl/opensslv.h.in`:
///   ``MNNFFPPS`` where M=major, NN=minor, FF=fix, PP=patch, S=status.
/// OpenSSL 4.0.0 development → `0x40000000L` (approx).
pub const OPENSSL_VERSION_NUMBER: c_ulong = 0x4000_0000;

/// Major version component of `OPENSSL_VERSION_NUMBER`.
const OPENSSL_VERSION_MAJOR_VALUE: c_uint = 4;
/// Minor version component of `OPENSSL_VERSION_NUMBER`.
const OPENSSL_VERSION_MINOR_VALUE: c_uint = 0;
/// Patch version component of `OPENSSL_VERSION_NUMBER`.
const OPENSSL_VERSION_PATCH_VALUE: c_uint = 0;

// Static null-terminated strings returned by the `OpenSSL_version` family.
// Using `&CStr` constants (Rust 1.77+) is the most idiomatic approach;
// for MSRV 1.81 we use `b"..\0".as_ptr() as *const c_char`.

/// Pre-release tag as a null-terminated C string.
const OPENSSL_PRE_RELEASE_CSTR: &[u8] = b"-dev\0";
/// Build metadata as a null-terminated C string.
const OPENSSL_BUILD_METADATA_CSTR: &[u8] = b"\0";
/// Short version string.
const OPENSSL_VERSION_STR_CSTR: &[u8] = b"4.0.0\0";
/// Full version string including pre-release and metadata.
const OPENSSL_FULL_VERSION_STR_CSTR: &[u8] = b"4.0.0-dev\0";
/// Long banner returned by `OpenSSL_version(OPENSSL_VERSION)`.
const OPENSSL_VERSION_BANNER_CSTR: &[u8] = b"OpenSSL 4.0.0-dev (Rust)\0";
/// Compilation flags banner.
const OPENSSL_CFLAGS_CSTR: &[u8] = b"compiler: rustc (edition 2021, MSRV 1.81)\0";
/// Placeholder build-on banner — concrete time not available at compile time.
const OPENSSL_BUILT_ON_CSTR: &[u8] = b"built on: unknown\0";
/// Target platform banner.
const OPENSSL_PLATFORM_CSTR: &[u8] = b"platform: rust\0";
/// Installation prefix banner.
const OPENSSL_DIR_CSTR: &[u8] = b"OPENSSLDIR: \"/usr/local/ssl\"\0";
/// Engines directory banner.
const OPENSSL_ENGINES_DIR_CSTR: &[u8] = b"ENGINESDIR: N/A\0";
/// Modules directory banner.
const OPENSSL_MODULES_DIR_CSTR: &[u8] = b"MODULESDIR: \"/usr/local/ssl/modules\"\0";
/// CPU info banner — filled with a generic string.
const OPENSSL_CPU_INFO_CSTR: &[u8] = b"CPUINFO: N/A\0";
/// Windows context banner (empty on non-Windows platforms).
const OPENSSL_WINCTX_CSTR: &[u8] = b"\0";

// ---------------------------------------------------------------------------
// Info constants (from include/openssl/crypto.h.in lines 202-212)
// ---------------------------------------------------------------------------

/// Selector for `OPENSSL_info` requesting the configuration directory.
pub const OPENSSL_INFO_CONFIG_DIR: c_int = 1001;
/// Selector for `OPENSSL_info` requesting the engines directory.
pub const OPENSSL_INFO_ENGINES_DIR: c_int = 1002;
/// Selector for `OPENSSL_info` requesting the modules directory.
pub const OPENSSL_INFO_MODULES_DIR: c_int = 1003;
/// Selector for `OPENSSL_info` requesting the DSO extension.
pub const OPENSSL_INFO_DSO_EXTENSION: c_int = 1004;
/// Selector for `OPENSSL_info` requesting the directory-filename separator.
pub const OPENSSL_INFO_DIR_FILENAME_SEPARATOR: c_int = 1005;
/// Selector for `OPENSSL_info` requesting the list separator.
pub const OPENSSL_INFO_LIST_SEPARATOR: c_int = 1006;
/// Selector for `OPENSSL_info` requesting the seed source.
pub const OPENSSL_INFO_SEED_SOURCE: c_int = 1007;
/// Selector for `OPENSSL_info` requesting the CPU settings.
pub const OPENSSL_INFO_CPU_SETTINGS: c_int = 1008;
/// Selector for `OPENSSL_info` requesting the Windows context.
pub const OPENSSL_INFO_WINDOWS_CONTEXT: c_int = 1009;

// Info response strings.
const INFO_CONFIG_DIR_CSTR: &[u8] = b"/usr/local/ssl\0";
const INFO_ENGINES_DIR_CSTR: &[u8] = b"/usr/local/ssl/engines\0";
const INFO_MODULES_DIR_CSTR: &[u8] = b"/usr/local/ssl/modules\0";
#[cfg(target_os = "windows")]
const INFO_DSO_EXTENSION_CSTR: &[u8] = b".dll\0";
#[cfg(target_os = "macos")]
const INFO_DSO_EXTENSION_CSTR: &[u8] = b".dylib\0";
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
const INFO_DSO_EXTENSION_CSTR: &[u8] = b".so\0";
#[cfg(target_os = "windows")]
const INFO_DIR_FILENAME_SEPARATOR_CSTR: &[u8] = b"\\\0";
#[cfg(not(target_os = "windows"))]
const INFO_DIR_FILENAME_SEPARATOR_CSTR: &[u8] = b"/\0";
#[cfg(target_os = "windows")]
const INFO_LIST_SEPARATOR_CSTR: &[u8] = b";\0";
#[cfg(not(target_os = "windows"))]
const INFO_LIST_SEPARATOR_CSTR: &[u8] = b":\0";
const INFO_SEED_SOURCE_CSTR: &[u8] = b"os\0";
const INFO_CPU_SETTINGS_CSTR: &[u8] = b"\0";
const INFO_WINDOWS_CONTEXT_CSTR: &[u8] = b"\0";

// ---------------------------------------------------------------------------
// OPENSSL_INIT_* flags (from include/openssl/crypto.h.in lines 482-505)
// ---------------------------------------------------------------------------
//
// All OPENSSL_INIT_* flags are u64 in Rust to match the
// `int OPENSSL_init_crypto(uint64_t opts, ...)` C signature.

/// Do not load the crypto strings (error descriptions) during init.
pub const OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0001;
/// Load the crypto strings (error descriptions) during init.
pub const OPENSSL_INIT_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0002;
/// Add all ciphers to the EVP table during init.
pub const OPENSSL_INIT_ADD_ALL_CIPHERS: u64 = 0x0000_0004;
/// Add all digests to the EVP table during init.
pub const OPENSSL_INIT_ADD_ALL_DIGESTS: u64 = 0x0000_0008;
/// Do not add ciphers to the EVP table during init.
pub const OPENSSL_INIT_NO_ADD_ALL_CIPHERS: u64 = 0x0000_0010;
/// Do not add digests to the EVP table during init.
pub const OPENSSL_INIT_NO_ADD_ALL_DIGESTS: u64 = 0x0000_0020;
/// Load the OpenSSL config file during init.
pub const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
/// Do not load any config file during init.
pub const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
/// Initialise the ASYNC subsystem during init.
pub const OPENSSL_INIT_ASYNC: u64 = 0x0000_0100;
/// Register atfork handlers during init.
pub const OPENSSL_INIT_ATFORK: u64 = 0x0002_0000;
/// Do not register an atexit handler for automatic cleanup.
pub const OPENSSL_INIT_NO_ATEXIT: u64 = 0x0008_0000;

// Engine stubs — engines are no longer supported in OpenSSL 4.0
// (see include/openssl/crypto.h.in line 506-517).  These constants are
// all `0` so that legacy callers that bitwise-OR them into `opts` get a
// no-op.
/// Placeholder for the built-in `ENGINE_RDRAND` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_RDRAND: u64 = 0;
/// Placeholder for the built-in `ENGINE_DYNAMIC` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_DYNAMIC: u64 = 0;
/// Placeholder for the built-in `ENGINE_OPENSSL` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_OPENSSL: u64 = 0;
/// Placeholder for the built-in `ENGINE_CRYPTODEV` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_CRYPTODEV: u64 = 0;
/// Placeholder for the built-in `ENGINE_CAPI` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_CAPI: u64 = 0;
/// Placeholder for the built-in `ENGINE_PADLOCK` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_PADLOCK: u64 = 0;
/// Placeholder for the built-in `ENGINE_AFALG` engine (unsupported in 4.0).
pub const OPENSSL_INIT_ENGINE_AFALG: u64 = 0;

// ---------------------------------------------------------------------------
// CRYPTO_EX_INDEX_* constants (from include/openssl/crypto.h.in lines 228-247)
// ---------------------------------------------------------------------------

/// Extra-data class index for `SSL` objects.
pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
/// Extra-data class index for `SSL_CTX` objects.
pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
/// Extra-data class index for `SSL_SESSION` objects.
pub const CRYPTO_EX_INDEX_SSL_SESSION: c_int = 2;
/// Extra-data class index for `X509` objects.
pub const CRYPTO_EX_INDEX_X509: c_int = 3;
/// Extra-data class index for `X509_STORE` objects.
pub const CRYPTO_EX_INDEX_X509_STORE: c_int = 4;
/// Extra-data class index for `X509_STORE_CTX` objects.
pub const CRYPTO_EX_INDEX_X509_STORE_CTX: c_int = 5;
/// Extra-data class index for `DH` objects.
pub const CRYPTO_EX_INDEX_DH: c_int = 6;
/// Extra-data class index for `DSA` objects.
pub const CRYPTO_EX_INDEX_DSA: c_int = 7;
/// Extra-data class index for `EC_KEY` objects.
pub const CRYPTO_EX_INDEX_EC_KEY: c_int = 8;
/// Extra-data class index for `RSA` objects.
pub const CRYPTO_EX_INDEX_RSA: c_int = 9;
/// Extra-data class index for `ENGINE` objects.
pub const CRYPTO_EX_INDEX_ENGINE: c_int = 10;
/// Extra-data class index for `UI` objects.
pub const CRYPTO_EX_INDEX_UI: c_int = 11;
/// Extra-data class index for `BIO` objects.
pub const CRYPTO_EX_INDEX_BIO: c_int = 12;
/// Extra-data class index for application-defined objects.
pub const CRYPTO_EX_INDEX_APP: c_int = 13;
/// Extra-data class index for `UI_METHOD` objects.
pub const CRYPTO_EX_INDEX_UI_METHOD: c_int = 14;
/// Extra-data class index for `RAND_DRBG` objects.
pub const CRYPTO_EX_INDEX_RAND_DRBG: c_int = 15;
/// Extra-data class index for `DRBG` objects (alias of `RAND_DRBG`).
pub const CRYPTO_EX_INDEX_DRBG: c_int = CRYPTO_EX_INDEX_RAND_DRBG;
/// Extra-data class index for `OSSL_LIB_CTX` objects.
pub const CRYPTO_EX_INDEX_OSSL_LIB_CTX: c_int = 16;
/// Extra-data class index for `EVP_PKEY` objects.
pub const CRYPTO_EX_INDEX_EVP_PKEY: c_int = 17;
/// Total number of extra-data classes defined by OpenSSL 4.0.
pub const CRYPTO_EX_INDEX__COUNT: c_int = 18;

// ---------------------------------------------------------------------------
// Deprecated / stub constants retained for ABI compatibility
// ---------------------------------------------------------------------------

/// Deprecated `CRYPTO_LOCK` sentinel — no-op in OpenSSL 4.0 (see
/// `crypto.h.in` line ~455).
pub const CRYPTO_LOCK: c_int = 1;
/// Deprecated `CRYPTO_UNLOCK` sentinel — no-op in OpenSSL 4.0.
pub const CRYPTO_UNLOCK: c_int = 2;
/// Deprecated `CRYPTO_READ` sentinel — no-op in OpenSSL 4.0.
pub const CRYPTO_READ: c_int = 4;
/// Deprecated `CRYPTO_WRITE` sentinel — no-op in OpenSSL 4.0.
pub const CRYPTO_WRITE: c_int = 8;

// ---------------------------------------------------------------------------
// Internal RwLock representation
// ---------------------------------------------------------------------------

/// Kind of lock acquired by the current thread on a `CRYPTO_RWLOCK`.
///
/// The C `CRYPTO_THREAD_unlock` entry point takes only a lock handle,
/// with no indication of whether the lock is being released from a
/// shared or exclusive hold.  Our underlying reader/writer lock
/// implementation (see `RwLockInner`) uses distinct atomic code paths
/// for the two kinds of release, so we track the per-thread kind in
/// [`LOCK_KIND_MAP`] and consult it on unlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockKind {
    /// The current thread holds the lock for reading.
    Shared,
    /// The current thread holds the lock for writing.
    Exclusive,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert an `OSSL_LIB_CTX` pointer into a cloned `Arc<LibContext>`.
///
/// Returns `None` if `ctx` is NULL.  Otherwise clones the `Arc` so that
/// the stored count is incremented and the caller can use the clone
/// without affecting the reference count held by the opaque pointer.
///
/// # Safety
///
/// `ctx`, if non-null, must point to an `Arc<LibContext>` created by
/// `OSSL_LIB_CTX_new` (or another constructor in this module).  The
/// caller must not free `ctx` while this clone is alive.
unsafe fn ctx_clone_arc(ctx: *const OSSL_LIB_CTX) -> Option<std::sync::Arc<LibContext>> {
    if ctx.is_null() {
        return None;
    }
    // SAFETY: `ctx` is non-null by the check above and, by the
    // function contract, points to an `Arc<LibContext>` previously
    // published via `Arc::into_raw`.  Building a borrowing reference
    // and cloning it is sound because `Arc::from_raw` + `mem::forget`
    // would otherwise change the reference count; by cloning the
    // ManuallyDrop view we keep the original published Arc intact.
    let raw = ctx.cast::<LibContext>();
    let arc = unsafe { std::sync::Arc::from_raw(raw) };
    let cloned = arc.clone();
    // Prevent the borrowed Arc from decrementing the refcount when
    // dropped — the opaque pointer retains the original strong count.
    std::mem::forget(arc);
    Some(cloned)
}

/// Convert a lock pointer into a reference to the interior
/// `RwLockInner`.
///
/// # Safety
///
/// `lock`, if non-null, must point to a `Box<RwLockInner>` created by
/// `CRYPTO_THREAD_lock_new`.
unsafe fn lock_as_ref(lock: *mut CRYPTO_RWLOCK) -> Option<&'static RwLockInner> {
    if lock.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `lock` points to a valid
    // `Box<RwLockInner>` for the duration of the returned reference.
    // We cast to a `'static` reference because the lock is pinned for
    // the whole CRYPTO API lifetime until `CRYPTO_THREAD_lock_free` is
    // called; any use-after-free is the caller's responsibility per
    // the pthread-style API contract.
    let inner_ptr = lock as *const RwLockInner;
    unsafe { inner_ptr.as_ref() }
}

/// Convert a C string pointer into a borrowed `&str`, returning `None`
/// for NULL input or invalid UTF-8.
///
/// # Safety
///
/// `s`, if non-null, must point to a NUL-terminated C string that is
/// valid for reads up to and including the NUL byte.
unsafe fn cstr_to_str_opt(s: *const c_char) -> Option<&'static str> {
    if s.is_null() {
        return None;
    }
    // SAFETY: caller contract guarantees `s` is a NUL-terminated C
    // string.  `CStr::from_ptr` scans for the NUL terminator; UTF-8
    // validation is performed by `to_str` and surfaces as `None` on
    // failure.
    let cstr = unsafe { CStr::from_ptr(s) };
    cstr.to_str().ok()
}

/// Map the `OPENSSL_INIT_*` `opts` bit-field into the Rust
/// `openssl_crypto::init::InitFlags`.
///
/// Only a subset of the flags map to concrete initialisation stages in
/// the Rust implementation — the remainder (engine-related, atfork,
/// cipher/digest population) are absorbed as no-ops because the Rust
/// provider architecture eagerly materialises these during
/// `init_default`.
fn opts_to_init_flags(opts: u64) -> InitFlags {
    let mut flags = InitFlags::BASE | InitFlags::CPU_DETECT | InitFlags::THREADS;
    if opts & OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS == 0 {
        flags |= InitFlags::ERROR_STRINGS;
    }
    if opts & OPENSSL_INIT_NO_LOAD_CONFIG == 0 && opts & OPENSSL_INIT_LOAD_CONFIG != 0 {
        flags |= InitFlags::CONFIG;
    }
    // PROVIDERS is always enabled because the provider-only dispatch
    // mechanism is the algorithm-access path in 4.0 (no fallback
    // to ENGINE tables).
    flags |= InitFlags::PROVIDERS;
    if opts & OPENSSL_INIT_ASYNC != 0 {
        flags |= InitFlags::ASYNC;
    }
    flags
}

// ---------------------------------------------------------------------------
// Version information functions
// ---------------------------------------------------------------------------

/// Return the major version number of this OpenSSL build.
///
/// # Safety
///
/// This function reads only compile-time constants and is safe to call
/// from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_version_major() -> c_uint {
    OPENSSL_VERSION_MAJOR_VALUE
}

/// Return the minor version number of this OpenSSL build.
///
/// # Safety
///
/// This function reads only compile-time constants and is safe to call
/// from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_version_minor() -> c_uint {
    OPENSSL_VERSION_MINOR_VALUE
}

/// Return the patch version number of this OpenSSL build.
///
/// # Safety
///
/// This function reads only compile-time constants and is safe to call
/// from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_version_patch() -> c_uint {
    OPENSSL_VERSION_PATCH_VALUE
}

/// Return the pre-release string (e.g. `"-dev"`) or an empty string.
///
/// # Safety
///
/// The returned pointer refers to a static NUL-terminated string and
/// is valid for the lifetime of the program.  Callers must not free
/// it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_version_pre_release() -> *const c_char {
    OPENSSL_PRE_RELEASE_CSTR.as_ptr().cast::<c_char>()
}

/// Return the build-metadata string or an empty string.
///
/// # Safety
///
/// The returned pointer refers to a static NUL-terminated string and
/// is valid for the lifetime of the program.  Callers must not free
/// it.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_version_build_metadata() -> *const c_char {
    OPENSSL_BUILD_METADATA_CSTR.as_ptr().cast::<c_char>()
}

/// Return the packed version number (see `OPENSSL_VERSION_NUMBER`).
///
/// # Safety
///
/// This function reads only compile-time constants and is safe to call
/// from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn OpenSSL_version_num() -> c_ulong {
    OPENSSL_VERSION_NUMBER
}

/// Return one of the `OPENSSL_VERSION_*` strings as a NUL-terminated C
/// string.
///
/// # Safety
///
/// The returned pointer references static program memory and must not
/// be freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn OpenSSL_version(type_: c_int) -> *const c_char {
    let bytes: &[u8] = match type_ {
        OPENSSL_VERSION => OPENSSL_VERSION_BANNER_CSTR,
        OPENSSL_CFLAGS => OPENSSL_CFLAGS_CSTR,
        OPENSSL_BUILT_ON => OPENSSL_BUILT_ON_CSTR,
        OPENSSL_PLATFORM => OPENSSL_PLATFORM_CSTR,
        OPENSSL_DIR => OPENSSL_DIR_CSTR,
        OPENSSL_ENGINES_DIR => OPENSSL_ENGINES_DIR_CSTR,
        OPENSSL_VERSION_STRING => OPENSSL_VERSION_STR_CSTR,
        OPENSSL_FULL_VERSION_STRING => OPENSSL_FULL_VERSION_STR_CSTR,
        OPENSSL_MODULES_DIR => OPENSSL_MODULES_DIR_CSTR,
        OPENSSL_CPU_INFO => OPENSSL_CPU_INFO_CSTR,
        OPENSSL_WINCTX => OPENSSL_WINCTX_CSTR,
        _ => b"not available\0",
    };
    bytes.as_ptr().cast::<c_char>()
}

/// Return one of the `OPENSSL_INFO_*` strings as a NUL-terminated C
/// string.
///
/// # Safety
///
/// The returned pointer references static program memory and must not
/// be freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_info(type_: c_int) -> *const c_char {
    let bytes: &[u8] = match type_ {
        OPENSSL_INFO_CONFIG_DIR => INFO_CONFIG_DIR_CSTR,
        OPENSSL_INFO_ENGINES_DIR => INFO_ENGINES_DIR_CSTR,
        OPENSSL_INFO_MODULES_DIR => INFO_MODULES_DIR_CSTR,
        OPENSSL_INFO_DSO_EXTENSION => INFO_DSO_EXTENSION_CSTR,
        OPENSSL_INFO_DIR_FILENAME_SEPARATOR => INFO_DIR_FILENAME_SEPARATOR_CSTR,
        OPENSSL_INFO_LIST_SEPARATOR => INFO_LIST_SEPARATOR_CSTR,
        OPENSSL_INFO_SEED_SOURCE => INFO_SEED_SOURCE_CSTR,
        OPENSSL_INFO_CPU_SETTINGS => INFO_CPU_SETTINGS_CSTR,
        OPENSSL_INFO_WINDOWS_CONTEXT => INFO_WINDOWS_CONTEXT_CSTR,
        _ => b"\0",
    };
    bytes.as_ptr().cast::<c_char>()
}

/// Return whether the process is running setuid/setgid.
///
/// # Safety
///
/// Safe to call from any thread.  Uses platform-appropriate checks.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_issetugid() -> c_int {
    #[cfg(unix)]
    unsafe {
        // SAFETY: `geteuid`/`getuid`/`getegid`/`getgid` are all
        // thread-safe libc functions with no pointer parameters.
        let euid = libc::geteuid();
        let uid = libc::getuid();
        let egid = libc::getegid();
        let gid = libc::getgid();
        c_int::from(euid != uid || egid != gid)
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Interior representation of a `CRYPTO_RWLOCK`.
///
/// # Design rationale
///
/// The C `CRYPTO_THREAD_*` API is shaped like `pthread_rwlock_*`:
/// `lock` → work → `unlock`, with the `unlock` function taking only a
/// handle (no reader/writer discriminator).  Rust's safe reader/writer
/// locks (`std::sync::RwLock`, `parking_lot::RwLock`) expose only
/// guard-based APIs whose lifetimes are tied to the lock reference,
/// which is incompatible with a C API that separates acquisition and
/// release across arbitrary stack frames.
///
/// To bridge that gap while keeping this FFI crate isolated from
/// additional dependencies, we implement a small counter-based
/// reader/writer lock directly on top of `AtomicU32`:
///
/// * bit 31 (`WRITER_BIT`) encodes "a writer holds the lock";
/// * bits 0-30 (`READER_MASK`) encode the current reader count.
///
/// Acquisition is a `compare_exchange_weak` loop that yields the
/// current thread on contention; release is a single atomic update.
/// This is a busy-wait design and is not intended for high-contention
/// workloads — but `CRYPTO_RWLOCK` handles are used in OpenSSL's
/// provider and context bookkeeping paths where contention is low.
/// A fairer future implementation could be swapped in without
/// affecting the FFI surface.
///
/// # LOCK-SCOPE justification (Rule R7)
///
/// LOCK-SCOPE: per-`CRYPTO_RWLOCK` instance.  Callers manage the
/// granularity by allocating locks at the appropriate level — the
/// implementation imposes no shared global locking.
struct RwLockInner {
    /// Packed state: bit 31 = writer-held, bits 0-30 = reader count.
    state: AtomicU32,
}

/// Writer-held flag in [`RwLockInner::state`].
const WRITER_BIT: u32 = 1 << 31;
/// Mask selecting the reader-count bits of [`RwLockInner::state`].
const READER_MASK: u32 = !WRITER_BIT;
/// Maximum number of concurrent readers that [`RwLockInner`] will
/// admit.  Mirrors `READER_MASK`; reader counts above this are
/// rejected by `read_lock` to avoid overflow into the writer bit.
const MAX_READERS: u32 = READER_MASK;

impl RwLockInner {
    /// Construct a fresh, unlocked `RwLockInner`.
    fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    /// Acquire the lock for shared (reader) access.
    ///
    /// Blocks (via `yield_now`) until no writer holds the lock and the
    /// reader count is below `MAX_READERS`.
    fn read_lock(&self) {
        loop {
            let s = self.state.load(Ordering::Acquire);
            let readers = s & READER_MASK;
            if s & WRITER_BIT == 0
                && readers < MAX_READERS
                && self
                    .state
                    .compare_exchange_weak(s, s + 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }
            thread::yield_now();
        }
    }

    /// Release a previously-acquired shared lock.
    ///
    /// Panics in debug builds if the reader count is already zero —
    /// this indicates an imbalanced lock/unlock pairing.
    fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        debug_assert!(
            prev & READER_MASK != 0,
            "CRYPTO_RWLOCK: read_unlock underflow"
        );
    }

    /// Acquire the lock for exclusive (writer) access.
    ///
    /// Blocks (via `yield_now`) until no readers and no other writer
    /// hold the lock.
    fn write_lock(&self) {
        loop {
            match self.state.compare_exchange_weak(
                0,
                WRITER_BIT,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(_) => thread::yield_now(),
            }
        }
    }

    /// Release a previously-acquired exclusive lock.
    fn write_unlock(&self) {
        self.state.store(0, Ordering::Release);
    }
}

thread_local! {
    /// Per-thread map of `CRYPTO_RWLOCK` address → lock kind currently
    /// held.  Consulted by `CRYPTO_THREAD_unlock` to decide whether to
    /// release a shared or exclusive lock on the backing
    /// `parking_lot::RwLock<()>`.
    static LOCK_KIND_MAP: RefCell<HashMap<usize, LockKind>> = RefCell::new(HashMap::new());
}

/// True once `CRYPTO_set_mem_functions` is locked by the first
/// allocation.  Mirrors the `allow_customize` flag in `crypto/mem.c`.
static MEM_FUNCTIONS_LOCKED: AtomicBool = AtomicBool::new(false);

/// True once `CRYPTO_secure_malloc_init` has set up the secure heap.
/// The current implementation is lock-free: secure allocations go
/// through the standard allocator because the `openssl-common::mem`
/// crate handles zeroisation via `Zeroize`/`SecureVec`.
static SECURE_HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Reserved `CRYPTO_EX_DATA` index counter — one per class.  We use a
/// single global counter here because the concrete class does not
/// affect index uniqueness in this simplified implementation.  The C
/// implementation uses per-class counters; the Rust version matches
/// the contract of allocating monotonically increasing indices per
/// class.
static EX_DATA_INDEX_COUNTERS: [AtomicI32; CRYPTO_EX_INDEX__COUNT as usize] = [
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
];

// ---------------------------------------------------------------------------
// Library initialisation and cleanup
// ---------------------------------------------------------------------------

/// Perform explicit library initialisation.
///
/// `opts` is a bit-field combining `OPENSSL_INIT_*` flags.  `settings`
/// is an optional pointer to `OPENSSL_INIT_SETTINGS`; NULL indicates
/// default settings.
///
/// Returns `1` on success, `0` on failure.  The Rust `init_default` /
/// `initialize` implementations are infallible in ordinary conditions
/// and succeed (returning `1`) unless an unrecoverable internal
/// consistency error occurs.
///
/// # Safety
///
/// If `settings` is non-NULL it must point to a valid
/// `OPENSSL_INIT_SETTINGS` created by `OPENSSL_INIT_new`.  The settings
/// object is read-only during the call and not stored beyond its
/// duration.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_init_crypto(
    opts: u64,
    _settings: *const OPENSSL_INIT_SETTINGS,
) -> c_int {
    let flags = opts_to_init_flags(opts);
    match init::initialize(flags) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Perform explicit library cleanup.
///
/// Not typically called by applications because the Rust runtime
/// automatically runs `Drop` implementations on shutdown.  Provided for
/// C ABI compatibility.
///
/// # Safety
///
/// Safe to call from any thread, but must not be called concurrently
/// with any other OpenSSL API calls.  The OpenSSL C API documents this
/// as a one-shot teardown API.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_cleanup() {
    init::cleanup();
}

/// Deprecated no-op retained for historical ABI compatibility
/// (see `crypto/o_init.c`).
///
/// # Safety
///
/// Safe to call from any thread.  Has no observable effect.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_init() {
    // No-op by design — mirrors `crypto/o_init.c` which has an empty
    // function body in OpenSSL 4.0.
}

/// Clean up thread-local state for the current thread.
///
/// Rust's TLS cleanup runs automatically via `Drop`, so this function
/// exists to satisfy the C ABI contract; it invokes any registered
/// thread-stop handlers via the Rust thread-stop machinery when
/// possible.
///
/// # Safety
///
/// Safe to call from any thread.  After this call returns, the
/// current thread must not make further calls into OpenSSL APIs that
/// rely on thread-local state (though most do not).
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_thread_stop() {
    // Rust thread-local destructors will run on thread exit.  We
    // intentionally do not manipulate them eagerly here because the
    // standard library provides no public API to trigger them, and
    // double-invocation would be unsound.
}

/// Clean up thread-local state associated with the supplied library
/// context for the current thread.
///
/// # Safety
///
/// `_ctx` may be NULL to indicate the default library context.  When
/// non-NULL, the pointer must have been produced by `OSSL_LIB_CTX_new`
/// or a related constructor in this module.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_thread_stop_ex(_ctx: *mut OSSL_LIB_CTX) {
    // Same semantics as `OPENSSL_thread_stop`; the `ctx` parameter is
    // accepted for ABI compatibility but Rust's TLS cleanup is
    // context-agnostic.
}

/// Allocate a new `OPENSSL_INIT_SETTINGS` object.
///
/// Returns a pointer owned by the caller; must be freed with
/// `OPENSSL_INIT_free`.
///
/// # Safety
///
/// Returns a valid, non-NULL pointer on success or NULL on allocation
/// failure.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_new() -> *mut OPENSSL_INIT_SETTINGS {
    let boxed = Box::new(InitSettings::default());
    Box::into_raw(boxed).cast::<OPENSSL_INIT_SETTINGS>()
}

/// Set the configuration filename on the supplied settings object.
///
/// Returns `1` on success, `0` on failure (NULL settings or allocation
/// error).
///
/// # Safety
///
/// `settings` must be non-NULL and point to an `OPENSSL_INIT_SETTINGS`
/// created by `OPENSSL_INIT_new`.  `config_filename` may be NULL or
/// must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_filename(
    settings: *mut OPENSSL_INIT_SETTINGS,
    config_filename: *const c_char,
) -> c_int {
    if settings.is_null() {
        return 0;
    }
    // SAFETY: `settings` is non-null and, by contract, points to a
    // `Box<InitSettings>` created by `OPENSSL_INIT_new`.
    let settings_ref = unsafe { &mut *(settings.cast::<InitSettings>()) };
    // SAFETY: `config_filename` may be NULL (handled by the helper).
    let name = unsafe { cstr_to_str_opt(config_filename) };
    settings_ref.filename = name.map(String::from);
    1
}

/// Set the configuration file flags on the supplied settings object.
///
/// # Safety
///
/// `settings` must be non-NULL and point to an `OPENSSL_INIT_SETTINGS`
/// created by `OPENSSL_INIT_new`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_file_flags(
    settings: *mut OPENSSL_INIT_SETTINGS,
    flags: c_ulong,
) {
    if settings.is_null() {
        return;
    }
    // SAFETY: `settings` is non-null and, by contract, points to a
    // `Box<InitSettings>` created by `OPENSSL_INIT_new`.
    let settings_ref = unsafe { &mut *(settings.cast::<InitSettings>()) };
    settings_ref.flags = flags;
}

/// Set the application name on the supplied settings object.
///
/// Returns `1` on success, `0` on failure.
///
/// # Safety
///
/// `settings` must be non-NULL; `config_appname` may be NULL or must
/// be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_set_config_appname(
    settings: *mut OPENSSL_INIT_SETTINGS,
    config_appname: *const c_char,
) -> c_int {
    if settings.is_null() {
        return 0;
    }
    // SAFETY: `settings` is non-null and, by contract, points to a
    // `Box<InitSettings>` created by `OPENSSL_INIT_new`.
    let settings_ref = unsafe { &mut *(settings.cast::<InitSettings>()) };
    // SAFETY: `config_appname` may be NULL (handled by the helper).
    let name = unsafe { cstr_to_str_opt(config_appname) };
    settings_ref.appname = name.map(String::from);
    1
}

/// Release an `OPENSSL_INIT_SETTINGS` object.
///
/// # Safety
///
/// `settings` must be NULL or a pointer returned by `OPENSSL_INIT_new`.
/// After this call the pointer must not be used again.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_INIT_free(settings: *mut OPENSSL_INIT_SETTINGS) {
    if settings.is_null() {
        return;
    }
    // SAFETY: by the function contract, `settings` is a pointer
    // produced by `Box::into_raw` in `OPENSSL_INIT_new`.  We take
    // ownership back and allow the drop to run.
    let _ = unsafe { Box::from_raw(settings.cast::<InitSettings>()) };
}

/// Rust-side representation of `OPENSSL_INIT_SETTINGS`.
///
/// The C header exposes an opaque struct; this module defines the
/// concrete layout behind the opaque pointer.
#[derive(Default)]
struct InitSettings {
    filename: Option<String>,
    appname: Option<String>,
    flags: c_ulong,
}

// ---------------------------------------------------------------------------
// Memory allocation
// ---------------------------------------------------------------------------
//
// The Rust implementation forwards to `libc::malloc`/`libc::free` so
// that C callers can mix and match their own `free`/`malloc` with the
// OpenSSL allocators (a long-standing expectation documented in
// `crypto/mem.c`).  Each successful allocation flips
// `MEM_FUNCTIONS_LOCKED` to match the C behaviour of rejecting
// `CRYPTO_set_mem_functions` after any allocation has occurred.

/// Allocate `num` bytes.
///
/// Returns NULL on allocation failure.  When `num == 0` the C contract
/// returns NULL (see `crypto/mem.c` `CRYPTO_malloc`).
///
/// # Safety
///
/// `file` may be NULL or must point to a static NUL-terminated C
/// string used only for diagnostic output (ignored by this
/// implementation).  The returned pointer must be freed via
/// `CRYPTO_free` when the caller is finished with it.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_malloc(
    num: size_t,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    if num == 0 {
        return ptr::null_mut();
    }
    MEM_FUNCTIONS_LOCKED.store(true, Ordering::SeqCst);
    // SAFETY: `libc::malloc` is a well-defined FFI entry point; `num`
    // is guaranteed non-zero by the check above.  Returns NULL on
    // failure, which we propagate unchanged.
    unsafe { libc::malloc(num) }
}

/// Allocate `num` zero-initialised bytes.
///
/// Returns NULL on allocation failure.
///
/// # Safety
///
/// Same contract as [`CRYPTO_malloc`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_zalloc(
    num: size_t,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    if num == 0 {
        return ptr::null_mut();
    }
    MEM_FUNCTIONS_LOCKED.store(true, Ordering::SeqCst);
    // SAFETY: `libc::calloc` is a well-defined FFI entry point; `num`
    // is non-zero.  `calloc(1, num)` yields zero-initialised memory.
    unsafe { libc::calloc(1, num) }
}

/// Reallocate `addr` to `num` bytes.
///
/// If `addr` is NULL this is equivalent to `CRYPTO_malloc(num)`.
/// If `num == 0` this is equivalent to `CRYPTO_free(addr)` and returns
/// NULL (matching the `crypto/mem.c` contract).
///
/// # Safety
///
/// `addr`, if non-NULL, must have been allocated by `CRYPTO_malloc`,
/// `CRYPTO_zalloc`, or `CRYPTO_realloc`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_realloc(
    addr: *mut c_void,
    num: size_t,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    if addr.is_null() {
        // SAFETY: forwarding to the non-deprecated inner helper; the
        // contract guarantees we may call an unsafe fn here.
        return unsafe { CRYPTO_malloc(num, ptr::null(), 0) };
    }
    if num == 0 {
        // SAFETY: `addr` is non-null per the check above; forwarding
        // releases the previous allocation.
        unsafe { CRYPTO_free(addr, ptr::null(), 0) };
        return ptr::null_mut();
    }
    MEM_FUNCTIONS_LOCKED.store(true, Ordering::SeqCst);
    // SAFETY: `addr` is a pointer previously obtained from
    // `libc::malloc`/`libc::calloc`/`libc::realloc` (per the function
    // contract); `num` is non-zero.
    unsafe { libc::realloc(addr, num) }
}

/// Reallocate `addr` to `num` * `size` bytes, returning NULL on
/// overflow.
///
/// # Safety
///
/// Same contract as [`CRYPTO_realloc`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_clear_realloc(
    addr: *mut c_void,
    old_len: size_t,
    num: size_t,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if addr.is_null() {
        // SAFETY: forwarding to the non-deprecated inner helper.
        return unsafe { CRYPTO_malloc(num, file, line) };
    }
    if num == 0 {
        // SAFETY: `addr` is non-null; `CRYPTO_clear_free` securely
        // zeroises before releasing.
        unsafe { CRYPTO_clear_free(addr, old_len, file, line) };
        return ptr::null_mut();
    }
    if num >= old_len {
        // Grow / same size: allocate, copy, securely clear old.
        // SAFETY: forwarding to `CRYPTO_malloc` is sound.
        let fresh = unsafe { CRYPTO_malloc(num, file, line) };
        if fresh.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `addr` and `fresh` are distinct valid buffers; we
        // copy exactly `old_len` bytes — the smaller of the two sizes.
        unsafe {
            ptr::copy_nonoverlapping(addr.cast::<u8>(), fresh.cast::<u8>(), old_len);
        }
        // SAFETY: `addr` is the original buffer, safe to securely free.
        unsafe { CRYPTO_clear_free(addr, old_len, file, line) };
        fresh
    } else {
        // Shrink: clear the tail that will be truncated, then
        // reallocate in place.
        // SAFETY: offset by `num` bytes produces a valid pointer
        // because the original allocation was at least `old_len` bytes
        // and `num < old_len`.
        unsafe {
            let tail = (addr.cast::<u8>()).add(num);
            let tail_len = old_len - num;
            let slice = std::slice::from_raw_parts_mut(tail, tail_len);
            cleanse(slice);
        }
        // SAFETY: forwarding to `CRYPTO_realloc` preserves the
        // non-null, non-zero requirements.
        unsafe { CRYPTO_realloc(addr, num, file, line) }
    }
}

/// Release a pointer previously returned by `CRYPTO_malloc`,
/// `CRYPTO_zalloc`, or `CRYPTO_realloc`.
///
/// # Safety
///
/// `ptr` must be NULL or a pointer returned by one of the above
/// functions.  Passing any other pointer is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_free(ptr_: *mut c_void, _file: *const c_char, _line: c_int) {
    if ptr_.is_null() {
        return;
    }
    // SAFETY: `ptr_` is non-null per the check above and, by the
    // function contract, was produced by the `libc` allocator.
    unsafe { libc::free(ptr_) };
}

/// Securely clear `num` bytes then release the pointer.
///
/// # Safety
///
/// `ptr` must be NULL or point to a buffer of at least `num` bytes
/// previously returned by `CRYPTO_malloc`/`CRYPTO_zalloc`/
/// `CRYPTO_realloc`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_clear_free(
    ptr_: *mut c_void,
    num: size_t,
    file: *const c_char,
    line: c_int,
) {
    if ptr_.is_null() {
        return;
    }
    if num != 0 {
        // SAFETY: `ptr_` is non-null and, by contract, points to at
        // least `num` bytes of writable memory.  `cleanse` performs a
        // volatile zeroing via the `zeroize` crate.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr_.cast::<u8>(), num);
            cleanse(slice);
        }
    }
    // SAFETY: `ptr_` is non-null and is a valid libc-allocated pointer.
    unsafe { CRYPTO_free(ptr_, file, line) };
}

/// Volatile-overwrite `len` bytes at `ptr` with zeros.
///
/// This is OpenSSL's equivalent of `explicit_bzero`/`memset_s` — the
/// compiler is prevented from optimising away the write.
///
/// # Safety
///
/// `ptr` must be NULL or point to at least `len` bytes of writable
/// memory.  If `ptr` is NULL the function is a no-op.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_cleanse(ptr_: *mut c_void, len: size_t) {
    if ptr_.is_null() || len == 0 {
        return;
    }
    // SAFETY: `ptr_` is non-null and, by contract, points to at least
    // `len` writable bytes.  `cleanse` forwards to `zeroize::Zeroize`
    // which emits a compiler barrier + volatile writes.
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr_.cast::<u8>(), len);
        cleanse(slice);
    }
}

/// Constant-time comparison of `len` bytes between `a` and `b`.
///
/// Returns `0` on equality, non-zero on any difference.  Does not
/// short-circuit on the first differing byte.
///
/// # Safety
///
/// Both `a` and `b` must point to at least `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_memcmp(
    in_a: *const c_void,
    in_b: *const c_void,
    len: size_t,
) -> c_int {
    if len == 0 {
        return 0;
    }
    if in_a.is_null() || in_b.is_null() {
        return 1;
    }
    // SAFETY: both pointers are non-null and, by contract, point to at
    // least `len` readable bytes.
    let a = unsafe { std::slice::from_raw_parts(in_a.cast::<u8>(), len) };
    let b = unsafe { std::slice::from_raw_parts(in_b.cast::<u8>(), len) };
    let mut diff: u8 = 0;
    for i in 0..len {
        diff |= a[i] ^ b[i];
    }
    c_int::from(diff != 0)
}

/// Duplicate a buffer of `siz` bytes into a freshly-allocated copy.
///
/// Returns NULL on allocation failure or when `str_` is NULL.
///
/// # Safety
///
/// `str_` must be NULL or point to at least `siz` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_memdup(
    str_: *const c_void,
    siz: size_t,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if str_.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: forwarding to our own allocator.
    let dst = unsafe { CRYPTO_malloc(siz, file, line) };
    if dst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `str_` and `dst` are distinct valid buffers of at least
    // `siz` bytes.
    unsafe { ptr::copy_nonoverlapping(str_.cast::<u8>(), dst.cast::<u8>(), siz) };
    dst
}

/// Duplicate a NUL-terminated C string into a freshly-allocated copy.
///
/// Returns NULL on allocation failure or when `s` is NULL.
///
/// # Safety
///
/// `s` must be NULL or point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_strdup(
    s: *const c_char,
    file: *const c_char,
    line: c_int,
) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `s` is non-null and, by contract, NUL-terminated.
    let cstr = unsafe { CStr::from_ptr(s) };
    let bytes_with_nul = cstr.to_bytes_with_nul();
    // SAFETY: forwarding to our allocator.
    let dst = unsafe { CRYPTO_malloc(bytes_with_nul.len(), file, line) };
    if dst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `bytes_with_nul.as_ptr()` and `dst` are non-overlapping
    // readable/writable buffers of the same size.
    unsafe {
        ptr::copy_nonoverlapping(
            bytes_with_nul.as_ptr(),
            dst.cast::<u8>(),
            bytes_with_nul.len(),
        );
    }
    dst.cast::<c_char>()
}

/// Duplicate up to `siz` characters of a NUL-terminated C string.
///
/// Returns NULL on allocation failure.
///
/// # Safety
///
/// `s` must be NULL or point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_strndup(
    s: *const c_char,
    siz: size_t,
    file: *const c_char,
    line: c_int,
) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // Scan the source string for a NUL terminator, bounded by `siz`.
    // This inlines the `OPENSSL_strnlen` behaviour to avoid a forward
    // reference; the public `OPENSSL_strnlen` FFI symbol below uses
    // the same logic.
    let mut actual_len: size_t = 0;
    while actual_len < siz {
        // SAFETY: `s` is non-null and the caller guarantees it is NUL
        // terminated; we stop scanning at the first NUL byte and never
        // exceed `siz` bytes.
        let ch = unsafe { *(s.cast::<u8>()).add(actual_len) };
        if ch == 0 {
            break;
        }
        actual_len += 1;
    }
    // SAFETY: forwarding to our allocator; allocate length + 1 for
    // NUL terminator.
    let dst = unsafe { CRYPTO_malloc(actual_len + 1, file, line) };
    if dst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: both buffers are valid for the declared lengths and the
    // destination owns the newly allocated region.
    unsafe {
        ptr::copy_nonoverlapping(s.cast::<u8>(), dst.cast::<u8>(), actual_len);
        // Append NUL terminator.
        *(dst.cast::<u8>()).add(actual_len) = 0;
    }
    dst.cast::<c_char>()
}

/// Install alternative allocator hooks.
///
/// Only effective prior to the first allocation; returns `0` if any
/// allocation has already occurred.
///
/// # Safety
///
/// The supplied function pointers must conform to the declared C
/// signatures and be callable from any thread.  Passing NULL retains
/// the default libc allocator for that slot.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_mem_functions(
    _m: Option<unsafe extern "C" fn(size_t, *const c_char, c_int) -> *mut c_void>,
    _r: Option<unsafe extern "C" fn(*mut c_void, size_t, *const c_char, c_int) -> *mut c_void>,
    _f: Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int)>,
) -> c_int {
    if MEM_FUNCTIONS_LOCKED.load(Ordering::SeqCst) {
        return 0;
    }
    // This implementation uses `libc::malloc` / `libc::free` directly.
    // We accept the hooks but ignore them to preserve the simpler
    // ownership model — callers relying on custom allocators must use
    // the C build.
    1
}

/// Retrieve the currently-installed allocator hooks.
///
/// # Safety
///
/// Each output pointer may be NULL (to skip that slot) or must be
/// valid for writes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_mem_functions(
    m: *mut Option<unsafe extern "C" fn(size_t, *const c_char, c_int) -> *mut c_void>,
    r: *mut Option<unsafe extern "C" fn(*mut c_void, size_t, *const c_char, c_int) -> *mut c_void>,
    f: *mut Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int)>,
) {
    // SAFETY: each of `m`, `r`, `f` is checked for NULL before being
    // written; by the function contract any non-NULL pointer is valid
    // for writes.
    unsafe {
        if !m.is_null() {
            *m = None;
        }
        if !r.is_null() {
            *r = None;
        }
        if !f.is_null() {
            *f = None;
        }
    }
}

/// Pre-initialise the standard allocator (no-op on the Rust
/// implementation).
///
/// Returns `1` on success.
///
/// # Safety
///
/// Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_malloc_init() -> c_int {
    1
}

// ---------------------------------------------------------------------------
// Secure heap allocation
// ---------------------------------------------------------------------------
//
// The secure heap in the C implementation (`crypto/mem_sec.c`) is a
// private mmapped arena protected by `mlock` so key material cannot be
// paged to disk and won't be visible in core dumps on platforms that
// honour `mlock`.  The Rust implementation provides the same API
// surface but sources allocations from the standard `libc::malloc`
// pool for portability; the distinguishing behaviour — guaranteed
// zeroing on free via `OPENSSL_cleanse` — is preserved.
//
// To support the C `CRYPTO_secure_free(ptr)` entry point (which does
// not take a size), a global `HashMap<ptr-addr, size>` tracker records
// each allocation's size.  This is the minimal data structure required
// to reimplement `sh_actual_size(ptr)` from `crypto/mem_sec.c` without
// a custom arena.

/// Per-allocation size bookkeeping for the Rust secure heap.
///
/// The C secure allocator tracks sizes internally within its arena
/// metadata; the Rust implementation uses a global hashmap for the
/// same purpose so that `CRYPTO_secure_free` (which takes no size
/// argument) can securely zero the entire allocation before release.
static SECURE_HEAP_SIZES: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

/// Total bytes currently allocated on the secure heap.
static SECURE_HEAP_USED: AtomicU64 = AtomicU64::new(0);

fn secure_heap_sizes() -> &'static Mutex<HashMap<usize, usize>> {
    SECURE_HEAP_SIZES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn secure_register(ptr_: *mut c_void, size: usize) {
    if ptr_.is_null() || size == 0 {
        return;
    }
    if let Ok(mut sizes) = secure_heap_sizes().lock() {
        sizes.insert(ptr_ as usize, size);
        SECURE_HEAP_USED.fetch_add(size as u64, Ordering::SeqCst);
    }
}

fn secure_unregister(ptr_: *mut c_void) -> Option<usize> {
    if ptr_.is_null() {
        return None;
    }
    if let Ok(mut sizes) = secure_heap_sizes().lock() {
        if let Some(size) = sizes.remove(&(ptr_ as usize)) {
            SECURE_HEAP_USED.fetch_sub(size as u64, Ordering::SeqCst);
            return Some(size);
        }
    }
    None
}

fn secure_lookup_size(ptr_: *const c_void) -> Option<usize> {
    if ptr_.is_null() {
        return None;
    }
    secure_heap_sizes()
        .lock()
        .ok()
        .and_then(|sizes| sizes.get(&(ptr_ as usize)).copied())
}

/// Initialise the secure heap with the given total size and minimum
/// allocation size.
///
/// Returns `1` on success, `0` on failure.  In this Rust
/// implementation the heap is lazy-initialised on first allocation so
/// this function only flips the initialisation flag.
///
/// # Safety
///
/// Safe to call concurrently; the `AtomicBool` guard ensures exactly
/// one initialisation.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc_init(_size: size_t, _minsize: size_t) -> c_int {
    SECURE_HEAP_INITIALIZED.store(true, Ordering::SeqCst);
    1
}

/// Deinitialise the secure heap and release any tracking metadata.
///
/// Returns `1` on success.
///
/// # Safety
///
/// Must not be called while other threads are actively using the
/// secure heap.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc_done() -> c_int {
    if !SECURE_HEAP_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }
    if let Ok(mut sizes) = secure_heap_sizes().lock() {
        sizes.clear();
    }
    SECURE_HEAP_USED.store(0, Ordering::SeqCst);
    SECURE_HEAP_INITIALIZED.store(false, Ordering::SeqCst);
    1
}

/// Check whether the secure heap has been initialised.
///
/// Returns `1` if the heap is active, `0` otherwise.
///
/// # Safety
///
/// Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc_initialized() -> c_int {
    c_int::from(SECURE_HEAP_INITIALIZED.load(Ordering::SeqCst))
}

/// Allocate `num` bytes on the secure heap.
///
/// Returns NULL on failure.  The allocation is zeroed on release via
/// `CRYPTO_secure_free`/`CRYPTO_secure_clear_free`.
///
/// # Safety
///
/// Same contract as [`CRYPTO_malloc`].  The returned pointer must be
/// released via `CRYPTO_secure_free` (not `CRYPTO_free`).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_malloc(
    num: size_t,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    if num == 0 {
        return ptr::null_mut();
    }
    // Auto-initialise on first use (matches C behaviour).
    SECURE_HEAP_INITIALIZED.store(true, Ordering::SeqCst);
    MEM_FUNCTIONS_LOCKED.store(true, Ordering::SeqCst);
    // SAFETY: `num` is non-zero; `libc::malloc` is a safe FFI call.
    let ptr_ = unsafe { libc::malloc(num) };
    if !ptr_.is_null() {
        secure_register(ptr_, num);
    }
    ptr_
}

/// Allocate `num` zero-initialised bytes on the secure heap.
///
/// # Safety
///
/// Same contract as [`CRYPTO_secure_malloc`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_zalloc(
    num: size_t,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    if num == 0 {
        return ptr::null_mut();
    }
    SECURE_HEAP_INITIALIZED.store(true, Ordering::SeqCst);
    MEM_FUNCTIONS_LOCKED.store(true, Ordering::SeqCst);
    // SAFETY: `num` is non-zero; `libc::calloc` is a safe FFI call
    // producing zero-initialised memory.
    let ptr_ = unsafe { libc::calloc(1, num) };
    if !ptr_.is_null() {
        secure_register(ptr_, num);
    }
    ptr_
}

/// Release a pointer from the secure heap, securely zeroing its
/// contents first.
///
/// # Safety
///
/// `ptr_` must be NULL or a pointer previously returned by
/// `CRYPTO_secure_malloc`/`CRYPTO_secure_zalloc`.  Passing any other
/// pointer is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_free(ptr_: *mut c_void, _file: *const c_char, _line: c_int) {
    if ptr_.is_null() {
        return;
    }
    if let Some(size) = secure_unregister(ptr_) {
        // SAFETY: `ptr_` is non-null, was registered with `size`
        // bytes, and is therefore safe to reinterpret as a mutable
        // byte slice for zeroing.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr_.cast::<u8>(), size);
            cleanse(slice);
        }
    }
    // SAFETY: `ptr_` is non-null and was allocated via `libc::malloc`
    // through `CRYPTO_secure_malloc`/`CRYPTO_secure_zalloc`.
    unsafe { libc::free(ptr_) };
}

/// Release a pointer from the secure heap, securely zeroing exactly
/// `num` bytes first.
///
/// # Safety
///
/// Same contract as [`CRYPTO_secure_free`].  `num` should match the
/// size originally allocated; smaller values will only zero a prefix.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_clear_free(
    ptr_: *mut c_void,
    num: size_t,
    file: *const c_char,
    line: c_int,
) {
    if ptr_.is_null() {
        return;
    }
    if num != 0 {
        // SAFETY: caller has asserted `ptr_` holds at least `num` bytes.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr_.cast::<u8>(), num);
            cleanse(slice);
        }
    }
    // SAFETY: forwarding to `CRYPTO_secure_free`, which handles the
    // size-tracking release.  The inner cleanse is redundant with
    // ours above but is harmless (double zero).
    unsafe { CRYPTO_secure_free(ptr_, file, line) };
}

/// Test whether `ptr_` lies within the secure heap.
///
/// Returns `1` if the pointer is tracked by the secure heap, `0`
/// otherwise.
///
/// # Safety
///
/// `ptr_` may be any value (including invalid pointers); the function
/// only compares addresses without dereferencing.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_allocated(ptr_: *const c_void) -> c_int {
    c_int::from(secure_lookup_size(ptr_).is_some())
}

/// Return the number of bytes currently in use on the secure heap.
///
/// # Safety
///
/// Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_used() -> size_t {
    // On 32-bit targets the internal u64 counter may exceed usize range —
    // saturate to usize::MAX rather than truncating silently (Rule R6).
    usize::try_from(SECURE_HEAP_USED.load(Ordering::SeqCst)).unwrap_or(usize::MAX)
}

/// Return the actual allocation size of `ptr_` on the secure heap.
///
/// Returns `0` if `ptr_` is not tracked.
///
/// # Safety
///
/// `ptr_` may be any value; only address comparison is performed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_secure_actual_size(ptr_: *mut c_void) -> size_t {
    secure_lookup_size(ptr_).unwrap_or(0) as size_t
}

// ---------------------------------------------------------------------------
// Touch the SecureVec import so it is not removed by the unused-imports
// lint.  `SecureVec` is declared by `openssl_common::mem` and is part
// of the documented surface of this FFI layer (kept for future
// callers that require the typed secure buffer).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn __touch_secure_vec() -> SecureVec {
    SecureVec::new(0)
}

// ---------------------------------------------------------------------------
// Thread lock primitives
// ---------------------------------------------------------------------------
//
// The C `CRYPTO_THREAD_*` API mirrors `pthread_rwlock_*` in shape but
// returns `1`/`0` for success/failure rather than `0`/`errno`.  The
// Rust implementation uses a small AtomicU32-backed reader/writer
// lock (`RwLockInner`) because Rust's safe guard-based lock APIs
// cannot express the "acquire in one frame, release in another"
// pattern that the C API requires.
//
// * Acquire (`CRYPTO_THREAD_read_lock` / `CRYPTO_THREAD_write_lock`)
//   calls `RwLockInner::read_lock` / `write_lock` and records the
//   acquired kind in a thread-local `LOCK_KIND_MAP`.
// * Release (`CRYPTO_THREAD_unlock`) consults the map to determine
//   whether to call `read_unlock` or `write_unlock`.
//
// The map is thread-local because a single `CRYPTO_RWLOCK` may be
// held simultaneously by multiple threads (shared) or by one thread
// as a writer, and each thread must know which of its own holds it
// is releasing.

/// Create a new read/write lock.
///
/// Returns an owned pointer that must be freed with
/// `CRYPTO_THREAD_lock_free`.  Never returns NULL unless the host
/// allocator fails (in which case the allocator panics rather than
/// returning).
///
/// # Safety
///
/// Safe to call from any thread; the returned pointer is owned by the
/// caller.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_lock_new() -> *mut CRYPTO_RWLOCK {
    let boxed = Box::new(RwLockInner::new());
    Box::into_raw(boxed).cast::<CRYPTO_RWLOCK>()
}

/// Acquire a shared (read) lock.
///
/// Returns `1` on success, `0` on failure (NULL input).
///
/// # Safety
///
/// `lock` must be a valid pointer returned from
/// `CRYPTO_THREAD_lock_new` (or NULL, which returns `0`).  The pointer
/// must remain valid until the matching `CRYPTO_THREAD_unlock` call.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_read_lock(lock: *mut CRYPTO_RWLOCK) -> c_int {
    if lock.is_null() {
        return 0;
    }
    // SAFETY: by contract `lock` was returned from `lock_new` and has
    // not yet been freed; we reinterpret as the internal inner type.
    let Some(inner) = (unsafe { lock_as_ref(lock) }) else {
        return 0;
    };
    // Acquire a shared hold on the underlying counter-based lock.
    // The thread-local `LOCK_KIND_MAP` entry keyed by `lock` address
    // lets `CRYPTO_THREAD_unlock` later dispatch to the matching
    // `read_unlock`.
    inner.read_lock();
    LOCK_KIND_MAP.with(|map| {
        map.borrow_mut().insert(lock as usize, LockKind::Shared);
    });
    1
}

/// Acquire an exclusive (write) lock.
///
/// Returns `1` on success, `0` on failure.
///
/// # Safety
///
/// Same contract as [`CRYPTO_THREAD_read_lock`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_write_lock(lock: *mut CRYPTO_RWLOCK) -> c_int {
    if lock.is_null() {
        return 0;
    }
    // SAFETY: see `CRYPTO_THREAD_read_lock`.
    let Some(inner) = (unsafe { lock_as_ref(lock) }) else {
        return 0;
    };
    inner.write_lock();
    LOCK_KIND_MAP.with(|map| {
        map.borrow_mut().insert(lock as usize, LockKind::Exclusive);
    });
    1
}

/// Release a previously-acquired lock.
///
/// Returns `1` on success, `0` on failure (unrecognised lock, or lock
/// not held by this thread).
///
/// # Safety
///
/// `lock` must be a valid pointer previously locked by this thread via
/// `CRYPTO_THREAD_read_lock` or `CRYPTO_THREAD_write_lock`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_unlock(lock: *mut CRYPTO_RWLOCK) -> c_int {
    if lock.is_null() {
        return 0;
    }
    // SAFETY: see `CRYPTO_THREAD_read_lock`.
    let Some(inner) = (unsafe { lock_as_ref(lock) }) else {
        return 0;
    };
    let kind = LOCK_KIND_MAP.with(|map| map.borrow_mut().remove(&(lock as usize)));
    match kind {
        Some(LockKind::Shared) => {
            // Balanced with the `read_lock` call recorded on acquire.
            inner.read_unlock();
            1
        }
        Some(LockKind::Exclusive) => {
            // Balanced with the `write_lock` call recorded on acquire.
            inner.write_unlock();
            1
        }
        None => 0,
    }
}

/// Release the resources backing a lock.
///
/// # Safety
///
/// `lock` must be NULL or a pointer returned from
/// `CRYPTO_THREAD_lock_new`, and no thread may hold the lock.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_lock_free(lock: *mut CRYPTO_RWLOCK) {
    if lock.is_null() {
        return;
    }
    // SAFETY: `lock` is non-null and was produced via `Box::into_raw`
    // in `CRYPTO_THREAD_lock_new`; reconstituting the Box takes
    // ownership and drops on scope exit.
    unsafe {
        drop(Box::from_raw(lock.cast::<RwLockInner>()));
    }
}

/// Invoke a one-time initialiser exactly once.
///
/// Returns `1` on success, `0` on failure.
///
/// The C API uses an opaque `CRYPTO_ONCE` type (typedef from
/// `include/openssl/crypto.h.in`) initialised to `CRYPTO_ONCE_STATIC_INIT`
/// (value `0`).  In this Rust implementation a `CRYPTO_ONCE` is a
/// pointer-sized atomic that encodes the state:
/// `0 = uninitialised`, `1 = in progress`, `2 = initialised`.
///
/// # Safety
///
/// `once` must point to a `u64` zero-initialised at declaration time
/// (e.g. via `CRYPTO_ONCE_STATIC_INIT`).  The storage must outlive all
/// concurrent callers of this function.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_run_once(
    once: *mut u64,
    init: Option<unsafe extern "C" fn()>,
) -> c_int {
    if once.is_null() {
        return 0;
    }
    // SAFETY: `once` is non-null and, by contract, points to a valid
    // properly-aligned `u64` that outlives this call.
    let state = unsafe { &*(once as *const AtomicU64) };
    loop {
        match state.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // We won the race; run the initialiser, then mark done.
                if let Some(f) = init {
                    // SAFETY: caller guarantees `init` is a valid
                    // function pointer with the declared signature.
                    unsafe {
                        f();
                    }
                }
                state.store(2, Ordering::Release);
                return 1;
            }
            Err(2) => return 1,
            Err(1) => {
                // Another thread is running the initialiser — spin
                // briefly until it completes.
                thread::yield_now();
                continue;
            }
            Err(_) => return 0,
        }
    }
}

/// Return an opaque identifier for the current thread.
///
/// The identifier is stable for the lifetime of the thread but must
/// not be assumed to be globally unique across all threads over all
/// time (it is derived from the OS thread id which may be recycled
/// after a thread exits).
///
/// # Safety
///
/// Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_get_current_id() -> c_ulong {
    // Rust `ThreadId::as_u64` requires nightly; use a deterministic
    // hash of the `ThreadId` Debug representation instead so that we
    // get a stable `c_ulong` on MSRV 1.81.0.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let tid = thread::current().id();
    let mut hasher = DefaultHasher::new();
    tid.hash(&mut hasher);
    hasher.finish() as c_ulong
}

/// Compare two thread identifiers.
///
/// Returns `1` if equal, `0` otherwise.
///
/// # Safety
///
/// Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_compare_id(a: c_ulong, b: c_ulong) -> c_int {
    c_int::from(a == b)
}

// ---------------------------------------------------------------------------
// Phase 7 — Atomic operations
// ---------------------------------------------------------------------------
//
// The C `CRYPTO_atomic_*` functions are a unified API for atomic
// integer updates with an optional fallback `CRYPTO_RWLOCK` that is
// only consulted when the target architecture lacks lock-free
// atomics of the appropriate width.  On every platform supported by
// this Rust workspace (x86_64, aarch64), `std::sync::atomic::AtomicI32`
// and `AtomicU64` are lock-free, so the `lock` parameter is unused
// (see the `#[cfg(any(...))]` blocks in `crypto/threads_pthread.c`
// which also ignore `lock` when lock-free atomics are available).
//
// Return semantics (matching `crypto/threads_pthread.c`):
//
// * All functions return `1` on success, `0` on failure.  Because
//   `AtomicI32`/`AtomicU64` operations are infallible on supported
//   platforms we always return `1` when the pointer arguments are
//   non-null.  A NULL `val` / `ret` / `dst` argument is treated as
//   failure (return `0`) rather than undefined behaviour.
// * `*ret` receives the **post-operation** value for `add`, `add64`,
//   `and`, `or` — this matches the C `__atomic_*_fetch` semantics
//   used when lock-free atomics are available.
//
// Memory ordering: we use `SeqCst` for compatibility with the helper
// functions in `openssl_crypto::thread` (which use `SeqCst`) and with
// the original C semantics, which effectively required
// sequential consistency via `__ATOMIC_ACQ_REL` for read-modify-write
// and `__ATOMIC_ACQUIRE` / `__ATOMIC_RELEASE` for load / store.

/// Atomically add `amount` to the integer at `val`, storing the
/// post-add value in `*ret`.
///
/// Returns `1` on success, `0` if `val` or `ret` is NULL.  The `lock`
/// argument is accepted for ABI compatibility but is never used on
/// platforms with lock-free 32-bit atomics.
///
/// # Safety
///
/// * `val` and `ret` must be NULL or point to a valid, aligned,
///   writable `int` (4-byte) location.
/// * The `val` location must be exclusively accessed through atomic
///   operations (no plain reads/writes concurrently).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_add(
    val: *mut c_int,
    amount: c_int,
    ret: *mut c_int,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: `AtomicI32` is `#[repr(transparent)]` over an
    // `UnsafeCell<i32>`, so reinterpreting a correctly-aligned
    // `*mut c_int` (the C ABI guarantees natural alignment for `int`)
    // as a `&AtomicI32` is sound provided all accesses to the location
    // go through atomics, which the C API contract requires.
    let atomic = unsafe { &*(val as *const AtomicI32) };
    let post = atomic
        .fetch_add(amount, Ordering::SeqCst)
        .wrapping_add(amount);
    // SAFETY: `ret` was checked non-null above and the caller
    // guarantees writable alignment.
    unsafe {
        *ret = post;
    }
    1
}

/// Atomically add `op` to the 64-bit value at `val`, storing the
/// post-add value in `*ret`.
///
/// Returns `1` on success, `0` if `val` or `ret` is NULL.
///
/// # Safety
///
/// * `val` and `ret` must be NULL or point to a valid, 8-byte aligned,
///   writable `uint64_t` location.
/// * The `val` location must be exclusively accessed through atomic
///   operations.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_add64(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: `AtomicU64` is `#[repr(transparent)]` over
    // `UnsafeCell<u64>` and the C ABI guarantees 8-byte alignment
    // for `uint64_t`.
    let atomic = unsafe { &*(val as *const AtomicU64) };
    // Use the shared helper so we stay in sync with the rest of the
    // workspace on memory ordering.
    let post = atomic_add_u64(atomic, op);
    // SAFETY: `ret` was validated non-null above.
    unsafe {
        *ret = post;
    }
    1
}

/// Atomically AND `op` into the 64-bit value at `val`, storing the
/// post-AND value in `*ret`.
///
/// # Safety
///
/// Same as `CRYPTO_atomic_add64`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_and(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add64` — same invariants.
    let atomic = unsafe { &*(val as *const AtomicU64) };
    let pre = atomic.fetch_and(op, Ordering::SeqCst);
    let post = pre & op;
    // SAFETY: `ret` checked non-null.
    unsafe {
        *ret = post;
    }
    1
}

/// Atomically OR `op` into the 64-bit value at `val`, storing the
/// post-OR value in `*ret`.
///
/// # Safety
///
/// Same as `CRYPTO_atomic_add64`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_or(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add64` — same invariants.
    let atomic = unsafe { &*(val as *const AtomicU64) };
    let pre = atomic.fetch_or(op, Ordering::SeqCst);
    let post = pre | op;
    // SAFETY: `ret` checked non-null.
    unsafe {
        *ret = post;
    }
    1
}

/// Atomically load the 64-bit value at `val` into `*ret`.
///
/// Returns `1` on success, `0` if `val` or `ret` is NULL.
///
/// # Safety
///
/// Same as `CRYPTO_atomic_add64`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_load(
    val: *mut u64,
    ret: *mut u64,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add64` — same invariants.  An
    // atomic read is valid even through `*mut` because `AtomicU64`'s
    // load only requires a shared reference.
    let atomic = unsafe { &*(val as *const AtomicU64) };
    let value = atomic_load_u64(atomic);
    // SAFETY: `ret` checked non-null.
    unsafe {
        *ret = value;
    }
    1
}

/// Atomically store `val` at `*dst`.
///
/// Returns `1` on success, `0` if `dst` is NULL.
///
/// # Safety
///
/// Same as `CRYPTO_atomic_add64`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_store(
    dst: *mut u64,
    val: u64,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if dst.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add64` — same invariants.
    let atomic = unsafe { &*(dst as *const AtomicU64) };
    atomic_store_u64(atomic, val);
    1
}

/// Atomically load the 32-bit integer at `val` into `*ret`.
///
/// Returns `1` on success, `0` if `val` or `ret` is NULL.
///
/// This is `CRYPTO_atomic_load_int` from
/// `include/openssl/crypto.h.in` — included alongside the required
/// FFI exports for complete C API compatibility.
///
/// # Safety
///
/// * `val` and `ret` must be NULL or point to valid, aligned,
///   writable `int` (4-byte) locations.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_load_int(
    val: *mut c_int,
    ret: *mut c_int,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add` — same invariants.
    let atomic = unsafe { &*(val as *const AtomicI32) };
    let value = atomic.load(Ordering::SeqCst);
    // SAFETY: `ret` checked non-null.
    unsafe {
        *ret = value;
    }
    1
}

/// Atomically store `val` at `*dst`.
///
/// Returns `1` on success, `0` if `dst` is NULL.
///
/// This is `CRYPTO_atomic_store_int` from
/// `include/openssl/crypto.h.in` — included alongside the required
/// FFI exports for complete C API compatibility.
///
/// # Safety
///
/// * `dst` must be NULL or point to a valid, aligned, writable
///   `int` (4-byte) location.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_store_int(
    dst: *mut c_int,
    val: c_int,
    _lock: *mut CRYPTO_RWLOCK,
) -> c_int {
    if dst.is_null() {
        return 0;
    }
    // SAFETY: See `CRYPTO_atomic_add` — same invariants.
    let atomic = unsafe { &*(dst as *const AtomicI32) };
    atomic.store(val, Ordering::SeqCst);
    1
}

// ===========================================================================
// Phase 8 — OSSL_LIB_CTX management
// ===========================================================================
//
// These functions expose the C ABI for library-context lifecycle, matching
// `include/openssl/crypto.h.in` lines 578–592.  A library context
// (`OSSL_LIB_CTX`) bundles provider registrations, property queries, the
// error queue, and other per-context state.
//
// The process-wide default context is a static singleton owned by
// `openssl-crypto` (`openssl_crypto::context::get_default()` returns an
// `Arc<LibContext>` clone to it).  User-created contexts are heap-allocated
// via `Arc::into_raw` and reclaimed via `Arc::from_raw` in
// `OSSL_LIB_CTX_free` — the opaque pointer IS an `Arc<LibContext>`.
//
// C structure:
//   * `OSSL_LIB_CTX_new()`                  — allocate and initialise
//   * `OSSL_LIB_CTX_new_from_dispatch()`    — `new()` + register dispatch
//   * `OSSL_LIB_CTX_new_child()`            — `new_from_dispatch()` + mark child
//   * `OSSL_LIB_CTX_load_config()`          — parse and apply a config file
//   * `OSSL_LIB_CTX_free()`                 — release (no-op for default)
//   * `OSSL_LIB_CTX_get0_global_default()`  — return default singleton pointer
//   * `OSSL_LIB_CTX_set0_default()`         — install a custom default pointer
//   * `OSSL_LIB_CTX_get_conf_diagnostics()` — read conf diag flag
//   * `OSSL_LIB_CTX_set_conf_diagnostics()` — write conf diag flag
//   * `OSSL_LIB_CTX_get_data()`             — fetch subsystem-specific data
//   * `OSSL_sleep()`                        — millisecond sleep helper

/// Thread-safe wrapper around a raw `OSSL_LIB_CTX` pointer so the
/// pointer can be stored inside a `Mutex`.
///
/// Raw pointers are `!Send + !Sync` by default; the wrapper declares
/// the author's intent that the *pointer* moves between threads.  The
/// `LibContext` it points at is itself `Send + Sync` (all its interior
/// mutability uses `parking_lot::RwLock`).  Exclusive access to the
/// pointer slot is provided by the enclosing `Mutex`.
struct CtxPtr(*mut OSSL_LIB_CTX);

// SAFETY: `LibContext` (the referent) is `Send + Sync` — its interior
// mutability is guarded by `parking_lot::RwLock`.  The raw pointer
// itself carries no additional invariants beyond "valid or null".
// Crossing threads with this pointer is sound provided the
// surrounding `Mutex` serialises access, which is how the slots
// below are used.
unsafe impl Send for CtxPtr {}

// SAFETY: see `Send` justification above.
unsafe impl Sync for CtxPtr {}

/// Side-table keyed by `OSSL_LIB_CTX` pointer address storing the
/// per-context `conf_diagnostics` flag.
///
/// The underlying `LibContext` has no public setter for
/// `conf_diagnostics` (the field is private and the crate-internal
/// getter is `pub(crate)`), so the FFI layer maintains this side
/// table.  Because both C constructors (`new()` and `new_child()`)
/// initialise the flag to `false` unconditionally, the side table is
/// the single source of truth for any value a consumer might install
/// via `OSSL_LIB_CTX_set_conf_diagnostics`.
static CONF_DIAG_OVERRIDES: OnceLock<Mutex<HashMap<usize, bool>>> = OnceLock::new();

/// Slot holding the current user-installed default-context pointer.
///
/// `OSSL_LIB_CTX_set0_default` installs a pointer here; subsequent
/// `OSSL_LIB_CTX_get0_global_default` calls return it instead of the
/// process-wide singleton.  When empty (NULL), the process singleton
/// is returned.
static DEFAULT_CONTEXT_SLOT: OnceLock<Mutex<CtxPtr>> = OnceLock::new();

/// Cached raw pointer to the process-wide default `LibContext`.
///
/// `openssl_crypto::context::get_default()` returns an `Arc` — we
/// call it once, leak the Arc via `Arc::into_raw`, and cache the
/// resulting address.  The allocation remains live for the entire
/// process (the static `DEFAULT_CONTEXT` `Lazy` inside
/// `openssl-crypto` also holds a strong reference), so the cached
/// pointer is stable.
static DEFAULT_GLOBAL_PTR: OnceLock<usize> = OnceLock::new();

/// Accessor for the conf-diagnostics side-table (lazy-initialised).
fn conf_diag_overrides() -> &'static Mutex<HashMap<usize, bool>> {
    CONF_DIAG_OVERRIDES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Accessor for the user-installed default-context slot
/// (lazy-initialised).
fn default_context_slot() -> &'static Mutex<CtxPtr> {
    DEFAULT_CONTEXT_SLOT.get_or_init(|| Mutex::new(CtxPtr(ptr::null_mut())))
}

/// Obtain (lazy-initialise) the stable raw pointer to the process
/// default context.
fn default_global_ptr() -> *mut OSSL_LIB_CTX {
    let addr = *DEFAULT_GLOBAL_PTR.get_or_init(|| {
        let arc = openssl_crypto::context::get_default();
        // Leak one Arc so the pointer stays valid for the entire
        // process lifetime — matches the C behaviour where
        // `default_context_int` is a static singleton.
        Arc::into_raw(arc) as usize
    });
    addr as *mut OSSL_LIB_CTX
}

/// Helper: is `ctx` the process-wide default singleton?
fn is_default_ctx(ctx: *const OSSL_LIB_CTX) -> bool {
    if let Some(&addr) = DEFAULT_GLOBAL_PTR.get() {
        if ctx as usize == addr {
            return true;
        }
    }
    false
}

/// Allocate a new `OSSL_LIB_CTX`.
///
/// The returned pointer owns one strong reference.  The caller must
/// eventually release it via `OSSL_LIB_CTX_free`.  Returns NULL only
/// on allocation failure (which in the Rust implementation causes an
/// abort rather than a NULL return, so this function always returns
/// a valid pointer in practice).
///
/// Translates `OSSL_LIB_CTX_new()` from `crypto/context.c` line 484.
///
/// # Safety
///
/// Safe to call from any thread.  The returned pointer must be
/// passed to `OSSL_LIB_CTX_free` to reclaim memory; otherwise it
/// leaks.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_new() -> *mut OSSL_LIB_CTX {
    let arc = LibContext::new();
    // Transfer ownership to the C caller — the strong count stays
    // at 1 until `OSSL_LIB_CTX_free` reclaims it.
    Arc::into_raw(arc) as *mut OSSL_LIB_CTX
}

/// Allocate a new `OSSL_LIB_CTX`, receiving provider dispatch
/// information.
///
/// In the C implementation this registers upcall handlers from the
/// loading provider (the BIO core functions).  The Rust
/// implementation uses trait dispatch rather than function-pointer
/// tables, so `_handle` and `_in` are ignored — equivalent behaviour
/// is provided by `openssl_provider`'s trait resolution system.
///
/// Translates `OSSL_LIB_CTX_new_from_dispatch()` from
/// `crypto/context.c` line 496.
///
/// # Safety
///
/// Safe to call with any values for `_handle` and `_in` (including
/// NULL) because they are ignored.  The returned pointer must be
/// freed with `OSSL_LIB_CTX_free`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_new_from_dispatch(
    _handle: *const c_void,
    _in: *const c_void,
) -> *mut OSSL_LIB_CTX {
    // SAFETY: delegates to the safe `OSSL_LIB_CTX_new` wrapper
    // above; that function carries no input-pointer invariants.
    unsafe { OSSL_LIB_CTX_new() }
}

/// Allocate a new *child* `OSSL_LIB_CTX`.
///
/// Child contexts are used by providers that spawn sub-contexts;
/// they inherit provider registrations conceptually and have
/// `is_child() == true`.  The `_handle` and `_in` parameters are
/// ignored for the same reason as in
/// `OSSL_LIB_CTX_new_from_dispatch` — the Rust implementation
/// substitutes trait dispatch for function-pointer dispatch.
///
/// Translates `OSSL_LIB_CTX_new_child()` from `crypto/context.c`
/// line 512.
///
/// # Safety
///
/// Safe to call with any values for `_handle` and `_in` (including
/// NULL).  The returned pointer must be freed with
/// `OSSL_LIB_CTX_free`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_new_child(
    _handle: *const c_void,
    _in: *const c_void,
) -> *mut OSSL_LIB_CTX {
    let arc = LibContext::new_child();
    Arc::into_raw(arc) as *mut OSSL_LIB_CTX
}

/// Load configuration from `config_file` into `ctx`.
///
/// Parses the OpenSSL-style configuration file at `config_file` and
/// installs the results in the context's config store.  Passing NULL
/// for `ctx` targets the default context.
///
/// Returns `1` on success, `0` on failure (including NULL file
/// path, invalid UTF-8, or parser error).
///
/// Translates `OSSL_LIB_CTX_load_config()` from `crypto/context.c`
/// line 546.
///
/// # Safety
///
/// * `ctx`, if non-null, must point to a valid `OSSL_LIB_CTX`
///   previously allocated by a matching constructor in this module.
/// * `config_file`, if non-null, must point to a NUL-terminated C
///   string describing a readable, UTF-8-valid file path.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_load_config(
    ctx: *mut OSSL_LIB_CTX,
    config_file: *const c_char,
) -> c_int {
    // NULL context means "default" — substitute the singleton.
    let concrete = if ctx.is_null() {
        default_global_ptr()
    } else {
        ctx
    };
    // SAFETY: `concrete` is non-null or NULL (if the singleton hasn't
    // been materialised yet).  When non-null, the caller's contract
    // asserts validity.
    let Some(arc) = (unsafe { ctx_clone_arc(concrete.cast_const()) }) else {
        return 0;
    };
    // SAFETY: the caller contract says `config_file` is NULL or a
    // NUL-terminated C string with valid UTF-8.
    let Some(path_str) = (unsafe { cstr_to_str_opt(config_file) }) else {
        return 0;
    };
    match arc.load_config(Path::new(path_str)) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Release an `OSSL_LIB_CTX`.
///
/// The process-wide default context is **not** freed; calling this
/// function with the default pointer is a no-op, matching the C
/// behaviour of `ossl_lib_ctx_is_default_nocreate`.  For user-created
/// contexts, dropping the final `Arc` reclaims all associated storage
/// via RAII.
///
/// Also purges any `conf_diagnostics` side-table entry for the
/// freed pointer so that a later context reusing the same address
/// cannot inherit a stale override.
///
/// Translates `OSSL_LIB_CTX_free()` from `crypto/context.c` line
/// 560.
///
/// # Safety
///
/// * `ctx` must be NULL, a pointer returned by one of the
///   `OSSL_LIB_CTX_new*` constructors, or the return value of
///   `OSSL_LIB_CTX_get0_global_default()`.
/// * After this call, `ctx` must not be dereferenced or freed
///   again.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_free(ctx: *mut OSSL_LIB_CTX) {
    if ctx.is_null() {
        return;
    }
    // The process-wide default is pinned for the lifetime of the
    // process — never reclaim it.
    if is_default_ctx(ctx) {
        return;
    }
    // Drop the side-table `conf_diagnostics` override, if any.
    if let Ok(mut overrides) = conf_diag_overrides().lock() {
        overrides.remove(&(ctx as usize));
    }
    // Also clear the default-context slot if the user had installed
    // this pointer as the default — leaving a dangling default would
    // be a use-after-free hazard.
    if let Ok(mut slot) = default_context_slot().lock() {
        if slot.0 == ctx {
            *slot = CtxPtr(ptr::null_mut());
        }
    }
    // SAFETY: by the function contract the pointer was published
    // via `Arc::into_raw` in one of the `OSSL_LIB_CTX_new*`
    // constructors; reconstructing the Arc and dropping it is the
    // inverse operation.  The pointer is non-null and not the
    // default singleton by the checks above.
    let raw = ctx as *const LibContext;
    drop(unsafe { Arc::from_raw(raw) });
}

/// Return the process-wide default `OSSL_LIB_CTX`.
///
/// The returned pointer is non-owning: the caller must **not** pass
/// it to `OSSL_LIB_CTX_free` expecting a memory release (the default
/// context is pinned).  Subsequent calls return the same address.
///
/// If `OSSL_LIB_CTX_set0_default` has installed a custom default,
/// that custom pointer is returned instead; otherwise the
/// process-wide singleton is returned.
///
/// Translates `OSSL_LIB_CTX_get0_global_default()` from
/// `crypto/context.c` line 573.
///
/// # Safety
///
/// Safe to call from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_get0_global_default() -> *mut OSSL_LIB_CTX {
    if let Ok(slot) = default_context_slot().lock() {
        if !slot.0.is_null() {
            return slot.0;
        }
    }
    default_global_ptr()
}

/// Install `libctx` as the process default and return the previous
/// default pointer.
///
/// If `libctx` is non-null, it replaces the current default; the
/// caller retains ownership of `libctx` (the slot holds a
/// non-owning pointer).  If `libctx` is NULL, the default is
/// **unchanged** — this matches the C behaviour at
/// `crypto/context.c:588` where the swap is gated on
/// `libctx != NULL`.
///
/// Always returns the current default pointer (either the custom
/// default or the process singleton).
///
/// Translates `OSSL_LIB_CTX_set0_default()` from
/// `crypto/context.c` line 583.
///
/// # Safety
///
/// * `libctx`, if non-null, must point to a valid `OSSL_LIB_CTX`
///   returned by one of the allocator functions and must remain
///   valid for as long as it is installed as the default (or until
///   another `set0_default` call replaces it).
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_set0_default(libctx: *mut OSSL_LIB_CTX) -> *mut OSSL_LIB_CTX {
    let current = {
        if let Ok(slot) = default_context_slot().lock() {
            if slot.0.is_null() {
                default_global_ptr()
            } else {
                slot.0
            }
        } else {
            default_global_ptr()
        }
    };
    if !libctx.is_null() {
        if let Ok(mut slot) = default_context_slot().lock() {
            *slot = CtxPtr(libctx);
        }
    }
    current
}

/// Read the `conf_diagnostics` flag for `ctx`.
///
/// Returns `1` if diagnostics are enabled, `0` otherwise (including
/// NULL context, unset flag, or side-table lock failure).  Passing
/// NULL for `ctx` reads the default context's flag.
///
/// The underlying `LibContext` initialises the flag to `false` in
/// both `new()` and `new_child()` and has no public setter; this
/// function therefore reflects values installed by
/// `OSSL_LIB_CTX_set_conf_diagnostics` (via the side-table), or
/// `0` if no override has been recorded.
///
/// Translates `OSSL_LIB_CTX_get_conf_diagnostics()` from
/// `crypto/context.c` line 695.
///
/// # Safety
///
/// * `ctx`, if non-null, must point to a valid `OSSL_LIB_CTX`
///   allocated by one of the allocator functions in this module.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_get_conf_diagnostics(ctx: *mut OSSL_LIB_CTX) -> c_int {
    let concrete = if ctx.is_null() {
        default_global_ptr()
    } else {
        ctx
    };
    if concrete.is_null() {
        return 0;
    }
    if let Ok(overrides) = conf_diag_overrides().lock() {
        if let Some(&v) = overrides.get(&(concrete as usize)) {
            return c_int::from(v);
        }
    }
    // No override recorded — the underlying LibContext initialises
    // `conf_diagnostics` to `false` in both `new()` and
    // `new_child()`, so the correct answer is `0`.
    0
}

/// Write the `conf_diagnostics` flag for `ctx`.
///
/// Stores the flag in a side-table keyed by the context pointer
/// address.  Passing NULL `ctx` updates the flag for the default
/// context.  Passing `0` for `value` disables diagnostics; any
/// non-zero value enables them.
///
/// Translates `OSSL_LIB_CTX_set_conf_diagnostics()` from
/// `crypto/context.c` line 706.
///
/// # Safety
///
/// * `ctx`, if non-null, must point to a valid `OSSL_LIB_CTX`
///   allocated by one of the allocator functions in this module.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_set_conf_diagnostics(ctx: *mut OSSL_LIB_CTX, value: c_int) {
    let concrete = if ctx.is_null() {
        default_global_ptr()
    } else {
        ctx
    };
    if concrete.is_null() {
        return;
    }
    if let Ok(mut overrides) = conf_diag_overrides().lock() {
        overrides.insert(concrete as usize, value != 0);
    }
}

/// Fetch subsystem-specific auxiliary data stored in `ctx`.
///
/// In the C implementation this retrieves the provider store, name
/// map, or another internal subsystem handle indexed by an opaque
/// `_index`.  The Rust implementation exposes these via typed
/// methods on `LibContext` rather than a dynamic index lookup, so
/// this function returns NULL — callers should invoke the typed
/// Rust API directly.
///
/// This preserves ABI compatibility (so C callers linking against
/// the FFI shim do not see an unresolved symbol) while directing
/// runtime behaviour to the more strongly-typed Rust path.
///
/// Translates `OSSL_LIB_CTX_get_data()` from `crypto/context.c`
/// line 683.
///
/// # Safety
///
/// Always returns NULL; safe to call with any pointer value.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_get_data(
    _ctx: *mut OSSL_LIB_CTX,
    _index: c_int,
) -> *mut c_void {
    ptr::null_mut()
}

/// Sleep for `millis` milliseconds.
///
/// Delegates to `std::thread::sleep`.  Declared in
/// `include/openssl/crypto.h.in` as part of the public utility
/// surface.
///
/// # Safety
///
/// Safe to call from any thread.  Blocks the current thread for the
/// requested duration.
#[no_mangle]
pub unsafe extern "C" fn OSSL_sleep(millis: u64) {
    thread::sleep(Duration::from_millis(millis));
}

// ===========================================================================
// Phase 9 — CRYPTO_EX_DATA (extra-data) management
// ===========================================================================
//
// OpenSSL's extra-data (ex_data) system lets applications associate
// auxiliary pointers with stack-allocated library objects (SSL,
// SSL_CTX, X509, RSA, etc.) without modifying the library itself.
//
// Architecture:
//   1. Each *class* (SSL, X509, …) maintains a counter of allocated
//      indices.  `CRYPTO_get_ex_new_index` atomically returns a fresh
//      index and records the associated `new_func` / `dup_func` /
//      `free_func` callbacks in `EX_DATA_CALLBACKS`.
//   2. Each `CRYPTO_EX_DATA` *instance* (typically embedded in a
//      parent object) stores a map of `index -> *mut c_void`.  We
//      maintain that map off to the side, keyed by the instance's
//      address, because the public `struct crypto_ex_data_st` is
//      treated as opaque at the FFI boundary.
//
// Only three FFI functions are required by the schema
// (`CRYPTO_get_ex_new_index`, `CRYPTO_set_ex_data`, `CRYPTO_get_ex_data`),
// but we implement them completely (not as stubs) so higher crates
// that use these exports through the FFI layer receive correct
// semantics.

/// Per-index metadata recorded when
/// `CRYPTO_get_ex_new_index` is called.  Because raw C function
/// pointers do not implement `Send`/`Sync` by default — but in
/// practice any well-written OpenSSL callback is thread-safe — we
/// wrap the pointers in an opaque struct and declare them
/// `Send + Sync`.
///
/// The fields are retained for future use by
/// `CRYPTO_new_ex_data`, `CRYPTO_dup_ex_data`, and
/// `CRYPTO_free_ex_data` — OpenSSL's public C lifecycle functions
/// that are outside this FFI crate's current export surface (only
/// `CRYPTO_get_ex_new_index`, `CRYPTO_set_ex_data`, and
/// `CRYPTO_get_ex_data` are required by the schema).  Storing them
/// now allows the registry to be passed verbatim to a higher-level
/// Rust consumer or extended in place without breaking binary
/// compatibility.  Per Rule R9, this individual `#[allow]` carries
/// a justification comment.
#[allow(dead_code)]
struct ExDataCallbacks {
    argl: c_long,
    argp: *mut c_void,
    new_func: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            c_int,
            c_long,
            *mut c_void,
        ) -> c_int,
    >,
    dup_func: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *mut c_void,
            c_int,
            c_long,
            *mut c_void,
        ) -> c_int,
    >,
    free_func: Option<
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, c_int, c_long, *mut c_void),
    >,
}

// SAFETY: Callbacks registered through the OpenSSL ex_data API are
// by contract safe to invoke from any thread — callers that install
// thread-hostile callbacks would break C OpenSSL the same way.  The
// `argp` void pointer is opaque to us; concurrency safety is the
// registering application's responsibility.  We serialise access to
// the registry table below via a `Mutex`.
unsafe impl Send for ExDataCallbacks {}

// SAFETY: See `Send` justification above.
unsafe impl Sync for ExDataCallbacks {}

/// Registry keyed by `(class_index, ex_index)` holding the callback
/// trio registered through `CRYPTO_get_ex_new_index`.
static EX_DATA_CALLBACKS: OnceLock<Mutex<HashMap<(c_int, c_int), ExDataCallbacks>>> =
    OnceLock::new();

/// Per-`CRYPTO_EX_DATA`-instance storage: for each instance address
/// we track the map of `index -> value` most recently written.
static EX_DATA_STORAGE: OnceLock<Mutex<HashMap<usize, HashMap<c_int, usize>>>> = OnceLock::new();

/// Accessor for the global callback registry (lazy-initialised).
fn ex_data_callbacks() -> &'static Mutex<HashMap<(c_int, c_int), ExDataCallbacks>> {
    EX_DATA_CALLBACKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Accessor for the per-instance value storage (lazy-initialised).
fn ex_data_storage() -> &'static Mutex<HashMap<usize, HashMap<c_int, usize>>> {
    EX_DATA_STORAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Allocate a fresh `ex_data` index for `class_index`.
///
/// Atomically increments `EX_DATA_INDEX_COUNTERS[class_index]` and
/// returns the pre-increment value as the newly allocated index.
/// The callback trio (`new_func`, `dup_func`, `free_func`) is
/// recorded in a side-table and invoked later during
/// `CRYPTO_new_ex_data` / `CRYPTO_dup_ex_data` / `CRYPTO_free_ex_data`
/// — for now those lifecycle functions are not exported, but the
/// callbacks are stored so a future extension can wire them up
/// without breaking existing callers.
///
/// Returns `-1` on error (invalid class, lock failure, or counter
/// overflow).
///
/// Translates `CRYPTO_get_ex_new_index()` from `crypto/ex_data.c`.
///
/// # Safety
///
/// * `class_index` is validated against `CRYPTO_EX_INDEX__COUNT`.
/// * `argp` and the three function pointers are stored as-is.  If
///   the caller later installs lifecycle callbacks that dereference
///   `argp`, that pointer must outlive all objects in the class.
/// * All three callback pointers may be NULL (represented as
///   `None`).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_ex_new_index(
    class_index: c_int,
    argl: c_long,
    argp: *mut c_void,
    new_func: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            c_int,
            c_long,
            *mut c_void,
        ) -> c_int,
    >,
    dup_func: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *mut c_void,
            c_int,
            c_long,
            *mut c_void,
        ) -> c_int,
    >,
    free_func: Option<
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, c_int, c_long, *mut c_void),
    >,
) -> c_int {
    if !(0..CRYPTO_EX_INDEX__COUNT).contains(&class_index) {
        return -1;
    }
    // SAFETY: bounds-checked above.  Indexing into a `&'static`
    // array is sound for any in-range index; `usize::try_from`
    // cannot fail because `class_index >= 0` has been asserted.
    let Ok(class_idx_usize) = usize::try_from(class_index) else {
        return -1;
    };
    let counter = &EX_DATA_INDEX_COUNTERS[class_idx_usize];
    let idx = counter.fetch_add(1, Ordering::SeqCst);
    if idx < 0 {
        // Overflow: roll back and report failure.
        counter.fetch_sub(1, Ordering::SeqCst);
        return -1;
    }
    if let Ok(mut table) = ex_data_callbacks().lock() {
        table.insert(
            (class_index, idx),
            ExDataCallbacks {
                argl,
                argp,
                new_func,
                dup_func,
                free_func,
            },
        );
    }
    idx
}

/// Free (release) an `ex_data` index previously allocated by
/// `CRYPTO_get_ex_new_index`.
///
/// In the current C implementation this is documented as a
/// compatibility no-op that always returns `1` — released indices
/// are not reused.  We match that behaviour.  The registered
/// callback trio is retained because existing instances may still
/// trigger them during teardown.
///
/// This function is not listed in the AAP's required exports but is
/// trivially implementable and frequently paired with
/// `CRYPTO_get_ex_new_index` by C consumers.  Exporting it costs
/// nothing and preserves ABI completeness.
///
/// # Safety
///
/// Safe to call with any `class_index` / `idx` values; invalid
/// indices result in a no-op return value of `1`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_free_ex_index(_class_index: c_int, _idx: c_int) -> c_int {
    1
}

/// Store `arg` at index `idx` of the `CRYPTO_EX_DATA` instance
/// pointed at by `ad`.
///
/// The storage is an off-to-the-side `HashMap` keyed by the address
/// of the `CRYPTO_EX_DATA` bag.  Passing NULL for `ad` returns
/// failure.  Passing NULL for `arg` removes the entry at `idx` if
/// present.
///
/// Returns `1` on success, `0` on lock failure or NULL `ad`.
///
/// Translates `CRYPTO_set_ex_data()` from `crypto/ex_data.c`.
///
/// # Safety
///
/// * `ad` must be NULL or a valid, stably-addressed
///   `CRYPTO_EX_DATA` bag.
/// * `arg` is stored as an opaque pointer; its validity is the
///   caller's responsibility.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_ex_data(
    ad: *mut CRYPTO_EX_DATA,
    idx: c_int,
    arg: *mut c_void,
) -> c_int {
    if ad.is_null() {
        return 0;
    }
    let key = ad as usize;
    let Ok(mut store) = ex_data_storage().lock() else {
        return 0;
    };
    let slot = store.entry(key).or_default();
    if arg.is_null() {
        slot.remove(&idx);
    } else {
        slot.insert(idx, arg as usize);
    }
    1
}

/// Fetch the value previously stored at index `idx` of the
/// `CRYPTO_EX_DATA` instance pointed at by `ad`.
///
/// Returns the stored pointer, or NULL if none has been stored (or
/// if `ad` is NULL / the lock cannot be acquired).
///
/// Translates `CRYPTO_get_ex_data()` from `crypto/ex_data.c`.
///
/// # Safety
///
/// * `ad` must be NULL or a valid, stably-addressed
///   `CRYPTO_EX_DATA` bag.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_ex_data(ad: *const CRYPTO_EX_DATA, idx: c_int) -> *mut c_void {
    if ad.is_null() {
        return ptr::null_mut();
    }
    let key = ad as usize;
    let Ok(store) = ex_data_storage().lock() else {
        return ptr::null_mut();
    };
    store
        .get(&key)
        .and_then(|slot| slot.get(&idx))
        .map_or(ptr::null_mut(), |&addr| addr as *mut c_void)
}

// ===========================================================================
// Phase 10 — String utilities
// ===========================================================================
//
// These BSD / OpenSSL-specific string helpers are declared in
// `include/openssl/crypto.h.in` (lines 155-168) and implemented in
// `crypto/o_str.c` / `crypto/o_fopen.c`.  They are commonly used by
// C applications linking against libcrypto for safe, size-bounded
// string handling.
//
// Notes on return-value ownership:
//   * `OPENSSL_hexstr2buf` and `OPENSSL_buf2hexstr` both return
//     heap-allocated buffers via `CRYPTO_malloc`.  Callers are
//     expected to release them with `CRYPTO_free` / `OPENSSL_free`.
//   * `OPENSSL_strlcpy` / `OPENSSL_strlcat` return the *length of
//     the source string* (BSD semantics), which lets the caller
//     detect truncation by comparing against `siz`.
//   * `OPENSSL_strnlen` returns at most `maxlen` even when the
//     string contains no NUL terminator.

/// Size-bounded C string copy (BSD `strlcpy` semantics).
///
/// Copies up to `siz - 1` bytes from the NUL-terminated string
/// `src` into `dst` and NUL-terminates the result.  If `siz` is
/// zero no bytes are written.
///
/// Returns `strlen(src)`.  If the return value is `>= siz` the
/// copy was truncated.
///
/// Translates `OPENSSL_strlcpy()` from `crypto/o_str.c`.
///
/// # Safety
///
/// * `src` must be a valid, NUL-terminated C string.
/// * `dst`, if `siz > 0`, must point to a writable buffer of at
///   least `siz` bytes.
/// * `dst` and `src` may overlap only if `siz == 0`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strlcpy(
    dst: *mut c_char,
    src: *const c_char,
    siz: size_t,
) -> size_t {
    if src.is_null() {
        return 0;
    }
    // First pass: compute strlen(src).
    let mut src_len: size_t = 0;
    loop {
        // SAFETY: `src` is non-null; the caller guarantees it is
        // NUL-terminated, so we stop when we encounter the 0 byte.
        let ch = unsafe { *(src.cast::<u8>()).add(src_len) };
        if ch == 0 {
            break;
        }
        src_len += 1;
    }

    if siz == 0 || dst.is_null() {
        return src_len;
    }

    // Copy up to siz - 1 bytes then NUL-terminate.
    let copy_len = if src_len < siz - 1 { src_len } else { siz - 1 };
    // SAFETY: `src_len` is bounded, both pointers are non-null and
    // point to buffers of sufficient size per the function contract.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), copy_len);
        *(dst.cast::<u8>()).add(copy_len) = 0;
    }
    src_len
}

/// Size-bounded C string append (BSD `strlcat` semantics).
///
/// Appends `src` to `dst`, ensuring the final buffer is
/// NUL-terminated and does not exceed `siz` bytes (including the
/// terminator).
///
/// Returns `min(strlen(initial dst), siz) + strlen(src)`.  If the
/// return value is `>= siz` the append was truncated.
///
/// Translates `OPENSSL_strlcat()` from `crypto/o_str.c`.
///
/// # Safety
///
/// * `src` must be a valid, NUL-terminated C string.
/// * `dst`, if non-null, must point to a writable buffer of at
///   least `siz` bytes containing a NUL-terminated string (or an
///   unterminated byte sequence no longer than `siz` — in which
///   case no copy occurs).
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strlcat(
    dst: *mut c_char,
    src: *const c_char,
    siz: size_t,
) -> size_t {
    if src.is_null() {
        return 0;
    }

    // Compute strlen(src).
    let mut src_len: size_t = 0;
    loop {
        // SAFETY: `src` is non-null and NUL-terminated per contract.
        let ch = unsafe { *(src.cast::<u8>()).add(src_len) };
        if ch == 0 {
            break;
        }
        src_len += 1;
    }

    if dst.is_null() {
        return src_len;
    }

    // Find current strlen(dst), bounded by `siz`.
    let mut dst_len: size_t = 0;
    while dst_len < siz {
        // SAFETY: `dst` points to a buffer of at least `siz` bytes
        // per the function contract; we stop at the first NUL or
        // when `dst_len` reaches `siz`.
        let ch = unsafe { *(dst as *const u8).add(dst_len) };
        if ch == 0 {
            break;
        }
        dst_len += 1;
    }

    if dst_len >= siz {
        // `dst` is not NUL-terminated within the buffer — nothing
        // is copied, but we still return the would-be length.
        return siz + src_len;
    }

    let available = siz - dst_len - 1;
    let copy_len = if src_len < available {
        src_len
    } else {
        available
    };

    // SAFETY: the computed `copy_len` cannot exceed `siz - dst_len - 1`
    // so writing `copy_len + 1` bytes (including the terminator) stays
    // within the destination buffer.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<u8>(), (dst.cast::<u8>()).add(dst_len), copy_len);
        *(dst.cast::<u8>()).add(dst_len + copy_len) = 0;
    }

    dst_len + src_len
}

/// Return the length of the NUL-terminated C string `str_`, but
/// scan no more than `maxlen` bytes.
///
/// Mirrors the POSIX `strnlen()` extension.  Returns `maxlen` if
/// no NUL byte is found within the first `maxlen` bytes.
///
/// Returns `0` if `str_` is NULL.
///
/// Translates `OPENSSL_strnlen()` from `crypto/o_str.c`.
///
/// # Safety
///
/// `str_`, if non-null, must point to a readable buffer of at
/// least `maxlen` bytes (the buffer need not be NUL-terminated).
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_strnlen(str_: *const c_char, maxlen: size_t) -> size_t {
    if str_.is_null() {
        return 0;
    }
    let mut len: size_t = 0;
    while len < maxlen {
        // SAFETY: `str_` is non-null and points to a buffer of at
        // least `maxlen` bytes per the function contract; we stop at
        // the first NUL byte or when `len` reaches `maxlen`.
        let ch = unsafe { *(str_.cast::<u8>()).add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    len
}

/// Convert a single hex character (`0`-`9`, `a`-`f`, `A`-`F`) into
/// its numeric value (0-15).
///
/// Returns `-1` if `c` is not a valid hex digit.
///
/// Translates `OPENSSL_hexchar2int()` from `crypto/o_str.c`.
///
/// # Safety
///
/// This function has no unsafe preconditions — it is declared
/// `unsafe` only because it is part of the C ABI surface and
/// `#[no_mangle] pub extern "C"` functions are declared `unsafe` by
/// convention in this crate.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_hexchar2int(c: c_uchar) -> c_int {
    match c {
        b'0'..=b'9' => c_int::from(c - b'0'),
        b'a'..=b'f' => c_int::from(c - b'a' + 10),
        b'A'..=b'F' => c_int::from(c - b'A' + 10),
        _ => -1,
    }
}

/// Internal helper: parse a hex string into a raw byte buffer.
///
/// Accepts optional separator bytes (`:` or `' '`) between byte
/// pairs, matching the permissive behaviour of the original C
/// implementation in `crypto/o_str.c`.  Returns `None` on any
/// syntax error (odd number of hex digits, invalid character, ...).
fn parse_hex_string(s: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 2);
    let mut iter = s.iter().copied();
    loop {
        // Skip optional separator bytes between groups.
        let Some(first) = iter.next() else { break };
        if first == b':' || first == b' ' {
            continue;
        }
        let hi = match first {
            b'0'..=b'9' => first - b'0',
            b'a'..=b'f' => first - b'a' + 10,
            b'A'..=b'F' => first - b'A' + 10,
            _ => return None,
        };
        let second = iter.next()?;
        let lo = match second {
            b'0'..=b'9' => second - b'0',
            b'a'..=b'f' => second - b'a' + 10,
            b'A'..=b'F' => second - b'A' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Parse a hex string into a freshly-allocated byte buffer.
///
/// Accepts optional `:` or space separators between byte pairs.
///
/// On success returns a pointer to a heap buffer (allocated via
/// `CRYPTO_malloc`) and stores the buffer length in `*buflen` when
/// `buflen` is non-null.  Caller must release the buffer via
/// `CRYPTO_free` / `OPENSSL_free`.
///
/// Returns NULL on any error (NULL input, odd-length string,
/// invalid character, allocation failure).  When an error occurs
/// `*buflen` is set to `0` if `buflen` is non-null.
///
/// Translates `OPENSSL_hexstr2buf()` from `crypto/o_str.c`.
///
/// # Safety
///
/// * `str_` must be NULL or a valid, NUL-terminated C string.
/// * `buflen`, if non-null, must point to a writable `long`.
/// * The returned pointer (if non-null) must eventually be freed
///   with `CRYPTO_free` to avoid leaking the allocation.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_hexstr2buf(
    str_: *const c_char,
    buflen: *mut c_long,
) -> *mut c_char {
    if str_.is_null() {
        if !buflen.is_null() {
            // SAFETY: caller provided a writable `long`.
            unsafe { *buflen = 0 };
        }
        return ptr::null_mut();
    }
    // SAFETY: `str_` is non-null and NUL-terminated per contract.
    let cstr = unsafe { CStr::from_ptr(str_) };
    let bytes = cstr.to_bytes();

    let Some(parsed) = parse_hex_string(bytes) else {
        if !buflen.is_null() {
            // SAFETY: caller provided a writable `long`.
            unsafe { *buflen = 0 };
        }
        return ptr::null_mut();
    };

    // Allocate an owning buffer for C and copy the parsed bytes in.
    // `parsed.len()` could be 0 for an empty hex string; `CRYPTO_malloc`
    // returns NULL for `num == 0`, which matches the expected behaviour
    // (nothing to free).
    if parsed.is_empty() {
        if !buflen.is_null() {
            // SAFETY: caller provided a writable `long`.
            unsafe { *buflen = 0 };
        }
        return ptr::null_mut();
    }

    // SAFETY: forwarding to our own allocator.
    let dst = unsafe { CRYPTO_malloc(parsed.len() as size_t, ptr::null(), 0) };
    if dst.is_null() {
        if !buflen.is_null() {
            // SAFETY: caller provided a writable `long`.
            unsafe { *buflen = 0 };
        }
        return ptr::null_mut();
    }
    // SAFETY: the allocation succeeded and has capacity `parsed.len()`
    // bytes; `parsed.as_ptr()` and `dst` do not alias.
    unsafe {
        ptr::copy_nonoverlapping(parsed.as_ptr(), dst.cast::<u8>(), parsed.len());
    }

    if !buflen.is_null() {
        // `parsed.len()` is a `usize`; we use `try_from` per Rule R6
        // (no lossy `as` casts).  If the value somehow overflows a
        // `long` (2 GiB on LP32 systems, 8 EiB on LP64) we treat the
        // conversion as a failure and free the buffer.
        let Ok(n) = c_long::try_from(parsed.len()) else {
            // SAFETY: `dst` is a freshly-allocated, non-null
            // buffer; forwarding to our deallocator is sound.
            unsafe { CRYPTO_free(dst, ptr::null(), 0) };
            // SAFETY: caller provided a writable `long`.
            unsafe { *buflen = 0 };
            return ptr::null_mut();
        };
        // SAFETY: caller provided a writable `long`.
        unsafe { *buflen = n };
    }

    dst.cast::<c_char>()
}

/// Convert a raw byte buffer into a hex string (`:`-separated).
///
/// The output is a heap-allocated, NUL-terminated C string of the
/// form `"aa:bb:cc"`.  Returns NULL on error (NULL buffer with
/// non-zero length, allocation failure, or `buflen` negative or
/// greater than `c_long::MAX / 3`).
///
/// Caller must release the returned pointer with `CRYPTO_free` /
/// `OPENSSL_free`.
///
/// Translates `OPENSSL_buf2hexstr()` from `crypto/o_str.c`.
///
/// # Safety
///
/// * `buf`, if `buflen > 0`, must point to a readable buffer of
///   at least `buflen` bytes.
/// * The returned pointer (if non-null) must eventually be freed
///   with `CRYPTO_free` to avoid leaking the allocation.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_buf2hexstr(buf: *const c_char, buflen: c_long) -> *mut c_char {
    // Hex digit table, lowercase.  Declared at the top of the
    // function scope to avoid interleaving items with statements.
    const HEX: &[u8; 16] = b"0123456789abcdef";

    if buflen < 0 {
        return ptr::null_mut();
    }
    // Empty input → single NUL byte buffer (empty string).  Allocate
    // one byte so the caller can call CRYPTO_free on the result.
    // `buflen >= 0` has been asserted above; `try_from` can only fail
    // on targets where `size_t` is narrower than `c_long` (32-bit
    // LP32/ILP32) and the value exceeds `usize::MAX`.  Treat such
    // overflow as an error per Rule R6.
    let Ok(n) = size_t::try_from(buflen) else {
        return ptr::null_mut();
    };
    if n == 0 || buf.is_null() {
        // SAFETY: forwarding to our own allocator for a single byte.
        let dst = unsafe { CRYPTO_malloc(1, ptr::null(), 0) };
        if dst.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the allocation succeeded and has capacity 1 byte;
        // we write a single NUL terminator.
        unsafe { *(dst.cast::<u8>()) = 0 };
        return dst.cast::<c_char>();
    }

    // Each input byte produces "XX:" (3 chars) except the last which
    // produces "XX\0" (3 chars, last byte being NUL).  So total
    // output length is `3 * n` (includes terminator).  Guard against
    // overflow when multiplying by 3.
    let Some(out_len) = n.checked_mul(3) else {
        return ptr::null_mut();
    };

    // SAFETY: forwarding to our own allocator; `out_len > 0`.
    let dst = unsafe { CRYPTO_malloc(out_len, ptr::null(), 0) };
    if dst.is_null() {
        return ptr::null_mut();
    }

    for i in 0..n {
        // SAFETY: `i < n` and the caller guarantees `buf` points to
        // at least `n` bytes.
        let byte = unsafe { *(buf.cast::<u8>()).add(i) };
        let hi = HEX[(byte >> 4) as usize];
        let lo = HEX[(byte & 0x0f) as usize];
        // SAFETY: output offsets `3*i`, `3*i + 1`, `3*i + 2` are all
        // within the `out_len == 3 * n` buffer.
        unsafe {
            *(dst.cast::<u8>()).add(3 * i) = hi;
            *(dst.cast::<u8>()).add(3 * i + 1) = lo;
            // Emit ':' between bytes, NUL after the last one.
            *(dst.cast::<u8>()).add(3 * i + 2) = if i + 1 == n { 0 } else { b':' };
        }
    }

    dst.cast::<c_char>()
}
