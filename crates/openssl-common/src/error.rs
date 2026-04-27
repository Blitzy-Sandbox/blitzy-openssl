//! Error handling infrastructure for the OpenSSL Rust workspace.
//!
//! Replaces the C `ERR_*` thread-local error stack with idiomatic Rust
//! `Result<T, E>` error types using `thiserror` derive macros. Per AAP §0.7.7,
//! error stacking maps to [`std::error::Error::source()`] chains, and
//! thread-local queues are replaced by explicit `Result` propagation via
//! the `?` operator.
//!
//! # Error Hierarchy
//!
//! The error types form a layered chain mirroring the crate dependency graph:
//!
//! ```text
//! CommonError ← CryptoError ← SslError
//!      ↑              ↑
//!      └── ProviderError
//!      └── FipsError
//! ```
//!
//! Each higher-level error can wrap a lower-level one via `#[from]`, enabling
//! seamless `?`-based propagation across crate boundaries.
//!
//! # Migration from C
//!
//! | C Construct               | Rust Equivalent                        |
//! |---------------------------|----------------------------------------|
//! | `ERR_put_error()`         | `return Err(…)`                        |
//! | `ERR_get_error()`         | `match result { Err(e) => … }`         |
//! | `ERR_error_string_n()`    | `Display` impl via `#[error("…")]`     |
//! | `ERR_LIB_*` constants     | `ErrorLibrary` enum variants         |
//! | `ERR_STATE` ring buffer   | `ErrorStack` (FFI compatibility only) |
//! | Thread-local error queue  | `Result<T, E>` return values           |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All variants carry structured data; no integer sentinels.
//! - **R6 (Lossless Casts):** `CastOverflow` wraps [`std::num::TryFromIntError`].
//! - **R7 (Lock Granularity):** `ErrorStack` is not shared by default.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from every crate entry point via `Result<T, E>`.

use std::fmt;
use std::io;
use std::num::TryFromIntError;

use thiserror::Error;

// =============================================================================
// ErrorLibrary — OpenSSL Library Identifier Codes
// =============================================================================

/// Identifies the OpenSSL subsystem that originated an error.
///
/// Directly translates the C `ERR_LIB_*` constants and the
/// `ERR_str_libraries[]` array from `crypto/err/err.c` (lines 36–81).
/// Each variant maps to the display string used by `ERR_lib_error_string()`.
///
/// # Examples
///
/// ```
/// use openssl_common::error::ErrorLibrary;
///
/// let lib = ErrorLibrary::Rsa;
/// assert_eq!(format!("{}", lib), "rsa routines");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ErrorLibrary {
    /// Unknown or unset library (`ERR_LIB_NONE`).
    None,
    /// System call errors (`ERR_LIB_SYS`).
    Sys,
    /// Big number arithmetic (`ERR_LIB_BN`).
    Bn,
    /// RSA operations (`ERR_LIB_RSA`).
    Rsa,
    /// Diffie-Hellman key exchange (`ERR_LIB_DH`).
    Dh,
    /// Digital envelope / EVP abstraction (`ERR_LIB_EVP`).
    Evp,
    /// Memory buffer management (`ERR_LIB_BUF`).
    Buf,
    /// Object identifier routines (`ERR_LIB_OBJ`).
    Obj,
    /// PEM encoding/decoding (`ERR_LIB_PEM`).
    Pem,
    /// DSA signatures (`ERR_LIB_DSA`).
    Dsa,
    /// X.509 certificate handling (`ERR_LIB_X509`).
    X509,
    /// ASN.1 encoding/decoding (`ERR_LIB_ASN1`).
    Asn1,
    /// Configuration file parsing (`ERR_LIB_CONF`).
    Conf,
    /// Common libcrypto routines (`ERR_LIB_CRYPTO`).
    Crypto,
    /// Elliptic curve operations (`ERR_LIB_EC`).
    Ec,
    /// SSL/TLS protocol (`ERR_LIB_SSL`).
    Ssl,
    /// BIO I/O abstraction (`ERR_LIB_BIO`).
    Bio,
    /// PKCS#7 / CMS operations (`ERR_LIB_PKCS7`).
    Pkcs7,
    /// X.509 v3 extensions (`ERR_LIB_X509V3`).
    X509v3,
    /// PKCS#12 key store (`ERR_LIB_PKCS12`).
    Pkcs12,
    /// Random number generation (`ERR_LIB_RAND`).
    Rand,
    /// Dynamic shared object loading (`ERR_LIB_DSO`).
    Dso,
    /// RFC 3161 timestamping (`ERR_LIB_TS`).
    Ts,
    /// Engine subsystem (`ERR_LIB_ENGINE`).
    Engine,
    /// OCSP stapling (`ERR_LIB_OCSP`).
    Ocsp,
    /// User interface abstraction (`ERR_LIB_UI`).
    Ui,
    /// FIPS module (`ERR_LIB_FIPS`).
    Fips,
    /// CMS signed/enveloped data (`ERR_LIB_CMS`).
    Cms,
    /// Certificate Request Message Format (`ERR_LIB_CRMF`).
    Crmf,
    /// Certificate Management Protocol (`ERR_LIB_CMP`).
    Cmp,
    /// HMAC message authentication (`ERR_LIB_HMAC`).
    Hmac,
    /// Certificate Transparency (`ERR_LIB_CT`).
    Ct,
    /// Async job infrastructure (`ERR_LIB_ASYNC`).
    Async,
    /// Key derivation functions (`ERR_LIB_KDF`).
    Kdf,
    /// `OSSL_STORE` URI-based key/cert loading (`ERR_LIB_OSSL_STORE`).
    Store,
    /// SM2 elliptic curve (`ERR_LIB_SM2`).
    Sm2,
    /// Enhanced security services (`ERR_LIB_ESS`).
    Ess,
    /// Provider subsystem (`ERR_LIB_PROV`).
    Provider,
    /// Key/certificate encoder (`ERR_LIB_OSSL_ENCODER`).
    Encoder,
    /// Key/certificate decoder (`ERR_LIB_OSSL_DECODER`).
    Decoder,
    /// HTTP client for OCSP/CMP (`ERR_LIB_HTTP`).
    Http,
}

impl fmt::Display for ErrorLibrary {
    /// Formats the library identifier using the same strings as the C
    /// `ERR_str_libraries[]` array in `crypto/err/err.c`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::None => "unknown library",
            Self::Sys => "system library",
            Self::Bn => "bignum routines",
            Self::Rsa => "rsa routines",
            Self::Dh => "Diffie-Hellman routines",
            Self::Evp => "digital envelope routines",
            Self::Buf => "memory buffer routines",
            Self::Obj => "object identifier routines",
            Self::Pem => "PEM routines",
            Self::Dsa => "dsa routines",
            Self::X509 => "x509 certificate routines",
            Self::Asn1 => "asn1 encoding routines",
            Self::Conf => "configuration file routines",
            Self::Crypto => "common libcrypto routines",
            Self::Ec => "elliptic curve routines",
            Self::Ssl => "SSL routines",
            Self::Bio => "BIO routines",
            Self::Pkcs7 => "PKCS7 routines",
            Self::X509v3 => "X509 V3 routines",
            Self::Pkcs12 => "PKCS12 routines",
            Self::Rand => "random number generator",
            Self::Dso => "DSO support routines",
            Self::Ts => "time stamp routines",
            Self::Engine => "engine routines",
            Self::Ocsp => "OCSP routines",
            Self::Ui => "UI routines",
            Self::Fips => "FIPS routines",
            Self::Cms => "CMS routines",
            Self::Crmf => "CRMF routines",
            Self::Cmp => "CMP routines",
            Self::Hmac => "HMAC routines",
            Self::Ct => "CT routines",
            Self::Async => "ASYNC routines",
            Self::Kdf => "KDF routines",
            Self::Store => "STORE routines",
            Self::Sm2 => "SM2 routines",
            Self::Ess => "ESS routines",
            Self::Provider => "Provider routines",
            Self::Encoder => "ENCODER routines",
            Self::Decoder => "DECODER routines",
            Self::Http => "HTTP routines",
        };
        f.write_str(name)
    }
}

// =============================================================================
// CommonError — Foundation Error Type for openssl-common
// =============================================================================

/// Root error type for the `openssl-common` crate.
///
/// Covers infrastructure-level failures: I/O, configuration, parameter
/// handling, numeric overflow, memory, and initialization state.  Every
/// higher-level crate error (`CryptoError`, `SslError`, etc.) can wrap
/// a `CommonError` via `#[from]`, enabling seamless `?` propagation.
///
/// # C Mapping
///
/// | Rust Variant         | C Origin                                    |
/// |----------------------|---------------------------------------------|
/// | `Io`                 | `SYSerr()` / `ERR_LIB_SYS`                 |
/// | `Config`             | `CONFerr()` / `ERR_LIB_CONF`               |
/// | `ParamTypeMismatch`  | `OSSL_PARAM_locate()` type check failures   |
/// | `ParamNotFound`      | `OSSL_PARAM_locate()` returning `NULL`      |
/// | `ArithmeticOverflow` | `safe_math.h` overflow detection             |
/// | `CastOverflow`       | Narrowing cast failures (Rule R6)           |
/// | `InvalidArgument`    | `ERR_R_PASSED_INVALID_ARGUMENT`             |
/// | `Memory`             | `ERR_R_MALLOC_FAILURE`                      |
/// | `NotInitialized`     | `ERR_R_INIT_FAIL` (pre-init)               |
/// | `AlreadyInitialized` | Double `OPENSSL_init_crypto()` guard        |
/// | `Unsupported`        | `ERR_R_UNSUPPORTED`                         |
/// | `Internal`           | `ERR_R_INTERNAL_ERROR`                      |
#[derive(Debug, Error)]
pub enum CommonError {
    /// An I/O operation failed.
    ///
    /// Wraps [`std::io::Error`] via `#[from]` for seamless `?` conversion
    /// from any I/O call site.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A configuration file could not be parsed or contained invalid values.
    #[error("configuration error: {message}")]
    Config {
        /// Human-readable description of the configuration failure.
        message: String,
    },

    /// An [`OSSL_PARAM`](crate::param)-equivalent lookup found a parameter
    /// with the wrong type.
    #[error("parameter type mismatch: expected {expected}, got {actual} for key '{key}'")]
    ParamTypeMismatch {
        /// The parameter key that was looked up.
        key: String,
        /// The expected type name.
        expected: &'static str,
        /// The actual type name found.
        actual: &'static str,
    },

    /// A required parameter key was not present in the parameter set.
    #[error("parameter not found: '{key}'")]
    ParamNotFound {
        /// The missing parameter key.
        key: String,
    },

    /// A checked arithmetic operation overflowed.
    ///
    /// Replaces the C `safe_math.h` overflow detection with Rust's
    /// `checked_*` / `overflowing_*` methods.
    #[error("arithmetic overflow in {operation}")]
    ArithmeticOverflow {
        /// A human-readable label for the operation that overflowed
        /// (e.g., `"bignum addition"`).
        operation: &'static str,
    },

    /// A numeric cast would have lost data.
    ///
    /// Wraps `TryFromIntError` via `#[from]`, enforcing **Rule R6**
    /// (lossless numeric casts — no bare `as` for narrowing conversions).
    #[error("numeric cast overflow: {0}")]
    CastOverflow(#[from] TryFromIntError),

    /// A function received an argument that failed validation.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// A memory allocation or secure-memory operation failed.
    #[error("memory error: {0}")]
    Memory(String),

    /// A subsystem was accessed before it was initialized.
    #[error("not initialized: {0}")]
    NotInitialized(&'static str),

    /// A subsystem was initialized more than once when only a single
    /// initialization is permitted.
    #[error("already initialized: {0}")]
    AlreadyInitialized(&'static str),

    /// The requested operation is not supported by the current build
    /// configuration or provider.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// An internal logic error occurred that should never happen in
    /// correct code. Typically indicates a bug.
    #[error("internal error: {0}")]
    Internal(String),
}

// =============================================================================
// CryptoError — Error Type for openssl-crypto (libcrypto equivalent)
// =============================================================================

/// Error type for the `openssl-crypto` crate covering all cryptographic
/// operations: algorithm fetch, key management, encoding/decoding,
/// verification, and random number generation.
///
/// Wraps `CommonError` via `#[from]` so that any common infrastructure
/// failure can be propagated transparently through cryptographic call sites.
///
/// # Error Chain
///
/// ```text
/// io::Error ──→ CommonError::Io ──→ CryptoError::Common
/// TryFromIntError ──→ CommonError::CastOverflow ──→ CryptoError::Common
/// ```
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A lower-level common infrastructure error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// A provider operation failed (e.g., algorithm dispatch, provider init).
    #[error("provider error: {0}")]
    Provider(String),

    /// An algorithm was requested but could not be found in any loaded
    /// provider (mirrors `EVP_*_fetch()` returning `NULL`).
    #[error("algorithm not found: {0}")]
    AlgorithmNotFound(String),

    /// A key operation failed (generation, import, export, validation).
    #[error("key error: {0}")]
    Key(String),

    /// An encoding or decoding operation failed (DER, PEM, PKCS#8, etc.).
    #[error("encoding error: {0}")]
    Encoding(String),

    /// A cryptographic verification check failed (signature, MAC, hash).
    #[error("verification failed: {0}")]
    Verification(String),

    /// Random number generation or DRBG seeding failed.
    #[error("random number generation failed: {0}")]
    Rand(String),

    /// An I/O operation within the crypto layer failed.
    ///
    /// This is a separate variant from `Common(CommonError::Io(_))` to
    /// allow crypto-layer code to produce I/O errors directly without
    /// wrapping through `CommonError`.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// =============================================================================
// SslError — Error Type for openssl-ssl (libssl equivalent)
// =============================================================================

/// Error type for the `openssl-ssl` crate covering TLS, DTLS, QUIC, and
/// ECH protocol operations.
///
/// Wraps both `CommonError` and `CryptoError` via `#[from]`, forming
/// the highest level of the library error chain.
///
/// # Error Chain
///
/// ```text
/// CommonError ──→ SslError::Common
/// CryptoError ──→ SslError::Crypto
/// ```
#[derive(Debug, Error)]
pub enum SslError {
    /// A lower-level common infrastructure error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// A lower-level cryptographic operation error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A TLS/DTLS/QUIC handshake failed at a specific stage.
    #[error("handshake error: {0}")]
    Handshake(String),

    /// A protocol-level violation was detected (unexpected message,
    /// invalid state transition, version mismatch).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A certificate-related operation failed (loading, verification,
    /// chain building, hostname check).
    #[error("certificate error: {0}")]
    Certificate(String),

    /// A session operation failed (cache miss, ticket decryption,
    /// serialization).
    #[error("session error: {0}")]
    Session(String),

    /// A QUIC-specific error occurred (stream reset, connection ID
    /// mismatch, congestion).
    #[error("QUIC error: {0}")]
    Quic(String),

    /// The peer closed the connection (clean shutdown or abrupt reset).
    #[error("connection closed")]
    ConnectionClosed,
}

// =============================================================================
// ProviderError — Error Type for openssl-provider
// =============================================================================

/// Error type for the `openssl-provider` crate covering provider
/// lifecycle, algorithm dispatch, and registration operations.
///
/// Wraps `CommonError` via `#[from]` for infrastructure failure
/// propagation.
///
/// # C Mapping
///
/// | Rust Variant           | C Origin                                        |
/// |------------------------|-------------------------------------------------|
/// | `NotFound`             | `OSSL_PROVIDER_load()` returning `NULL`         |
/// | `Dispatch`             | `OSSL_DISPATCH` table lookup failure            |
/// | `Init`                 | Provider `OSSL_provider_init()` failure          |
/// | `AlgorithmUnavailable` | `EVP_*_fetch()` with no matching implementation |
#[derive(Debug, Error)]
pub enum ProviderError {
    /// A lower-level common infrastructure error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// A provider with the given name could not be found or loaded.
    #[error("provider not found: {0}")]
    NotFound(String),

    /// A provider dispatch table lookup failed (function ID not registered).
    #[error("dispatch error: {0}")]
    Dispatch(String),

    /// Provider initialization failed (the provider's `init` entry point
    /// returned an error).
    #[error("initialization failed: {0}")]
    Init(String),

    /// The requested algorithm is not available in any loaded provider.
    #[error("algorithm unavailable: {0}")]
    AlgorithmUnavailable(String),
}

// =============================================================================
// FipsError — Error Type for openssl-fips
// =============================================================================

/// Error type for the `openssl-fips` crate covering FIPS 140-3 module
/// operations: Power-On Self-Test (POST), integrity verification, Known
/// Answer Tests (KATs), and approved-algorithm indicator checks.
///
/// Wraps `CommonError` via `#[from]` for infrastructure failure
/// propagation.
///
/// # FIPS State Machine
///
/// ```text
/// PowerOn ──→ SelfTesting ──┬──→ Operational
///                           └──→ Error
/// ```
///
/// Errors from the self-test or integrity-check phases transition the
/// FIPS module to the `Error` state, from which no cryptographic
/// operations are permitted.
///
/// # C Mapping
///
/// | Rust Variant            | C Origin                                       |
/// |-------------------------|------------------------------------------------|
/// | `SelfTestFailed`        | `providers/fips/self_test.c` KAT failure       |
/// | `IntegrityCheckFailed`  | Module checksum mismatch at load time          |
/// | `NotOperational`        | FIPS state != `Operational`                    |
/// | `NotApproved`           | Algorithm not on FIPS approved list            |
#[derive(Debug, Error)]
pub enum FipsError {
    /// A lower-level common infrastructure error.
    #[error(transparent)]
    Common(#[from] CommonError),

    /// One or more Known Answer Tests (KATs) failed during the
    /// Power-On Self-Test (POST).
    #[error("FIPS self-test failed: {0}")]
    SelfTestFailed(String),

    /// The FIPS module integrity checksum did not match the expected
    /// value, indicating possible tampering or corruption.
    #[error("FIPS integrity check failed")]
    IntegrityCheckFailed,

    /// A cryptographic operation was attempted while the FIPS module
    /// is not in the `Operational` state.
    #[error("FIPS not in operational state: current state is {0}")]
    NotOperational(String),

    /// The requested algorithm is not on the FIPS 140-3 approved list.
    #[error("algorithm not FIPS approved: {0}")]
    NotApproved(String),
}

// =============================================================================
// ErrorDetail — Enriched Error Record (replaces ERR_STATE ring buffer entries)
// =============================================================================

/// A single enriched error record capturing the originating library,
/// reason string, source location, and optional auxiliary data.
///
/// This is the Rust equivalent of a single entry in the C `ERR_STATE`
/// ring buffer defined in `crypto/err/err_local.h`. In idiomatic Rust
/// code, error context is typically carried by the error enum variants
/// themselves and by the [`std::error::Error::source()`] chain. The
/// `ErrorDetail` struct exists primarily for:
///
/// 1. **FFI compatibility** — C callers using `ERR_get_error()` expect
///    per-error metadata (library, file, line, function).
/// 2. **Diagnostics logging** — structured error records can be
///    serialized to JSON for observability pipelines.
///
/// # Serialization
///
/// Derives [`serde::Serialize`] to support JSON output for diagnostics
/// and observability integration.
///
/// # Examples
///
/// ```
/// use openssl_common::error::{ErrorDetail, ErrorLibrary};
///
/// let detail = ErrorDetail {
///     library: ErrorLibrary::Rsa,
///     reason: "key too short".to_string(),
///     file: file!(),
///     line: line!(),
///     function: module_path!(),
///     data: Some("minimum 2048 bits required".to_string()),
/// };
/// assert_eq!(detail.library, ErrorLibrary::Rsa);
/// ```
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorDetail {
    /// The library subsystem that originated this error.
    pub library: ErrorLibrary,

    /// A human-readable reason string describing the error.
    pub reason: String,

    /// The source file where the error was created (via `file!()`).
    pub file: &'static str,

    /// The line number where the error was created (via `line!()`).
    pub line: u32,

    /// The function or module path where the error was created
    /// (via `module_path!()`).
    pub function: &'static str,

    /// Optional auxiliary data providing additional context
    /// (e.g., the invalid value that triggered the error).
    pub data: Option<String>,
}

impl fmt::Display for ErrorDetail {
    /// Formats the error detail in a style similar to the C
    /// `ERR_error_string_n()` output: `library:reason:file:line:function`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.library, self.reason, self.file, self.line, self.function
        )?;
        if let Some(ref data) = self.data {
            write!(f, ":{data}")?;
        }
        Ok(())
    }
}

// =============================================================================
// ErrorStack — Accumulator for Multiple Error Records
// =============================================================================

/// An ordered collection of `ErrorDetail` records, used for FFI
/// compatibility with the C `ERR_get_error()` / `ERR_peek_error()` API.
///
/// In idiomatic Rust, errors propagate via `Result<T, E>` and the
/// `?` operator, so the stack is rarely needed directly. It exists to
/// support the `openssl-ffi` crate's C ABI layer, which must present
/// a thread-local error queue to C callers.
///
/// # Thread Safety
///
/// `ErrorStack` is **not** shared between threads by default — each
/// FFI thread should own its own instance. If sharing is required,
/// wrap in `Arc<Mutex<ErrorStack>>` and document with
/// `// LOCK-SCOPE: <justification>` per **Rule R7**.
///
/// # Examples
///
/// ```
/// use openssl_common::error::{ErrorStack, ErrorDetail, ErrorLibrary};
///
/// let mut stack = ErrorStack::new();
/// assert!(stack.is_empty());
///
/// stack.push(ErrorDetail {
///     library: ErrorLibrary::Ssl,
///     reason: "handshake timeout".to_string(),
///     file: file!(),
///     line: line!(),
///     function: module_path!(),
///     data: None,
/// });
/// assert_eq!(stack.len(), 1);
///
/// let popped = stack.pop();
/// assert!(popped.is_some());
/// assert!(stack.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct ErrorStack {
    /// Internal storage for error details, ordered from oldest (index 0)
    /// to newest (last index).
    errors: Vec<ErrorDetail>,
}

impl ErrorStack {
    /// Creates a new, empty error stack.
    #[must_use]
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Pushes an error detail onto the top of the stack.
    ///
    /// The most recently pushed error is considered the "current" error,
    /// matching the semantics of `ERR_put_error()` in C.
    pub fn push(&mut self, detail: ErrorDetail) {
        self.errors.push(detail);
    }

    /// Removes and returns the most recent error from the stack, or
    /// `None` if the stack is empty.
    ///
    /// Matches the semantics of `ERR_get_error()` in C.
    pub fn pop(&mut self) -> Option<ErrorDetail> {
        self.errors.pop()
    }

    /// Returns `true` if the stack contains no error records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the number of error records currently on the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Removes all error records from the stack.
    ///
    /// Equivalent to `ERR_clear_error()` in C.
    pub fn clear(&mut self) {
        self.errors.clear();
    }

    /// Returns an iterator over the error records from oldest to newest.
    ///
    /// Useful for printing or serializing the complete error chain,
    /// similar to `ERR_print_errors_fp()` in C.
    pub fn iter(&self) -> impl Iterator<Item = &ErrorDetail> {
        self.errors.iter()
    }
}

impl fmt::Display for ErrorStack {
    /// Formats all errors in the stack, one per line, from oldest to newest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, detail) in self.errors.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{detail}")?;
        }
        Ok(())
    }
}

// =============================================================================
// err_detail! Macro — Convenience Constructor for ErrorDetail
// =============================================================================

/// Constructs an `ErrorDetail` record with automatic source location
/// capture via `file!()`, `line!()`, and `module_path!()`.
///
/// This macro eliminates boilerplate when creating error details for
/// the FFI-facing `ErrorStack`. In idiomatic Rust code, prefer
/// returning `Err(SomeError::Variant { … })` directly instead.
///
/// # Usage
///
/// ```
/// use openssl_common::{err_detail, error::{ErrorDetail, ErrorLibrary}};
///
/// // Without auxiliary data:
/// let detail: ErrorDetail = err_detail!(ErrorLibrary::Rsa, "key too short");
///
/// // With auxiliary data:
/// let detail: ErrorDetail = err_detail!(
///     ErrorLibrary::Evp,
///     "unsupported algorithm",
///     "requested: CHACHA20-POLY1305"
/// );
/// assert!(detail.data.is_some());
/// ```
#[macro_export]
macro_rules! err_detail {
    ($lib:expr, $reason:expr) => {
        $crate::error::ErrorDetail {
            library: $lib,
            reason: $reason.to_string(),
            file: file!(),
            line: line!(),
            function: module_path!(),
            data: None,
        }
    };
    ($lib:expr, $reason:expr, $data:expr) => {
        $crate::error::ErrorDetail {
            library: $lib,
            reason: $reason.to_string(),
            file: file!(),
            line: line!(),
            function: module_path!(),
            data: Some($data.to_string()),
        }
    };
}

// =============================================================================
// Result Type Aliases
// =============================================================================

/// Convenience `Result` alias for operations in `openssl-common`.
///
/// Functions returning this type use `CommonError` as their error variant.
pub type CommonResult<T> = Result<T, CommonError>;

/// Convenience `Result` alias for operations in `openssl-crypto`.
///
/// Functions returning this type use `CryptoError` as their error variant.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Convenience `Result` alias for operations in `openssl-ssl`.
///
/// Functions returning this type use `SslError` as their error variant.
pub type SslResult<T> = Result<T, SslError>;

/// Convenience `Result` alias for operations in `openssl-provider`.
///
/// Functions returning this type use `ProviderError` as their error variant.
pub type ProviderResult<T> = Result<T, ProviderError>;

/// Convenience `Result` alias for operations in `openssl-fips`.
///
/// Functions returning this type use `FipsError` as their error variant.
pub type FipsResult<T> = Result<T, FipsError>;
