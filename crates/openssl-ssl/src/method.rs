//! SSL method constructors — Rust equivalent of `ssl/methods.c`.
//!
//! This module replaces the C macro-generated `SSL_METHOD` constructors
//! (`IMPLEMENT_tls_meth_func`, `IMPLEMENT_dtls1_meth_func`) with an idiomatic
//! Rust enum-and-struct approach. Each SSL method is a singleton `&'static SslMethod`
//! backed by [`once_cell::sync::Lazy`], replacing the C static const struct pattern.
//!
//! # Architecture
//!
//! In the C codebase, `ssl/methods.c` uses two macros to expand into 25+
//! `SSL_METHOD` constructor functions, each returning a pointer to a static
//! struct containing function pointers for accept, connect, read, write, etc.
//! The Rust translation separates *protocol metadata* (version, role, flags)
//! from *behavior dispatch* (which is handled by the state machine and record
//! layer modules via trait-based dispatch).
//!
//! # Wire Version Constants
//!
//! Wire version numbers match the TLS/DTLS on-the-wire encoding from
//! `include/openssl/prov_ssl.h`:
//!
//! | Protocol   | Wire Version |
//! |------------|-------------|
//! | TLS 1.0    | `0x0301`    |
//! | TLS 1.1    | `0x0302`    |
//! | TLS 1.2    | `0x0303`    |
//! | TLS 1.3    | `0x0304`    |
//! | DTLS 1.0   | `0xFEFF`    |
//! | DTLS 1.2   | `0xFEFD`    |
//!
//! # Feature Gating
//!
//! Protocol version methods are gated behind Cargo feature flags, replacing
//! the C preprocessor `OPENSSL_NO_*` guards:
//!
//! | C Guard                        | Rust Feature |
//! |-------------------------------|-------------|
//! | `OPENSSL_NO_TLS1_3`           | `tls13`     |
//! | `OPENSSL_NO_TLS1_2_METHOD`    | `tls12`     |
//! | `OPENSSL_NO_TLS1_1_METHOD`    | `tls11`     |
//! | `OPENSSL_NO_TLS1_METHOD`      | `tls10`     |
//! | `OPENSSL_NO_DTLS`             | `dtls`      |
//!
//! # Thread Safety
//!
//! All `SslMethod` instances are immutable singletons initialized via
//! `once_cell::sync::Lazy`. They are `Send + Sync` and require no locking.
//!
//! # Examples
//!
//! ```rust
//! use openssl_ssl::method::SslMethod;
//!
//! // Get the general-purpose TLS method (any supported version, client+server)
//! let method = SslMethod::tls();
//! assert!(method.version().is_tls());
//! ```

use std::fmt;

use bitflags::bitflags;
use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// Wire version constants — from include/openssl/prov_ssl.h
// These are u16 constants matching the TLS/DTLS on-the-wire encoding.
// Using named constants avoids bare numeric literals and satisfies Rule R6
// (no bare `as` casts for narrowing conversions).
// ---------------------------------------------------------------------------

/// TLS 1.0 wire version (`0x0301`).
const TLS1_VERSION: u16 = 0x0301;

/// TLS 1.1 wire version (`0x0302`).
const TLS1_1_VERSION: u16 = 0x0302;

/// TLS 1.2 wire version (`0x0303`).
const TLS1_2_VERSION: u16 = 0x0303;

/// TLS 1.3 wire version (`0x0304`).
const TLS1_3_VERSION: u16 = 0x0304;

/// DTLS 1.0 wire version (`0xFEFF`).
///
/// Note: DTLS version numbers are inverted compared to TLS — lower numeric
/// values represent *newer* protocol versions. This matches the encoding
/// in `include/openssl/prov_ssl.h`.
const DTLS1_VERSION: u16 = 0xFEFF;

/// DTLS 1.2 wire version (`0xFEFD`).
const DTLS1_2_VERSION: u16 = 0xFEFD;

/// Sentinel for "any TLS version" — used by `TLS_method()` to indicate
/// version negotiation should select the highest mutually supported version.
/// This is an internal-only value and never appears on the wire.
/// Matches `TLS_ANY_VERSION` from `include/openssl/tls1.h`.
const TLS_ANY_VERSION: u32 = 0x10000;

/// Sentinel for "any DTLS version" — used by `DTLS_method()`.
/// Matches `DTLS_ANY_VERSION` from `include/openssl/dtls1.h`.
const DTLS_ANY_VERSION: u32 = 0x1FFFF;

// ===========================================================================
// ProtocolVersion
// ===========================================================================

/// TLS/DTLS protocol version identifier.
///
/// Represents a specific TLS or DTLS protocol version, or a wildcard sentinel
/// (`TlsAny` / `DtlsAny`) indicating that the highest mutually supported
/// version should be negotiated.
///
/// # Ordering
///
/// The derived `PartialOrd`/`Ord` follows enum declaration order, which
/// corresponds to ascending TLS version. DTLS variants are ordered separately
/// because DTLS wire versions are inverted (lower numeric = newer).
///
/// # Mapping to C constants
///
/// | Rust Variant              | C Constant         | Wire Value  |
/// |--------------------------|--------------------|------------|
/// | `ProtocolVersion::TlsAny`| `TLS_ANY_VERSION`  | `0x10000`  |
/// | `ProtocolVersion::Tls1_0`| `TLS1_VERSION`     | `0x0301`   |
/// | `ProtocolVersion::Tls1_1`| `TLS1_1_VERSION`   | `0x0302`   |
/// | `ProtocolVersion::Tls1_2`| `TLS1_2_VERSION`   | `0x0303`   |
/// | `ProtocolVersion::Tls1_3`| `TLS1_3_VERSION`   | `0x0304`   |
/// | `ProtocolVersion::DtlsAny`| `DTLS_ANY_VERSION`| `0x1FFFF`  |
/// | `ProtocolVersion::Dtls1_0`| `DTLS1_VERSION`   | `0xFEFF`   |
/// | `ProtocolVersion::Dtls1_2`| `DTLS1_2_VERSION`  | `0xFEFD`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// Wildcard: negotiate the highest supported TLS version.
    /// Equivalent to `TLS_ANY_VERSION` in the C codebase.
    TlsAny,
    /// TLS 1.0 (RFC 2246). Wire version `0x0301`.
    Tls1_0,
    /// TLS 1.1 (RFC 4346). Wire version `0x0302`.
    Tls1_1,
    /// TLS 1.2 (RFC 5246). Wire version `0x0303`.
    Tls1_2,
    /// TLS 1.3 (RFC 8446). Wire version `0x0304`.
    Tls1_3,
    /// Wildcard: negotiate the highest supported DTLS version.
    /// Equivalent to `DTLS_ANY_VERSION` in the C codebase.
    DtlsAny,
    /// DTLS 1.0 (RFC 4347). Wire version `0xFEFF`.
    Dtls1_0,
    /// DTLS 1.2 (RFC 6347). Wire version `0xFEFD`.
    Dtls1_2,
}

impl ProtocolVersion {
    /// Returns the on-the-wire version number for this protocol version.
    ///
    /// For concrete versions this returns the standard TLS/DTLS wire encoding
    /// as a `u16`. For wildcard versions (`TlsAny`, `DtlsAny`) this returns
    /// `None` because wildcards have no wire representation — they are
    /// internal-only sentinels used during version negotiation.
    ///
    /// # Rule R5 Compliance
    ///
    /// Returns `Option<u16>` instead of a sentinel value (such as `0`) to
    /// indicate that wildcard versions have no wire encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::ProtocolVersion;
    ///
    /// assert_eq!(ProtocolVersion::Tls1_3.wire_version(), Some(0x0304));
    /// assert_eq!(ProtocolVersion::TlsAny.wire_version(), None);
    /// ```
    #[must_use]
    pub const fn wire_version(self) -> Option<u16> {
        match self {
            Self::TlsAny | Self::DtlsAny => None,
            Self::Tls1_0 => Some(TLS1_VERSION),
            Self::Tls1_1 => Some(TLS1_1_VERSION),
            Self::Tls1_2 => Some(TLS1_2_VERSION),
            Self::Tls1_3 => Some(TLS1_3_VERSION),
            Self::Dtls1_0 => Some(DTLS1_VERSION),
            Self::Dtls1_2 => Some(DTLS1_2_VERSION),
        }
    }

    /// Returns the raw numeric representation of this protocol version.
    ///
    /// Unlike [`wire_version`](Self::wire_version), this returns a value for
    /// *every* variant including wildcards. Wildcard values use the extended
    /// `u32` range (`TLS_ANY_VERSION = 0x10000`, `DTLS_ANY_VERSION = 0x1FFFF`)
    /// matching the C definitions in `include/openssl/tls1.h` and
    /// `include/openssl/dtls1.h`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::ProtocolVersion;
    ///
    /// assert_eq!(ProtocolVersion::Tls1_3.as_raw(), 0x0304);
    /// assert_eq!(ProtocolVersion::TlsAny.as_raw(), 0x10000);
    /// ```
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::TlsAny => TLS_ANY_VERSION,
            Self::Tls1_0 => TLS1_VERSION as u32,
            Self::Tls1_1 => TLS1_1_VERSION as u32,
            Self::Tls1_2 => TLS1_2_VERSION as u32,
            Self::Tls1_3 => TLS1_3_VERSION as u32,
            Self::DtlsAny => DTLS_ANY_VERSION,
            Self::Dtls1_0 => DTLS1_VERSION as u32,
            Self::Dtls1_2 => DTLS1_2_VERSION as u32,
        }
    }

    /// Attempts to convert a raw numeric version to a [`ProtocolVersion`].
    ///
    /// Accepts both the standard `u16` wire versions and the extended `u32`
    /// sentinel values used for `TlsAny` and `DtlsAny`.
    ///
    /// # Rule R5 Compliance
    ///
    /// Returns `Option<ProtocolVersion>` — `None` for unrecognized values
    /// instead of a sentinel or panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::ProtocolVersion;
    ///
    /// assert_eq!(ProtocolVersion::from_raw(0x0304), Some(ProtocolVersion::Tls1_3));
    /// assert_eq!(ProtocolVersion::from_raw(0x10000), Some(ProtocolVersion::TlsAny));
    /// assert_eq!(ProtocolVersion::from_raw(0xFFFF), None);
    /// ```
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            TLS_ANY_VERSION => Some(Self::TlsAny),
            0x0301 => Some(Self::Tls1_0),
            0x0302 => Some(Self::Tls1_1),
            0x0303 => Some(Self::Tls1_2),
            0x0304 => Some(Self::Tls1_3),
            DTLS_ANY_VERSION => Some(Self::DtlsAny),
            0xFEFF => Some(Self::Dtls1_0),
            0xFEFD => Some(Self::Dtls1_2),
            _ => None,
        }
    }

    /// Returns `true` if this is a TLS protocol version (including `TlsAny`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::ProtocolVersion;
    ///
    /// assert!(ProtocolVersion::Tls1_3.is_tls());
    /// assert!(ProtocolVersion::TlsAny.is_tls());
    /// assert!(!ProtocolVersion::Dtls1_2.is_tls());
    /// ```
    #[must_use]
    pub const fn is_tls(self) -> bool {
        matches!(
            self,
            Self::TlsAny | Self::Tls1_0 | Self::Tls1_1 | Self::Tls1_2 | Self::Tls1_3
        )
    }

    /// Returns `true` if this is a DTLS protocol version (including `DtlsAny`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::ProtocolVersion;
    ///
    /// assert!(ProtocolVersion::Dtls1_2.is_dtls());
    /// assert!(ProtocolVersion::DtlsAny.is_dtls());
    /// assert!(!ProtocolVersion::Tls1_3.is_dtls());
    /// ```
    #[must_use]
    pub const fn is_dtls(self) -> bool {
        matches!(self, Self::DtlsAny | Self::Dtls1_0 | Self::Dtls1_2)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsAny => f.write_str("TLS (any version)"),
            Self::Tls1_0 => f.write_str("TLSv1.0"),
            Self::Tls1_1 => f.write_str("TLSv1.1"),
            Self::Tls1_2 => f.write_str("TLSv1.2"),
            Self::Tls1_3 => f.write_str("TLSv1.3"),
            Self::DtlsAny => f.write_str("DTLS (any version)"),
            Self::Dtls1_0 => f.write_str("DTLSv1.0"),
            Self::Dtls1_2 => f.write_str("DTLSv1.2"),
        }
    }
}

// ===========================================================================
// SslRole
// ===========================================================================

/// Specifies whether an [`SslMethod`] is restricted to client-only,
/// server-only, or both (full duplex) operation.
///
/// In the C codebase, separate functions are generated for each role:
/// - `TLS_method()` → `SslRole::Both`
/// - `TLS_client_method()` → `SslRole::Client`
/// - `TLS_server_method()` → `SslRole::Server`
///
/// The role determines which handshake state machine transitions are valid.
/// A `Client`-only method cannot accept incoming connections; a `Server`-only
/// method cannot initiate outgoing connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SslRole {
    /// Client-only: can initiate connections via `SSL_connect()`.
    /// The accept (server) code path is unavailable.
    Client,
    /// Server-only: can accept connections via `SSL_accept()`.
    /// The connect (client) code path is unavailable.
    Server,
    /// Full duplex: can both initiate and accept connections.
    /// This is the default role returned by `SslMethod::tls()`.
    Both,
}

impl fmt::Display for SslRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => f.write_str("client"),
            Self::Server => f.write_str("server"),
            Self::Both => f.write_str("client+server"),
        }
    }
}

// ===========================================================================
// SslMethodFlags
// ===========================================================================

bitflags! {
    /// Flags controlling SSL method behavior.
    ///
    /// These flags replace the C `SSL_METHOD_NO_*` integer constants defined
    /// in `ssl/ssl_local.h` (lines 2264–2265):
    ///
    /// ```c
    /// #define SSL_METHOD_NO_FIPS   (1U << 0)
    /// #define SSL_METHOD_NO_SUITEB (1U << 1)
    /// ```
    ///
    /// Flags are set on [`SslMethod`] instances to indicate that certain
    /// compliance modes are not supported by that protocol version.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_ssl::method::SslMethodFlags;
    ///
    /// let flags = SslMethodFlags::NO_SUITEB | SslMethodFlags::NO_FIPS;
    /// assert!(flags.contains(SslMethodFlags::NO_SUITEB));
    /// assert_eq!(flags.bits(), 0b11);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SslMethodFlags: u32 {
        /// This method does not support FIPS mode operation.
        ///
        /// Corresponds to `SSL_METHOD_NO_FIPS` (`1U << 0`) in C.
        /// Set on legacy protocol versions that use algorithms not approved
        /// for FIPS 140-3 operation (e.g., TLS 1.0 with MD5-based PRF).
        const NO_FIPS = 1 << 0;

        /// This method does not support Suite B (RFC 6460) operation.
        ///
        /// Corresponds to `SSL_METHOD_NO_SUITEB` (`1U << 1`) in C.
        /// Set on protocol versions older than TLS 1.2 because Suite B
        /// requires TLS 1.2+ with specific cipher suites (AES-GCM + ECDSA).
        const NO_SUITEB = 1 << 1;
    }
}

impl fmt::Display for SslMethodFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("(none)");
        }
        let mut first = true;
        if self.contains(Self::NO_FIPS) {
            f.write_str("NO_FIPS")?;
            first = false;
        }
        if self.contains(Self::NO_SUITEB) {
            if !first {
                f.write_str(" | ")?;
            }
            f.write_str("NO_SUITEB")?;
        }
        Ok(())
    }
}

// ===========================================================================
// SslMethod
// ===========================================================================

/// SSL/TLS method descriptor — Rust equivalent of the C `SSL_METHOD` struct.
///
/// An `SslMethod` captures the protocol metadata (version, role, flags,
/// min/max version bounds) for a TLS or DTLS connection factory. In the C
/// codebase, `SSL_METHOD` also contains function pointers for read, write,
/// accept, connect, etc.; in Rust these behaviors are handled by trait-based
/// dispatch in the state machine and record layer modules.
///
/// # Construction
///
/// `SslMethod` instances are constructed via associated functions that return
/// `&'static SslMethod` references to lazily-initialized singletons:
///
/// ```rust
/// use openssl_ssl::method::SslMethod;
///
/// let tls = SslMethod::tls();          // any version, client+server
/// let client = SslMethod::tls_client(); // any version, client only
/// let server = SslMethod::tls_server(); // any version, server only
/// ```
///
/// # Thread Safety
///
/// // LOCK-SCOPE: none — immutable singletons (Rule R7)
///
/// All `SslMethod` instances are immutable `&'static` references backed by
/// `once_cell::sync::Lazy`. They are `Send + Sync` without requiring any
/// locking. The `Lazy` ensures thread-safe one-time initialization.
///
/// # Lifetime
///
/// Methods are `'static` — they live for the entire program duration,
/// matching the C behavior where `SSL_METHOD` structs are static constants.
///
/// # Rule R10 Compliance
///
/// Every method constructor is reachable from the `SslCtx::new(method)` entry
/// point, which accepts `&'static SslMethod` to configure a new SSL context.
#[derive(Debug)]
pub struct SslMethod {
    /// The protocol version this method is configured for.
    version: ProtocolVersion,
    /// Whether this method is client-only, server-only, or both.
    role: SslRole,
    /// Flags controlling FIPS/Suite B compatibility.
    flags: SslMethodFlags,
    /// Minimum protocol version for negotiation, or `None` for default.
    ///
    /// When `Some`, version negotiation will not select a version below this.
    /// When `None`, the library default minimum applies.
    ///
    /// Rule R5: `Option<ProtocolVersion>` replaces the C sentinel of 0 for
    /// "no minimum specified".
    min_version: Option<ProtocolVersion>,
    /// Maximum protocol version for negotiation, or `None` for default.
    ///
    /// When `Some`, version negotiation will not select a version above this.
    /// When `None`, the library default maximum applies.
    ///
    /// Rule R5: `Option<ProtocolVersion>` replaces the C sentinel of 0 for
    /// "no maximum specified".
    max_version: Option<ProtocolVersion>,
}

impl SslMethod {
    /// Returns the protocol version this method is configured for.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the role (client, server, or both) for this method.
    #[must_use]
    pub const fn role(&self) -> SslRole {
        self.role
    }

    /// Returns the flags set on this method.
    #[must_use]
    pub const fn flags(&self) -> SslMethodFlags {
        self.flags
    }

    /// Returns the minimum version for negotiation, or `None` if the
    /// library default should be used.
    ///
    /// Rule R5: returns `Option<ProtocolVersion>` — no sentinel values.
    #[must_use]
    pub const fn min_version(&self) -> Option<ProtocolVersion> {
        self.min_version
    }

    /// Returns the maximum version for negotiation, or `None` if the
    /// library default should be used.
    ///
    /// Rule R5: returns `Option<ProtocolVersion>` — no sentinel values.
    #[must_use]
    pub const fn max_version(&self) -> Option<ProtocolVersion> {
        self.max_version
    }
}

// ---------------------------------------------------------------------------
// TLS method constructors (any version)
// ---------------------------------------------------------------------------
// These are always available regardless of feature flags, matching the C
// behavior where TLS_method(), TLS_client_method(), and TLS_server_method()
// are always defined.

// LOCK-SCOPE: none — immutable singletons (Rule R7)
static TLS_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
    version: ProtocolVersion::TlsAny,
    role: SslRole::Both,
    flags: SslMethodFlags::empty(),
    min_version: None,
    max_version: None,
});

// LOCK-SCOPE: none — immutable singletons (Rule R7)
static TLS_CLIENT_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
    version: ProtocolVersion::TlsAny,
    role: SslRole::Client,
    flags: SslMethodFlags::empty(),
    min_version: None,
    max_version: None,
});

// LOCK-SCOPE: none — immutable singletons (Rule R7)
static TLS_SERVER_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
    version: ProtocolVersion::TlsAny,
    role: SslRole::Server,
    flags: SslMethodFlags::empty(),
    min_version: None,
    max_version: None,
});

impl SslMethod {
    /// General-purpose TLS method — equivalent to C `TLS_method()`.
    ///
    /// Returns a method that supports any TLS version (1.0 through 1.3)
    /// with both client and server roles. Version negotiation selects the
    /// highest mutually supported version.
    ///
    /// This is the recommended method for most applications.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// const SSL_METHOD *TLS_method(void);
    /// ```
    #[must_use]
    pub fn tls() -> &'static SslMethod {
        &TLS_METHOD
    }

    /// Client-only TLS method — equivalent to C `TLS_client_method()`.
    ///
    /// Returns a method that supports any TLS version but is restricted to
    /// the client role. The server accept code path is unavailable.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// const SSL_METHOD *TLS_client_method(void);
    /// ```
    #[must_use]
    pub fn tls_client() -> &'static SslMethod {
        &TLS_CLIENT_METHOD
    }

    /// Server-only TLS method — equivalent to C `TLS_server_method()`.
    ///
    /// Returns a method that supports any TLS version but is restricted to
    /// the server role. The client connect code path is unavailable.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// const SSL_METHOD *TLS_server_method(void);
    /// ```
    #[must_use]
    pub fn tls_server() -> &'static SslMethod {
        &TLS_SERVER_METHOD
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3 method constructors
// Gated by `#[cfg(feature = "tls13")]` — replaces `#ifndef OPENSSL_NO_TLS1_3`
// ---------------------------------------------------------------------------

#[cfg(feature = "tls13")]
mod tls13_methods {
    use super::{Lazy, ProtocolVersion, SslMethod, SslMethodFlags, SslRole};

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static TLS_1_3_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Tls1_3,
        role: SslRole::Both,
        flags: SslMethodFlags::empty(),
        min_version: Some(ProtocolVersion::Tls1_3),
        max_version: Some(ProtocolVersion::Tls1_3),
    });
}

impl SslMethod {
    /// TLS 1.3–only method — equivalent to C `tlsv1_3_method()`.
    ///
    /// Returns a method pinned to TLS 1.3 (RFC 8446) for both client and
    /// server roles. Version negotiation is restricted to TLS 1.3 only.
    ///
    /// # Feature Gate
    ///
    /// Requires the `tls13` feature flag (enabled by default). This replaces
    /// the C `#ifndef OPENSSL_NO_TLS1_3` guard.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// const SSL_METHOD *tlsv1_3_method(void);
    /// const SSL_METHOD *tlsv1_3_client_method(void);
    /// const SSL_METHOD *tlsv1_3_server_method(void);
    /// ```
    ///
    /// In the Rust API, the single method with `SslRole::Both` serves the
    /// same purpose as all three C functions. Role can be inspected via
    /// [`SslMethod::role()`].
    #[cfg(feature = "tls13")]
    #[must_use]
    pub fn tls_1_3() -> &'static SslMethod {
        &tls13_methods::TLS_1_3_METHOD
    }
}

// ---------------------------------------------------------------------------
// TLS 1.2 method constructors
// Gated by `#[cfg(feature = "tls12")]` — replaces `#ifndef OPENSSL_NO_TLS1_2_METHOD`
// ---------------------------------------------------------------------------

#[cfg(feature = "tls12")]
mod tls12_methods {
    use super::{Lazy, ProtocolVersion, SslMethod, SslMethodFlags, SslRole};

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static TLS_1_2_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Tls1_2,
        role: SslRole::Both,
        flags: SslMethodFlags::empty(),
        min_version: Some(ProtocolVersion::Tls1_2),
        max_version: Some(ProtocolVersion::Tls1_2),
    });
}

impl SslMethod {
    /// TLS 1.2–only method — equivalent to C `tlsv1_2_method()`.
    ///
    /// Returns a method pinned to TLS 1.2 (RFC 5246) for both client and
    /// server roles. Version negotiation is restricted to TLS 1.2 only.
    ///
    /// # Feature Gate
    ///
    /// Requires the `tls12` feature flag (enabled by default). This replaces
    /// the C `#ifndef OPENSSL_NO_TLS1_2_METHOD` guard.
    #[cfg(feature = "tls12")]
    #[must_use]
    pub fn tls_1_2() -> &'static SslMethod {
        &tls12_methods::TLS_1_2_METHOD
    }
}

// ---------------------------------------------------------------------------
// TLS 1.1 method constructors
// Gated by `#[cfg(feature = "tls11")]` — replaces `#ifndef OPENSSL_NO_TLS1_1_METHOD`
//
// In the C source, TLS 1.1 methods have SSL_METHOD_NO_SUITEB set because
// Suite B requires TLS 1.2+ with specific cipher suites.
// ---------------------------------------------------------------------------

#[cfg(feature = "tls11")]
mod tls11_methods {
    use super::{Lazy, ProtocolVersion, SslMethod, SslMethodFlags, SslRole};

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static TLS_1_1_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Tls1_1,
        role: SslRole::Both,
        flags: SslMethodFlags::NO_SUITEB,
        min_version: Some(ProtocolVersion::Tls1_1),
        max_version: Some(ProtocolVersion::Tls1_1),
    });
}

impl SslMethod {
    /// TLS 1.1–only method — equivalent to C `tlsv1_1_method()`.
    ///
    /// Returns a method pinned to TLS 1.1 (RFC 4346) for both client and
    /// server roles. Suite B mode is not supported (flag `NO_SUITEB` is set)
    /// because Suite B requires TLS 1.2+.
    ///
    /// # Feature Gate
    ///
    /// Requires the `tls11` feature flag (enabled by default). This replaces
    /// the C `#ifndef OPENSSL_NO_TLS1_1_METHOD` guard.
    #[cfg(feature = "tls11")]
    #[must_use]
    pub fn tls_1_1() -> &'static SslMethod {
        &tls11_methods::TLS_1_1_METHOD
    }
}

// ---------------------------------------------------------------------------
// TLS 1.0 method constructors
// Gated by `#[cfg(feature = "tls10")]` — replaces `#ifndef OPENSSL_NO_TLS1_METHOD`
//
// In the C source, TLS 1.0 methods have SSL_METHOD_NO_SUITEB set because
// Suite B requires TLS 1.2+ with specific cipher suites.
// ---------------------------------------------------------------------------

#[cfg(feature = "tls10")]
mod tls10_methods {
    use super::{Lazy, ProtocolVersion, SslMethod, SslMethodFlags, SslRole};

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static TLS_1_0_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Tls1_0,
        role: SslRole::Both,
        flags: SslMethodFlags::NO_SUITEB,
        min_version: Some(ProtocolVersion::Tls1_0),
        max_version: Some(ProtocolVersion::Tls1_0),
    });
}

impl SslMethod {
    /// TLS 1.0–only method — equivalent to C `tlsv1_method()`.
    ///
    /// Returns a method pinned to TLS 1.0 (RFC 2246) for both client and
    /// server roles. Suite B mode is not supported (flag `NO_SUITEB` is set)
    /// because Suite B requires TLS 1.2+.
    ///
    /// # Feature Gate
    ///
    /// Requires the `tls10` feature flag (enabled by default). This replaces
    /// the C `#ifndef OPENSSL_NO_TLS1_METHOD` guard.
    ///
    /// # Security Warning
    ///
    /// TLS 1.0 is considered insecure and should not be used in production.
    /// Consider using [`SslMethod::tls()`] to negotiate the highest available
    /// version, or pin to [`SslMethod::tls_1_2()`] or [`SslMethod::tls_1_3()`].
    #[cfg(feature = "tls10")]
    #[must_use]
    pub fn tls_1_0() -> &'static SslMethod {
        &tls10_methods::TLS_1_0_METHOD
    }
}

// ---------------------------------------------------------------------------
// DTLS method constructors
// Gated by `#[cfg(feature = "dtls")]` — replaces `#ifndef OPENSSL_NO_DTLS`
//
// DTLS version numbers are inverted: 0xFEFF = DTLS 1.0, 0xFEFD = DTLS 1.2.
// Lower numeric values represent newer DTLS versions.
// ---------------------------------------------------------------------------

#[cfg(feature = "dtls")]
mod dtls_methods {
    use super::{Lazy, ProtocolVersion, SslMethod, SslMethodFlags, SslRole};

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static DTLS_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::DtlsAny,
        role: SslRole::Both,
        flags: SslMethodFlags::empty(),
        min_version: None,
        max_version: None,
    });

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static DTLS_CLIENT_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::DtlsAny,
        role: SslRole::Client,
        flags: SslMethodFlags::empty(),
        min_version: None,
        max_version: None,
    });

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static DTLS_SERVER_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::DtlsAny,
        role: SslRole::Server,
        flags: SslMethodFlags::empty(),
        min_version: None,
        max_version: None,
    });

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    // In the C source, DTLS 1.0 methods have SSL_METHOD_NO_SUITEB set.
    pub(super) static DTLS_1_0_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Dtls1_0,
        role: SslRole::Both,
        flags: SslMethodFlags::NO_SUITEB,
        min_version: Some(ProtocolVersion::Dtls1_0),
        max_version: Some(ProtocolVersion::Dtls1_0),
    });

    // LOCK-SCOPE: none — immutable singletons (Rule R7)
    pub(super) static DTLS_1_2_METHOD: Lazy<SslMethod> = Lazy::new(|| SslMethod {
        version: ProtocolVersion::Dtls1_2,
        role: SslRole::Both,
        flags: SslMethodFlags::empty(),
        min_version: Some(ProtocolVersion::Dtls1_2),
        max_version: Some(ProtocolVersion::Dtls1_2),
    });
}

impl SslMethod {
    /// General-purpose DTLS method — equivalent to C `DTLS_method()`.
    ///
    /// Returns a method that supports any DTLS version (1.0 and 1.2) with
    /// both client and server roles. Version negotiation selects the highest
    /// mutually supported DTLS version.
    ///
    /// # Feature Gate
    ///
    /// Requires the `dtls` feature flag (enabled by default). This replaces
    /// the C `#ifndef OPENSSL_NO_DTLS` guard.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// const SSL_METHOD *DTLS_method(void);
    /// ```
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn dtls() -> &'static SslMethod {
        &dtls_methods::DTLS_METHOD
    }

    /// Client-only DTLS method — equivalent to C `DTLS_client_method()`.
    ///
    /// Returns a method that supports any DTLS version but is restricted to
    /// the client role.
    ///
    /// # Feature Gate
    ///
    /// Requires the `dtls` feature flag (enabled by default).
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn dtls_client() -> &'static SslMethod {
        &dtls_methods::DTLS_CLIENT_METHOD
    }

    /// Server-only DTLS method — equivalent to C `DTLS_server_method()`.
    ///
    /// Returns a method that supports any DTLS version but is restricted to
    /// the server role.
    ///
    /// # Feature Gate
    ///
    /// Requires the `dtls` feature flag (enabled by default).
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn dtls_server() -> &'static SslMethod {
        &dtls_methods::DTLS_SERVER_METHOD
    }

    /// DTLS 1.0–only method — equivalent to C `dtlsv1_method()`.
    ///
    /// Returns a method pinned to DTLS 1.0 (RFC 4347) for both client and
    /// server roles. Suite B mode is not supported (flag `NO_SUITEB` is set)
    /// because Suite B requires DTLS 1.2+.
    ///
    /// # Feature Gate
    ///
    /// Requires the `dtls` feature flag (enabled by default). In the C source,
    /// DTLS 1.0 methods are separately gated by `OPENSSL_NO_DTLS1_METHOD`.
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn dtls_1_0() -> &'static SslMethod {
        &dtls_methods::DTLS_1_0_METHOD
    }

    /// DTLS 1.2–only method — equivalent to C `dtlsv1_2_method()`.
    ///
    /// Returns a method pinned to DTLS 1.2 (RFC 6347) for both client and
    /// server roles. No flags are set — DTLS 1.2 supports both FIPS and
    /// Suite B operation.
    ///
    /// # Feature Gate
    ///
    /// Requires the `dtls` feature flag (enabled by default). In the C source,
    /// DTLS 1.2 methods are separately gated by `OPENSSL_NO_DTLS1_2_METHOD`.
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn dtls_1_2() -> &'static SslMethod {
        &dtls_methods::DTLS_1_2_METHOD
    }
}

impl fmt::Display for SslMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SslMethod({}, role={})", self.version, self.role)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ProtocolVersion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_protocol_version_wire_versions() {
        assert_eq!(ProtocolVersion::Tls1_0.wire_version(), Some(0x0301));
        assert_eq!(ProtocolVersion::Tls1_1.wire_version(), Some(0x0302));
        assert_eq!(ProtocolVersion::Tls1_2.wire_version(), Some(0x0303));
        assert_eq!(ProtocolVersion::Tls1_3.wire_version(), Some(0x0304));
        assert_eq!(ProtocolVersion::Dtls1_0.wire_version(), Some(0xFEFF));
        assert_eq!(ProtocolVersion::Dtls1_2.wire_version(), Some(0xFEFD));
    }

    #[test]
    fn test_protocol_version_wildcard_wire_version_is_none() {
        assert_eq!(ProtocolVersion::TlsAny.wire_version(), None);
        assert_eq!(ProtocolVersion::DtlsAny.wire_version(), None);
    }

    #[test]
    fn test_protocol_version_as_raw() {
        assert_eq!(ProtocolVersion::TlsAny.as_raw(), 0x10000);
        assert_eq!(ProtocolVersion::Tls1_0.as_raw(), 0x0301);
        assert_eq!(ProtocolVersion::Tls1_1.as_raw(), 0x0302);
        assert_eq!(ProtocolVersion::Tls1_2.as_raw(), 0x0303);
        assert_eq!(ProtocolVersion::Tls1_3.as_raw(), 0x0304);
        assert_eq!(ProtocolVersion::DtlsAny.as_raw(), 0x1FFFF);
        assert_eq!(ProtocolVersion::Dtls1_0.as_raw(), 0xFEFF);
        assert_eq!(ProtocolVersion::Dtls1_2.as_raw(), 0xFEFD);
    }

    #[test]
    fn test_protocol_version_from_raw_roundtrip() {
        let versions = [
            ProtocolVersion::TlsAny,
            ProtocolVersion::Tls1_0,
            ProtocolVersion::Tls1_1,
            ProtocolVersion::Tls1_2,
            ProtocolVersion::Tls1_3,
            ProtocolVersion::DtlsAny,
            ProtocolVersion::Dtls1_0,
            ProtocolVersion::Dtls1_2,
        ];
        for v in &versions {
            let raw = v.as_raw();
            let back = ProtocolVersion::from_raw(raw);
            assert_eq!(back, Some(*v), "roundtrip failed for {v:?} (raw={raw:#x})");
        }
    }

    #[test]
    fn test_protocol_version_from_raw_unknown() {
        assert_eq!(ProtocolVersion::from_raw(0x0000), None);
        assert_eq!(ProtocolVersion::from_raw(0xFFFF), None);
        assert_eq!(ProtocolVersion::from_raw(0x0300), None); // SSL 3.0 not supported
        assert_eq!(ProtocolVersion::from_raw(0x0100), None); // DTLS1_BAD_VER not mapped
    }

    #[test]
    fn test_protocol_version_is_tls() {
        assert!(ProtocolVersion::TlsAny.is_tls());
        assert!(ProtocolVersion::Tls1_0.is_tls());
        assert!(ProtocolVersion::Tls1_1.is_tls());
        assert!(ProtocolVersion::Tls1_2.is_tls());
        assert!(ProtocolVersion::Tls1_3.is_tls());
        assert!(!ProtocolVersion::DtlsAny.is_tls());
        assert!(!ProtocolVersion::Dtls1_0.is_tls());
        assert!(!ProtocolVersion::Dtls1_2.is_tls());
    }

    #[test]
    fn test_protocol_version_is_dtls() {
        assert!(!ProtocolVersion::TlsAny.is_dtls());
        assert!(!ProtocolVersion::Tls1_0.is_dtls());
        assert!(!ProtocolVersion::Tls1_3.is_dtls());
        assert!(ProtocolVersion::DtlsAny.is_dtls());
        assert!(ProtocolVersion::Dtls1_0.is_dtls());
        assert!(ProtocolVersion::Dtls1_2.is_dtls());
    }

    #[test]
    fn test_protocol_version_display() {
        assert_eq!(format!("{}", ProtocolVersion::TlsAny), "TLS (any version)");
        assert_eq!(format!("{}", ProtocolVersion::Tls1_0), "TLSv1.0");
        assert_eq!(format!("{}", ProtocolVersion::Tls1_1), "TLSv1.1");
        assert_eq!(format!("{}", ProtocolVersion::Tls1_2), "TLSv1.2");
        assert_eq!(format!("{}", ProtocolVersion::Tls1_3), "TLSv1.3");
        assert_eq!(
            format!("{}", ProtocolVersion::DtlsAny),
            "DTLS (any version)"
        );
        assert_eq!(format!("{}", ProtocolVersion::Dtls1_0), "DTLSv1.0");
        assert_eq!(format!("{}", ProtocolVersion::Dtls1_2), "DTLSv1.2");
    }

    #[test]
    fn test_protocol_version_ordering() {
        // TLS versions should be ordered by ascending version
        assert!(ProtocolVersion::Tls1_0 < ProtocolVersion::Tls1_1);
        assert!(ProtocolVersion::Tls1_1 < ProtocolVersion::Tls1_2);
        assert!(ProtocolVersion::Tls1_2 < ProtocolVersion::Tls1_3);
    }

    #[test]
    fn test_protocol_version_clone_copy() {
        let v = ProtocolVersion::Tls1_3;
        let v2 = v; // Copy
        let v3 = v.clone(); // Clone
        assert_eq!(v, v2);
        assert_eq!(v, v3);
    }

    // -----------------------------------------------------------------------
    // SslRole tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssl_role_display() {
        assert_eq!(format!("{}", SslRole::Client), "client");
        assert_eq!(format!("{}", SslRole::Server), "server");
        assert_eq!(format!("{}", SslRole::Both), "client+server");
    }

    #[test]
    fn test_ssl_role_equality() {
        assert_eq!(SslRole::Client, SslRole::Client);
        assert_ne!(SslRole::Client, SslRole::Server);
        assert_ne!(SslRole::Server, SslRole::Both);
    }

    // -----------------------------------------------------------------------
    // SslMethodFlags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssl_method_flags_empty() {
        let flags = SslMethodFlags::empty();
        assert!(flags.is_empty());
        assert!(!flags.contains(SslMethodFlags::NO_FIPS));
        assert!(!flags.contains(SslMethodFlags::NO_SUITEB));
    }

    #[test]
    fn test_ssl_method_flags_individual() {
        let no_fips = SslMethodFlags::NO_FIPS;
        assert!(no_fips.contains(SslMethodFlags::NO_FIPS));
        assert!(!no_fips.contains(SslMethodFlags::NO_SUITEB));

        let no_suiteb = SslMethodFlags::NO_SUITEB;
        assert!(no_suiteb.contains(SslMethodFlags::NO_SUITEB));
        assert!(!no_suiteb.contains(SslMethodFlags::NO_FIPS));
    }

    #[test]
    fn test_ssl_method_flags_combined() {
        let flags = SslMethodFlags::NO_FIPS | SslMethodFlags::NO_SUITEB;
        assert!(flags.contains(SslMethodFlags::NO_FIPS));
        assert!(flags.contains(SslMethodFlags::NO_SUITEB));
        assert_eq!(flags.bits(), 0b11);
    }

    #[test]
    fn test_ssl_method_flags_all() {
        let all = SslMethodFlags::all();
        assert!(all.contains(SslMethodFlags::NO_FIPS));
        assert!(all.contains(SslMethodFlags::NO_SUITEB));
    }

    #[test]
    fn test_ssl_method_flags_insert_remove() {
        let mut flags = SslMethodFlags::empty();
        flags.insert(SslMethodFlags::NO_FIPS);
        assert!(flags.contains(SslMethodFlags::NO_FIPS));

        flags.remove(SslMethodFlags::NO_FIPS);
        assert!(!flags.contains(SslMethodFlags::NO_FIPS));
    }

    #[test]
    fn test_ssl_method_flags_bits() {
        assert_eq!(SslMethodFlags::NO_FIPS.bits(), 1);
        assert_eq!(SslMethodFlags::NO_SUITEB.bits(), 2);
        assert_eq!(SslMethodFlags::empty().bits(), 0);
    }

    #[test]
    fn test_ssl_method_flags_display() {
        assert_eq!(format!("{}", SslMethodFlags::empty()), "(none)");
        assert_eq!(format!("{}", SslMethodFlags::NO_FIPS), "NO_FIPS");
        assert_eq!(format!("{}", SslMethodFlags::NO_SUITEB), "NO_SUITEB");
        assert_eq!(
            format!("{}", SslMethodFlags::NO_FIPS | SslMethodFlags::NO_SUITEB),
            "NO_FIPS | NO_SUITEB"
        );
    }

    // -----------------------------------------------------------------------
    // SslMethod — TLS constructors (always available)
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_method() {
        let m = SslMethod::tls();
        assert_eq!(m.version(), ProtocolVersion::TlsAny);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().is_empty());
        assert_eq!(m.min_version(), None);
        assert_eq!(m.max_version(), None);
    }

    #[test]
    fn test_tls_client_method() {
        let m = SslMethod::tls_client();
        assert_eq!(m.version(), ProtocolVersion::TlsAny);
        assert_eq!(m.role(), SslRole::Client);
        assert!(m.flags().is_empty());
    }

    #[test]
    fn test_tls_server_method() {
        let m = SslMethod::tls_server();
        assert_eq!(m.version(), ProtocolVersion::TlsAny);
        assert_eq!(m.role(), SslRole::Server);
        assert!(m.flags().is_empty());
    }

    #[test]
    fn test_tls_method_is_singleton() {
        let m1 = SslMethod::tls();
        let m2 = SslMethod::tls();
        assert!(
            std::ptr::eq(m1, m2),
            "tls() should return the same &'static reference"
        );
    }

    #[test]
    fn test_tls_client_method_is_singleton() {
        let m1 = SslMethod::tls_client();
        let m2 = SslMethod::tls_client();
        assert!(std::ptr::eq(m1, m2));
    }

    #[test]
    fn test_tls_server_method_is_singleton() {
        let m1 = SslMethod::tls_server();
        let m2 = SslMethod::tls_server();
        assert!(std::ptr::eq(m1, m2));
    }

    // -----------------------------------------------------------------------
    // SslMethod — TLS version-specific constructors
    // -----------------------------------------------------------------------

    #[cfg(feature = "tls13")]
    #[test]
    fn test_tls_1_3_method() {
        let m = SslMethod::tls_1_3();
        assert_eq!(m.version(), ProtocolVersion::Tls1_3);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().is_empty());
        assert_eq!(m.min_version(), Some(ProtocolVersion::Tls1_3));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Tls1_3));
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_tls_1_2_method() {
        let m = SslMethod::tls_1_2();
        assert_eq!(m.version(), ProtocolVersion::Tls1_2);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().is_empty());
        assert_eq!(m.min_version(), Some(ProtocolVersion::Tls1_2));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Tls1_2));
    }

    #[cfg(feature = "tls11")]
    #[test]
    fn test_tls_1_1_method() {
        let m = SslMethod::tls_1_1();
        assert_eq!(m.version(), ProtocolVersion::Tls1_1);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().contains(SslMethodFlags::NO_SUITEB));
        assert!(!m.flags().contains(SslMethodFlags::NO_FIPS));
        assert_eq!(m.min_version(), Some(ProtocolVersion::Tls1_1));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Tls1_1));
    }

    #[cfg(feature = "tls10")]
    #[test]
    fn test_tls_1_0_method() {
        let m = SslMethod::tls_1_0();
        assert_eq!(m.version(), ProtocolVersion::Tls1_0);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().contains(SslMethodFlags::NO_SUITEB));
        assert!(!m.flags().contains(SslMethodFlags::NO_FIPS));
        assert_eq!(m.min_version(), Some(ProtocolVersion::Tls1_0));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Tls1_0));
    }

    // -----------------------------------------------------------------------
    // SslMethod — DTLS constructors
    // -----------------------------------------------------------------------

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_method() {
        let m = SslMethod::dtls();
        assert_eq!(m.version(), ProtocolVersion::DtlsAny);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().is_empty());
        assert_eq!(m.min_version(), None);
        assert_eq!(m.max_version(), None);
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_client_method() {
        let m = SslMethod::dtls_client();
        assert_eq!(m.version(), ProtocolVersion::DtlsAny);
        assert_eq!(m.role(), SslRole::Client);
        assert!(m.flags().is_empty());
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_server_method() {
        let m = SslMethod::dtls_server();
        assert_eq!(m.version(), ProtocolVersion::DtlsAny);
        assert_eq!(m.role(), SslRole::Server);
        assert!(m.flags().is_empty());
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_1_0_method() {
        let m = SslMethod::dtls_1_0();
        assert_eq!(m.version(), ProtocolVersion::Dtls1_0);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().contains(SslMethodFlags::NO_SUITEB));
        assert_eq!(m.min_version(), Some(ProtocolVersion::Dtls1_0));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Dtls1_0));
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_1_2_method() {
        let m = SslMethod::dtls_1_2();
        assert_eq!(m.version(), ProtocolVersion::Dtls1_2);
        assert_eq!(m.role(), SslRole::Both);
        assert!(m.flags().is_empty());
        assert_eq!(m.min_version(), Some(ProtocolVersion::Dtls1_2));
        assert_eq!(m.max_version(), Some(ProtocolVersion::Dtls1_2));
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_method_singletons() {
        assert!(std::ptr::eq(SslMethod::dtls(), SslMethod::dtls()));
        assert!(std::ptr::eq(
            SslMethod::dtls_client(),
            SslMethod::dtls_client()
        ));
        assert!(std::ptr::eq(
            SslMethod::dtls_server(),
            SslMethod::dtls_server()
        ));
        assert!(std::ptr::eq(SslMethod::dtls_1_0(), SslMethod::dtls_1_0()));
        assert!(std::ptr::eq(SslMethod::dtls_1_2(), SslMethod::dtls_1_2()));
    }

    // -----------------------------------------------------------------------
    // SslMethod — Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssl_method_display() {
        let m = SslMethod::tls();
        let display = format!("{m}");
        assert!(display.contains("TLS (any version)"));
        assert!(display.contains("client+server"));
    }

    // -----------------------------------------------------------------------
    // Cross-cutting: Send + Sync verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssl_method_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SslMethod>();
        assert_send_sync::<ProtocolVersion>();
        assert_send_sync::<SslRole>();
        assert_send_sync::<SslMethodFlags>();
    }

    // -----------------------------------------------------------------------
    // Version protocol family classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_methods_have_tls_version() {
        assert!(SslMethod::tls().version().is_tls());
        assert!(SslMethod::tls_client().version().is_tls());
        assert!(SslMethod::tls_server().version().is_tls());
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn test_dtls_methods_have_dtls_version() {
        assert!(SslMethod::dtls().version().is_dtls());
        assert!(SslMethod::dtls_client().version().is_dtls());
        assert!(SslMethod::dtls_server().version().is_dtls());
        assert!(SslMethod::dtls_1_0().version().is_dtls());
        assert!(SslMethod::dtls_1_2().version().is_dtls());
    }
}
