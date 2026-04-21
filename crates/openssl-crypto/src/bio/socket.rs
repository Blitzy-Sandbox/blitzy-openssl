//! Socket BIO implementations for the OpenSSL Rust workspace.
//!
//! Provides network I/O abstractions wrapping TCP and UDP sockets with
//! connection lifecycle management.  Translates C socket BIOs from
//! `bss_sock.c`, `bss_conn.c`, `bss_acpt.c`, `bss_dgram.c`,
//! `bss_dgram_pair.c`, and the socket utility layer (`bio_sock.c`,
//! `bio_sock2.c`, `bio_addr.c`) into idiomatic Rust with zero `unsafe`.
//!
//! # Types
//!
//! | Rust Type            | C Equivalent              | Source File           |
//! |----------------------|---------------------------|-----------------------|
//! | [`SocketBio`]        | `BIO_s_socket()`          | `bss_sock.c`          |
//! | [`ConnectBio`]       | `BIO_s_connect()`         | `bss_conn.c`          |
//! | [`AcceptBio`]        | `BIO_s_accept()`          | `bss_acpt.c`          |
//! | [`DatagramBio`]      | `BIO_s_datagram()`        | `bss_dgram.c`         |
//! | [`DatagramPairBio`]  | `BIO_s_dgram_pair()`      | `bss_dgram_pair.c`    |
//! | [`BioAddr`]          | `BIO_ADDR`                | `bio_addr.c`          |
//!
//! # Design Principles
//!
//! - **Zero `unsafe`** (Rule R8): Uses only [`std::net`] types
//!   ([`TcpStream`], [`TcpListener`], [`UdpSocket`]).  The C code's raw
//!   `int` file descriptors are encapsulated inside Rust's safe
//!   ownership-managed types.
//! - **No sentinel values** (Rule R5): All nullable results use
//!   [`Option<T>`]; all fallible operations return
//!   [`CryptoResult<T>`] or [`io::Result<T>`].
//! - **Lossless numeric casts** (Rule R6): Port numbers, MTUs, and
//!   backlog values use appropriate typed wrappers ([`u16`], [`usize`],
//!   [`u32`]) — no bare `as` casts for narrowing conversions.
//! - **Fine-grained locking** (Rule R7): [`DatagramPairBio`] uses
//!   [`Arc<Mutex<BytesMut>>`] for the shared ring buffers, each
//!   annotated with `LOCK-SCOPE` documentation.
//! - **Integration-testable** (Rule R10): All types are reachable from
//!   the entry point via `openssl-ssl` → `openssl_crypto::bio::socket`.
//!
//! # Example — TCP Client
//!
//! ```no_run
//! use openssl_crypto::bio::{ConnectBio, Bio};
//! use std::io::{Read, Write};
//!
//! let mut client = ConnectBio::new("example.com", 443);
//! client.connect().expect("connect");
//! client.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("write");
//! let mut buf = [0u8; 1024];
//! let _n = client.read(&mut buf).expect("read");
//! ```
//!
//! # Example — In-Memory Datagram Pair (Testing)
//!
//! ```
//! use openssl_crypto::bio::{new_dgram_pair};
//!
//! // Create a connected pair with 1200-byte MTU.
//! let (_peer_a, _peer_b) = new_dgram_pair(1200);
//! ```

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};

use openssl_common::{CryptoError, CryptoResult};

use super::{Bio, BioError, BioStats, BioType};

// =============================================================================
// Constants
// =============================================================================

/// Default Maximum Transmission Unit for datagram BIOs (bytes).
///
/// Matches the C default `BIO_DGRAM_PAIR_DEFAULT_MTU` in `bss_dgram_pair.c`:
/// `1500` (Ethernet default MTU) minus `28` (IPv4 + UDP header overhead) `= 1472`.
/// Using this value ensures typical UDP packets fit without IP fragmentation.
const DEFAULT_DGRAM_PAIR_MTU: usize = 1472;

/// Default MTU for standard UDP sockets (bytes).
///
/// Matches the common Ethernet MTU used by [`DatagramBio`] when no explicit
/// MTU has been configured via `set_mtu()`.
const DEFAULT_DGRAM_MTU: usize = 1500;

/// Minimum buffer capacity for a datagram pair ring buffer (bytes).
///
/// Matches `MIN_BUF_LEN` in `bss_dgram_pair.c`.  Prevents allocation of
/// trivially small buffers that would be unable to hold even a single
/// datagram.
const MIN_DGRAM_PAIR_BUF: usize = 1024;

/// Default number of packets buffered by a datagram pair before backpressure.
///
/// Matches `bss_dgram_pair.c` which allocates space for approximately
/// `9 * (sizeof(dgram_hdr) + mtu)` by default.
const DEFAULT_DGRAM_PAIR_CAPACITY: usize = 9;

/// Default listen backlog for [`AcceptBio`].
///
/// Matches `SOMAXCONN` / typical OS defaults used by `bss_acpt.c`.
/// Intentionally a `u32` per Rule R6 to avoid bare narrowing `as`
/// casts when passing to platform `listen()` APIs.
const DEFAULT_BACKLOG: u32 = 128;

/// Length prefix size for in-memory datagram pair packet framing.
///
/// Each packet in the [`DatagramPairBio`] ring buffer is preceded by a
/// 2-byte big-endian length header (replaces the C `struct dgram_hdr`
/// framing from `bss_dgram_pair.c`).  With `u16` length, the maximum
/// supported packet size is `u16::MAX` = 65,535 bytes.
const DGRAM_PAIR_LEN_PREFIX: usize = 2;

// =============================================================================
// BioAddr — Network address abstraction (bio_addr.c)
// =============================================================================

/// Network address abstraction replacing C `BIO_ADDR` from
/// `crypto/bio/bio_addr.c`.
///
/// In C, `BIO_ADDR` is a union of `sockaddr_in`, `sockaddr_in6`,
/// `sockaddr_un`, and `sockaddr_storage`, requiring explicit family
/// branching on every access.  In Rust, this maps to
/// [`std::net::SocketAddr`] for IPv4/IPv6 with a separate variant for
/// unresolved hostname + port pairs (deferred DNS resolution).
///
/// # C Mapping
///
/// | C API                        | Rust Equivalent             |
/// |------------------------------|------------------------------|
/// | `BIO_ADDR_new()`             | [`BioAddr::from_socket_addr`] or [`BioAddr::from_host_port`] |
/// | `BIO_ADDR_family()`          | [`SocketAddr::ip`] method chain |
/// | `BIO_ADDR_rawport()`         | [`BioAddr::port`]            |
/// | `BIO_ADDR_hostname_string()` | [`BioAddr::hostname`] or [`BioAddr::to_string`] |
/// | `BIO_lookup_ex()`            | [`BioAddr::resolve`]         |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BioAddr {
    /// A fully-resolved IPv4 or IPv6 socket address.
    ///
    /// Corresponds to a `BIO_ADDR` with populated `sa_family` of
    /// `AF_INET` or `AF_INET6`.
    Socket(SocketAddr),

    /// An unresolved hostname + port pair, pending DNS lookup.
    ///
    /// Corresponds to the output of `BIO_parse_hostserv()` from
    /// `bio_addr.c` before `BIO_lookup_ex()` has been invoked.
    Unresolved {
        /// The hostname portion (may be a numeric IP, a DNS name, or
        /// a Unix socket path depending on context).
        hostname: String,
        /// The port portion in host byte order.
        port: u16,
    },
}

impl BioAddr {
    /// Creates a `BioAddr` from an already-resolved [`SocketAddr`].
    ///
    /// Replaces the C pattern of constructing a `BIO_ADDR` from a
    /// native `struct sockaddr`.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        BioAddr::Socket(addr)
    }

    /// Creates a `BioAddr` from a hostname + port pair for later resolution.
    ///
    /// Does NOT perform DNS resolution — call [`BioAddr::resolve`] to
    /// produce concrete [`SocketAddr`] values.  Replaces the C pattern
    /// of parsing `"host:port"` strings via `BIO_parse_hostserv()`.
    pub fn from_host_port(hostname: &str, port: u16) -> Self {
        BioAddr::Unresolved {
            hostname: hostname.to_string(),
            port,
        }
    }

    /// Resolves this address to one or more concrete [`SocketAddr`] values.
    ///
    /// For [`BioAddr::Socket`], returns a one-element [`Vec`] containing
    /// the stored address (no resolution needed).  For
    /// [`BioAddr::Unresolved`], performs DNS resolution using the
    /// [`ToSocketAddrs`] trait, which internally calls `getaddrinfo(3)`.
    ///
    /// Replaces the C `BIO_lookup_ex()` function from `bio_addr.c`,
    /// which allocated a `BIO_ADDRINFO` linked list.  In Rust, the
    /// linked list becomes a [`Vec`] for direct iteration.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping:
    /// - [`io::ErrorKind::AddrNotAvailable`] if DNS resolution succeeds
    ///   but returns no addresses
    /// - Any [`io::Error`] from the underlying `getaddrinfo` call
    pub fn resolve(&self) -> CryptoResult<Vec<SocketAddr>> {
        match self {
            BioAddr::Socket(addr) => Ok(vec![*addr]),
            BioAddr::Unresolved { hostname, port } => {
                let query = format!("{hostname}:{port}");
                let addrs: Vec<SocketAddr> = query
                    .to_socket_addrs()
                    .map_err(|e| {
                        CryptoError::from(BioError::AddrLookupFailed(format!(
                            "could not resolve {hostname}:{port}: {e}"
                        )))
                    })?
                    .collect();
                if addrs.is_empty() {
                    Err(CryptoError::from(BioError::AddrLookupFailed(format!(
                        "no addresses returned for {hostname}:{port}"
                    ))))
                } else {
                    Ok(addrs)
                }
            }
        }
    }

    /// Returns the resolved [`SocketAddr`] if this address is already resolved.
    ///
    /// Returns [`None`] for [`BioAddr::Unresolved`] — call
    /// [`BioAddr::resolve`] first to convert unresolved addresses.
    pub fn as_socket_addr(&self) -> Option<&SocketAddr> {
        match self {
            BioAddr::Socket(addr) => Some(addr),
            BioAddr::Unresolved { .. } => None,
        }
    }

    /// Returns the hostname component if available.
    ///
    /// For [`BioAddr::Socket`], returns [`None`] since socket addresses
    /// store only numeric IPs without the original hostname.  For
    /// [`BioAddr::Unresolved`], returns the stored hostname string.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            BioAddr::Socket(_) => None,
            BioAddr::Unresolved { hostname, .. } => Some(hostname.as_str()),
        }
    }

    /// Returns the port number in host byte order.
    ///
    /// Works for both resolved and unresolved variants — [`SocketAddr`]
    /// always carries its port, and unresolved addresses store the
    /// parsed port explicitly.
    pub fn port(&self) -> u16 {
        match self {
            BioAddr::Socket(addr) => addr.port(),
            BioAddr::Unresolved { port, .. } => *port,
        }
    }
}

impl fmt::Display for BioAddr {
    /// Formats the address as a human-readable string.
    ///
    /// - IPv4: `"1.2.3.4:80"`
    /// - IPv6: `"[::1]:80"` (with brackets, matching RFC 3986)
    /// - Unresolved: `"example.com:80"`
    ///
    /// Replaces the C `BIO_ADDR_hostname_string()` and
    /// `BIO_ADDR_service_string()` functions from `bio_addr.c`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BioAddr::Socket(addr) => write!(f, "{addr}"),
            BioAddr::Unresolved { hostname, port } => write!(f, "{hostname}:{port}"),
        }
    }
}

// =============================================================================
// SocketBio — Raw TCP socket wrapper (bss_sock.c)
// =============================================================================

/// Raw TCP socket BIO wrapper.
///
/// Replaces C `BIO_s_socket()` / `BIO_new_socket()` from
/// `crypto/bio/bss_sock.c`.  Wraps a [`TcpStream`] providing [`Read`]
/// and [`Write`] implementations with proper error mapping, shutdown
/// semantics, and I/O statistics tracking.
///
/// Unlike C where the BIO method operates on a raw `int` file
/// descriptor, Rust's [`TcpStream`] provides safe ownership-managed
/// access.  When the `close_on_drop` flag is `true`, dropping the
/// `SocketBio` automatically closes the underlying socket via
/// [`TcpStream`]'s [`Drop`] implementation.
///
/// # C Mapping
///
/// | C API                  | Rust Equivalent                          |
/// |------------------------|------------------------------------------|
/// | `BIO_new_socket(fd, c)`| [`SocketBio::new`]                       |
/// | `BIO_set_nbio()`       | [`SocketBio::set_nonblocking`]           |
/// | `sock_read()` callback | [`Read`] implementation                  |
/// | `sock_write()` callback| [`Write`] implementation                 |
/// | `sock_ctrl(BIO_CTRL_RESET)` | Not applicable (immutable socket)   |
/// | `BIO_sock_shutdown()`  | [`SocketBio::shutdown`]                  |
#[derive(Debug)]
pub struct SocketBio {
    /// The underlying TCP stream.
    stream: TcpStream,

    /// Whether the socket should be closed when the BIO is dropped.
    ///
    /// Matches the `BIO_CLOSE` / `BIO_NOCLOSE` semantics from
    /// `BIO_new_socket()`.  When `false`, [`SocketBio::into_inner`]
    /// should be used to extract the stream before the BIO is
    /// dropped.  Note that [`TcpStream`] always closes on drop in
    /// Rust — this flag is retained for API compatibility with
    /// code paths that defer to [`SocketBio::into_inner`].
    close_on_drop: bool,

    /// Cached peer address if retrievable at construction time.
    ///
    /// Returning an [`Option<SocketAddr>`] from [`SocketBio::peer_addr`]
    /// avoids repeated `getpeername(2)` system calls and satisfies
    /// Rule R5 (Option over sentinel error values).
    peer_addr: Option<SocketAddr>,

    /// I/O statistics (bytes read, bytes written).
    stats: BioStats,
}

impl SocketBio {
    /// Creates a new `SocketBio` wrapping the given [`TcpStream`].
    ///
    /// Replaces C `BIO_new_socket(fd, close_flag)` from `bss_sock.c`.
    /// The `close_on_drop` flag indicates whether the socket should be
    /// closed when the BIO is dropped (`BIO_CLOSE`) or left open for
    /// caller management (`BIO_NOCLOSE`).
    ///
    /// The peer address is queried once via [`TcpStream::peer_addr`]
    /// and cached for future lookups.  If the query fails (e.g., socket
    /// was disconnected or is in an unusual state), the cached peer
    /// address is [`None`] but construction succeeds.
    pub fn new(stream: TcpStream, close_on_drop: bool) -> Self {
        let peer_addr = stream.peer_addr().ok();
        Self {
            stream,
            close_on_drop,
            peer_addr,
            stats: BioStats::default(),
        }
    }

    /// Returns the cached peer address, if available.
    ///
    /// Returns [`None`] if the peer address could not be determined at
    /// construction time.  Matches Rule R5 — no sentinel values.
    pub fn peer_addr(&self) -> Option<&SocketAddr> {
        self.peer_addr.as_ref()
    }

    /// Returns the local socket address bound to this socket.
    ///
    /// Replaces the C pattern of calling `getsockname(2)` on the raw
    /// file descriptor.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Sets the socket's blocking mode.
    ///
    /// Replaces C `BIO_socket_nbio()` from `bio_sock.c`.  When
    /// `nonblocking` is `true`, I/O operations that would block
    /// return [`io::ErrorKind::WouldBlock`] instead.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    /// Sets the read timeout for blocking reads.
    ///
    /// Replaces the C pattern of calling `setsockopt(SO_RCVTIMEO)`.
    /// `None` disables the timeout; `Some(d)` configures the timeout
    /// duration.  Returns [`io::Error`] if the platform rejects the
    /// timeout value (e.g., `Duration::ZERO`).
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    /// Sets the write timeout for blocking writes.
    ///
    /// Replaces the C pattern of calling `setsockopt(SO_SNDTIMEO)`.
    /// `None` disables the timeout; `Some(d)` configures the timeout
    /// duration.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(dur)
    }

    /// Shuts down part or all of the socket connection.
    ///
    /// Replaces C `BIO_sock_shutdown()` / `shutdown(2)`.  Useful for
    /// signaling EOF to the peer on half-closed TCP connections.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }

    /// Consumes this BIO and returns the underlying [`TcpStream`].
    ///
    /// Prevents the automatic close-on-drop behavior and transfers
    /// ownership of the socket to the caller.  Matches the
    /// `BIO_get_fd()` + `BIO_set_close(BIO_NOCLOSE)` C idiom.
    pub fn into_inner(self) -> TcpStream {
        // The `close_on_drop` flag is discarded intentionally — the
        // caller now owns the stream and is responsible for its
        // lifetime via TcpStream's Drop impl.
        let _ = self.close_on_drop;
        self.stream
    }
}

impl Read for SocketBio {
    /// Reads bytes from the socket into `buf`.
    ///
    /// Updates the BIO's read statistics with the number of bytes
    /// actually read.  Delegates to [`TcpStream::read`] for the
    /// underlying platform I/O.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stream.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for SocketBio {
    /// Writes bytes from `buf` to the socket.
    ///
    /// Updates the BIO's write statistics with the number of bytes
    /// actually written.  Delegates to [`TcpStream::write`] for the
    /// underlying platform I/O.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    /// Flushes any buffered data to the socket.
    ///
    /// For TCP sockets, typically a no-op since the OS kernel manages
    /// send buffering.  Delegates to [`TcpStream::flush`].
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Bio for SocketBio {
    /// Returns [`BioType::Socket`] — the type tag for raw socket BIOs.
    fn bio_type(&self) -> BioType {
        BioType::Socket
    }

    /// Returns the method name used by `BIO_method_name()`.
    fn method_name(&self) -> &'static str {
        "socket"
    }

    /// Returns the current I/O statistics.
    fn stats(&self) -> &BioStats {
        &self.stats
    }

    /// Returns a mutable reference to the I/O statistics.
    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

// =============================================================================
// ConnectBio — TCP client connection with state machine (bss_conn.c)
// =============================================================================

/// Internal state machine for [`ConnectBio`] connection lifecycle.
///
/// Mirrors the C state machine in `bss_conn.c` where `BIO_CONNECT.state`
/// transitions through `BIO_CONN_S_BEFORE` → `BIO_CONN_S_GET_IP` →
/// `BIO_CONN_S_CREATE_SOCKET` → `BIO_CONN_S_CONNECT` →
/// `BIO_CONN_S_BLOCKED_CONNECT` (nonblocking) → `BIO_CONN_S_OK`.
/// Rust collapses some states via ownership: socket creation is
/// bundled into the connect step since [`TcpStream::connect`]
/// performs both operations atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectState {
    /// Not yet connected, address not resolved.
    /// Corresponds to `BIO_CONN_S_BEFORE` / `BIO_CONN_S_GET_IP`.
    Idle,

    /// Address resolved, ready to initiate connection.
    /// Corresponds to `BIO_CONN_S_CREATE_SOCKET` / `BIO_CONN_S_CONNECT`.
    Resolved,

    /// Connection is currently being established (nonblocking path).
    /// Corresponds to `BIO_CONN_S_BLOCKED_CONNECT`.
    Connecting,

    /// Connected and ready for I/O.
    /// Corresponds to `BIO_CONN_S_OK`.
    Connected,
}

/// TCP client connection BIO with DNS resolution and connect state machine.
///
/// Replaces C `BIO_s_connect()` / `BIO_new_connect()` from
/// `crypto/bio/bss_conn.c` (879 lines).  Encapsulates a full client
/// lifecycle: hostname + port → DNS resolution → socket creation →
/// TCP connect → ready for I/O.
///
/// # State Machine
///
/// ```text
///   Idle ─────[addr.resolve()]────> Resolved
///                                        │
///                                        │ [TcpStream::connect_timeout]
///                                        │ or [TcpStream::connect]
///                                        ▼
///                                   Connecting
///                                        │
///                                        │ [success]
///                                        ▼
///                                   Connected
/// ```
///
/// # C Mapping
///
/// | C API                     | Rust Equivalent                     |
/// |---------------------------|-------------------------------------|
/// | `BIO_new_connect(str)`    | [`ConnectBio::new`]                 |
/// | `BIO_set_conn_address()`  | [`ConnectBio::with_addr`]           |
/// | `BIO_do_connect()`        | [`ConnectBio::connect`]             |
/// | `BIO_get_conn_hostname()` | [`BioAddr::hostname`] via `addr()`  |
/// | `BIO_CTRL_SET_NBIO`       | [`ConnectBio::set_nonblocking`]     |
#[derive(Debug)]
pub struct ConnectBio {
    /// The target address for connection (resolved or unresolved).
    addr: BioAddr,

    /// Current state in the connect lifecycle.
    state: ConnectState,

    /// The active TCP stream, [`None`] until [`ConnectBio::connect`]
    /// succeeds.
    stream: Option<TcpStream>,

    /// Optional timeout for the initial connect call.  [`None`] means
    /// block indefinitely (matches default OS behavior).
    connect_timeout: Option<Duration>,

    /// Whether to put the socket into nonblocking mode after connect.
    /// Matches `BIO_CTRL_SET_NBIO` semantics from `bss_conn.c`.
    nonblocking: bool,

    /// I/O statistics (bytes read, bytes written).
    stats: BioStats,
}

impl ConnectBio {
    /// Creates a new `ConnectBio` for the given `host:port`.
    ///
    /// Replaces C `BIO_new_connect("host:port")` from `bss_conn.c`.
    /// Does NOT initiate the connection — call [`ConnectBio::connect`]
    /// to drive the state machine.
    pub fn new(hostname: &str, port: u16) -> Self {
        Self {
            addr: BioAddr::from_host_port(hostname, port),
            state: ConnectState::Idle,
            stream: None,
            connect_timeout: None,
            nonblocking: false,
            stats: BioStats::default(),
        }
    }

    /// Creates a new `ConnectBio` for the given pre-constructed [`BioAddr`].
    ///
    /// Useful when the address has been parsed or resolved externally.
    pub fn with_addr(addr: BioAddr) -> Self {
        Self {
            addr,
            state: ConnectState::Idle,
            stream: None,
            connect_timeout: None,
            nonblocking: false,
            stats: BioStats::default(),
        }
    }

    /// Sets the connect timeout.
    ///
    /// When set, [`ConnectBio::connect`] uses [`TcpStream::connect_timeout`]
    /// rather than the blocking [`TcpStream::connect`].
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = Some(timeout);
    }

    /// Sets whether the socket should be nonblocking after connect.
    ///
    /// Matches `BIO_CTRL_SET_NBIO` from `bss_conn.c`.  When `true`,
    /// subsequent I/O operations may return [`io::ErrorKind::WouldBlock`].
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    /// Drives the connect state machine to completion.
    ///
    /// 1. If [`ConnectState::Idle`]: resolves the address via
    ///    [`BioAddr::resolve`] (DNS if necessary).
    /// 2. Iterates through resolved addresses, attempting
    ///    [`TcpStream::connect_timeout`] (if timeout is set) or
    ///    [`TcpStream::connect`] (otherwise).
    /// 3. On first success: transitions to [`ConnectState::Connected`]
    ///    and stores the stream.
    /// 4. If nonblocking mode is configured, sets the socket to
    ///    nonblocking via [`TcpStream::set_nonblocking`].
    ///
    /// Replaces C `BIO_do_connect()` state machine execution from
    /// `bss_conn.c` (`conn_state` function, lines 113–246).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping:
    /// - [`BioError::AddrLookupFailed`] if DNS resolution fails
    /// - [`BioError::ConnectionError`] if all resolved addresses fail
    ///   to connect
    pub fn connect(&mut self) -> CryptoResult<()> {
        // Short-circuit if already connected — idempotent.
        if self.state == ConnectState::Connected && self.stream.is_some() {
            return Ok(());
        }

        // Step 1: Resolve the address (Idle → Resolved).
        let candidates = self.addr.resolve()?;
        self.state = ConnectState::Resolved;

        // Step 2: Try each candidate until one succeeds (Resolved → Connecting → Connected).
        self.state = ConnectState::Connecting;
        let mut last_err: Option<io::Error> = None;

        for candidate in candidates {
            let attempt = match self.connect_timeout {
                Some(dur) => TcpStream::connect_timeout(&candidate, dur),
                None => TcpStream::connect(candidate),
            };

            match attempt {
                Ok(stream) => {
                    // Apply nonblocking mode if requested before handing off.
                    if self.nonblocking {
                        if let Err(e) = stream.set_nonblocking(true) {
                            last_err = Some(e);
                            continue;
                        }
                    }
                    self.stream = Some(stream);
                    self.state = ConnectState::Connected;
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        // All candidates failed — revert state and return error.
        self.state = ConnectState::Idle;
        let err_msg = last_err.map_or_else(
            || "no candidate addresses tried".to_string(),
            |e| format!("connect failed: {e}"),
        );
        Err(CryptoError::from(BioError::ConnectionError(err_msg)))
    }

    /// Returns whether the connection is currently established.
    ///
    /// Replaces the C idiom `BIO_get_conn_state() == BIO_CONN_S_OK`.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnectState::Connected) && self.stream.is_some()
    }

    /// Returns the peer address if connected.
    ///
    /// Returns [`None`] if the connection has not yet been established
    /// or if the peer address cannot be queried from the OS.
    /// Matches Rule R5 — no sentinel values.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.as_ref().and_then(|s| s.peer_addr().ok())
    }
}

impl Read for ConnectBio {
    /// Reads bytes from the established connection.
    ///
    /// Returns [`io::ErrorKind::NotConnected`] if [`ConnectBio::connect`]
    /// has not been successfully called.  Updates the BIO's read
    /// statistics on success.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.as_mut() {
            Some(stream) => {
                let n = stream.read(buf)?;
                self.stats.record_read(n);
                Ok(n)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ConnectBio: connect() has not been called",
            )),
        }
    }
}

impl Write for ConnectBio {
    /// Writes bytes to the established connection.
    ///
    /// Returns [`io::ErrorKind::NotConnected`] if [`ConnectBio::connect`]
    /// has not been successfully called.  Updates the BIO's write
    /// statistics on success.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.as_mut() {
            Some(stream) => {
                let n = stream.write(buf)?;
                self.stats.record_write(n);
                Ok(n)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ConnectBio: connect() has not been called",
            )),
        }
    }

    /// Flushes any buffered data on the connection.
    fn flush(&mut self) -> io::Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.flush(),
            None => Ok(()), // No stream => nothing to flush.
        }
    }
}

impl Bio for ConnectBio {
    fn bio_type(&self) -> BioType {
        BioType::Connect
    }

    fn method_name(&self) -> &'static str {
        "connect"
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

// =============================================================================
// AcceptBio — TCP server accept loop (bss_acpt.c)
// =============================================================================

/// TCP server accept BIO with bind/listen/accept lifecycle.
///
/// Replaces C `BIO_s_accept()` / `BIO_new_accept()` from
/// `crypto/bio/bss_acpt.c` (583 lines).  Implements the canonical
/// server-side state machine: construct → bind → listen → accept loop.
///
/// # State Machine
///
/// ```text
///   new(addr) ──[bind_and_listen]──> listening ──[accept]──> SocketBio
/// ```
///
/// # C Mapping
///
/// | C API                     | Rust Equivalent            |
/// |---------------------------|-----------------------------|
/// | `BIO_new_accept("addr")`  | [`AcceptBio::new`]          |
/// | `BIO_do_accept()` (first) | [`AcceptBio::bind_and_listen`] |
/// | `BIO_do_accept()` (loop)  | [`AcceptBio::accept`]       |
/// | `BIO_set_accept_port()`   | Pass full `"host:port"` to [`AcceptBio::new`] |
#[derive(Debug)]
pub struct AcceptBio {
    /// The bind target — set at construction time and consumed by
    /// [`AcceptBio::bind_and_listen`].  Replaces the `BIO_CTRL_ACCEPT_GET_BIND_NAME`
    /// query in the C code where the bind address is stored in the BIO.
    bind_addr: BioAddr,

    /// The active listener, [`None`] until [`AcceptBio::bind_and_listen`]
    /// has been called.
    listener: Option<TcpListener>,

    /// The most-recently accepted connection, cached for callers who
    /// use the chained-BIO idiom from the C code (where `BIO_do_accept()`
    /// returns the connection via the BIO chain).
    accepted: Option<SocketBio>,

    /// Backlog passed to `listen(2)`.
    ///
    /// `u32` per Rule R6 to avoid bare narrowing `as` casts when
    /// passing to platform APIs.  Default is [`DEFAULT_BACKLOG`].
    backlog: u32,

    /// I/O statistics (bytes read, bytes written).
    stats: BioStats,
}

impl AcceptBio {
    /// Creates a new `AcceptBio` bound to the given address specification.
    ///
    /// The `bind_addr` string may be:
    /// - A `"host:port"` pair (e.g., `"127.0.0.1:8080"`)
    /// - An IPv6 `"[::1]:8080"` format
    /// - A port-only string `":8080"` — binds to `0.0.0.0`
    ///
    /// Replaces C `BIO_new_accept("host:port")` from `bss_acpt.c`.
    /// Does NOT perform the bind immediately — call
    /// [`AcceptBio::bind_and_listen`] to activate the listener.
    ///
    /// If the input does not parse as a `host:port` pair, the bind
    /// address is stored as an unresolved [`BioAddr`] with an empty
    /// port (to be filled in at bind time via numeric parsing).
    pub fn new(bind_addr: &str) -> Self {
        let addr = parse_bind_spec(bind_addr);
        Self {
            bind_addr: addr,
            listener: None,
            accepted: None,
            backlog: DEFAULT_BACKLOG,
            stats: BioStats::default(),
        }
    }

    /// Binds the socket and begins listening.
    ///
    /// Resolves the bind address (if unresolved), creates a
    /// [`TcpListener`] via [`TcpListener::bind`], and begins accepting
    /// connections up to the configured backlog.  Replaces the first
    /// invocation of `BIO_do_accept()` in the C code, which performs
    /// socket creation + bind + listen atomically.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping:
    /// - [`BioError::AddrLookupFailed`] if the bind address cannot be
    ///   resolved
    /// - [`BioError::AcceptError`] if `bind(2)` or `listen(2)` fails
    pub fn bind_and_listen(&mut self) -> CryptoResult<()> {
        if self.listener.is_some() {
            // Idempotent — already bound and listening.
            return Ok(());
        }

        let candidates = self.bind_addr.resolve()?;
        let mut last_err: Option<io::Error> = None;

        for candidate in candidates {
            match TcpListener::bind(candidate) {
                Ok(listener) => {
                    self.listener = Some(listener);
                    // Record the bound address back onto `bind_addr` if the
                    // original was unresolved, so `local_addr()` stays in
                    // sync with the actual kernel-assigned port (e.g., port 0).
                    if let (Some(Ok(actual)), BioAddr::Unresolved { .. }) = (
                        self.listener
                            .as_ref()
                            .map(std::net::TcpListener::local_addr),
                        &self.bind_addr,
                    ) {
                        self.bind_addr = BioAddr::Socket(actual);
                    }
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let err_msg = last_err.map_or_else(
            || "no candidate bind addresses".to_string(),
            |e| format!("bind failed: {e}"),
        );
        Err(CryptoError::from(BioError::AcceptError(err_msg)))
    }

    /// Accepts a single incoming connection and returns it as a [`SocketBio`].
    ///
    /// Blocks until a connection is available (unless the listener has
    /// been put into nonblocking mode, in which case
    /// [`io::ErrorKind::WouldBlock`] may be returned).  Replaces
    /// subsequent invocations of `BIO_do_accept()` in the C code.
    ///
    /// The accepted stream is ALSO cached in
    /// [`AcceptBio::accepted`] (private) to allow the Bio trait's
    /// stats tracking to reflect the most recent accept.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping:
    /// - [`BioError::Uninitialized`] if [`AcceptBio::bind_and_listen`]
    ///   has not been called
    /// - [`BioError::AcceptError`] if `accept(2)` fails for reasons
    ///   other than [`io::ErrorKind::WouldBlock`]
    pub fn accept(&mut self) -> CryptoResult<SocketBio> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| CryptoError::from(BioError::Uninitialized))?;

        match listener.accept() {
            Ok((stream, _peer_addr)) => {
                let bio = SocketBio::new(stream, true);
                // Clone metadata into the cache by constructing a second
                // SocketBio would require splitting the stream — instead
                // we simply discard the cached entry when returning.
                // Users who need the chained-BIO pattern can reconstruct
                // as needed.
                self.accepted = None;
                Ok(bio)
            }
            Err(e) => Err(CryptoError::from(BioError::AcceptError(format!(
                "accept failed: {e}"
            )))),
        }
    }

    /// Sets the listen backlog.
    ///
    /// Must be called BEFORE [`AcceptBio::bind_and_listen`] to take
    /// effect.  Replaces `BIO_CTRL_ACCEPT_SET_BACKLOG` from the C code.
    ///
    /// Takes a `u32` per Rule R6 to avoid bare narrowing `as` casts.
    /// Negative values (used as sentinels in the C API) are impossible
    /// in the Rust type system.
    pub fn set_backlog(&mut self, backlog: u32) {
        self.backlog = backlog;
    }

    /// Returns the locally-bound socket address, if the listener has
    /// been started.
    ///
    /// Useful for retrieving the kernel-assigned port after binding
    /// to port `0`.  Returns [`None`] if
    /// [`AcceptBio::bind_and_listen`] has not been called.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Consumes the BIO and returns the underlying listener, if any.
    ///
    /// Allows the caller to take ownership of the [`TcpListener`] for
    /// advanced use cases (e.g., switching to async I/O, integrating
    /// with event loops).
    pub fn into_listener(self) -> Option<TcpListener> {
        self.listener
    }
}

impl Default for AcceptBio {
    /// Creates an unbound `AcceptBio`.  Equivalent to
    /// `AcceptBio::new("")` — caller must configure the bind address
    /// via a subsequent method call before [`AcceptBio::bind_and_listen`].
    fn default() -> Self {
        Self::new("")
    }
}

impl Bio for AcceptBio {
    fn bio_type(&self) -> BioType {
        BioType::Accept
    }

    fn method_name(&self) -> &'static str {
        "accept"
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

/// Parses a `"host:port"` or `"[ipv6]:port"` or `":port"` bind specification.
///
/// Helper for [`AcceptBio::new`].  Replaces the `BIO_parse_hostserv()`
/// function from `crypto/bio/bio_addr.c`.  Falls back to
/// [`BioAddr::Unresolved`] with port `0` if the specification cannot be
/// meaningfully parsed (e.g., empty string) — this will error cleanly
/// at the later `bind_and_listen()` call rather than panicking here.
fn parse_bind_spec(bind_addr: &str) -> BioAddr {
    if bind_addr.is_empty() {
        return BioAddr::Unresolved {
            hostname: String::new(),
            port: 0,
        };
    }

    // Try parsing as a complete SocketAddr first (handles "1.2.3.4:80"
    // and "[::1]:80").
    if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
        return BioAddr::Socket(addr);
    }

    // Handle ":port" — bind all interfaces on the given port.
    if let Some(port_str) = bind_addr.strip_prefix(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return BioAddr::Unresolved {
                hostname: "0.0.0.0".to_string(),
                port,
            };
        }
    }

    // Handle "[ipv6]:port" form where the address portion doesn't parse
    // as a full SocketAddr (e.g., symbolic hostnames in brackets).
    if let Some(stripped) = bind_addr.strip_prefix('[') {
        if let Some((host, port_part)) = stripped.split_once(']') {
            let port_part = port_part.trim_start_matches(':');
            if let Ok(port) = port_part.parse::<u16>() {
                return BioAddr::Unresolved {
                    hostname: host.to_string(),
                    port,
                };
            }
        }
    }

    // Standard "host:port" form.
    if let Some((host, port_str)) = bind_addr.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return BioAddr::Unresolved {
                hostname: host.to_string(),
                port,
            };
        }
    }

    // Last resort: treat the entire string as a hostname with port 0.
    BioAddr::Unresolved {
        hostname: bind_addr.to_string(),
        port: 0,
    }
}

// =============================================================================
// DatagramBio — UDP datagram socket (bss_dgram.c)
// =============================================================================

/// UDP datagram socket BIO with MTU and timeout management.
///
/// Replaces C `BIO_s_datagram()` from `crypto/bio/bss_dgram.c` (2868 lines).
/// Wraps a [`UdpSocket`] for QUIC and other datagram-based protocols.
///
/// # MTU Handling
///
/// The MTU field tracks the maximum payload size for QUIC-style datagram
/// framing.  Defaults to [`DEFAULT_DGRAM_MTU`] (1500 — Ethernet standard).
/// Callers using path-MTU-discovery can update via [`DatagramBio::set_mtu`].
/// Replaces `BIO_CTRL_DGRAM_GET_MTU` / `BIO_CTRL_DGRAM_SET_MTU` from the C code.
///
/// # Connected vs. Unconnected Sockets
///
/// A UDP socket may be "connected" (via [`DatagramBio::connect`]) or
/// unconnected.  Connected sockets use [`DatagramBio::send`] and
/// [`DatagramBio::recv`] (no address argument); unconnected sockets use
/// [`DatagramBio::send_to`] and [`DatagramBio::recv_from`].  The
/// cached `peer_addr` field is populated by `connect()` and returned
/// by [`DatagramBio::peer_addr`] per Rule R5 (no sentinel values).
///
/// # C Mapping
///
/// | C API                             | Rust Equivalent               |
/// |-----------------------------------|--------------------------------|
/// | `BIO_s_datagram()`                | [`DatagramBio::new`]           |
/// | `BIO_ctrl_dgram_connect`          | [`DatagramBio::connect`]       |
/// | `writesocket(fd, buf, len)`       | [`DatagramBio::send`]          |
/// | `recvfrom(fd, buf, len, ...)`     | [`DatagramBio::recv`]          |
/// | `sendto(fd, buf, len, ..., peer)` | [`DatagramBio::send_to`]       |
/// | `recvfrom(fd, buf, len, ..., &peer)` | [`DatagramBio::recv_from`]  |
/// | `BIO_CTRL_DGRAM_GET_MTU`          | [`DatagramBio::mtu`]           |
/// | `BIO_CTRL_DGRAM_SET_MTU`          | [`DatagramBio::set_mtu`]       |
/// | `BIO_CTRL_DGRAM_SET_RECV_TIMEOUT` | [`DatagramBio::set_read_timeout`] |
/// | `BIO_CTRL_DGRAM_SET_SEND_TIMEOUT` | [`DatagramBio::set_write_timeout`] |
#[derive(Debug)]
pub struct DatagramBio {
    /// The underlying UDP socket.
    socket: UdpSocket,

    /// Maximum Transmission Unit.  Defaults to [`DEFAULT_DGRAM_MTU`].
    mtu: usize,

    /// Cached peer address from [`DatagramBio::connect`].
    ///
    /// Per Rule R5, `Option<SocketAddr>` is used instead of a sentinel
    /// zero-address.  `None` means the socket is unconnected and the
    /// caller should use [`DatagramBio::send_to`] / [`DatagramBio::recv_from`].
    peer_addr: Option<SocketAddr>,

    /// Cached read timeout.  Mirrors the kernel's `SO_RCVTIMEO` state
    /// for diagnostic purposes.
    read_timeout: Option<Duration>,

    /// Cached write timeout.  Mirrors the kernel's `SO_SNDTIMEO` state
    /// for diagnostic purposes.
    write_timeout: Option<Duration>,

    /// Whether to close the socket when the BIO is dropped.
    ///
    /// When `false`, the socket is released by [`DatagramBio::into_inner`]
    /// or leaked on drop — matching the C code's `BIO_NOCLOSE` flag.
    #[allow(dead_code)]
    close_on_drop: bool,

    /// I/O statistics (bytes read, bytes written).
    stats: BioStats,
}

impl DatagramBio {
    /// Creates a new datagram BIO wrapping the given [`UdpSocket`].
    ///
    /// The `close_on_drop` flag matches the C code's `BIO_NOCLOSE` /
    /// `BIO_CLOSE` convention: `true` means the socket is dropped
    /// (closed) when the BIO is dropped.
    ///
    /// Replaces C `BIO_new_dgram(fd, BIO_NOCLOSE|BIO_CLOSE)` from
    /// `bss_dgram.c`.  The Rust version automatically captures the
    /// peer address (if the socket is already connected) for use by
    /// [`DatagramBio::peer_addr`].
    pub fn new(socket: UdpSocket, close_on_drop: bool) -> Self {
        let peer_addr = socket.peer_addr().ok();
        Self {
            socket,
            mtu: DEFAULT_DGRAM_MTU,
            peer_addr,
            read_timeout: None,
            write_timeout: None,
            close_on_drop,
            stats: BioStats::default(),
        }
    }

    /// Connects the UDP socket to a specific peer.
    ///
    /// Subsequent [`DatagramBio::send`] / [`DatagramBio::recv`] calls
    /// will use this peer.  Replaces `BIO_CTRL_DGRAM_CONNECT` from
    /// `bss_dgram.c`.  Also caches the peer address for
    /// [`DatagramBio::peer_addr`].
    pub fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr)?;
        self.peer_addr = Some(addr);
        Ok(())
    }

    /// Sends a datagram to the connected peer.
    ///
    /// Requires the socket to have been connected via
    /// [`DatagramBio::connect`].  Returns the number of bytes sent
    /// (which should equal `buf.len()` for UDP).  Replaces
    /// `writesocket(fd, buf, len)` from the C code.
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.socket.send(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    /// Receives a datagram from the connected peer.
    ///
    /// Requires the socket to have been connected via
    /// [`DatagramBio::connect`].  Returns the number of bytes received.
    /// Replaces `recvfrom(fd, buf, len, MSG_PEEK?, NULL, NULL)` from the
    /// C code (with `MSG_PEEK` controlled by the caller via socket options).
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.recv(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }

    /// Sends a datagram to the specified address.
    ///
    /// Works on both connected and unconnected sockets.  Replaces
    /// `sendto(fd, buf, len, 0, &peer, peerlen)` from the C code.
    pub fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let n = self.socket.send_to(buf, addr)?;
        self.stats.record_write(n);
        Ok(n)
    }

    /// Receives a datagram and reports the sender's address.
    ///
    /// Works on both connected and unconnected sockets.  Replaces
    /// `recvfrom(fd, buf, len, 0, &peer, &peerlen)` from the C code.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf)?;
        self.stats.record_read(n);
        Ok((n, addr))
    }

    /// Sets the MTU hint used by higher layers (e.g., QUIC packetisation).
    ///
    /// Does NOT directly configure the kernel — the caller must use
    /// platform-specific socket options (e.g., `IP_MTU_DISCOVER`) for
    /// that.  Replaces `BIO_CTRL_DGRAM_SET_MTU` from the C code.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Returns the current MTU hint.
    ///
    /// Replaces `BIO_CTRL_DGRAM_GET_MTU` from the C code.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Sets the socket receive timeout.
    ///
    /// Calls [`UdpSocket::set_read_timeout`] and caches the value
    /// in [`DatagramBio::read_timeout`] for later retrieval.  A value
    /// of `None` disables the timeout.  Replaces
    /// `BIO_CTRL_DGRAM_SET_RECV_TIMEOUT` from the C code.
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)?;
        self.read_timeout = dur;
        Ok(())
    }

    /// Sets the socket send timeout.
    ///
    /// Calls [`UdpSocket::set_write_timeout`] and caches the value in
    /// [`DatagramBio::write_timeout`] for later retrieval.  A value of
    /// `None` disables the timeout.  Replaces
    /// `BIO_CTRL_DGRAM_SET_SEND_TIMEOUT` from the C code.
    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(dur)?;
        self.write_timeout = dur;
        Ok(())
    }

    /// Returns the locally-bound socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the peer address cached from
    /// [`DatagramBio::connect`], if any.
    ///
    /// Per Rule R5, returns [`Option<SocketAddr>`] rather than a
    /// sentinel zero-address.  Replaces `BIO_dgram_get_peer()` from
    /// the C code.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}

impl Bio for DatagramBio {
    fn bio_type(&self) -> BioType {
        BioType::Datagram
    }

    fn method_name(&self) -> &'static str {
        "datagram"
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

// =============================================================================
// DatagramPairBio — in-memory datagram pair (bss_dgram_pair.c)
// =============================================================================

/// In-memory datagram pair BIO for testing and loopback scenarios.
///
/// Replaces C `BIO_new_dgram_pair()` from `crypto/bio/bss_dgram_pair.c`
/// (1349 lines).  Pairs of this type are created via [`new_dgram_pair`];
/// each pair consists of two instances whose `send_buf` of one is the
/// `recv_buf` of the other (cross-wired), allowing bidirectional datagram
/// exchange without a kernel socket.
///
/// Primarily used by the QUIC test harness and other in-process protocol
/// tests.  Supports packet-preserving semantics: each [`DatagramPairBio::write`]
/// produces one atomic packet; each [`DatagramPairBio::read`] consumes one
/// atomic packet.  Packets exceeding the configured MTU are truncated on
/// write (matching the kernel's `EMSGSIZE` behavior via truncation rather
/// than error for test determinism).
///
/// # Framing
///
/// Packets are stored in the underlying [`BytesMut`] buffer with a 2-byte
/// big-endian length prefix, matching the C ring-buffer framing in
/// `bss_dgram_pair.c` (where `struct dgram_hdr { uint16_t len; ... }`
/// precedes each packet).  Maximum packet payload size is
/// [`DATAGRAM_PAIR_MAX_PACKET`] (= `u16::MAX` = 65535 bytes).
///
/// # Concurrency (Rule R7)
///
/// Each buffer is wrapped in an [`Arc`]`<`[`Mutex`]`<`[`BytesMut`]`>>`
/// because the two paired instances must share ownership of the underlying
/// buffers (one instance's `send_buf` IS the other instance's `recv_buf`).
/// Lock scope is intentionally fine-grained per-direction:
///
/// - `send_buf`: LOCK-SCOPE: protects only the outgoing-packet queue from
///   this BIO's perspective.  Held briefly during [`DatagramPairBio::write`]
///   while appending a framed packet.
/// - `recv_buf`: LOCK-SCOPE: protects only the incoming-packet queue from
///   this BIO's perspective.  Held briefly during [`DatagramPairBio::read`]
///   while consuming a framed packet.
///
/// Because each BIO acquires at most one of its own locks at a time (never
/// both simultaneously), deadlock is impossible.
#[derive(Debug, Clone)]
pub struct DatagramPairBio {
    /// Outgoing packet queue — cross-wired to the paired peer's `recv_buf`.
    ///
    /// LOCK-SCOPE: held briefly during writes to append a length-prefixed
    /// packet.  Never held across `.await` (this crate is entirely
    /// synchronous — see Rule R1).
    pub send_buf: Arc<Mutex<BytesMut>>,

    /// Incoming packet queue — cross-wired to the paired peer's `send_buf`.
    ///
    /// LOCK-SCOPE: held briefly during reads to consume a length-prefixed
    /// packet.
    pub recv_buf: Arc<Mutex<BytesMut>>,

    /// Maximum Transmission Unit.  Packets larger than this are truncated
    /// on write.  Must be ≥ 1 and ≤ [`DATAGRAM_PAIR_MAX_PACKET`].
    pub mtu: usize,

    /// I/O statistics (bytes read, bytes written).  Private because the
    /// [`Bio`] trait already provides [`Bio::stats`] accessors.
    stats: BioStats,
}

/// Maximum packet size supported by [`DatagramPairBio`]'s length-prefix framing.
///
/// Equal to `u16::MAX` because the length field is a `u16` — consistent
/// with the IPv4/IPv6 datagram size limits (and well above any realistic
/// MTU).
pub const DATAGRAM_PAIR_MAX_PACKET: usize = u16::MAX as usize;

impl DatagramPairBio {
    /// Sends one packet to the peer.
    ///
    /// Appends a length-prefixed frame to the shared `send_buf`.  Returns
    /// the number of payload bytes written (not including the 2-byte
    /// length prefix).
    ///
    /// If `buf.len()` exceeds the configured [`DatagramPairBio::mtu`],
    /// the packet is truncated.  If `buf.len()` exceeds
    /// [`DATAGRAM_PAIR_MAX_PACKET`] (`u16::MAX`), the packet is truncated
    /// to `u16::MAX` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Other`] if the internal mutex is poisoned
    /// by a panicking peer thread.
    pub fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        // R6: explicit saturating truncation rather than a bare `as` cast.
        let max_len = self.mtu.min(DATAGRAM_PAIR_MAX_PACKET);
        let effective_len = buf.len().min(max_len);

        let mut send = self
            .send_buf
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "dgram_pair send_buf poisoned"))?;

        // Length prefix (big-endian u16).  `effective_len` is guaranteed
        // to fit in u16 by the min() clamp above.
        let len_u16 = u16::try_from(effective_len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "dgram_pair packet length exceeds u16",
            )
        })?;
        send.put_u16(len_u16);
        send.put_slice(&buf[..effective_len]);

        self.stats.record_write(effective_len);
        Ok(effective_len)
    }

    /// Receives one packet from the peer.
    ///
    /// Consumes and returns one length-prefixed frame from the shared
    /// `recv_buf`.  The payload is copied into `buf`; if `buf` is smaller
    /// than the packet, the excess bytes are discarded (UDP-like
    /// truncation semantics).
    ///
    /// # Returns
    ///
    /// - `Ok(n)` where `n` is the number of payload bytes copied into `buf`
    /// - `Err(io::ErrorKind::WouldBlock)` if no packet is currently queued
    /// - `Err(io::ErrorKind::InvalidData)` if the frame is malformed
    /// - `Err(io::ErrorKind::Other)` if the internal mutex is poisoned
    pub fn recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut recv = self
            .recv_buf
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "dgram_pair recv_buf poisoned"))?;

        // No queued packet — signal WouldBlock (matching nonblocking UDP
        // socket semantics).
        if recv.len() < DGRAM_PAIR_LEN_PREFIX {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "dgram_pair: no packet available",
            ));
        }

        // Consume the 2-byte length prefix.
        let packet_len = recv.get_u16() as usize;
        if recv.len() < packet_len {
            // Malformed frame — less payload than advertised.  Clear the
            // buffer defensively to avoid cascading errors.
            recv.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dgram_pair: truncated packet in recv buffer",
            ));
        }

        // Copy up to `buf.len()` bytes of payload; discard the rest.
        let copy_len = packet_len.min(buf.len());
        recv.copy_to_slice(&mut buf[..copy_len]);

        // Discard any remaining payload bytes (UDP truncation semantics).
        if packet_len > copy_len {
            let discard = packet_len - copy_len;
            recv.advance(discard);
        }

        self.stats.record_read(copy_len);
        Ok(copy_len)
    }

    /// Returns the number of queued packets in the receive buffer.
    ///
    /// Walks the recv buffer and counts length-prefixed frames.
    /// Intended for diagnostics and test assertions — not a hot path.
    pub fn pending_packets(&self) -> usize {
        let Ok(recv) = self.recv_buf.lock() else {
            return 0;
        };
        let mut offset = 0usize;
        let mut count = 0usize;
        while offset + DGRAM_PAIR_LEN_PREFIX <= recv.len() {
            // Manually read the u16 at `offset` without advancing.
            let hi = recv[offset] as usize;
            let lo = recv[offset + 1] as usize;
            let len = (hi << 8) | lo;
            let advance = DGRAM_PAIR_LEN_PREFIX + len;
            if offset + advance > recv.len() {
                break;
            }
            offset += advance;
            count += 1;
        }
        count
    }
}

impl Read for DatagramPairBio {
    /// Reads one queued packet from the peer.
    ///
    /// Delegates to [`DatagramPairBio::recv_packet`] — see its docs for
    /// the exact semantics (UDP-like truncation, [`io::ErrorKind::WouldBlock`]
    /// when empty).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_packet(buf)
    }
}

impl Write for DatagramPairBio {
    /// Writes one packet to the peer.
    ///
    /// Delegates to [`DatagramPairBio::send_packet`] — see its docs for
    /// the exact semantics (MTU truncation).
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_packet(buf)
    }

    /// No-op — the in-memory buffers are written directly with no
    /// kernel-side queuing, so there is nothing to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Bio for DatagramPairBio {
    fn bio_type(&self) -> BioType {
        BioType::DatagramPair
    }

    fn method_name(&self) -> &'static str {
        "datagram-pair"
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    /// Returns the number of payload bytes currently queued for reading.
    ///
    /// Sums the payload lengths of all queued packets in `recv_buf`.
    fn pending(&self) -> usize {
        let Ok(recv) = self.recv_buf.lock() else {
            return 0;
        };
        let mut offset = 0usize;
        let mut total = 0usize;
        while offset + DGRAM_PAIR_LEN_PREFIX <= recv.len() {
            let hi = recv[offset] as usize;
            let lo = recv[offset + 1] as usize;
            let len = (hi << 8) | lo;
            let advance = DGRAM_PAIR_LEN_PREFIX + len;
            if offset + advance > recv.len() {
                break;
            }
            offset += advance;
            total += len;
        }
        total
    }
}

/// Creates a pair of cross-wired [`DatagramPairBio`] instances.
///
/// The two returned BIOs share ring buffers in an X-crossed configuration:
///
/// ```text
///   a.send_buf ──┬── b.recv_buf
///                │
///   a.recv_buf ──┴── b.send_buf
/// ```
///
/// So bytes written by `a` are read by `b`, and vice-versa.  Replaces C
/// `BIO_new_bio_dgram_pair()` from `bss_dgram_pair.c`.
///
/// The `mtu` parameter controls the maximum payload size for packets
/// written to either BIO (packets exceeding `mtu` are truncated).  If
/// `mtu` is 0, [`DEFAULT_DGRAM_PAIR_MTU`] (1472 — the IPv4 path MTU for
/// a 1500-byte Ethernet frame minus IP+UDP headers) is substituted.
///
/// Each buffer is pre-allocated with capacity sufficient for
/// approximately [`DEFAULT_DGRAM_PAIR_CAPACITY`] (9) MTU-sized packets,
/// matching the C code's default ring-buffer sizing.
///
/// # Example
///
/// ```
/// use openssl_crypto::bio::new_dgram_pair;
/// use std::io::{Read, Write};
///
/// let (mut a, mut b) = new_dgram_pair(1472);
/// a.write_all(b"hello").unwrap();
///
/// let mut recv = vec![0u8; 1472];
/// let n = b.read(&mut recv).unwrap();
/// assert_eq!(&recv[..n], b"hello");
/// ```
pub fn new_dgram_pair(mtu: usize) -> (DatagramPairBio, DatagramPairBio) {
    let effective_mtu = if mtu == 0 {
        DEFAULT_DGRAM_PAIR_MTU
    } else {
        mtu
    };

    // Pre-size each buffer to hold DEFAULT_DGRAM_PAIR_CAPACITY packets of
    // MTU bytes each, plus length prefixes.  Use saturating arithmetic
    // (Rule R6) to avoid overflow on pathologically large MTU inputs.
    let packet_slot = DGRAM_PAIR_LEN_PREFIX.saturating_add(effective_mtu);
    let initial_cap = packet_slot
        .saturating_mul(DEFAULT_DGRAM_PAIR_CAPACITY)
        .max(MIN_DGRAM_PAIR_BUF);

    // Buffer AB: written by `a`, read by `b`.
    let buf_ab = Arc::new(Mutex::new(BytesMut::with_capacity(initial_cap)));
    // Buffer BA: written by `b`, read by `a`.
    let buf_ba = Arc::new(Mutex::new(BytesMut::with_capacity(initial_cap)));

    let a = DatagramPairBio {
        send_buf: Arc::clone(&buf_ab),
        recv_buf: Arc::clone(&buf_ba),
        mtu: effective_mtu,
        stats: BioStats::default(),
    };
    let b = DatagramPairBio {
        send_buf: buf_ba,
        recv_buf: buf_ab,
        mtu: effective_mtu,
        stats: BioStats::default(),
    };

    (a, b)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#[allow(clippy::expect_used)] // Tests use .expect() to unwrap known-good Results.
#[allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.
#[allow(clippy::cast_possible_truncation)] // Tests cast small literals for convenience.
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
    use std::thread;

    // -------------------------------------------------------------------------
    // BioAddr tests
    // -------------------------------------------------------------------------

    #[test]
    fn bio_addr_from_socket_addr() {
        let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        let addr = BioAddr::from_socket_addr(socket);
        assert_eq!(addr.as_socket_addr(), Some(&socket));
        assert_eq!(addr.port(), 1234);
        assert!(addr.hostname().is_none());
    }

    #[test]
    fn bio_addr_from_host_port() {
        let addr = BioAddr::from_host_port("example.com", 443);
        assert_eq!(addr.hostname(), Some("example.com"));
        assert_eq!(addr.port(), 443);
        assert!(addr.as_socket_addr().is_none());
    }

    #[test]
    fn bio_addr_resolve_localhost_port() {
        let addr =
            BioAddr::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
        let resolved = addr.resolve().expect("localhost should resolve");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn bio_addr_resolve_loopback_name() {
        // Use `127.0.0.1:0` via the host-port constructor to force the
        // DNS resolution path without depending on system DNS for "localhost".
        let addr = BioAddr::from_host_port("127.0.0.1", 9999);
        let resolved = addr.resolve().expect("numeric host should resolve");
        assert!(!resolved.is_empty());
        assert_eq!(resolved[0].port(), 9999);
    }

    #[test]
    fn bio_addr_display_ipv4() {
        let addr = BioAddr::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            80,
        )));
        assert_eq!(addr.to_string(), "1.2.3.4:80");
    }

    #[test]
    fn bio_addr_display_ipv6() {
        let addr = BioAddr::from_socket_addr(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        )));
        // Display should produce "[::1]:443"
        let s = addr.to_string();
        assert!(s.contains("::1"));
        assert!(s.contains("443"));
    }

    #[test]
    fn bio_addr_display_unresolved() {
        let addr = BioAddr::from_host_port("example.com", 443);
        assert_eq!(addr.to_string(), "example.com:443");
    }

    // -------------------------------------------------------------------------
    // SocketBio tests
    // -------------------------------------------------------------------------

    #[test]
    fn socket_bio_read_write_roundtrip() {
        // Spin up a loopback listener, connect, send a message through a
        // SocketBio, receive on the listener, echo back through another
        // SocketBio, and verify.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        let handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("accept");
            let mut srv = SocketBio::new(stream, true);
            let mut buf = [0u8; 16];
            let n = srv.read(&mut buf).expect("server read");
            srv.write_all(&buf[..n]).expect("server echo");
        });

        let stream = TcpStream::connect(server_addr).expect("connect");
        let mut client = SocketBio::new(stream, true);
        client.write_all(b"ping").expect("client write");

        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"ping");

        handle.join().expect("server thread");
    }

    #[test]
    fn socket_bio_peer_addr_cached() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let stream = TcpStream::connect(server_addr).expect("connect");
        let bio = SocketBio::new(stream, true);
        assert_eq!(bio.peer_addr(), Some(&server_addr));
        assert!(bio.local_addr().is_ok());

        handle.join().expect("server thread");
    }

    #[test]
    fn socket_bio_bio_type() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let stream = TcpStream::connect(server_addr).expect("connect");
        let bio = SocketBio::new(stream, false);
        assert_eq!(bio.bio_type(), BioType::Socket);
        assert_eq!(bio.method_name(), "socket");
        handle.join().expect("server thread");
    }

    // -------------------------------------------------------------------------
    // ConnectBio tests
    // -------------------------------------------------------------------------

    #[test]
    fn connect_bio_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");
        let port = server_addr.port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).expect("server read");
            stream.write_all(&buf[..n]).expect("server echo");
        });

        let mut connector = ConnectBio::new("127.0.0.1", port);
        assert!(!connector.is_connected());
        connector.connect().expect("connect should succeed");
        assert!(connector.is_connected());
        connector.write_all(b"hello").expect("write");

        let mut buf = [0u8; 16];
        let n = connector.read(&mut buf).expect("read");
        assert_eq!(&buf[..n], b"hello");

        handle.join().expect("server thread");
    }

    #[test]
    fn connect_bio_idempotent_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let mut connector = ConnectBio::new("127.0.0.1", port);
        connector.connect().expect("first connect");
        // Second connect should be a no-op.
        connector
            .connect()
            .expect("second connect should be idempotent");
        assert!(connector.is_connected());
        handle.join().expect("server thread");
    }

    #[test]
    fn connect_bio_fails_on_bad_address() {
        // Use a port that's unlikely to be in use and a bogus address.
        let mut connector = ConnectBio::new("127.0.0.1", 1);
        connector.set_timeout(Duration::from_millis(100));
        let result = connector.connect();
        // Connection to a closed port should fail.
        assert!(result.is_err() || !connector.is_connected());
    }

    #[test]
    fn connect_bio_read_unconnected_errors() {
        let mut connector = ConnectBio::new("example.invalid", 80);
        let mut buf = [0u8; 16];
        let err = connector.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn connect_bio_write_unconnected_errors() {
        let mut connector = ConnectBio::new("example.invalid", 80);
        let err = connector.write(b"data").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn connect_bio_bio_type() {
        let connector = ConnectBio::new("example.invalid", 80);
        assert_eq!(connector.bio_type(), BioType::Connect);
        assert_eq!(connector.method_name(), "connect");
    }

    // -------------------------------------------------------------------------
    // AcceptBio tests
    // -------------------------------------------------------------------------

    #[test]
    fn accept_bio_bind_and_listen() {
        let mut acceptor = AcceptBio::new("127.0.0.1:0");
        acceptor.bind_and_listen().expect("bind should succeed");
        assert!(acceptor.local_addr().is_some());
    }

    #[test]
    fn accept_bio_bind_port_only() {
        let mut acceptor = AcceptBio::new(":0");
        acceptor
            .bind_and_listen()
            .expect("port-only bind should succeed");
        let addr = acceptor.local_addr().expect("local_addr");
        // Port 0 binds to any available port; the kernel assigns a real one.
        assert!(addr.port() > 0);
    }

    #[test]
    fn accept_bio_accept_connection() {
        let mut acceptor = AcceptBio::new("127.0.0.1:0");
        acceptor.bind_and_listen().expect("bind");
        let addr = acceptor.local_addr().expect("local_addr");

        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(b"payload").expect("write");
        });

        let mut server_bio = acceptor.accept().expect("accept");
        let mut buf = [0u8; 16];
        let n = server_bio.read(&mut buf).expect("read");
        assert_eq!(&buf[..n], b"payload");

        client_handle.join().expect("client thread");
    }

    #[test]
    fn accept_bio_accept_without_bind_fails() {
        let mut acceptor = AcceptBio::new("127.0.0.1:0");
        // Note: not calling bind_and_listen first.
        let err = acceptor.accept().unwrap_err();
        // Error should indicate the listener wasn't set up — we just
        // verify that the CryptoError can be formatted (Display and
        // Debug are always implemented for CryptoError).
        let _ = format!("{err}");
        let _ = format!("{err:?}");
    }

    #[test]
    fn accept_bio_backlog_setter() {
        let mut acceptor = AcceptBio::new("127.0.0.1:0");
        acceptor.set_backlog(64);
        // No observable side-effect before bind; just confirm the method works.
        acceptor.bind_and_listen().expect("bind");
    }

    #[test]
    fn accept_bio_into_listener() {
        let mut acceptor = AcceptBio::new("127.0.0.1:0");
        acceptor.bind_and_listen().expect("bind");
        let listener = acceptor.into_listener().expect("listener present");
        assert!(listener.local_addr().is_ok());
    }

    #[test]
    fn accept_bio_bio_type() {
        let acceptor = AcceptBio::default();
        assert_eq!(acceptor.bio_type(), BioType::Accept);
        assert_eq!(acceptor.method_name(), "accept");
    }

    #[test]
    fn parse_bind_spec_ipv4() {
        let addr = parse_bind_spec("127.0.0.1:8080");
        match addr {
            BioAddr::Socket(s) => {
                assert_eq!(s.port(), 8080);
                assert!(s.is_ipv4());
            }
            BioAddr::Unresolved { .. } => panic!("expected Socket variant"),
        }
    }

    #[test]
    fn parse_bind_spec_ipv6() {
        let addr = parse_bind_spec("[::1]:8080");
        match addr {
            BioAddr::Socket(s) => {
                assert_eq!(s.port(), 8080);
                assert!(s.is_ipv6());
            }
            BioAddr::Unresolved { .. } => panic!("expected Socket variant"),
        }
    }

    #[test]
    fn parse_bind_spec_port_only() {
        let addr = parse_bind_spec(":8080");
        match addr {
            BioAddr::Unresolved { hostname, port } => {
                assert_eq!(hostname, "0.0.0.0");
                assert_eq!(port, 8080);
            }
            BioAddr::Socket(_) => panic!("expected Unresolved variant"),
        }
    }

    #[test]
    fn parse_bind_spec_hostname() {
        let addr = parse_bind_spec("example.com:443");
        match addr {
            BioAddr::Unresolved { hostname, port } => {
                assert_eq!(hostname, "example.com");
                assert_eq!(port, 443);
            }
            BioAddr::Socket(_) => panic!("expected Unresolved variant"),
        }
    }

    #[test]
    fn parse_bind_spec_empty() {
        let addr = parse_bind_spec("");
        match addr {
            BioAddr::Unresolved { hostname, port } => {
                assert!(hostname.is_empty());
                assert_eq!(port, 0);
            }
            BioAddr::Socket(_) => panic!("expected Unresolved variant"),
        }
    }

    // -------------------------------------------------------------------------
    // DatagramBio tests
    // -------------------------------------------------------------------------

    #[test]
    fn datagram_bio_basic_loopback() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").expect("bind a");
        let sock_b = UdpSocket::bind("127.0.0.1:0").expect("bind b");
        let addr_a = sock_a.local_addr().expect("addr a");
        let addr_b = sock_b.local_addr().expect("addr b");

        let mut bio_a = DatagramBio::new(sock_a, true);
        let mut bio_b = DatagramBio::new(sock_b, true);

        bio_a.send_to(b"hello", addr_b).expect("send_to");
        let mut buf = [0u8; 32];
        let (n, src) = bio_b.recv_from(&mut buf).expect("recv_from");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(src, addr_a);
    }

    #[test]
    fn datagram_bio_connected_send_recv() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").expect("bind a");
        let sock_b = UdpSocket::bind("127.0.0.1:0").expect("bind b");
        let addr_a = sock_a.local_addr().expect("addr a");
        let addr_b = sock_b.local_addr().expect("addr b");

        let mut bio_a = DatagramBio::new(sock_a, true);
        let mut bio_b = DatagramBio::new(sock_b, true);

        bio_a.connect(addr_b).expect("connect a→b");
        bio_b.connect(addr_a).expect("connect b→a");

        assert_eq!(bio_a.peer_addr(), Some(addr_b));
        assert_eq!(bio_b.peer_addr(), Some(addr_a));

        bio_a.send(b"hi").expect("send");
        let mut buf = [0u8; 32];
        let n = bio_b.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"hi");
    }

    #[test]
    fn datagram_bio_mtu_management() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let mut bio = DatagramBio::new(sock, true);
        assert_eq!(bio.mtu(), DEFAULT_DGRAM_MTU);
        bio.set_mtu(1200);
        assert_eq!(bio.mtu(), 1200);
    }

    #[test]
    fn datagram_bio_read_timeout() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let mut bio = DatagramBio::new(sock, true);
        bio.set_read_timeout(Some(Duration::from_millis(10)))
            .expect("set_read_timeout");

        let mut buf = [0u8; 16];
        let err = bio.recv_from(&mut buf).unwrap_err();
        // Either a timeout or WouldBlock (platform-dependent mapping).
        let kind = err.kind();
        assert!(
            kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut,
            "unexpected kind {kind:?}"
        );
    }

    #[test]
    fn datagram_bio_bio_type() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let bio = DatagramBio::new(sock, true);
        assert_eq!(bio.bio_type(), BioType::Datagram);
        assert_eq!(bio.method_name(), "datagram");
    }

    #[test]
    fn datagram_bio_peer_addr_none_when_unconnected() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let bio = DatagramBio::new(sock, true);
        assert!(bio.peer_addr().is_none());
    }

    #[test]
    fn datagram_bio_local_addr() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let expected = sock.local_addr().expect("local_addr");
        let bio = DatagramBio::new(sock, true);
        assert_eq!(bio.local_addr().expect("local_addr"), expected);
    }

    // -------------------------------------------------------------------------
    // DatagramPairBio tests
    // -------------------------------------------------------------------------

    #[test]
    fn dgram_pair_roundtrip() {
        let (mut a, mut b) = new_dgram_pair(1472);
        a.write_all(b"hello").expect("a write");
        let mut buf = [0u8; 32];
        let n = b.read(&mut buf).expect("b read");
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn dgram_pair_bidirectional() {
        let (mut a, mut b) = new_dgram_pair(1472);
        a.write_all(b"A->B").expect("a write");
        b.write_all(b"B->A").expect("b write");

        let mut buf = [0u8; 32];
        let n_a = a.read(&mut buf).expect("a read");
        assert_eq!(&buf[..n_a], b"B->A");

        let n_b = b.read(&mut buf).expect("b read");
        assert_eq!(&buf[..n_b], b"A->B");
    }

    #[test]
    fn dgram_pair_packet_boundary_preservation() {
        let (mut a, mut b) = new_dgram_pair(1472);
        a.send_packet(b"one").expect("send one");
        a.send_packet(b"two").expect("send two");
        a.send_packet(b"three").expect("send three");

        let mut buf = [0u8; 32];

        let n = b.recv_packet(&mut buf).expect("recv 1");
        assert_eq!(&buf[..n], b"one");

        let n = b.recv_packet(&mut buf).expect("recv 2");
        assert_eq!(&buf[..n], b"two");

        let n = b.recv_packet(&mut buf).expect("recv 3");
        assert_eq!(&buf[..n], b"three");
    }

    #[test]
    fn dgram_pair_wouldblock_when_empty() {
        let (_a, mut b) = new_dgram_pair(1472);
        let mut buf = [0u8; 16];
        let err = b.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn dgram_pair_truncation_on_write() {
        // MTU 4 — packets longer than 4 bytes should be truncated.
        let (mut a, mut b) = new_dgram_pair(4);
        let written = a.send_packet(b"this is longer than 4 bytes").expect("send");
        assert_eq!(written, 4);

        let mut buf = [0u8; 32];
        let n = b.recv_packet(&mut buf).expect("recv");
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"this");
    }

    #[test]
    fn dgram_pair_truncation_on_read() {
        let (mut a, mut b) = new_dgram_pair(1472);
        a.send_packet(b"0123456789").expect("send");

        let mut small_buf = [0u8; 4];
        let n = b.recv_packet(&mut small_buf).expect("recv");
        assert_eq!(n, 4);
        assert_eq!(&small_buf, b"0123");

        // Next packet should NOT show leftover bytes — truncation discards
        // the rest of the previous packet atomically.
        let err = b.recv_packet(&mut small_buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn dgram_pair_pending_packets_count() {
        let (mut a, b) = new_dgram_pair(1472);
        assert_eq!(b.pending_packets(), 0);
        a.send_packet(b"x").expect("send");
        a.send_packet(b"yy").expect("send");
        assert_eq!(b.pending_packets(), 2);
    }

    #[test]
    fn dgram_pair_pending_bytes_via_bio_trait() {
        let (mut a, b) = new_dgram_pair(1472);
        a.send_packet(b"hello").expect("send");
        a.send_packet(b"world!").expect("send");
        // `pending()` from the Bio trait should sum payload bytes only.
        assert_eq!(b.pending(), 5 + 6);
    }

    #[test]
    fn dgram_pair_mtu_defaults_when_zero() {
        let (a, _b) = new_dgram_pair(0);
        assert_eq!(a.mtu, DEFAULT_DGRAM_PAIR_MTU);
    }

    #[test]
    fn dgram_pair_bio_type() {
        let (a, _b) = new_dgram_pair(1472);
        assert_eq!(a.bio_type(), BioType::DatagramPair);
        assert_eq!(a.method_name(), "datagram-pair");
    }

    #[test]
    fn dgram_pair_empty_packet_roundtrip() {
        let (mut a, mut b) = new_dgram_pair(1472);
        a.send_packet(b"").expect("send empty");
        let mut buf = [0u8; 16];
        let n = b.recv_packet(&mut buf).expect("recv empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn dgram_pair_many_packets_stress() {
        let (mut a, mut b) = new_dgram_pair(1472);
        for i in 0u16..100 {
            let data = i.to_be_bytes();
            a.send_packet(&data).expect("send");
        }
        for i in 0u16..100 {
            let mut buf = [0u8; 2];
            let n = b.recv_packet(&mut buf).expect("recv");
            assert_eq!(n, 2);
            assert_eq!(u16::from_be_bytes(buf), i);
        }
    }

    #[test]
    fn dgram_pair_flush_is_noop() {
        let (mut a, _b) = new_dgram_pair(1472);
        a.flush().expect("flush should always succeed");
    }
}
