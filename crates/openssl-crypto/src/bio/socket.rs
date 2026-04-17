//! Socket BIO implementations (TCP, UDP, connect, accept).
//!
//! Stub module — full implementation provided by dedicated agent.

use super::{Bio, BioStats, BioType};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Network address for BIO operations, replacing C `BIO_ADDR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BioAddr {
    /// Resolved socket address.
    Socket(SocketAddr),
    /// Unresolved hostname + port string.
    Unresolved {
        /// The hostname.
        host: String,
        /// The port number.
        port: u16,
    },
}

impl BioAddr {
    /// Creates a `BioAddr` from a `SocketAddr`.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        BioAddr::Socket(addr)
    }

    /// Creates a `BioAddr` from a hostname and port.
    pub fn from_host_port(host: &str, port: u16) -> Self {
        BioAddr::Unresolved {
            host: host.to_string(),
            port,
        }
    }

    /// Resolves an unresolved address to a `SocketAddr`.
    pub fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            BioAddr::Socket(addr) => Ok(*addr),
            BioAddr::Unresolved { host, port } => {
                let addr_str = format!("{host}:{port}");
                addr_str.to_socket_addrs()?.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses found")
                })
            }
        }
    }

    /// Returns the `SocketAddr` if already resolved.
    pub fn as_socket_addr(&self) -> Option<&SocketAddr> {
        match self {
            BioAddr::Socket(addr) => Some(addr),
            BioAddr::Unresolved { .. } => None,
        }
    }

    /// Returns the hostname string.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            BioAddr::Socket(_) => None,
            BioAddr::Unresolved { host, .. } => Some(host.as_str()),
        }
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        match self {
            BioAddr::Socket(addr) => addr.port(),
            BioAddr::Unresolved { port, .. } => *port,
        }
    }
}

impl std::fmt::Display for BioAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BioAddr::Socket(addr) => write!(f, "{addr}"),
            BioAddr::Unresolved { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// TCP socket BIO wrapping a connected `TcpStream`.
///
/// Replaces C `BIO_s_socket()`.
#[derive(Debug)]
pub struct SocketBio {
    stream: TcpStream,
    stats: BioStats,
}

impl SocketBio {
    /// Creates a new socket BIO from a connected TCP stream.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            stats: BioStats::new(),
        }
    }

    /// Returns the remote peer's address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Returns the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Sets non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    /// Sets the read timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// Sets the write timeout.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    /// Shuts down the connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }

    /// Consumes and returns the inner TCP stream.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl Read for SocketBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stream.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for SocketBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Bio for SocketBio {
    fn bio_type(&self) -> BioType {
        BioType::Socket
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "socket"
    }
}

/// Connect BIO — initiates TCP connections, replacing C `BIO_s_connect()`.
#[derive(Debug)]
pub struct ConnectBio {
    addr: BioAddr,
    stream: Option<TcpStream>,
    timeout: Option<Duration>,
    nonblocking: bool,
    stats: BioStats,
}

impl ConnectBio {
    /// Creates a new connect BIO targeting a host:port string.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            addr: BioAddr::from_host_port(host, port),
            stream: None,
            timeout: None,
            nonblocking: false,
            stats: BioStats::new(),
        }
    }

    /// Creates a connect BIO with a pre-resolved address.
    pub fn with_addr(addr: BioAddr) -> Self {
        Self {
            addr,
            stream: None,
            timeout: None,
            nonblocking: false,
            stats: BioStats::new(),
        }
    }

    /// Sets the connection timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Sets non-blocking mode.
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    /// Attempts to connect.
    pub fn connect(&mut self) -> io::Result<()> {
        let socket_addr = self.addr.resolve()?;
        let stream = match self.timeout {
            Some(dur) => TcpStream::connect_timeout(&socket_addr, dur)?,
            None => TcpStream::connect(socket_addr)?,
        };
        if self.nonblocking {
            stream.set_nonblocking(true)?;
        }
        self.stream = Some(stream);
        Ok(())
    }

    /// Returns true if connected.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Returns the peer address if connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not connected"))?
            .peer_addr()
    }
}

impl Read for ConnectBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not connected"))?;
        let n = stream.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for ConnectBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not connected"))?;
        let n = stream.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(stream) = self.stream.as_mut() {
            stream.flush()
        } else {
            Ok(())
        }
    }
}

impl Bio for ConnectBio {
    fn bio_type(&self) -> BioType {
        BioType::Connect
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "connect"
    }
}

/// Accept BIO — listens for and accepts TCP connections, replacing C `BIO_s_accept()`.
#[derive(Debug)]
pub struct AcceptBio {
    listener: Option<TcpListener>,
    backlog: i32,
    stats: BioStats,
}

impl AcceptBio {
    /// Creates a new accept BIO (not yet bound).
    pub fn new() -> Self {
        Self {
            listener: None,
            backlog: 128,
            stats: BioStats::new(),
        }
    }

    /// Binds to the address and starts listening.
    pub fn bind_and_listen(&mut self, addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.listener = Some(listener);
        Ok(())
    }

    /// Accepts an incoming connection, returning a `SocketBio`.
    pub fn accept(&self) -> io::Result<SocketBio> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not bound"))?;
        let (stream, _addr) = listener.accept()?;
        Ok(SocketBio::new(stream))
    }

    /// Sets the listen backlog.
    pub fn set_backlog(&mut self, backlog: i32) {
        self.backlog = backlog;
    }

    /// Returns the local address if bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not bound"))?
            .local_addr()
    }

    /// Consumes and returns the inner `TcpListener`.
    pub fn into_listener(self) -> Option<TcpListener> {
        self.listener
    }
}

impl Default for AcceptBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Bio for AcceptBio {
    fn bio_type(&self) -> BioType {
        BioType::Accept
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "accept"
    }
}

/// Datagram (UDP) BIO, replacing C `BIO_s_datagram()`.
#[derive(Debug)]
pub struct DatagramBio {
    socket: UdpSocket,
    mtu: usize,
    stats: BioStats,
}

impl DatagramBio {
    /// Creates a new datagram BIO from a bound UDP socket.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            mtu: 1500,
            stats: BioStats::new(),
        }
    }

    /// Connects the UDP socket to a remote address.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr)
    }

    /// Sends data to the connected peer.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    /// Receives data from the connected peer.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    /// Sends data to a specific address.
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr)
    }

    /// Receives data and the sender's address.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    /// Sets the MTU hint.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Returns the MTU hint.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Sets the read timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Sets the write timeout.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the peer address (if connected).
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}

impl Bio for DatagramBio {
    fn bio_type(&self) -> BioType {
        BioType::Datagram
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "datagram"
    }
}
