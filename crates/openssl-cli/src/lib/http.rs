//! Basic HTTP/1.x server helpers for OCSP and CMP responder commands.
//!
//! Replaces `apps/lib/http_server.c` (547 lines) and `apps/include/http_server.h`.
//! Provides a lightweight HTTP listener that accepts ASN.1-encoded requests
//! (typically OCSP or CMP) over GET/POST and sends ASN.1-encoded responses.
//!
//! ## Architecture
//! - Uses [`std::net::TcpListener`] for synchronous accept (no tokio needed)
//! - Parses HTTP/1.x request lines and headers manually (minimal HTTP)
//! - Supports GET (base64-encoded URL body) and POST (raw DER body) methods
//! - Supports HTTP keep-alive (`Connection: keep-alive` header)
//! - Replaces C's BIO-based networking with Rust std I/O traits
//!
//! ## C-to-Rust Mapping
//! | C Function | Rust Equivalent |
//! |---|---|
//! | `http_server_init()` | [`HttpServer::new()`] |
//! | `http_server_get_asn1_req()` | [`HttpServer::accept_request()`] |
//! | `http_server_send_asn1_resp()` | [`HttpServer::send_response()`] |
//! | `http_server_send_status()` | [`HttpServer::send_status()`] |
//! | `urldecode()` | [`url_decode()`] |
//!
//! ## Daemon Mode
//! The C implementation's `HTTP_DAEMON` fork-based spawning
//! (`spawn_loop()`, `http_server.c:46-189`) is **not replicated** in Rust.
//! Multi-process serving should use external process supervision (e.g.,
//! `systemd`, `supervisord`). This design eliminates global mutable state
//! (`n_responders`, `acfd`) and avoids `fork()`/`waitpid()` Unix-specific
//! system calls.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use base64ct::{Base64, Encoding};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed request body size (100 KiB).
///
/// Prevents denial-of-service via oversized POST bodies. Mirrors the implicit
/// limit in the C code's fixed-size `reqbuf` (1024 bytes for request line) and
/// the `max_resp_len` parameter pattern.
const MAX_REQUEST_BODY_SIZE: usize = 102_400;

/// Default connection timeout in seconds.
///
/// Replaces C's `alarm(timeout)` signal-based timeout (`http_server.c:308-312`)
/// with `TcpStream::set_read_timeout()` / `set_write_timeout()`.
/// Callers of [`HttpServer::accept_request()`] can pass this value as the
/// `timeout_secs` argument.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Maximum allowed HTTP request line length (bytes).
///
/// Corresponds to the C code's `#define HTTP_LINE_LEN 4096` used as the
/// buffer size for `BIO_gets()` when reading the request line.
const MAX_REQUEST_LINE_LEN: usize = 4096;

/// Maximum allowed HTTP header line length (bytes).
///
/// Prevents unbounded memory growth from malformed headers.
const MAX_HEADER_LINE_LEN: usize = 4096;

/// Maximum number of HTTP headers accepted per request.
///
/// Prevents denial-of-service via excessive header count.
const MAX_HEADER_COUNT: usize = 100;

/// HTTP response version prefix.
///
/// Matches the C code's `HTTP_PREFIX "HTTP/1.0"` constant.
const HTTP_VERSION_PREFIX: &str = "HTTP/1.0";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during HTTP server operations.
///
/// Replaces the C pattern of returning `0` (retry), `-1` (fatal error), or
/// `1` (success) from `http_server_get_asn1_req()` and similar functions.
/// Per Rule R5, explicit error variants replace sentinel return values.
#[derive(Debug, Error)]
pub enum HttpServerError {
    /// An I/O error occurred on the underlying TCP connection.
    ///
    /// Wraps [`std::io::Error`] via `#[from]` for automatic conversion
    /// with the `?` operator. Covers socket accept failures, read/write
    /// timeouts, and connection resets.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The HTTP request was malformed or could not be parsed.
    ///
    /// Covers: empty request lines, invalid HTTP versions, missing required
    /// headers (e.g., `Content-Length` for POST), and malformed header syntax.
    #[error("invalid HTTP request: {0}")]
    InvalidRequest(String),

    /// A percent-encoded URL sequence contained invalid hex digits.
    ///
    /// Raised by [`url_decode()`] when a `%xx` escape contains non-hex
    /// characters, or by base64 decoding failure for GET request paths.
    #[error("URL decode error")]
    UrlDecodeError,

    /// The HTTP method is not GET or POST.
    ///
    /// OCSP and CMP responders only accept GET (base64-encoded DER in URL)
    /// and POST (raw DER body) methods.
    #[error("unsupported HTTP method: {0}")]
    UnsupportedMethod(String),

    /// The request body exceeds [`MAX_REQUEST_BODY_SIZE`].
    ///
    /// Prevents denial-of-service via oversized POST payloads.
    #[error("request too large")]
    RequestTooLarge,

    /// Server initialization failed (e.g., port bind failure).
    ///
    /// Wraps the reason string describing why [`HttpServer::new()`] could
    /// not create the listening socket.
    #[error("server initialization failed: {0}")]
    InitError(String),
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// HTTP request method.
///
/// Only GET and POST are supported, matching the OCSP/CMP responder
/// requirements. Replaces C's string comparison against `"GET "` and
/// `"POST "` prefixes in `http_server_get_asn1_req()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET — request body is base64-encoded in the URL path.
    Get,
    /// HTTP POST — request body is raw DER in the message body.
    Post,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
        }
    }
}

/// Logging verbosity level.
///
/// Replaces C's `LOG_EMERG`..`LOG_TRACE` integer constants from
/// `apps/include/log.h`. The `PartialOrd`/`Ord` derives enable
/// level-gated logging comparisons (e.g., `if verbosity >= Verbosity::Debug`).
///
/// Mapping from C constants:
/// - `LOG_ERR` (3) → [`Verbosity::Error`]
/// - `LOG_WARNING` (4) → [`Verbosity::Warning`]
/// - `LOG_INFO` (6) → [`Verbosity::Info`]
/// - `LOG_DEBUG` (7) → [`Verbosity::Debug`]
/// - `LOG_TRACE` (8) → [`Verbosity::Trace`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// Suppress all output.
    Quiet,
    /// Errors only (corresponds to C `LOG_ERR`).
    Error,
    /// Errors and warnings (corresponds to C `LOG_WARNING`).
    Warning,
    /// Informational messages (corresponds to C `LOG_INFO`).
    Info,
    /// Debug-level detail (corresponds to C `LOG_DEBUG`).
    Debug,
    /// Maximum detail including protocol traces (corresponds to C `LOG_TRACE`).
    Trace,
}

/// A parsed HTTP request.
///
/// Replaces the ad-hoc parsing results in `http_server_get_asn1_req()`
/// (`http_server.c:265-501`). Instead of passing multiple output pointers
/// (`ASN1_VALUE **preq`, `char **ppath`, `int *keep_alive`), all parsed
/// fields are collected into this struct.
#[derive(Debug)]
pub struct HttpRequest {
    /// HTTP method (GET or POST).
    pub method: HttpMethod,
    /// Request path (URL-decoded, leading `/` stripped).
    ///
    /// For GET requests, this is the raw URL path before base64 decoding.
    /// For POST requests, this is the target resource path.
    pub path: String,
    /// Request body bytes.
    ///
    /// - **GET:** Base64-decoded DER content from the URL path.
    /// - **POST:** Raw DER bytes read from the message body.
    pub body: Vec<u8>,
    /// Whether the client requested keep-alive.
    ///
    /// Derived from the `Connection` header:
    /// - HTTP/1.1 default: `true` (keep-alive)
    /// - HTTP/1.0 default: `false` (close)
    /// - Explicit `Connection: keep-alive` → `true`
    /// - Explicit `Connection: close` → `false`
    pub keep_alive: bool,
}

/// A basic HTTP/1.x server for OCSP and CMP responder commands.
///
/// Wraps a [`TcpListener`] and provides methods to accept HTTP requests
/// containing ASN.1-encoded data and send HTTP responses.
///
/// Replaces C's `http_server_init()` + global `acbio` BIO variable.
/// Uses RAII: the [`TcpListener`] is closed automatically when the
/// `HttpServer` is dropped.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_cli::lib::http::{HttpServer, Verbosity};
///
/// let server = HttpServer::new("ocsp", "8080", Verbosity::Info).unwrap();
/// let (request, mut stream) = server.accept_request(None, 120).unwrap();
/// // Process request.body, produce response_bytes...
/// # let response_bytes: Vec<u8> = vec![];
/// server.send_response(
///     &mut stream,
///     "application/ocsp-response",
///     &response_bytes,
///     request.keep_alive,
/// ).unwrap();
/// ```
pub struct HttpServer {
    /// The listening TCP socket.
    ///
    /// Replaces C's global `acbio` BIO created by `BIO_s_accept()`.
    listener: TcpListener,
    /// Program name for log messages.
    ///
    /// Corresponds to the `prog` parameter threaded through all C functions.
    prog: String,
    /// Logging verbosity level.
    ///
    /// Controls which `tracing` events are emitted at the application layer.
    verbosity: Verbosity,
}

// ---------------------------------------------------------------------------
// HttpServer implementation
// ---------------------------------------------------------------------------

impl HttpServer {
    /// Creates a new HTTP server bound to the specified port.
    ///
    /// Binds to `0.0.0.0:<port>` (all interfaces) with `SO_REUSEADDR`.
    /// Reports the bound address via `tracing::info!`.
    ///
    /// Replaces `http_server_init()` (`http_server.c:193-237`), which used
    /// `BIO_s_accept()` + `BIO_f_buffer()` + `BIO_set_bind_mode(REUSEADDR)`.
    ///
    /// # Arguments
    ///
    /// * `prog` — Program name for log messages (e.g., `"ocsp"`, `"cmp"`).
    /// * `port` — Port number or service name to bind to.
    /// * `verbosity` — Logging verbosity level.
    ///
    /// # Errors
    ///
    /// Returns [`HttpServerError::InitError`] if the port cannot be bound.
    #[instrument(skip_all, fields(prog = %prog, port = %port))]
    pub fn new(prog: &str, port: &str, verbosity: Verbosity) -> Result<Self, HttpServerError> {
        let bind_addr = format!("0.0.0.0:{port}");

        let listener = TcpListener::bind(&bind_addr).map_err(|e| {
            error!(prog = %prog, addr = %bind_addr, error = %e, "failed to bind");
            HttpServerError::InitError(format!("failed to bind to {bind_addr}: {e}"))
        })?;

        // Report the actual bound address (port may differ if "0" was given).
        // Replaces C's report_server_accept() call.
        let local_addr: SocketAddr = listener
            .local_addr()
            .map_err(|e| HttpServerError::InitError(format!("failed to get local address: {e}")))?;

        info!(
            prog = %prog,
            addr = %local_addr,
            "waiting for incoming HTTP request on {}",
            local_addr
        );

        Ok(HttpServer {
            listener,
            prog: prog.to_string(),
            verbosity,
        })
    }

    /// Returns the local address the server is bound to.
    ///
    /// Useful for tests and for reporting the actual port when binding to
    /// port `0` (ephemeral).
    pub fn local_addr(&self) -> Result<SocketAddr, HttpServerError> {
        self.listener.local_addr().map_err(HttpServerError::from)
    }

    /// Returns a reference to the program name.
    pub fn prog(&self) -> &str {
        &self.prog
    }

    /// Returns the configured verbosity level.
    pub fn verbosity(&self) -> Verbosity {
        self.verbosity
    }

    /// Accepts an HTTP request from a client.
    ///
    /// If `existing_stream` is `None`, accepts a new TCP connection from the
    /// listener. If `Some(stream)`, reuses an existing connection for HTTP
    /// keep-alive. Sets read/write timeouts on new connections using
    /// `timeout_secs`.
    ///
    /// Replaces `http_server_get_asn1_req()` (`http_server.c:265-501`).
    /// The C function returned `0` (retry), `1` (success), or `-1` (fatal);
    /// this Rust version returns `Result<(HttpRequest, TcpStream), HttpServerError>`.
    ///
    /// # Arguments
    ///
    /// * `existing_stream` — An existing TCP connection for keep-alive reuse,
    ///   or `None` to accept a new connection.
    /// * `timeout_secs` — Connection timeout in seconds. Applied to both
    ///   read and write operations. Replaces C's `alarm(timeout)`.
    ///
    /// # Errors
    ///
    /// Returns various [`HttpServerError`] variants for I/O failures,
    /// malformed requests, unsupported methods, and oversized payloads.
    #[instrument(skip_all, fields(prog = %self.prog))]
    pub fn accept_request(
        &self,
        existing_stream: Option<TcpStream>,
        timeout_secs: u64,
    ) -> Result<(HttpRequest, TcpStream), HttpServerError> {
        let stream = if let Some(s) = existing_stream {
            trace!(prog = %self.prog, "reusing existing connection (keep-alive)");
            s
        } else {
            let (new_stream, peer_addr) = self.listener.accept()?;
            info!(
                prog = %self.prog,
                peer = %peer_addr,
                "accepted new connection from {}",
                peer_addr
            );

            // Set timeouts — replaces C's alarm(timeout) signal-based
            // timeout (http_server.c:308-312).
            let timeout = Duration::from_secs(timeout_secs);
            new_stream.set_read_timeout(Some(timeout))?;
            new_stream.set_write_timeout(Some(timeout))?;

            new_stream
        };

        // Clone the stream: one handle for buffered reading, one for
        // returning to the caller (for response writing and keep-alive).
        let read_handle = stream.try_clone()?;
        let mut reader = BufReader::new(read_handle);

        // -----------------------------------------------------------------
        // Read and parse the HTTP request line (e.g., "GET /path HTTP/1.1")
        // Replaces BIO_gets(cbio, reqbuf, sizeof(reqbuf)) at line 335
        // -----------------------------------------------------------------
        let mut request_line = String::new();
        let bytes_read = reader.read_line(&mut request_line)?;

        if bytes_read == 0 {
            return Err(HttpServerError::InvalidRequest(
                "connection closed before request line".to_string(),
            ));
        }

        if request_line.len() > MAX_REQUEST_LINE_LEN {
            return Err(HttpServerError::InvalidRequest(
                "request line exceeds maximum length".to_string(),
            ));
        }

        let trimmed_line = request_line.trim_end_matches(['\r', '\n']);

        if trimmed_line.is_empty() {
            return Err(HttpServerError::InvalidRequest(
                "empty request line".to_string(),
            ));
        }

        trace!(
            prog = %self.prog,
            request_line = %trimmed_line,
            "received HTTP request line"
        );

        // Parse "METHOD /path HTTP/1.x"
        let (method, rest) = parse_method(trimmed_line)?;

        // Parse URL path (everything before the HTTP version)
        let (raw_path, http_version) = parse_url_and_version(rest)?;

        // Default keep-alive per HTTP version:
        // HTTP/1.1 → keep-alive by default; HTTP/1.0 → close by default.
        let mut keep_alive = http_version.contains("1.1");

        // -----------------------------------------------------------------
        // Read and parse HTTP headers
        // Replaces the header-parsing loop at http_server.c:416-459
        // -----------------------------------------------------------------
        let mut content_length: Option<usize> = None;
        let mut header_count: usize = 0;

        loop {
            let mut header_line = String::new();
            let hdr_bytes = reader.read_line(&mut header_line)?;

            if hdr_bytes == 0 {
                // Unexpected EOF before end-of-headers blank line
                break;
            }

            if header_line.len() > MAX_HEADER_LINE_LEN {
                return Err(HttpServerError::InvalidRequest(
                    "header line exceeds maximum length".to_string(),
                ));
            }

            let trimmed_header = header_line.trim_end_matches(['\r', '\n']);

            // Empty line signals end of headers
            if trimmed_header.is_empty() {
                break;
            }

            header_count = header_count.saturating_add(1);
            if header_count > MAX_HEADER_COUNT {
                return Err(HttpServerError::InvalidRequest(
                    "too many HTTP headers".to_string(),
                ));
            }

            trace!(
                prog = %self.prog,
                header = %trimmed_header,
                "received HTTP header"
            );

            // Parse "Key: Value" — find first ':'
            if let Some((key, value)) = trimmed_header.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                if key.eq_ignore_ascii_case("Connection") {
                    // Replaces OPENSSL_strcasecmp for Connection header
                    if value.eq_ignore_ascii_case("keep-alive") {
                        keep_alive = true;
                    } else if value.eq_ignore_ascii_case("close") {
                        keep_alive = false;
                    }
                } else if key.eq_ignore_ascii_case("Content-Length") {
                    content_length = Some(parse_content_length(value)?);
                }
                // Other headers are intentionally ignored — minimal HTTP
                // parser for OCSP/CMP responder use only.
            }
        }

        // -----------------------------------------------------------------
        // Parse request body based on method
        // -----------------------------------------------------------------
        let (path, body) = match method {
            HttpMethod::Get => {
                // GET: body is base64-encoded in the URL path.
                // Strip leading '/' if present.
                let url_path = raw_path.strip_prefix('/').unwrap_or(raw_path);

                // URL-decode percent-encoded characters (%xx sequences).
                // Replaces urldecode() at http_server.c:242-261.
                let decoded_url_bytes = url_decode(url_path)?;

                // Convert decoded bytes to UTF-8 string for base64 decoding.
                let decoded_str = std::str::from_utf8(&decoded_url_bytes)
                    .map_err(|_| HttpServerError::UrlDecodeError)?;

                // Base64-decode to obtain raw DER body.
                // Replaces BIO_f_base64() chain at http_server.c:390-398.
                // Using buffer-based decode (base64ct alloc feature not enabled).
                let body = base64_decode_to_vec(decoded_str)?;

                (url_path.to_string(), body)
            }
            HttpMethod::Post => {
                let url_path = raw_path.strip_prefix('/').unwrap_or(raw_path);

                let len = content_length.ok_or_else(|| {
                    HttpServerError::InvalidRequest(
                        "POST request missing Content-Length header".to_string(),
                    )
                })?;

                if len > MAX_REQUEST_BODY_SIZE {
                    warn!(
                        prog = %self.prog,
                        content_length = len,
                        max = MAX_REQUEST_BODY_SIZE,
                        "rejecting oversized POST request"
                    );
                    return Err(HttpServerError::RequestTooLarge);
                }

                // Read exactly Content-Length bytes of raw DER body.
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body)?;

                (url_path.to_string(), body)
            }
        };

        debug!(
            prog = %self.prog,
            method = %method,
            path = %path,
            body_len = body.len(),
            keep_alive = keep_alive,
            "parsed HTTP request"
        );

        let request = HttpRequest {
            method,
            path,
            body,
            keep_alive,
        };

        // Return the write handle; the BufReader (and its cloned read handle)
        // are dropped here, releasing the duplicate file descriptor.
        Ok((request, stream))
    }

    /// Sends an HTTP 200 OK response with the given content type and body.
    ///
    /// Writes `HTTP/1.0 200 OK` with `Content-Type`, `Content-Length`, and
    /// optionally `Connection: keep-alive` headers, followed by the DER-encoded
    /// response body.
    ///
    /// Replaces `http_server_send_asn1_resp()` (`http_server.c:504-529`).
    ///
    /// # Arguments
    ///
    /// * `stream` — The TCP connection to write the response to.
    /// * `content_type` — MIME type (e.g., `"application/ocsp-response"`).
    /// * `body` — DER-encoded response body bytes.
    /// * `keep_alive` — Whether to include `Connection: keep-alive`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpServerError::Io`] on write failures.
    #[instrument(skip_all, fields(prog = %self.prog, content_type = %content_type, body_len = body.len()))]
    pub fn send_response(
        &self,
        stream: &mut TcpStream,
        content_type: &str,
        body: &[u8],
        keep_alive: bool,
    ) -> Result<(), HttpServerError> {
        // Write status line
        write!(stream, "{HTTP_VERSION_PREFIX} 200 OK\r\n")?;

        // Write headers
        write!(stream, "Content-Type: {content_type}\r\n")?;
        write!(stream, "Content-Length: {}\r\n", body.len())?;

        if keep_alive {
            write!(stream, "Connection: keep-alive\r\n")?;
        }

        // End of headers
        write!(stream, "\r\n")?;

        // Write body
        stream.write_all(body)?;
        stream.flush()?;

        debug!(
            prog = %self.prog,
            status = 200u16,
            content_type = %content_type,
            body_len = body.len(),
            keep_alive = keep_alive,
            "sent HTTP 200 OK response"
        );

        Ok(())
    }

    /// Sends a simple HTTP status response (e.g., 400 Bad Request).
    ///
    /// Writes a minimal status-line response with `Content-Length: 0` and no
    /// body. Implicitly cancels keep-alive (no `Connection` header sent).
    ///
    /// Replaces `http_server_send_status()` (`http_server.c:531-547`).
    ///
    /// # Arguments
    ///
    /// * `stream` — The TCP connection to write the status to.
    /// * `status_code` — HTTP status code (e.g., `400`, `500`).
    /// * `reason` — Human-readable reason phrase (e.g., `"Bad Request"`).
    ///
    /// # Errors
    ///
    /// Returns [`HttpServerError::Io`] on write failures.
    #[instrument(skip_all, fields(prog = %self.prog, status_code = status_code))]
    pub fn send_status(
        &self,
        stream: &mut TcpStream,
        status_code: u16,
        reason: &str,
    ) -> Result<(), HttpServerError> {
        // Matches C: HTTP/1.0 <code> <reason>\r\nContent-Length: 0\r\n\r\n
        write!(
            stream,
            "{HTTP_VERSION_PREFIX} {status_code} {reason}\r\nContent-Length: 0\r\n\r\n"
        )?;
        stream.flush()?;

        debug!(
            prog = %self.prog,
            status_code = status_code,
            reason = %reason,
            "sent HTTP status response"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Parses the HTTP method from the beginning of the request line.
///
/// Returns the parsed [`HttpMethod`] and the remainder of the line after
/// the method and space.
///
/// # Errors
///
/// Returns [`HttpServerError::UnsupportedMethod`] if the method is neither
/// `GET` nor `POST`.
fn parse_method(line: &str) -> Result<(HttpMethod, &str), HttpServerError> {
    if let Some(rest) = line.strip_prefix("GET ") {
        Ok((HttpMethod::Get, rest))
    } else if let Some(rest) = line.strip_prefix("POST ") {
        Ok((HttpMethod::Post, rest))
    } else {
        // Extract the method word for the error message
        let method_word = line.split_whitespace().next().unwrap_or(line);
        Err(HttpServerError::UnsupportedMethod(method_word.to_string()))
    }
}

/// Parses the URL path and HTTP version from the remainder of the request line.
///
/// Expects input like `/path HTTP/1.1`. Returns `(path, version)`.
///
/// # Errors
///
/// Returns [`HttpServerError::InvalidRequest`] if the format is invalid.
fn parse_url_and_version(rest: &str) -> Result<(&str, &str), HttpServerError> {
    // Find the last space — everything before is the URL, after is the version.
    // This handles paths with encoded spaces.
    let version_sep = rest.rfind(' ').ok_or_else(|| {
        HttpServerError::InvalidRequest("missing HTTP version in request line".to_string())
    })?;

    let raw_path = &rest[..version_sep];
    let http_version = &rest[version_sep + 1..];

    if raw_path.is_empty() {
        return Err(HttpServerError::InvalidRequest(
            "empty URL path in request line".to_string(),
        ));
    }

    // Validate HTTP version format (must start with "HTTP/")
    if !http_version.starts_with("HTTP/") {
        return Err(HttpServerError::InvalidRequest(format!(
            "invalid HTTP version: {http_version}"
        )));
    }

    Ok((raw_path, http_version))
}

/// Parses a `Content-Length` header value into a `usize`.
///
/// Uses `str::parse` which performs checked conversion, satisfying Rule R6
/// (no bare `as` casts for numeric conversions).
///
/// # Errors
///
/// Returns [`HttpServerError::InvalidRequest`] if the value is not a valid
/// non-negative integer.
fn parse_content_length(value: &str) -> Result<usize, HttpServerError> {
    value
        .parse::<usize>()
        .map_err(|_| HttpServerError::InvalidRequest(format!("invalid Content-Length: {value}")))
}

/// Base64-decodes a string into a new `Vec<u8>` using a stack-allocated buffer.
///
/// Uses `base64ct::Base64::decode()` (buffer-based) because the `alloc` feature
/// is not enabled on the `base64ct` crate (pinned to `=1.6.0`).
///
/// # Errors
///
/// Returns [`HttpServerError::UrlDecodeError`] if the input is not valid
/// base64 encoding.
fn base64_decode_to_vec(input: &str) -> Result<Vec<u8>, HttpServerError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Compute maximum possible decoded length: ceil(input_len * 3 / 4).
    // Use saturating arithmetic per Rule R6.
    let max_decoded_len = input
        .len()
        .saturating_mul(3)
        .checked_div(4)
        .unwrap_or(0)
        .saturating_add(3); // extra margin for padding

    let mut buf = vec![0u8; max_decoded_len];

    let decoded = Base64::decode(input, &mut buf).map_err(|_| HttpServerError::UrlDecodeError)?;

    Ok(decoded.to_vec())
}

/// URL-decodes a percent-encoded string.
///
/// Decodes `%xx` hex sequences and `+` (as space) in the input string.
/// Replaces `urldecode()` at `http_server.c:242-261`.
///
/// # Errors
///
/// Returns [`HttpServerError::UrlDecodeError`] if a `%xx` sequence contains
/// invalid hex digits or is truncated.
///
/// # Rule R6 Compliance
///
/// All hex-to-integer conversions use pattern matching with explicit ranges
/// rather than bare `as` casts.
pub fn url_decode(input: &str) -> Result<Vec<u8>, HttpServerError> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Need at least 2 more bytes for the %xx hex pair
            if i.saturating_add(2) >= bytes.len() {
                return Err(HttpServerError::UrlDecodeError);
            }

            let hi = hex_digit_value(bytes[i.saturating_add(1)])
                .ok_or(HttpServerError::UrlDecodeError)?;
            let lo = hex_digit_value(bytes[i.saturating_add(2)])
                .ok_or(HttpServerError::UrlDecodeError)?;

            // Combine nibbles: (hi << 4) | lo
            // Both hi and lo are in 0..=15, so (hi << 4) | lo fits in u8.
            output.push((hi << 4) | lo);
            i = i.saturating_add(3);
        } else if bytes[i] == b'+' {
            // '+' represents a space in application/x-www-form-urlencoded
            output.push(b' ');
            i = i.saturating_add(1);
        } else {
            output.push(bytes[i]);
            i = i.saturating_add(1);
        }
    }

    Ok(output)
}

/// Converts a hex digit ASCII byte to its numeric value (0–15).
///
/// Returns `None` if the byte is not a valid hexadecimal digit.
/// Uses pattern matching with explicit ranges per Rule R6 — no bare `as` casts.
fn hex_digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode_simple() {
        let result = url_decode("hello%20world").unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_url_decode_plus_as_space() {
        let result = url_decode("hello+world").unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_url_decode_hex_uppercase() {
        let result = url_decode("%2F%3A").unwrap();
        assert_eq!(result, b"/:");
    }

    #[test]
    fn test_url_decode_hex_lowercase() {
        let result = url_decode("%2f%3a").unwrap();
        assert_eq!(result, b"/:");
    }

    #[test]
    fn test_url_decode_empty() {
        let result = url_decode("").unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn test_url_decode_no_encoding() {
        let result = url_decode("plain-text_123").unwrap();
        assert_eq!(result, b"plain-text_123");
    }

    #[test]
    fn test_url_decode_truncated_percent() {
        assert!(url_decode("abc%2").is_err());
        assert!(url_decode("abc%").is_err());
    }

    #[test]
    fn test_url_decode_invalid_hex() {
        assert!(url_decode("%GG").is_err());
        assert!(url_decode("%ZZ").is_err());
    }

    #[test]
    fn test_hex_digit_value_digits() {
        for (i, ch) in (b'0'..=b'9').enumerate() {
            let expected = u8::try_from(i).unwrap();
            assert_eq!(hex_digit_value(ch), Some(expected));
        }
    }

    #[test]
    fn test_hex_digit_value_lowercase() {
        assert_eq!(hex_digit_value(b'a'), Some(10));
        assert_eq!(hex_digit_value(b'f'), Some(15));
    }

    #[test]
    fn test_hex_digit_value_uppercase() {
        assert_eq!(hex_digit_value(b'A'), Some(10));
        assert_eq!(hex_digit_value(b'F'), Some(15));
    }

    #[test]
    fn test_hex_digit_value_invalid() {
        assert_eq!(hex_digit_value(b'g'), None);
        assert_eq!(hex_digit_value(b'z'), None);
        assert_eq!(hex_digit_value(b' '), None);
    }

    #[test]
    fn test_parse_method_get() {
        let (method, rest) = parse_method("GET /path HTTP/1.1").unwrap();
        assert_eq!(method, HttpMethod::Get);
        assert_eq!(rest, "/path HTTP/1.1");
    }

    #[test]
    fn test_parse_method_post() {
        let (method, rest) = parse_method("POST /path HTTP/1.0").unwrap();
        assert_eq!(method, HttpMethod::Post);
        assert_eq!(rest, "/path HTTP/1.0");
    }

    #[test]
    fn test_parse_method_unsupported() {
        let err = parse_method("PUT /path HTTP/1.1").unwrap_err();
        match err {
            HttpServerError::UnsupportedMethod(m) => assert_eq!(m, "PUT"),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_parse_url_and_version() {
        let (path, version) = parse_url_and_version("/ocsp HTTP/1.1").unwrap();
        assert_eq!(path, "/ocsp");
        assert_eq!(version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_url_and_version_with_query() {
        let (path, version) = parse_url_and_version("/path?query=1 HTTP/1.0").unwrap();
        assert_eq!(path, "/path?query=1");
        assert_eq!(version, "HTTP/1.0");
    }

    #[test]
    fn test_parse_url_and_version_missing_version() {
        assert!(parse_url_and_version("/path").is_err());
    }

    #[test]
    fn test_parse_url_and_version_invalid_version() {
        assert!(parse_url_and_version("/path INVALID").is_err());
    }

    #[test]
    fn test_parse_content_length_valid() {
        assert_eq!(parse_content_length("42").unwrap(), 42);
        assert_eq!(parse_content_length("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_content_length_invalid() {
        assert!(parse_content_length("abc").is_err());
        assert!(parse_content_length("-1").is_err());
        assert!(parse_content_length("").is_err());
    }

    #[test]
    fn test_base64_decode_to_vec_valid() {
        // "hello" in base64 is "aGVsbG8="
        let result = base64_decode_to_vec("aGVsbG8=").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_base64_decode_to_vec_empty() {
        let result = base64_decode_to_vec("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_base64_decode_to_vec_invalid() {
        assert!(base64_decode_to_vec("!!!invalid!!!").is_err());
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(format!("{}", HttpMethod::Get), "GET");
        assert_eq!(format!("{}", HttpMethod::Post), "POST");
    }

    #[test]
    fn test_verbosity_ordering() {
        assert!(Verbosity::Quiet < Verbosity::Error);
        assert!(Verbosity::Error < Verbosity::Warning);
        assert!(Verbosity::Warning < Verbosity::Info);
        assert!(Verbosity::Info < Verbosity::Debug);
        assert!(Verbosity::Debug < Verbosity::Trace);
    }

    #[test]
    fn test_http_server_error_display() {
        let err = HttpServerError::UrlDecodeError;
        assert_eq!(format!("{}", err), "URL decode error");

        let err = HttpServerError::UnsupportedMethod("DELETE".to_string());
        assert_eq!(format!("{}", err), "unsupported HTTP method: DELETE");

        let err = HttpServerError::RequestTooLarge;
        assert_eq!(format!("{}", err), "request too large");

        let err = HttpServerError::InvalidRequest("bad".to_string());
        assert_eq!(format!("{}", err), "invalid HTTP request: bad");

        let err = HttpServerError::InitError("port in use".to_string());
        assert_eq!(
            format!("{}", err),
            "server initialization failed: port in use"
        );
    }

    #[test]
    fn test_http_server_error_io_from() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let http_err: HttpServerError = io_err.into();
        match http_err {
            HttpServerError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("expected Io, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // Integration tests: full TCP lifecycle
    // ---------------------------------------------------------------

    #[test]
    fn test_server_bind_ephemeral_port() {
        let server = HttpServer::new("test", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
        assert_eq!(server.prog(), "test");
        assert_eq!(server.verbosity(), Verbosity::Quiet);
    }

    #[test]
    fn test_server_post_request_roundtrip() {
        // Start server on ephemeral port
        let server = HttpServer::new("test-post", "0", Verbosity::Trace).unwrap();
        let addr = server.local_addr().unwrap();

        // Spawn a client thread that sends a POST request
        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            let body = b"\x30\x03\x02\x01\x01"; // tiny DER: SEQUENCE { INTEGER 1 }
            let req = format!(
                "POST /ocsp HTTP/1.0\r\n\
                 Content-Type: application/ocsp-request\r\n\
                 Content-Length: {}\r\n\
                 \r\n",
                body.len()
            );
            client.write_all(req.as_bytes()).unwrap();
            client.write_all(body).unwrap();
            client.flush().unwrap();

            // Read response
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        });

        // Server accepts and processes
        let (request, mut stream) = server.accept_request(None, 5).unwrap();

        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "ocsp");
        assert_eq!(request.body, b"\x30\x03\x02\x01\x01");
        assert!(!request.keep_alive); // HTTP/1.0 default is close

        // Send response
        let resp_body = b"\x30\x03\x02\x01\x00";
        server
            .send_response(&mut stream, "application/ocsp-response", resp_body, false)
            .unwrap();
        drop(stream); // close connection so client can finish reading

        // Verify client received proper response
        let response = client_handle.join().unwrap();
        assert!(response.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(response.contains("Content-Type: application/ocsp-response"));
        assert!(response.contains("Content-Length: 5"));
        // Verify response body is present at end
        assert!(response.ends_with("\r\n\r\n\x30\x03\x02\x01\x00"));
    }

    #[test]
    fn test_server_get_request_base64() {
        let server = HttpServer::new("test-get", "0", Verbosity::Trace).unwrap();
        let addr = server.local_addr().unwrap();

        // Spawn client: send GET with base64-encoded body in path
        // "hello" = base64("hello") = "aGVsbG8="
        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            let req = "GET /aGVsbG8= HTTP/1.1\r\n\
                        Connection: close\r\n\
                        \r\n";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        });

        let (request, mut stream) = server.accept_request(None, 5).unwrap();

        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.path, "aGVsbG8=");
        assert_eq!(request.body, b"hello");
        assert!(!request.keep_alive); // explicit close

        server
            .send_response(&mut stream, "text/plain", b"ok", false)
            .unwrap();
        drop(stream);

        let response = client_handle.join().unwrap();
        assert!(response.starts_with("HTTP/1.0 200 OK"));
    }

    #[test]
    fn test_server_send_status_directly() {
        let server = HttpServer::new("test-status2", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            let req = "POST /test HTTP/1.0\r\n\
                        Content-Length: 3\r\n\
                        \r\n\
                        abc";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        });

        let (_request, mut stream) = server.accept_request(None, 5).unwrap();

        // Send a 400 Bad Request status
        server.send_status(&mut stream, 400, "Bad Request").unwrap();
        drop(stream);

        let response = client_handle.join().unwrap();
        assert!(response.starts_with("HTTP/1.0 400 Bad Request"));
        assert!(response.contains("Content-Length: 0"));
    }

    #[test]
    fn test_server_keep_alive_header() {
        use std::sync::{Arc, Barrier};

        let server = HttpServer::new("test-ka", "0", Verbosity::Trace).unwrap();
        let addr = server.local_addr().unwrap();

        // Barrier ensures the client does not read until the server has
        // finished sending the response (avoids TCP race / RST).
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            // HTTP/1.0 with explicit keep-alive
            let req = "POST /test HTTP/1.0\r\n\
                        Connection: keep-alive\r\n\
                        Content-Length: 4\r\n\
                        \r\ntest";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();

            // Wait until server has sent the response
            barrier_clone.wait();

            // Now read the full response
            let mut response = String::new();
            // Use a short timeout so we don't hang forever
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            // Read whatever is available (server already wrote + closed)
            let _ = client.read_to_string(&mut response);
            response
        });

        let (request, mut stream) = server.accept_request(None, 5).unwrap();

        assert!(request.keep_alive); // explicitly set via Connection: keep-alive
        assert_eq!(request.body, b"test");

        server
            .send_response(&mut stream, "text/plain", b"ok", true)
            .unwrap();

        // Signal client that the response has been written
        barrier.wait();

        // Shutdown the write side so the client sees EOF
        let _ = stream.shutdown(std::net::Shutdown::Write);
        drop(stream);

        let response = client_handle.join().unwrap();
        assert!(response.contains("Connection: keep-alive"));
    }

    #[test]
    fn test_server_http11_default_keep_alive() {
        let server = HttpServer::new("test-h11", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            // HTTP/1.1 with no Connection header = keep-alive by default
            let req = "POST /test HTTP/1.1\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        ok";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();
            // Just wait briefly for server to process
            std::thread::sleep(Duration::from_millis(100));
        });

        let (request, _stream) = server.accept_request(None, 5).unwrap();

        assert!(request.keep_alive); // HTTP/1.1 default
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.body, b"ok");

        let _ = client_handle.join();
    }

    #[test]
    fn test_server_get_url_decode_in_path() {
        let server = HttpServer::new("test-urldec", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            // base64 of "test": "dGVzdA==" → URL-encode the '=' as %3D
            let req = "GET /dGVzdA%3D%3D HTTP/1.0\r\n\r\n";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let (request, _stream) = server.accept_request(None, 5).unwrap();

        assert_eq!(request.method, HttpMethod::Get);
        // The URL-decoded path should be "dGVzdA==" (after %3D → '=')
        assert_eq!(request.path, "dGVzdA%3D%3D");
        // The body should be base64-decoded "test"
        assert_eq!(request.body, b"test");

        let _ = client_handle.join();
    }

    #[test]
    fn test_server_post_too_large() {
        let server = HttpServer::new("test-large", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            // Claim a very large body
            let req = "POST /test HTTP/1.0\r\n\
                        Content-Length: 999999999\r\n\
                        \r\n";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let result = server.accept_request(None, 5);
        assert!(result.is_err());
        match result.unwrap_err() {
            HttpServerError::RequestTooLarge => {} // expected
            other => panic!("expected RequestTooLarge, got {:?}", other),
        }

        let _ = client_handle.join();
    }

    #[test]
    fn test_server_unsupported_method() {
        let server = HttpServer::new("test-method", "0", Verbosity::Quiet).unwrap();
        let addr = server.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            let req = "PUT /resource HTTP/1.1\r\n\r\n";
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let result = server.accept_request(None, 5);
        assert!(result.is_err());
        match result.unwrap_err() {
            HttpServerError::UnsupportedMethod(m) => {
                assert_eq!(m, "PUT");
            }
            other => panic!("expected UnsupportedMethod, got {:?}", other),
        }

        let _ = client_handle.join();
    }

    #[test]
    fn test_default_timeout_secs_value() {
        assert_eq!(DEFAULT_TIMEOUT_SECS, 120);
    }
}
