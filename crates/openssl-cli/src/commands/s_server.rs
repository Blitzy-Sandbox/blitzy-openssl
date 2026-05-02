//! `s_server` subcommand implementation.
//!
//! TLS/DTLS/QUIC diagnostic server. Binds a listener on the configured
//! port, performs a TLS handshake with the configured certificate, and
//! prints connection diagnostics (peer certificate, negotiated cipher,
//! session ticket, ALPN, etc.).
//!
//! This module is currently a *thin dispatch stub*: the full TLS server
//! implementation lives in `openssl-ssl::ssl` and the production port to
//! Rust is tracked separately.  The stub exists so that the
//! `clap`-derived command dispatcher can wire the subcommand into
//! [`crate::commands::CliCommand::execute`] (Rule R10 — Wiring Before
//! Done) and so that integration tests can verify the dispatch path
//! end-to-end without depending on a live TLS endpoint.
//!
//! On invocation the stub emits the contract message
//! `"Command dispatched successfully. Full handler implementation pending."`
//! to standard error and returns [`Ok`].  The exact wording is
//! load-bearing — the integration test suite
//! (`crates/openssl-cli/src/tests/{callback,tls,pki}_tests.rs`) asserts
//! on it via the `DISPATCH_MSG` constant or via `predicate::str::contains`
//! to confirm that the binary parsed the command line, performed
//! library/provider initialisation, and reached the stub handler
//! successfully.
//!
//! Replaces `apps/s_server.c:s_server_main()` (3,500+ lines, full TLS
//! server accept loop + per-connection handler) with a dispatch-only
//! stub pending the production port.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Sentinel string emitted to `stderr` by every stub subcommand to
/// signal "argument parsing + library initialisation succeeded; the
/// algorithmic handler has not yet been ported from C".
///
/// Kept identical across stubs (and identical to the test-side
/// `pki_tests::DISPATCH_MSG`) so that integration tests can match a
/// single literal.  Do **not** localise, capitalise, or punctuate
/// differently — the test harness compares byte-for-byte.
const DISPATCH_MSG: &str = "Command dispatched successfully. Full handler implementation pending.";

/// Arguments for the `s_server` subcommand.
#[derive(Args, Debug)]
pub struct SServerArgs {}

impl SServerArgs {
    /// Execute the `s_server` subcommand.
    ///
    /// Emits [`DISPATCH_MSG`] on stderr and returns `Ok(())`.
    /// Replaces `apps/s_server.c:s_server_main()` (full TLS server
    /// accept loop) with a dispatch-only stub pending the production
    /// port.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        eprintln!("{DISPATCH_MSG}");
        Ok(())
    }
}
