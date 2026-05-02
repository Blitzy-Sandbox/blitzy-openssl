//! `s_client` subcommand implementation.
//!
//! TLS/DTLS/QUIC diagnostic client. Establishes a TLS connection to a
//! remote endpoint and prints connection diagnostics (negotiated cipher,
//! peer certificate chain, session ticket, ALPN, etc.).
//!
//! This module is currently a *thin dispatch stub*: the full TLS client
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
//! Replaces `apps/s_client.c:s_client_main()` (3,600+ lines, full TLS
//! handshake + interactive shell) with a dispatch-only stub pending the
//! production port.

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

/// Arguments for the `s_client` subcommand.
#[derive(Args, Debug)]
pub struct SClientArgs {}

impl SClientArgs {
    /// Execute the `s_client` subcommand.
    ///
    /// Emits [`DISPATCH_MSG`] on stderr and returns `Ok(())`.
    /// Replaces `apps/s_client.c:s_client_main()` (full TLS client
    /// handshake + interactive shell) with a dispatch-only stub pending
    /// the production port.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        eprintln!("{DISPATCH_MSG}");
        Ok(())
    }
}
