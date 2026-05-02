//! `x509` subcommand implementation.
//!
//! X.509 certificate display, signing, and conversion.
//!
//! This module is currently a *thin dispatch stub*: the full X.509
//! parse / display / re-sign / format-conversion pipeline is tracked
//! for production port from `apps/x509.c`.  The stub exists so that
//! the `clap`-derived command dispatcher can wire the subcommand into
//! [`crate::commands::CliCommand::execute`] (Rule R10 — Wiring Before
//! Done) and so that integration tests can verify the dispatch path
//! end-to-end without depending on the full handler.
//!
//! On invocation the stub emits the contract message
//! `"Command dispatched successfully. Full handler implementation pending."`
//! to standard error and returns [`Ok`].  The exact wording is
//! load-bearing — the integration test suite
//! (`crates/openssl-cli/src/tests/pki_tests.rs`) asserts on it via the
//! `DISPATCH_MSG` constant to confirm that the binary parsed the command
//! line, performed library/provider initialisation, and reached the stub
//! handler successfully.

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

/// Arguments for the `x509` subcommand.
#[derive(Args, Debug)]
pub struct X509Args {}

impl X509Args {
    /// Execute the `x509` subcommand.
    ///
    /// Emits [`DISPATCH_MSG`] on stderr and returns `Ok(())`.
    /// Replaces `apps/x509.c:x509_main()` (full certificate pipeline) with
    /// a dispatch-only stub pending the production port.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        eprintln!("{DISPATCH_MSG}");
        Ok(())
    }
}
