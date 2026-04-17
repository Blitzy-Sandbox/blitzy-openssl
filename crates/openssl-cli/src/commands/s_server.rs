//! `s_server` subcommand implementation.
//!
//! TLS/DTLS/QUIC server.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `s_server` subcommand.
#[derive(Args, Debug)]
pub struct SServerArgs {}

impl SServerArgs {
    /// Execute the `s_server` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
