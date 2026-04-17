//! `s_client` subcommand implementation.
//!
//! TLS/DTLS/QUIC client.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `s_client` subcommand.
#[derive(Args, Debug)]
pub struct SClientArgs {
}

impl SClientArgs {
    /// Execute the `s_client` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
