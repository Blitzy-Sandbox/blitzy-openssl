//! `info` subcommand implementation.
//!
//! Display build information.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `info` subcommand.
#[derive(Args, Debug)]
pub struct InfoArgs {}

impl InfoArgs {
    /// Execute the `info` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
