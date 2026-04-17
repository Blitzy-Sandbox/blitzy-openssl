//! `ech` subcommand implementation.
//!
//! ECH configuration management.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ech` subcommand.
#[derive(Args, Debug)]
pub struct EchArgs {
}

impl EchArgs {
    /// Execute the `ech` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
