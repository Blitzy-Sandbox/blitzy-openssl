//! `ec` subcommand implementation.
//!
//! EC key processing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ec` subcommand.
#[derive(Args, Debug)]
pub struct EcArgs {
}

impl EcArgs {
    /// Execute the `ec` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
