//! `smime` subcommand implementation.
//!
//! S/MIME mail operations.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `smime` subcommand.
#[derive(Args, Debug)]
pub struct SmimeArgs {
}

impl SmimeArgs {
    /// Execute the `smime` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
