//! `rehash` subcommand implementation.
//!
//! Certificate directory hash link creation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `rehash` subcommand.
#[derive(Args, Debug)]
pub struct RehashArgs {
}

impl RehashArgs {
    /// Execute the `rehash` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
