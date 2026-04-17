//! `rand` subcommand implementation.
//!
//! Random data generation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `rand` subcommand.
#[derive(Args, Debug)]
pub struct RandArgs {
}

impl RandArgs {
    /// Execute the `rand` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
