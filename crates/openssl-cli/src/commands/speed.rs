//! `speed` subcommand implementation.
//!
//! Cryptographic algorithm benchmark.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `speed` subcommand.
#[derive(Args, Debug)]
pub struct SpeedArgs {
}

impl SpeedArgs {
    /// Execute the `speed` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
