//! `prime` subcommand implementation.
//!
//! Prime number generation and testing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `prime` subcommand.
#[derive(Args, Debug)]
pub struct PrimeArgs {}

impl PrimeArgs {
    /// Execute the `prime` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
