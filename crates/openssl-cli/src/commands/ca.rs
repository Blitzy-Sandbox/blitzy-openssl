//! `ca` subcommand implementation.
//!
//! Certificate Authority management.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ca` subcommand.
#[derive(Args, Debug)]
pub struct CaArgs {}

impl CaArgs {
    /// Execute the `ca` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
