//! `list` subcommand implementation.
//!
//! List algorithms, providers, and capabilities.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `list` subcommand.
#[derive(Args, Debug)]
pub struct ListArgs {}

impl ListArgs {
    /// Execute the `list` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
