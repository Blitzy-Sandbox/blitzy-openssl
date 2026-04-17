//! `mac` subcommand implementation.
//!
//! MAC computation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `mac` subcommand.
#[derive(Args, Debug)]
pub struct MacArgs {}

impl MacArgs {
    /// Execute the `mac` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
