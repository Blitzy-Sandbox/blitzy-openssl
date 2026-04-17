//! `dhparam` subcommand implementation.
//!
//! DH parameter generation and management.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `dhparam` subcommand.
#[derive(Args, Debug)]
pub struct DhparamArgs {
}

impl DhparamArgs {
    /// Execute the `dhparam` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
