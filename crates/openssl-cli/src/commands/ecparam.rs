//! `ecparam` subcommand implementation.
//!
//! EC parameter generation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ecparam` subcommand.
#[derive(Args, Debug)]
pub struct EcparamArgs {}

impl EcparamArgs {
    /// Execute the `ecparam` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
