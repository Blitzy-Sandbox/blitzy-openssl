//! `dsaparam` subcommand implementation.
//!
//! DSA parameter generation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `dsaparam` subcommand.
#[derive(Args, Debug)]
pub struct DsaparamArgs {}

impl DsaparamArgs {
    /// Execute the `dsaparam` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
