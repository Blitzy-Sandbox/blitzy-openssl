//! `dsa` subcommand implementation.
//!
//! DSA key processing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `dsa` subcommand.
#[derive(Args, Debug)]
pub struct DsaArgs {}

impl DsaArgs {
    /// Execute the `dsa` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
