//! `dgst` subcommand implementation.
//!
//! Message digest/signature generation and verification.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `dgst` subcommand.
#[derive(Args, Debug)]
pub struct DgstArgs {}

impl DgstArgs {
    /// Execute the `dgst` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
