//! `pkey` subcommand implementation.
//!
//! Public/private key processing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkey` subcommand.
#[derive(Args, Debug)]
pub struct PkeyArgs {}

impl PkeyArgs {
    /// Execute the `pkey` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
