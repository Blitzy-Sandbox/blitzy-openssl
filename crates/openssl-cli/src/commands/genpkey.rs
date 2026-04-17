//! `genpkey` subcommand implementation.
//!
//! Generate private keys or key parameters.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `genpkey` subcommand.
#[derive(Args, Debug)]
pub struct GenpkeyArgs {}

impl GenpkeyArgs {
    /// Execute the `genpkey` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
