//! `storeutl` subcommand implementation.
//!
//! OSSL_STORE URI loading utility.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `storeutl` subcommand.
#[derive(Args, Debug)]
pub struct StoreutlArgs {
}

impl StoreutlArgs {
    /// Execute the `storeutl` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
