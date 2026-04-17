//! `genrsa` subcommand implementation.
//!
//! Generate RSA private key.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `genrsa` subcommand.
#[derive(Args, Debug)]
pub struct GenrsaArgs {}

impl GenrsaArgs {
    /// Execute the `genrsa` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
