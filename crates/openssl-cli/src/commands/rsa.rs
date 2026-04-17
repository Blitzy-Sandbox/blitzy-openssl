//! `rsa` subcommand implementation.
//!
//! RSA key processing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `rsa` subcommand.
#[derive(Args, Debug)]
pub struct RsaArgs {
}

impl RsaArgs {
    /// Execute the `rsa` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
