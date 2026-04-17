//! `rsautl` subcommand implementation.
//!
//! RSA utility (legacy).

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `rsautl` subcommand.
#[derive(Args, Debug)]
pub struct RsautlArgs {}

impl RsautlArgs {
    /// Execute the `rsautl` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
