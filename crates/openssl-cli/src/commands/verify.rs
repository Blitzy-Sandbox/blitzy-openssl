//! `verify` subcommand implementation.
//!
//! Certificate chain verification.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `verify` subcommand.
#[derive(Args, Debug)]
pub struct VerifyArgs {}

impl VerifyArgs {
    /// Execute the `verify` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
