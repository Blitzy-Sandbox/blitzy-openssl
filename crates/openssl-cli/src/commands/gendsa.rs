//! `gendsa` subcommand implementation.
//!
//! Generate DSA key from parameters.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `gendsa` subcommand.
#[derive(Args, Debug)]
pub struct GendsaArgs {
}

impl GendsaArgs {
    /// Execute the `gendsa` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
