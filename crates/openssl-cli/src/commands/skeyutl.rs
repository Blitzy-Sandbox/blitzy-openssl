//! `skeyutl` subcommand implementation.
//!
//! Symmetric key generation utility.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `skeyutl` subcommand.
#[derive(Args, Debug)]
pub struct SkeyutlArgs {
}

impl SkeyutlArgs {
    /// Execute the `skeyutl` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
