//! `enc` subcommand implementation.
//!
//! Symmetric cipher encryption/decryption.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `enc` subcommand.
#[derive(Args, Debug)]
pub struct EncArgs {}

impl EncArgs {
    /// Execute the `enc` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
