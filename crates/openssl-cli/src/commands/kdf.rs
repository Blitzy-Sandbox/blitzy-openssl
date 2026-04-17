//! `kdf` subcommand implementation.
//!
//! Key derivation function execution.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `kdf` subcommand.
#[derive(Args, Debug)]
pub struct KdfArgs {
}

impl KdfArgs {
    /// Execute the `kdf` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
