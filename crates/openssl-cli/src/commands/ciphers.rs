//! `ciphers` subcommand implementation.
//!
//! Cipher suite listing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ciphers` subcommand.
#[derive(Args, Debug)]
pub struct CiphersArgs {
}

impl CiphersArgs {
    /// Execute the `ciphers` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
