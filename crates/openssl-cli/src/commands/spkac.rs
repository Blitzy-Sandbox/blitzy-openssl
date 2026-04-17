//! `spkac` subcommand implementation.
//!
//! SPKAC handling.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `spkac` subcommand.
#[derive(Args, Debug)]
pub struct SpkacArgs {
}

impl SpkacArgs {
    /// Execute the `spkac` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
