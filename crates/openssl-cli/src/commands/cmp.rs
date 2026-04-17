//! `cmp` subcommand implementation.
//!
//! Certificate Management Protocol client.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `cmp` subcommand.
#[derive(Args, Debug)]
pub struct CmpArgs {
}

impl CmpArgs {
    /// Execute the `cmp` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
