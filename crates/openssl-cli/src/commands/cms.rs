//! `cms` subcommand implementation.
//!
//! CMS (Cryptographic Message Syntax) operations.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `cms` subcommand.
#[derive(Args, Debug)]
pub struct CmsArgs {
}

impl CmsArgs {
    /// Execute the `cms` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
