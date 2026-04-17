//! `version` subcommand implementation.
//!
//! Display version information.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `version` subcommand.
#[derive(Args, Debug)]
pub struct VersionArgs {
}

impl VersionArgs {
    /// Execute the `version` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
