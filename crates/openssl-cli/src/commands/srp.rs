//! `srp` subcommand implementation.
//!
//! SRP verifier database management (deprecated).

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `srp` subcommand.
#[derive(Args, Debug)]
pub struct SrpArgs {
}

impl SrpArgs {
    /// Execute the `srp` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
