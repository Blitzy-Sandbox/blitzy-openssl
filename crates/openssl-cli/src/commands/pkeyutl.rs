//! `pkeyutl` subcommand implementation.
//!
//! Public key algorithm utility.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkeyutl` subcommand.
#[derive(Args, Debug)]
pub struct PkeyutlArgs {
}

impl PkeyutlArgs {
    /// Execute the `pkeyutl` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
