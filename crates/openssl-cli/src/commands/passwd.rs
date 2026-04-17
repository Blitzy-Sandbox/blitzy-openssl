//! `passwd` subcommand implementation.
//!
//! Password hashing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `passwd` subcommand.
#[derive(Args, Debug)]
pub struct PasswdArgs {
}

impl PasswdArgs {
    /// Execute the `passwd` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
