//! `req` subcommand implementation.
//!
//! Certificate signing request (CSR) operations.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `req` subcommand.
#[derive(Args, Debug)]
pub struct ReqArgs {
}

impl ReqArgs {
    /// Execute the `req` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
