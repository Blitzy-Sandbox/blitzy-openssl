//! `crl` subcommand implementation.
//!
//! CRL inspection and generation.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `crl` subcommand.
#[derive(Args, Debug)]
pub struct CrlArgs {}

impl CrlArgs {
    /// Execute the `crl` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
