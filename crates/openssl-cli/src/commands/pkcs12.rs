//! `pkcs12` subcommand implementation.
//!
//! PKCS#12 file operations.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkcs12` subcommand.
#[derive(Args, Debug)]
pub struct Pkcs12Args {}

impl Pkcs12Args {
    /// Execute the `pkcs12` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
