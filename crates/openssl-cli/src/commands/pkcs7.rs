//! `pkcs7` subcommand implementation.
//!
//! PKCS#7 data processing.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkcs7` subcommand.
#[derive(Args, Debug)]
pub struct Pkcs7Args {}

impl Pkcs7Args {
    /// Execute the `pkcs7` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
