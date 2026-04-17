//! `pkcs8` subcommand implementation.
//!
//! PKCS#8 private key conversion.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkcs8` subcommand.
#[derive(Args, Debug)]
pub struct Pkcs8Args {
}

impl Pkcs8Args {
    /// Execute the `pkcs8` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
