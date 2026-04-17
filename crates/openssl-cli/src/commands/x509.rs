//! `x509` subcommand implementation.
//!
//! X.509 certificate display, signing, and conversion.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `x509` subcommand.
#[derive(Args, Debug)]
pub struct X509Args {
}

impl X509Args {
    /// Execute the `x509` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
