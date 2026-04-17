//! `crl2pkcs7` subcommand implementation.
//!
//! Package CRL/certs into PKCS#7.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `crl2pkcs7` subcommand.
#[derive(Args, Debug)]
pub struct Crl2pkcs7Args {
}

impl Crl2pkcs7Args {
    /// Execute the `crl2pkcs7` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
