//! `asn1parse` subcommand implementation.
//!
//! ASN.1 data parsing and display.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `asn1parse` subcommand.
#[derive(Args, Debug)]
pub struct Asn1parseArgs {}

impl Asn1parseArgs {
    /// Execute the `asn1parse` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
