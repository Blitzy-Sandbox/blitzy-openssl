//! `ocsp` subcommand implementation.
//!
//! OCSP client and responder.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ocsp` subcommand.
#[derive(Args, Debug)]
pub struct OcspArgs {
}

impl OcspArgs {
    /// Execute the `ocsp` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
