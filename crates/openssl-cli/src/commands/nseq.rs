//! `nseq` subcommand implementation.
//!
//! Netscape certificate sequence conversion.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `nseq` subcommand.
#[derive(Args, Debug)]
pub struct NseqArgs {
}

impl NseqArgs {
    /// Execute the `nseq` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
