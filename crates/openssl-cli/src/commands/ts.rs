//! `ts` subcommand implementation.
//!
//! RFC 3161 Time Stamp Authority operations.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `ts` subcommand.
#[derive(Args, Debug)]
pub struct TsArgs {
}

impl TsArgs {
    /// Execute the `ts` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
