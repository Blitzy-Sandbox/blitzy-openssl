//! `s_time` subcommand implementation.
//!
//! TLS connection timing benchmark.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `s_time` subcommand.
#[derive(Args, Debug)]
pub struct STimeArgs {}

impl STimeArgs {
    /// Execute the `s_time` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
