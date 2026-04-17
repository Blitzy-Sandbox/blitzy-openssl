//! `pkeyparam` subcommand implementation.
//!
//! Algorithm parameter round-trip.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `pkeyparam` subcommand.
#[derive(Args, Debug)]
pub struct PkeyparamArgs {}

impl PkeyparamArgs {
    /// Execute the `pkeyparam` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
