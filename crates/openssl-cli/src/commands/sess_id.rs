//! `sess_id` subcommand implementation.
//!
//! SSL/TLS session data management.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `sess_id` subcommand.
#[derive(Args, Debug)]
pub struct SessIdArgs {}

impl SessIdArgs {
    /// Execute the `sess_id` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
