//! `fipsinstall` subcommand implementation.
//!
//! FIPS module installation and configuration.

use clap::Args;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

/// Arguments for the `fipsinstall` subcommand.
#[derive(Args, Debug)]
pub struct FipsinstallArgs {}

impl FipsinstallArgs {
    /// Execute the `fipsinstall` subcommand.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        Ok(())
    }
}
