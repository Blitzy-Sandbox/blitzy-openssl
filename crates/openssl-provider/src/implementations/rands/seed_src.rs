//! OS Entropy Seed Source.
//!
//! Source: `providers/implementations/rands/seed_src.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use rand::rngs::OsRng;
use rand::RngCore;

/// Maximum security strength in bits.
pub const SEED_SRC_STRENGTH: u32 = 256;

/// Maximum number of bytes per request.
pub const SEED_SRC_MAX_REQUEST: usize = 1 << 16;

/// OS entropy seed source that provides true randomness from the
/// operating system via `getrandom(2)` / `CryptGenRandom`.
///
/// Implements [`RandContext`] directly (not wrapped by DRBG framework).
#[derive(Debug)]
pub struct SeedSource {
    /// Whether the source has been instantiated.
    instantiated: bool,
}

impl SeedSource {
    /// Creates a new OS entropy seed source.
    #[must_use]
    pub fn new() -> Self {
        Self { instantiated: false }
    }
}

impl Default for SeedSource {
    fn default() -> Self {
        Self::new()
    }
}

impl RandContext for SeedSource {
    fn instantiate(
        &mut self,
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        self.instantiated = true;
        Ok(())
    }

    fn generate(
        &mut self,
        output: &mut [u8],
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        if !self.instantiated {
            return Err(ProviderError::Init("SeedSource not instantiated".into()));
        }
        if output.len() > SEED_SRC_MAX_REQUEST {
            return Err(ProviderError::Dispatch(format!(
                "Requested {} bytes exceeds max {}",
                output.len(),
                SEED_SRC_MAX_REQUEST
            )));
        }
        OsRng.fill_bytes(output);
        Ok(())
    }

    fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        // OS entropy source is always fresh; reseed is a no-op.
        Ok(())
    }

    fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.instantiated = false;
        Ok(())
    }

    fn enable_locking(&mut self) -> ProviderResult<()> {
        // OsRng is inherently thread-safe.
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("state", ParamValue::Int32(i32::from(self.instantiated)));
        params.set("max_request", ParamValue::UInt64(SEED_SRC_MAX_REQUEST as u64));
        params.set("strength", ParamValue::UInt64(u64::from(SEED_SRC_STRENGTH)));
        Ok(params)
    }
}

/// Provider factory for OS entropy seed source instances.
pub struct SeedSourceProvider;

impl RandProvider for SeedSourceProvider {
    fn name(&self) -> &'static str {
        "SEED-SRC"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        Ok(Box::new(SeedSource::new()))
    }
}
