//! FIPS SP 800-90B Continuous RNG Health Test Wrapper.
//!
//! Source: `providers/implementations/rands/fips_crng_test.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

/// FIPS continuous RNG health test that wraps an underlying RNG
/// and applies continuous checks per SP 800-90B.
#[derive(Debug)]
pub struct CrngTest {
    /// Whether the test wrapper has been instantiated.
    instantiated: bool,
    /// Previous output block for comparison (continuous test).
    prev_block: Vec<u8>,
    /// Block size for the continuous test.
    block_size: usize,
}

impl CrngTest {
    /// Creates a new CRNG health test wrapper.
    #[must_use]
    pub fn new(block_size: usize) -> Self {
        Self {
            instantiated: false,
            prev_block: vec![0u8; block_size],
            block_size,
        }
    }
}

impl RandContext for CrngTest {
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
            return Err(ProviderError::Init("CrngTest not instantiated".into()));
        }
        // Fill from OS entropy for now (real impl wraps underlying DRBG)
        rand::rngs::OsRng.fill_bytes(output);

        // Continuous test: compare with previous block
        if output.len() >= self.block_size {
            let current_block = &output[..self.block_size];
            if current_block == self.prev_block.as_slice() {
                return Err(ProviderError::Dispatch(
                    "CRNG continuous test failure: repeated output block".into(),
                ));
            }
            self.prev_block[..self.block_size].copy_from_slice(current_block);
        }
        Ok(())
    }

    fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        Ok(())
    }

    fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.instantiated = false;
        self.prev_block.fill(0);
        Ok(())
    }

    fn enable_locking(&mut self) -> ProviderResult<()> {
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("state", ParamValue::Int32(i32::from(self.instantiated)));
        params.set("block_size", ParamValue::UInt64(self.block_size as u64));
        Ok(params)
    }
}

use rand::RngCore;

/// Provider factory for FIPS CRNG health test wrapper instances.
pub struct CrngTestProvider;

impl RandProvider for CrngTestProvider {
    fn name(&self) -> &'static str {
        "CRNG-TEST"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        Ok(Box::new(CrngTest::new(16)))
    }
}
