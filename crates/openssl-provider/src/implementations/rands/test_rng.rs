//! Deterministic Test RNG (xorshift32) for reproducible testing.
//!
//! Source: `providers/implementations/rands/test_rng.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

/// Deterministic test RNG using xorshift32.
///
/// Produces deterministic output from a fixed seed for reproducible test
/// scenarios. **Must never be used in production.**
#[derive(Debug)]
pub struct TestRng {
    /// Whether the RNG has been instantiated.
    instantiated: bool,
    /// Current xorshift32 state.
    state: u32,
    /// Initial seed for reset.
    seed: u32,
}

impl TestRng {
    /// Creates a new test RNG with a default seed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instantiated: false,
            state: 0x1234_5678,
            seed: 0x1234_5678,
        }
    }

    /// Creates a new test RNG with the specified seed.
    #[must_use]
    pub fn with_seed(seed: u32) -> Self {
        Self {
            instantiated: false,
            state: seed,
            seed,
        }
    }

    /// Xorshift32 step function.
    fn xorshift32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }
}

impl Default for TestRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RandContext for TestRng {
    fn instantiate(
        &mut self,
        _strength: u32,
        _prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        // Use additional input as seed if provided
        if additional.len() >= 4 {
            let seed = u32::from_le_bytes([
                additional[0],
                additional[1],
                additional[2],
                additional[3],
            ]);
            if seed != 0 {
                self.state = seed;
                self.seed = seed;
            }
        }
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
            return Err(ProviderError::Init("TestRng not instantiated".into()));
        }
        for chunk in output.chunks_mut(4) {
            let val = self.xorshift32();
            let bytes = val.to_le_bytes();
            let copy_len = chunk.len().min(4);
            chunk[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        Ok(())
    }

    fn reseed(
        &mut self,
        _prediction_resistance: bool,
        entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        // Mix entropy into state
        if entropy.len() >= 4 {
            let val = u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]]);
            self.state ^= val;
        }
        Ok(())
    }

    fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.instantiated = false;
        self.state = 0;
        Ok(())
    }

    fn enable_locking(&mut self) -> ProviderResult<()> {
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("state", ParamValue::Int32(i32::from(self.instantiated)));
        params.set("seed", ParamValue::UInt64(u64::from(self.seed)));
        Ok(params)
    }
}

/// Provider factory for deterministic test RNG instances.
pub struct TestRngProvider;

impl RandProvider for TestRngProvider {
    fn name(&self) -> &'static str {
        "TEST-RAND"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        Ok(Box::new(TestRng::new()))
    }
}
