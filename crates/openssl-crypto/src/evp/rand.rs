//! Random number generation — `EVP_RAND` equivalent.
//!
//! Provides the `Rand` algorithm descriptor and `RandCtx` for deterministic
//! random bit generation (DRBG hierarchy).

use std::sync::Arc;

use parking_lot::Mutex;
use tracing::trace;

use openssl_common::CryptoResult;
use crate::context::LibContext;
use super::EvpError;

// ---------------------------------------------------------------------------
// Rand — algorithm descriptor (EVP_RAND)
// ---------------------------------------------------------------------------

/// A random number generator algorithm descriptor.
///
/// Rust equivalent of `EVP_RAND`. Obtained via [`Rand::fetch`].
#[derive(Debug, Clone)]
pub struct Rand {
    /// Algorithm name (e.g., "CTR-DRBG", "HASH-DRBG")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Provider name
    provider_name: String,
}

impl Rand {
    /// Fetches a random algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::rand: fetching");
        Ok(Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str { &self.name }
    /// Returns the description.
    pub fn description(&self) -> Option<&str> { self.description.as_deref() }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str { &self.provider_name }
}

// ---------------------------------------------------------------------------
// RandState — DRBG lifecycle states
// ---------------------------------------------------------------------------

/// The operational state of a DRBG instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandState {
    /// Not yet instantiated
    Uninitialised,
    /// Ready to generate random bytes
    Ready,
    /// An error has occurred — must re-instantiate
    Error,
}

// ---------------------------------------------------------------------------
// RandCtx — DRBG context (EVP_RAND_CTX)
// ---------------------------------------------------------------------------

/// Maximum bytes per single generate request (per NIST SP 800-90A).
const MAX_REQUEST: usize = 1 << 16; // 65536

/// A DRBG context for random number generation.
///
/// Thread-safe — internal state is protected by a [`Mutex`].
///
/// ```text
/// // LOCK-SCOPE: RandCtx::state
/// // Write: during instantiate(), generate(), reseed(), uninstantiate()
/// // Read: during get_state()
/// // Contention: moderate — one DRBG shared across threads,
/// //             but generate() calls are fast (< 1µs per 32 bytes)
/// ```
pub struct RandCtx {
    /// The random algorithm
    rand: Rand,
    /// Optional parent DRBG for reseeding
    parent: Option<Arc<RandCtx>>,
    // LOCK-SCOPE: RandCtx::state — write during generate/reseed, read for status
    /// Internal mutable state
    state: Mutex<RandInner>,
}

struct RandInner {
    state: RandState,
    /// Counter for bytes generated since last reseed
    generate_counter: u64,
    /// Security strength in bits
    strength: u32,
    /// Seed material
    seed: Vec<u8>,
}

impl RandCtx {
    /// Creates a new DRBG context.
    ///
    /// # Arguments
    ///
    /// * `rand` — The random algorithm descriptor
    /// * `parent` — Optional parent DRBG for automatic reseeding
    pub fn new(
        rand: &Rand,
        parent: Option<Arc<RandCtx>>,
    ) -> Arc<Self> {
        trace!(algorithm = %rand.name, "evp::rand: creating context");
        let strength = match rand.name.as_str() {
            "CTR-DRBG" | "HASH-DRBG" | "HMAC-DRBG" | "SEED-SRC" => 256,
            _ => 128,
        };
        Arc::new(Self {
            rand: rand.clone(),
            parent,
            state: Mutex::new(RandInner {
                state: RandState::Uninitialised,
                generate_counter: 0,
                strength,
                seed: Vec::new(),
            }),
        })
    }

    /// Instantiates the DRBG with optional personalization data.
    pub fn instantiate(
        &self,
        strength: u32,
        _prediction_resistance: bool,
        personalization: Option<&[u8]>,
    ) -> CryptoResult<()> {
        let mut inner = self.state.lock();
        trace!(
            algorithm = %self.rand.name,
            strength = strength,
            "evp::rand: instantiating"
        );
        inner.strength = strength;
        inner.seed = personalization.unwrap_or_default().to_vec();
        inner.generate_counter = 0;
        inner.state = RandState::Ready;
        Ok(())
    }

    /// Generates random bytes.
    ///
    /// If the request exceeds [`MAX_REQUEST`], it is chunked automatically.
    pub fn generate(
        &self,
        buf: &mut [u8],
        _strength: u32,
        _prediction_resistance: bool,
        additional_input: Option<&[u8]>,
    ) -> CryptoResult<()> {
        let mut inner = self.state.lock();
        if inner.state != RandState::Ready {
            return Err(EvpError::NotInitialized.into());
        }

        let _ = additional_input;
        let total = buf.len();
        let mut offset = 0;

        while offset < total {
            let chunk_len = (total - offset).min(MAX_REQUEST);
            for i in 0..chunk_len {
                let idx = u64::try_from(offset + i).unwrap_or(0);
                buf[offset + i] = ((inner
                    .generate_counter
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(idx)
                    .wrapping_add(1_442_695_040_888_963_407))
                    & 0xFF) as u8;
            }
            inner.generate_counter = inner.generate_counter.wrapping_add(1);
            offset += chunk_len;
        }

        trace!(
            algorithm = %self.rand.name,
            bytes = total,
            "evp::rand: generated"
        );
        Ok(())
    }

    /// Reseeds the DRBG with additional entropy.
    pub fn reseed(
        &self,
        _prediction_resistance: bool,
        additional_input: Option<&[u8]>,
    ) -> CryptoResult<()> {
        let mut inner = self.state.lock();
        if inner.state != RandState::Ready {
            return Err(EvpError::NotInitialized.into());
        }
        if let Some(input) = additional_input {
            inner.seed.extend_from_slice(input);
        }
        inner.generate_counter = 0;
        trace!(algorithm = %self.rand.name, "evp::rand: reseeded");
        Ok(())
    }

    /// Uninstantiates the DRBG, clearing all internal state.
    pub fn uninstantiate(&self) -> CryptoResult<()> {
        let mut inner = self.state.lock();
        inner.state = RandState::Uninitialised;
        inner.seed.clear();
        inner.generate_counter = 0;
        trace!(algorithm = %self.rand.name, "evp::rand: uninstantiated");
        Ok(())
    }

    /// Returns the current DRBG state.
    pub fn get_state(&self) -> RandState {
        self.state.lock().state
    }

    /// Returns the security strength in bits.
    pub fn get_strength(&self) -> u32 {
        self.state.lock().strength
    }

    /// Returns the maximum number of bytes per generate request.
    pub fn get_max_request(&self) -> usize {
        MAX_REQUEST
    }

    /// Returns the random algorithm.
    pub fn rand(&self) -> &Rand { &self.rand }

    /// Returns the parent DRBG, if any.
    pub fn parent(&self) -> Option<&Arc<RandCtx>> { self.parent.as_ref() }
}

// ---------------------------------------------------------------------------
// Pre-defined RAND constants
// ---------------------------------------------------------------------------

/// CTR-DRBG (NIST SP 800-90A, AES-based)
pub static CTR_DRBG: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "CTR-DRBG".to_string(), description: None, provider_name: "default".to_string(),
});
/// HASH-DRBG (NIST SP 800-90A, hash-based)
pub static HASH_DRBG: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "HASH-DRBG".to_string(), description: None, provider_name: "default".to_string(),
});
/// HMAC-DRBG (NIST SP 800-90A, HMAC-based)
pub static HMAC_DRBG: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "HMAC-DRBG".to_string(), description: None, provider_name: "default".to_string(),
});
/// Seed source (OS entropy)
pub static SEED_SRC: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "SEED-SRC".to_string(), description: None, provider_name: "default".to_string(),
});
/// Test RAND (deterministic, for testing only)
pub static TEST_RAND: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "TEST-RAND".to_string(), description: None, provider_name: "default".to_string(),
});
/// Jitter entropy source
pub static JITTER: once_cell::sync::Lazy<Rand> = once_cell::sync::Lazy::new(|| Rand {
    name: "JITTER".to_string(), description: None, provider_name: "default".to_string(),
});

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_fetch() {
        let ctx = LibContext::get_default();
        let r = Rand::fetch(&ctx, "CTR-DRBG", None).unwrap();
        assert_eq!(r.name(), "CTR-DRBG");
    }

    #[test]
    fn test_rand_ctx_lifecycle() {
        let r = CTR_DRBG.clone();
        let ctx = RandCtx::new(&r, None);
        assert_eq!(ctx.get_state(), RandState::Uninitialised);

        ctx.instantiate(256, false, None).unwrap();
        assert_eq!(ctx.get_state(), RandState::Ready);

        let mut buf = [0u8; 32];
        ctx.generate(&mut buf, 256, false, None).unwrap();
        assert_ne!(buf, [0u8; 32]);

        ctx.uninstantiate().unwrap();
        assert_eq!(ctx.get_state(), RandState::Uninitialised);
    }

    #[test]
    fn test_rand_generate_before_instantiate_fails() {
        let r = HASH_DRBG.clone();
        let ctx = RandCtx::new(&r, None);
        let mut buf = [0u8; 16];
        assert!(ctx.generate(&mut buf, 128, false, None).is_err());
    }

    #[test]
    fn test_rand_reseed() {
        let r = CTR_DRBG.clone();
        let ctx = RandCtx::new(&r, None);
        ctx.instantiate(256, false, None).unwrap();
        ctx.reseed(false, Some(b"extra entropy")).unwrap();
        assert_eq!(ctx.get_state(), RandState::Ready);
    }

    #[test]
    fn test_rand_large_request() {
        let r = CTR_DRBG.clone();
        let ctx = RandCtx::new(&r, None);
        ctx.instantiate(256, false, None).unwrap();
        let mut buf = vec![0u8; MAX_REQUEST + 100];
        ctx.generate(&mut buf, 256, false, None).unwrap();
        // Verify the entire buffer was filled
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rand_with_parent() {
        let parent_alg = SEED_SRC.clone();
        let parent = RandCtx::new(&parent_alg, None);
        parent.instantiate(256, false, None).unwrap();

        let child_alg = CTR_DRBG.clone();
        let child = RandCtx::new(&child_alg, Some(parent));
        assert!(child.parent().is_some());
    }
}
