//! Deterministic Test RNG (xorshift32) for reproducible testing.
//!
//! Rust translation of `providers/implementations/rands/test_rng.c` (~300 lines).
//! Implements a deterministic provider RAND for reproducible testing that can
//! stream from pre-configured entropy/nonce buffers **or** generate via an
//! internal xorshift PRNG.
//!
//! # Operating Modes
//!
//! | Mode | `generate` flag | Byte source |
//! |------|-----------------|-------------|
//! | **Buffer** | `false` (default) | Pre-loaded entropy/nonce `Vec<u8>` buffers |
//! | **Generate** | `true` | Internal xorshift32 PRNG (Marsaglia algorithm) |
//!
//! # Security Warning
//!
//! This module is **NOT cryptographically secure**. It exists solely to enable
//! deterministic, reproducible test scenarios for the DRBG and provider
//! frameworks. It must **never** be used in production.
//!
//! # C Source Mapping
//!
//! | Rust Construct | C Construct | Location |
//! |----------------|-------------|----------|
//! | [`TestRng`] | `PROV_TEST_RNG` struct | `test_rng.c:30` |
//! | [`TestRng::gen_byte()`](TestRng::gen_byte) | `gen_byte()` | `test_rng.c:100` |
//! | [`TestRng::new()`] | `test_rng_new()` | `test_rng.c:51` |
//! | [`TestRng::instantiate()`] | `test_rng_instantiate()` | `test_rng.c:77` |
//! | [`TestRng::generate()`] | `test_rng_generate()` | `test_rng.c:115` |
//! | [`TestRng::nonce()`] | `test_rng_nonce()` | `test_rng.c:147` |
//! | [`TestRng::set_params()`] | `test_rng_set_ctx_params()` | `test_rng.c:211` |
//! | [`TestRng::get_params()`] | `test_rng_get_ctx_params()` | `test_rng.c:171` |
//! | [`TestRngProvider`] | `ossl_test_rng_functions[]` | `test_rng.c:305` |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All methods return `ProviderResult<T>` — no sentinel
//!   values (`0`, `-1`).
//! - **R6 (Lossless Casts):** Single `as u8` truncation in [`gen_byte()`](TestRng::gen_byte)
//!   documented with `// TRUNCATION:` justification.
//! - **R7 (Lock Granularity):** Optional `Mutex` field with `// LOCK-SCOPE:` annotation.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All public items documented with `///`.
//! - **R10 (Wiring):** Reachable via provider dispatch → `RandProvider` →
//!   `TestRngProvider` → `TestRng`.

// =============================================================================
// Imports
// =============================================================================

use crate::traits::{RandContext, RandProvider};
use super::drbg::RandState;
use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use parking_lot::Mutex;
use tracing::{debug, trace};
use zeroize::Zeroize;

// =============================================================================
// Constants
// =============================================================================

/// Initial xorshift32 seed set during [`TestRng::instantiate()`].
///
/// Matches the C value exactly: `"Value doesn't matter, so long as it isn't
/// zero"` — from `test_rng.c:92`.
const TEST_RNG_SEED: u32 = 221_953_166;

/// Default maximum bytes per [`TestRng::generate()`] call.
///
/// Matches the C `INT_MAX` default from `test_rng_new()`.
const DEFAULT_MAX_REQUEST: usize = 2_147_483_647;

// =============================================================================
// TestRng — Deterministic Test RNG Context
// =============================================================================

/// Deterministic test RNG for reproducible testing.
///
/// Can operate in two modes:
///
/// - **Buffer mode** (`generate = false`, default): Streams from pre-configured
///   entropy and nonce buffers set via [`set_params()`](Self::set_params).
///   Returns an error when the buffer is exhausted.
///
/// - **Generate mode** (`generate = true`): Uses an internal 32-bit xorshift
///   PRNG (Marsaglia's algorithm) seeded with [`TEST_RNG_SEED`] on
///   [`instantiate()`](Self::instantiate).
///
/// # Security Warning
///
/// This is **NOT** cryptographically secure. It exists solely for deterministic
/// testing of the DRBG and provider frameworks.
///
/// # C Mapping
///
/// Replaces the C `PROV_TEST_RNG` struct from `test_rng.c`.
#[derive(Debug)]
pub struct TestRng {
    /// DRBG lifecycle state: `Uninitialised` → `Ready` on instantiate,
    /// back to `Uninitialised` on uninstantiate.
    state: RandState,

    /// Operation mode flag.
    ///
    /// - `true` — xorshift PRNG mode (generate bytes via [`gen_byte()`](Self::gen_byte))
    /// - `false` — buffer mode (stream from pre-loaded entropy)
    generate: bool,

    /// Configured security strength in bits.
    ///
    /// Set via [`set_params()`](Self::set_params) before
    /// [`instantiate()`](Self::instantiate). Generate requests with a
    /// higher strength will be rejected.
    strength: u32,

    /// Maximum bytes per [`generate()`](Self::generate) call.
    ///
    /// Defaults to [`DEFAULT_MAX_REQUEST`] (`i32::MAX`), matching the C
    /// `INT_MAX` default.
    max_request: usize,

    /// Pre-loaded entropy buffer for buffer mode.
    ///
    /// Set via [`set_params()`](Self::set_params) with key `"entropy"`.
    entropy: Vec<u8>,

    /// Current read position within the entropy buffer.
    ///
    /// Reset to `0` on [`instantiate()`](Self::instantiate).
    entropy_pos: usize,

    /// Pre-loaded nonce buffer for buffer mode.
    ///
    /// Set via [`set_params()`](Self::set_params) with key `"nonce"`.
    nonce: Option<Vec<u8>>,

    /// 32-bit xorshift PRNG state (Marsaglia algorithm).
    ///
    /// Initialised to [`TEST_RNG_SEED`] on [`instantiate()`](Self::instantiate).
    seed: u32,

    /// Optional per-instance mutex for thread-safe access.
    ///
    // LOCK-SCOPE: Protects TestRng mutable state during concurrent access.
    // Low contention — test RNG is typically used in single-threaded test
    // contexts. Created lazily by enable_locking(). Replaces the C
    // CRYPTO_RWLOCK from test_rng.c.
    lock: Option<Mutex<()>>,
}

// =============================================================================
// TestRng — Core Implementation
// =============================================================================

impl TestRng {
    /// Creates a new uninitialised test RNG instance.
    ///
    /// The returned context is in [`RandState::Uninitialised`] state and must
    /// be configured via [`set_params()`](Self::set_params) and then
    /// [`instantiate()`](Self::instantiate)d before use.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_new()` from `test_rng.c`.
    #[must_use]
    pub fn new() -> Self {
        debug!("creating new TestRng context");
        Self {
            state: RandState::Uninitialised,
            generate: false,
            strength: 0,
            max_request: DEFAULT_MAX_REQUEST,
            entropy: Vec::new(),
            entropy_pos: 0,
            nonce: None,
            seed: 0,
            lock: None,
        }
    }

    /// Generates one pseudo-random byte using the 32-bit xorshift algorithm.
    ///
    /// Reference: George Marsaglia, "Xorshift RNGs", *Journal of Statistical
    /// Software* 8(14), 2003. `doi:10.18637/jss.v008.i14`.
    ///
    /// The algorithm performs three XOR-shift operations on the 32-bit state:
    ///
    /// ```text
    /// n ^= n << 13
    /// n ^= n >> 17
    /// n ^= n << 5
    /// ```
    ///
    /// and returns the low byte of the result.
    ///
    /// # C Mapping
    ///
    /// Replaces `gen_byte()` from `test_rng.c:100`.
    #[allow(clippy::cast_possible_truncation)]
    fn gen_byte(&mut self) -> u8 {
        let mut n = self.seed;
        n ^= n << 13;
        n ^= n >> 17;
        n ^= n << 5;
        self.seed = n;
        trace!(seed = n, byte = n & 0xff, "xorshift32 gen_byte");
        // TRUNCATION: intentional extraction of low byte per xorshift algorithm
        // spec. (n & 0xff) is guaranteed to be in range 0..=255, fitting in u8.
        (n & 0xff) as u8
    }

    /// Instantiates the test RNG, transitioning from `Uninitialised` to `Ready`.
    ///
    /// - Validates that the requested `strength` does not exceed the
    ///   configured [`self.strength`].
    /// - Resets the entropy buffer read position to zero.
    /// - Seeds the xorshift PRNG with [`TEST_RNG_SEED`] (`221953166`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if `strength` exceeds the configured
    /// maximum.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_instantiate()` from `test_rng.c:77`.
    pub fn instantiate(
        &mut self,
        strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        if strength > self.strength {
            return Err(ProviderError::Init(format!(
                "requested strength {} exceeds configured maximum {}",
                strength, self.strength
            )));
        }
        self.state = RandState::Ready;
        self.entropy_pos = 0;
        // Value doesn't matter, so long as it isn't zero (matching C exactly).
        self.seed = TEST_RNG_SEED;
        debug!(
            seed = TEST_RNG_SEED,
            strength = self.strength,
            generate = self.generate,
            "test RNG instantiated"
        );
        Ok(())
    }

    /// Uninstantiates the test RNG, resetting state to `Uninitialised`.
    ///
    /// Resets the entropy buffer read position and transitions the state
    /// back to [`RandState::Uninitialised`].
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_uninstantiate()` from `test_rng.c:96`.
    pub fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.entropy_pos = 0;
        self.state = RandState::Uninitialised;
        debug!("test RNG uninstantiated");
        Ok(())
    }

    /// Generates random bytes into `output`.
    ///
    /// In **generate mode** (`self.generate == true`), fills `output` with
    /// bytes from the xorshift PRNG via [`gen_byte()`](Self::gen_byte).
    ///
    /// In **buffer mode** (`self.generate == false`), copies bytes from the
    /// pre-loaded entropy buffer, advancing the internal read position.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Common(CommonError::NotInitialized)`] if the RNG
    ///   has not been instantiated.
    /// - [`ProviderError::Init`] if the requested `strength` exceeds the
    ///   configured maximum.
    /// - [`ProviderError::Common(CommonError::Internal)`] if the entropy
    ///   buffer is exhausted in buffer mode.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_generate()` from `test_rng.c:115`.
    pub fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        if self.state != RandState::Ready {
            return Err(ProviderError::Common(CommonError::NotInitialized(
                "test RNG is not instantiated",
            )));
        }
        if strength > self.strength {
            return Err(ProviderError::Init(format!(
                "requested strength {} exceeds configured strength {}",
                strength, self.strength
            )));
        }
        if self.generate {
            // Xorshift mode: fill output byte-by-byte via gen_byte().
            for byte in output.iter_mut() {
                *byte = self.gen_byte();
            }
            trace!(len = output.len(), mode = "xorshift", "generate");
        } else {
            // Buffer mode: stream from pre-loaded entropy.
            let remaining = self.entropy.len().saturating_sub(self.entropy_pos);
            if output.len() > remaining {
                return Err(ProviderError::Common(CommonError::Internal(format!(
                    "entropy buffer exhausted: requested {} bytes, only {} remaining",
                    output.len(),
                    remaining,
                ))));
            }
            let end = self.entropy_pos + output.len();
            output.copy_from_slice(&self.entropy[self.entropy_pos..end]);
            self.entropy_pos = end;
            trace!(
                len = output.len(),
                pos = self.entropy_pos,
                remaining = self.entropy.len().saturating_sub(self.entropy_pos),
                mode = "buffer",
                "generate"
            );
        }
        Ok(())
    }

    /// Reseeds the test RNG (no-op, always succeeds).
    ///
    /// The test RNG does not support reseeding — this is a deliberate no-op
    /// matching the C `test_rng_reseed()` which always returns `1`.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_reseed()` from `test_rng.c:142`.
    pub fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        trace!("test RNG reseed (no-op)");
        Ok(())
    }

    /// Generates a nonce from the xorshift PRNG or pre-loaded nonce buffer.
    ///
    /// In **generate mode**, fills `min_len` bytes via
    /// [`gen_byte()`](Self::gen_byte).
    ///
    /// In **buffer mode**, returns up to `max_len` bytes from the pre-loaded
    /// nonce buffer.
    ///
    /// # Parameters
    ///
    /// - `_strength` — Minimum security strength (currently unused by test RNG).
    /// - `min_len` — Minimum nonce length (used in generate mode).
    /// - `max_len` — Maximum nonce length (used to cap buffer mode output).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common(CommonError::Internal)`] if no nonce
    /// data is available in buffer mode.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_nonce()` from `test_rng.c:147`.
    pub fn nonce(
        &mut self,
        _strength: u32,
        min_len: usize,
        max_len: usize,
    ) -> ProviderResult<Vec<u8>> {
        if self.generate {
            // Xorshift mode: generate min_len bytes deterministically.
            let mut buf = vec![0u8; min_len];
            for byte in &mut buf {
                *byte = self.gen_byte();
            }
            trace!(len = min_len, mode = "xorshift", "nonce generated");
            Ok(buf)
        } else {
            // Buffer mode: return from pre-loaded nonce buffer.
            match &self.nonce {
                Some(nonce_buf) if !nonce_buf.is_empty() => {
                    let len = nonce_buf.len().min(max_len);
                    let result = nonce_buf[..len].to_vec();
                    trace!(len, mode = "buffer", "nonce generated");
                    Ok(result)
                }
                _ => Err(ProviderError::Common(CommonError::Internal(
                    "no nonce data available in buffer mode".into(),
                ))),
            }
        }
    }

    /// Sets context parameters for the test RNG.
    ///
    /// Accepted parameter keys:
    ///
    /// | Key | Type | Description |
    /// |-----|------|-------------|
    /// | `"strength"` | `UInt32` | Security strength in bits |
    /// | `"entropy"` | `OctetString` | Pre-loaded entropy buffer (buffer mode) |
    /// | `"nonce"` | `OctetString` | Pre-loaded nonce buffer (buffer mode) |
    /// | `"max_request"` | `UInt32` / `UInt64` | Max bytes per generate call |
    /// | `"generate"` | `UInt32` | `0` = buffer mode, non-zero = xorshift mode |
    ///
    /// Unknown keys are silently ignored (matching C `test_rng_set_ctx_params`
    /// behaviour).
    ///
    /// # Errors
    ///
    /// Returns a type-mismatch error (via `get_typed`) if a recognised key
    /// has the wrong [`ParamValue`] variant.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_set_ctx_params()` from `test_rng.c:211`.
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.contains("strength") {
            self.strength = params.get_typed::<u32>("strength")?;
            trace!(strength = self.strength, "set strength");
        }
        if params.contains("entropy") {
            if let Some(val) = params.get("entropy") {
                let bytes = val.as_bytes().ok_or_else(|| {
                    CommonError::ParamTypeMismatch {
                        key: "entropy".to_string(),
                        expected: "OctetString",
                        actual: val.param_type_name(),
                    }
                })?;
                self.entropy = bytes.to_vec();
                self.entropy_pos = 0;
                trace!(len = self.entropy.len(), "set entropy buffer");
            }
        }
        if params.contains("nonce") {
            if let Some(val) = params.get("nonce") {
                let bytes = val.as_bytes().ok_or_else(|| {
                    CommonError::ParamTypeMismatch {
                        key: "nonce".to_string(),
                        expected: "OctetString",
                        actual: val.param_type_name(),
                    }
                })?;
                self.nonce = Some(bytes.to_vec());
                trace!(len = bytes.len(), "set nonce buffer");
            }
        }
        if params.contains("max_request") {
            if let Some(val) = params.get("max_request") {
                // C uses OSSL_PARAM_get_size_t. Accept both UInt32 and UInt64
                // for flexibility, then convert to usize.
                let max_req = if let Some(v) = val.as_u64() {
                    usize::try_from(v).unwrap_or(usize::MAX)
                } else if let Some(v) = val.as_u32() {
                    usize::try_from(v).unwrap_or(usize::MAX)
                } else {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: "max_request".to_string(),
                        expected: "UInt32 or UInt64",
                        actual: val.param_type_name(),
                    }));
                };
                self.max_request = max_req;
                trace!(max_request = self.max_request, "set max_request");
            }
        }
        if params.contains("generate") {
            let gen_val: u32 = params.get_typed::<u32>("generate")?;
            self.generate = gen_val != 0;
            trace!(generate = self.generate, "set generate flag");
        }
        Ok(())
    }

    /// Retrieves context parameters (state, strength, `max_request`, generate).
    ///
    /// Returns a [`ParamSet`] containing:
    ///
    /// | Key | Type | Value |
    /// |-----|------|-------|
    /// | `"state"` | `Int32` | `0` = Uninitialised, `1` = Ready, `2` = Error |
    /// | `"strength"` | `UInt32` | Configured security strength (bits) |
    /// | `"max_request"` | `UInt32` | Max bytes per generate call |
    /// | `"generate"` | `UInt32` | `0` = buffer mode, `1` = xorshift mode |
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_get_ctx_params()` from `test_rng.c:171`.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();

        // State as integer: matches C EVP_RAND_STATE_* constants.
        let state_val: i32 = match self.state {
            RandState::Uninitialised => 0,
            RandState::Ready => 1,
            RandState::Error => 2,
        };
        params.set("state", ParamValue::Int32(state_val));
        params.set("strength", ParamValue::UInt32(self.strength));
        // max_request stored as UInt32 for compatibility with C OSSL_PARAM
        // get_uint (the C type is size_t but OSSL_PARAM reports it as uint).
        // We clamp to u32::MAX if the value exceeds it (only on 64-bit where
        // usize > u32::MAX is possible).
        let max_req_u32 = u32::try_from(self.max_request).unwrap_or(u32::MAX);
        params.set("max_request", ParamValue::UInt32(max_req_u32));
        params.set("generate", ParamValue::UInt32(u32::from(self.generate)));

        trace!(
            state = ?self.state,
            strength = self.strength,
            max_request = self.max_request,
            generate = self.generate,
            "get_params"
        );
        Ok(params)
    }

    /// Enables per-instance locking for thread-safe access.
    ///
    /// Creates a [`Mutex`] if one does not already exist. Subsequent calls
    /// are no-ops. In the Rust implementation, `&mut self` already guarantees
    /// exclusive access at the language level; the lock exists for structural
    /// parity with the C implementation and for potential use by external
    /// wrappers that share the context via `Arc<Mutex<TestRng>>`.
    ///
    /// # C Mapping
    ///
    /// Replaces `test_rng_enable_locking()` from `test_rng.c:287`.
    pub fn enable_locking(&mut self) -> ProviderResult<()> {
        if self.lock.is_none() {
            // LOCK-SCOPE: Creates a per-TestRng mutex for thread-safe
            // concurrent access. Low contention — test RNG is typically
            // used in single-threaded test contexts. Replaces C
            // CRYPTO_THREAD_lock_new() from test_rng.c.
            self.lock = Some(Mutex::new(()));
            debug!("test RNG locking enabled");
        }
        Ok(())
    }
}

// =============================================================================
// Default — Provide idiomatic default construction
// =============================================================================

impl Default for TestRng {
    /// Creates a new uninitialised test RNG (delegates to [`TestRng::new()`]).
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Zeroize — Secure Memory Cleanup
// =============================================================================

/// Secure zeroing of all sensitive test material.
///
/// Ensures that entropy buffers, nonce data, and the xorshift seed do not
/// persist in memory after the test RNG is freed. Replaces the C pattern of
/// `OPENSSL_free()` + `OPENSSL_cleanse()` in `test_rng_free()` from
/// `test_rng.c`.
///
/// Per AAP §0.7.6 and Rule R8: zero `unsafe` code.
impl Zeroize for TestRng {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
        if let Some(ref mut nonce_buf) = self.nonce {
            nonce_buf.zeroize();
        }
        self.nonce = None;
        self.seed.zeroize();
        self.entropy_pos = 0;
        self.strength = 0;
        self.max_request = 0;
        self.generate = false;
        self.state = RandState::Uninitialised;
    }
}

/// Drop implementation that securely zeroes all sensitive state before
/// deallocation.
///
/// Replaces `test_rng_free()` from `test_rng.c` which calls
/// `OPENSSL_free()` and `OPENSSL_cleanse()` on key material.
impl Drop for TestRng {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// RandContext — Trait Implementation
// =============================================================================

/// Implements the [`RandContext`] trait for the deterministic test RNG.
///
/// Each trait method delegates to the corresponding inherent method on
/// [`TestRng`]. The `&mut self` receiver already guarantees exclusive access
/// at the language level, so internal lock acquisition is unnecessary.
///
/// This trait implementation replaces the C `ossl_test_rng_functions[]`
/// dispatch table from `test_rng.c:305`.
impl RandContext for TestRng {
    /// Instantiates the test RNG (see [`TestRng::instantiate()`]).
    fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        TestRng::instantiate(self, strength, prediction_resistance, additional)
    }

    /// Generates random bytes (see [`TestRng::generate()`]).
    fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        TestRng::generate(self, output, strength, prediction_resistance, additional)
    }

    /// Reseeds the test RNG — no-op (see [`TestRng::reseed()`]).
    fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: &[u8],
        additional: &[u8],
    ) -> ProviderResult<()> {
        TestRng::reseed(self, prediction_resistance, entropy, additional)
    }

    /// Uninstantiates the test RNG (see [`TestRng::uninstantiate()`]).
    fn uninstantiate(&mut self) -> ProviderResult<()> {
        TestRng::uninstantiate(self)
    }

    /// Enables locking (see [`TestRng::enable_locking()`]).
    fn enable_locking(&mut self) -> ProviderResult<()> {
        TestRng::enable_locking(self)
    }

    /// Retrieves context parameters (see [`TestRng::get_params()`]).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        TestRng::get_params(self)
    }
}

// =============================================================================
// TestRngProvider — Provider Factory
// =============================================================================

/// Provider factory for deterministic test RNG instances.
///
/// Implements [`RandProvider`] to create [`TestRng`] contexts on demand.
/// The provider is registered with algorithm name `"TEST-RAND"`, matching
/// the C `ossl_test_rng_functions[]` dispatch table entry.
///
/// # Wiring (Rule R10)
///
/// Reachable via: default provider → algorithm dispatch → `RandProvider::new_ctx()`
/// → `TestRngProvider::new_ctx()` → `TestRng::new()`.
pub struct TestRngProvider;

impl RandProvider for TestRngProvider {
    /// Returns the canonical algorithm name: `"TEST-RAND"`.
    fn name(&self) -> &'static str {
        "TEST-RAND"
    }

    /// Creates a new [`TestRng`] context wrapped in a boxed trait object.
    ///
    /// The returned context is in [`RandState::Uninitialised`] state and
    /// must be configured via parameter setting and then instantiated.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        debug!("creating new TEST-RAND context via provider");
        Ok(Box::new(TestRng::new()))
    }
}
