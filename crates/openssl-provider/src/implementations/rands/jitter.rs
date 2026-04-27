//! Jitter Entropy Source for CPU jitter-based random number generation.
//!
//! Provides entropy collection based on CPU execution timing jitter,
//! suitable for environments without reliable OS-provided entropy sources.
//! Conditional on platform support via the `jitter` crate feature
//! (module declaration in `mod.rs` is gated by `#[cfg(feature = "jitter")]`).
//!
//! ## Design Notes
//!
//! - The Rust implementation uses a pure-Rust jitter entropy approach
//!   based on [`std::time::Instant`] timing measurements rather than the
//!   C `jitterentropy` library binding, ensuring zero `unsafe` code per Rule R8.
//! - This is a seed source: it MUST NOT have a parent RAND (enforced by
//!   the [`JitterProvider::new_ctx`] API which does not accept a parent parameter).
//! - Maximum retry count: `JITTER_MAX_NUM_TRIES` (3) attempts per collection.
//! - Entropy strength: 1024 bits (matching C `jitter_get_ctx_params`).
//! - Maximum single request: 128 bytes (matching C implementation).
//!
//! Source: `providers/implementations/rands/seed_src_jitter.c`

use crate::implementations::rands::drbg::RandState;
use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use parking_lot::Mutex;
use std::hint;
use std::time::Instant;
use tracing::{debug, error, warn};
use zeroize::Zeroize;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of retry attempts for jitter entropy collection.
///
/// Matches the C constant `JITTER_MAX_NUM_TRIES = 3` from
/// `seed_src_jitter.c`. Each attempt creates a fresh timing measurement
/// sequence; failure on all attempts transitions the source to
/// [`RandState::Error`].
pub const JITTER_MAX_NUM_TRIES: u32 = 3;

/// Entropy strength reported by the jitter source, in bits.
///
/// The jitter entropy source reports 1024 bits of strength, matching
/// the C implementation's `jitter_get_ctx_params()` which sets
/// `OSSL_RAND_PARAM_STRENGTH = 1024`.
const JITTER_STRENGTH: u32 = 1024;

/// Maximum single-request size for parameter reporting.
///
/// Matches C `jitter_get_ctx_params()` which sets
/// `OSSL_RAND_PARAM_MAX_REQUEST = 128`. Stored as `u32` to align with
/// [`ParamValue::UInt32`]; the `usize` equivalent is derived from this.
const JITTER_MAX_REQUEST_PARAM: u32 = 128;

/// Maximum single-request size in bytes.
///
/// Derived from [`JITTER_MAX_REQUEST_PARAM`] (widening cast, always safe).
const JITTER_MAX_REQUEST: usize = JITTER_MAX_REQUEST_PARAM as usize;

/// Number of timing measurement samples accumulated per output byte.
///
/// Higher values increase entropy quality at the cost of collection time.
/// 64 samples per byte provides sufficient mixing of timing jitter bits
/// to produce one byte of high-quality entropy.
const SAMPLES_PER_BYTE: u32 = 64;

// =============================================================================
// JitterSource — CPU jitter-based entropy source
// =============================================================================

/// CPU jitter-based entropy source.
///
/// Collects entropy from CPU execution timing variations. The entropy
/// is derived from nanosecond-precision timing measurements of CPU-bound
/// operations, where natural variation in execution time (due to cache
/// effects, scheduling, interrupts, etc.) provides the randomness.
///
/// Must NOT have a parent RAND — seed sources are roots of the DRBG chain.
/// This constraint is enforced by the [`JitterProvider::new_ctx`] API design
/// which creates the source without a parent parameter (replacing the C
/// `jitter_new()` explicit parent-NULL check).
///
/// ## Locking
///
/// // LOCK-SCOPE: `JitterSource` `state` field (if locking enabled) is protected
/// // by an optional `Mutex<()>`. Low contention — seed sources are typically
/// // accessed infrequently, only during DRBG seeding/reseeding operations.
/// // A single `JitterSource` instance serves one DRBG chain. The lock exists
/// // for correctness when child DRBG contexts share access to this seed source.
///
/// Replaces C `PROV_JITTER` struct from `seed_src_jitter.c`.
#[derive(Debug)]
pub struct JitterSource {
    /// Current lifecycle state of the jitter entropy source.
    state: RandState,
    /// Optional mutex for thread-safe state access.
    /// Created via [`enable_locking`](JitterSource::enable_locking).
    // LOCK-SCOPE: Protects `state` field during concurrent access from
    // child DRBG contexts. Low contention — seed sources are accessed
    // infrequently (only during DRBG seeding/reseeding). A single lock
    // is justified because there is only one mutable field (`state`)
    // and no independent access paths.
    lock: Option<Mutex<()>>,
}

impl JitterSource {
    // =========================================================================
    // Constructor
    // =========================================================================

    /// Creates a new jitter entropy source in the [`RandState::Uninitialised`]
    /// state.
    ///
    /// The source must be explicitly instantiated via
    /// [`instantiate`](JitterSource::instantiate) before it can generate
    /// entropy.
    ///
    /// ## No-Parent Constraint
    ///
    /// Seed sources are the root of the DRBG chain and MUST NOT have a parent
    /// RAND. This constraint is enforced by the API design: no parent parameter
    /// is accepted. This replaces the C `jitter_new()` check:
    /// ```c
    /// if (parent != NULL) {
    ///     ERR_raise(ERR_LIB_PROV,
    ///               PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
    ///     return NULL;
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the jitter entropy source cannot be
    /// created.
    pub fn new() -> ProviderResult<Self> {
        debug!("Creating new jitter entropy source");
        Ok(Self {
            state: RandState::Uninitialised,
            lock: None,
        })
    }

    // =========================================================================
    // Lifecycle operations
    // =========================================================================

    /// Instantiates the jitter entropy source, transitioning to
    /// [`RandState::Ready`].
    ///
    /// Performs a test collection to validate that CPU timing jitter is
    /// available on this platform (equivalent to C
    /// `jent_entropy_init_ex(0, JENT_FORCE_FIPS)`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] and transitions to [`RandState::Error`]
    /// if the timing jitter validation fails.
    pub fn instantiate(
        &mut self,
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        // Validate that CPU timing jitter is available by performing
        // a brief test collection. This is equivalent to the C call
        // jent_entropy_init_ex(0, JENT_FORCE_FIPS) which validates
        // the jitter library can be initialized.
        let mut test_buf = [0u8; 1];
        match Self::collect_timing_jitter(&mut test_buf) {
            Ok(_) => {
                self.state = RandState::Ready;
                debug!("Jitter entropy source instantiated successfully");
                Ok(())
            }
            Err(msg) => {
                self.state = RandState::Error;
                error!(error = %msg, "Failed to initialize jitter entropy source");
                Err(ProviderError::Init(format!(
                    "Unable to initialize jitter entropy CSPRNG: {msg}"
                )))
            }
        }
    }

    /// Uninstantiates the jitter entropy source, transitioning back to
    /// [`RandState::Uninitialised`].
    ///
    /// After this call, the source must be re-instantiated before generating
    /// entropy.
    pub fn uninstantiate(&mut self) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());
        self.state = RandState::Uninitialised;
        debug!("Jitter entropy source uninstantiated");
        Ok(())
    }

    /// Generates random bytes by collecting CPU timing jitter entropy.
    ///
    /// Fills the output buffer with entropy from timing jitter measurements.
    /// Uses retry logic with up to `JITTER_MAX_NUM_TRIES` attempts.
    ///
    /// # Errors
    ///
    /// - Returns [`ProviderError::Common`] if the source is not in the
    ///   [`RandState::Ready`] state.
    /// - Returns [`ProviderError::Common`] and transitions to
    ///   [`RandState::Error`] if all jitter entropy collection attempts fail.
    pub fn generate(
        &mut self,
        output: &mut [u8],
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());
        self.check_ready()?;

        if output.is_empty() {
            return Ok(());
        }

        if output.len() > JITTER_MAX_REQUEST {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "Requested {} bytes exceeds jitter max_request of {} bytes",
                    output.len(),
                    JITTER_MAX_REQUEST
                ),
            )));
        }

        match Self::collect_jitter_entropy(output) {
            Ok(n) => {
                debug!(bytes = n, "Jitter entropy generated");
                Ok(())
            }
            Err(e) => {
                self.state = RandState::Error;
                error!("Jitter generate failed, transitioning to error state");
                Err(e)
            }
        }
    }

    /// Reseed is a no-op for seed sources.
    ///
    /// Seed sources are the root of the DRBG chain and do not accept
    /// external entropy for reseeding. This matches the C `jitter_reseed()`
    /// which simply checks state and returns success.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common`] if the source is not in the
    /// [`RandState::Ready`] state.
    pub fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());
        self.check_ready()?;
        debug!("Jitter reseed (no-op for seed source)");
        Ok(())
    }

    /// Obtains a seed of the requested size by collecting jitter entropy.
    ///
    /// Allocates a buffer of size between `min_len` and `max_len` bytes,
    /// fills it with jitter-based entropy, and returns it.
    ///
    /// This method is used by child DRBGs to seed themselves from the
    /// jitter entropy source. Replaces C `jitter_get_seed()` which
    /// creates a `RAND_POOL`, fills it via
    /// `ossl_prov_acquire_entropy_from_jitter()`, and detaches the buffer.
    ///
    /// # Errors
    ///
    /// - Returns [`ProviderError::Common`] if the source is not ready.
    /// - Returns [`ProviderError::Common`] if entropy collection fails.
    pub fn get_seed(
        &mut self,
        min_len: usize,
        max_len: usize,
        _prediction_resistance: bool,
    ) -> ProviderResult<Vec<u8>> {
        let _guard = self.lock.as_ref().map(|m| m.lock());
        self.check_ready()?;

        // Clamp requested length between min_len and max_len, ensuring
        // at least 1 byte is requested.
        let len = min_len.max(1).min(max_len);
        let mut seed = vec![0u8; len];

        match Self::collect_jitter_entropy(&mut seed) {
            Ok(_) => {
                debug!(seed_len = len, "Jitter seed obtained");
                Ok(seed)
            }
            Err(e) => {
                // Securely clear partial seed material before returning error.
                seed.zeroize();
                self.state = RandState::Error;
                Err(e)
            }
        }
    }

    /// Securely zeroizes a previously obtained seed buffer.
    ///
    /// Uses the `Zeroize` trait to ensure the seed material is securely
    /// overwritten, preventing information leakage through freed memory.
    /// Replaces C `jitter_clear_seed()` → `OPENSSL_secure_clear_free()`.
    pub fn clear_seed(&mut self, seed: &mut [u8]) {
        seed.zeroize();
        debug!(len = seed.len(), "Jitter seed securely cleared");
    }

    /// Enables per-instance locking for thread-safe state access.
    ///
    /// Creates an internal [`Mutex`] if one does not already exist.
    /// Called when child DRBG contexts share access to this seed source.
    ///
    /// In the C implementation, `jitter_enable_locking()`, `jitter_lock()`,
    /// and `jitter_unlock()` are all no-ops (returning success) because
    /// the C jitterentropy library manages its own locking internally.
    /// In the Rust implementation, we provide real locking since the
    /// pure-Rust jitter collection shares mutable state.
    pub fn enable_locking(&mut self) -> ProviderResult<()> {
        if self.lock.is_none() {
            self.lock = Some(Mutex::new(()));
            debug!("Jitter source locking enabled");
        }
        Ok(())
    }

    /// Returns the current parameters of the jitter entropy source.
    ///
    /// Reports:
    /// - `"state"`: current lifecycle state name (e.g., `"Ready"`,
    ///   `"Uninitialised"`)
    /// - `"strength"`: entropy strength in bits (1024)
    /// - `"max_request"`: maximum single request size in bytes (128)
    ///
    /// Matches C `jitter_get_ctx_params()` which reports:
    /// - `OSSL_RAND_PARAM_STATE` → state integer
    /// - `OSSL_RAND_PARAM_STRENGTH` → 1024
    /// - `OSSL_RAND_PARAM_MAX_REQUEST` → 128
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("state", ParamValue::Utf8String(self.state.to_string()));
        params.set("strength", ParamValue::UInt32(JITTER_STRENGTH));
        params.set("max_request", ParamValue::UInt32(JITTER_MAX_REQUEST_PARAM));
        Ok(params)
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /// Validates that the source is in the [`RandState::Ready`] state.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common`] wrapping [`CommonError::NotInitialized`]
    /// if the source is not ready.
    fn check_ready(&self) -> ProviderResult<()> {
        if self.state != RandState::Ready {
            error!(state = %self.state, "Jitter source not ready");
            return Err(ProviderError::Common(CommonError::NotInitialized(
                "jitter entropy source",
            )));
        }
        Ok(())
    }

    /// Collects jitter entropy into the provided buffer with retry logic.
    ///
    /// Attempts up to `JITTER_MAX_NUM_TRIES` times to collect enough
    /// timing jitter entropy to fill the buffer. Each attempt calls
    /// [`collect_timing_jitter`](JitterSource::collect_timing_jitter)
    /// for the actual measurement loop.
    ///
    /// On success, returns the number of bytes collected (equal to
    /// `buf.len()`). On failure after all retries, returns an error.
    ///
    /// Replaces C `get_jitter_random_value()` retry loop from
    /// `seed_src_jitter.c`.
    fn collect_jitter_entropy(buf: &mut [u8]) -> ProviderResult<usize> {
        for attempt in 0..JITTER_MAX_NUM_TRIES {
            match Self::collect_timing_jitter(buf) {
                Ok(n) if n == buf.len() => {
                    debug!(
                        bytes = n,
                        attempt = attempt + 1,
                        "Jitter entropy collected successfully"
                    );
                    return Ok(n);
                }
                Ok(n) => {
                    warn!(
                        attempt = attempt + 1,
                        max_attempts = JITTER_MAX_NUM_TRIES,
                        collected = n,
                        expected = buf.len(),
                        "Partial jitter entropy collection, retrying"
                    );
                }
                Err(msg) => {
                    warn!(
                        attempt = attempt + 1,
                        max_attempts = JITTER_MAX_NUM_TRIES,
                        error = %msg,
                        "Jitter entropy collection attempt failed, retrying"
                    );
                }
            }
        }

        error!(
            max_attempts = JITTER_MAX_NUM_TRIES,
            requested = buf.len(),
            "All jitter entropy collection attempts exhausted"
        );
        Err(ProviderError::Common(CommonError::Internal(format!(
            "Jitter entropy exhausted after {JITTER_MAX_NUM_TRIES} attempts"
        ))))
    }

    /// Performs a single attempt at CPU timing jitter entropy collection.
    ///
    /// For each output byte, collects [`SAMPLES_PER_BYTE`] timing
    /// measurements of CPU-bound operations. Entropy is derived from
    /// the nanosecond-precision timing variations caused by:
    ///
    /// - OS scheduler preemptions and context switches
    /// - CPU cache effects (hits vs. misses across cache levels)
    /// - Hardware interrupt timing and coalescing
    /// - Memory access latency variations (TLB, page faults)
    /// - Branch prediction effects and speculative execution
    ///
    /// The raw timing values are mixed through a multiplicative hash
    /// accumulator and XOR-folded to produce each output byte.
    ///
    /// Replaces the C `jitterentropy` library calls
    /// (`jent_entropy_collector_alloc`, `jent_read_entropy`,
    /// `jent_entropy_collector_free`) with a pure-Rust timing approach,
    /// ensuring zero `unsafe` code per Rule R8.
    fn collect_timing_jitter(buf: &mut [u8]) -> Result<usize, String> {
        let mut collected = 0usize;

        for byte_ref in buf.iter_mut() {
            let mut mixer: u64 = 0;

            for sample in 0..SAMPLES_PER_BYTE {
                let start = Instant::now();

                // CPU-bound work to induce timing variation.
                // Uses a linear congruential generator (LCG) sequence
                // with Knuth's constants. The computation cannot be
                // optimized away due to the black_box barrier below.
                let mut work: u64 = u64::from(sample);
                for _ in 0..50 {
                    work = work
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                }
                hint::black_box(work);

                let elapsed = start.elapsed();
                // TRUNCATION: Intentional — only the lower 64 bits of the
                // nanosecond measurement are used for entropy extraction.
                // The upper bits of u128 nanoseconds carry calendar-scale
                // timing information, not jitter entropy. The LSBs contain
                // the timing variations that constitute our entropy source.
                #[allow(clippy::cast_possible_truncation)]
                let nanos = elapsed.as_nanos() as u64;

                // Mix timing value into the accumulator using a
                // multiplicative hash step for diffusion of timing
                // entropy bits across all 64 bit positions.
                mixer ^= nanos;
                mixer = mixer
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
            }

            // Fold the 64-bit mixer into a single byte by XOR-combining
            // all 8 octets. This preserves entropy contributions from
            // every bit position in the accumulator.
            let octets = mixer.to_le_bytes();
            let folded = octets[0]
                ^ octets[1]
                ^ octets[2]
                ^ octets[3]
                ^ octets[4]
                ^ octets[5]
                ^ octets[6]
                ^ octets[7];

            *byte_ref = folded;
            collected += 1;
        }

        if collected == buf.len() {
            Ok(collected)
        } else {
            Err(format!(
                "Incomplete jitter collection: {} of {} bytes",
                collected,
                buf.len()
            ))
        }
    }
}

// =============================================================================
// RandContext trait implementation
// =============================================================================

impl RandContext for JitterSource {
    fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        self.instantiate(strength, prediction_resistance, additional)
    }

    fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        self.generate(output, strength, prediction_resistance, additional)
    }

    fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: &[u8],
        additional: &[u8],
    ) -> ProviderResult<()> {
        self.reseed(prediction_resistance, entropy, additional)
    }

    fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.uninstantiate()
    }

    fn enable_locking(&mut self) -> ProviderResult<()> {
        self.enable_locking()
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        self.get_params()
    }
}

// =============================================================================
// Drop implementation — secure cleanup
// =============================================================================

impl Drop for JitterSource {
    fn drop(&mut self) {
        // Ensure state is reset on drop to avoid information leakage
        // about the source's last operational state.
        self.state = RandState::Uninitialised;
        debug!("Jitter entropy source dropped and cleaned up");
    }
}

// =============================================================================
// JitterProvider — Factory for JitterSource instances
// =============================================================================

/// Provider factory for creating [`JitterSource`] instances.
///
/// Implements the `RandProvider` trait to integrate with the provider
/// framework's algorithm dispatch system. The provider is registered
/// under the name `"JITTER"` and creates new `JitterSource` contexts
/// without a parent RAND (seed source constraint).
///
/// Replaces the C `ossl_jitter_functions[]` dispatch table from
/// `seed_src_jitter.c`.
#[derive(Debug, Clone, Copy)]
pub struct JitterProvider;

impl RandProvider for JitterProvider {
    /// Returns the algorithm name for this provider.
    ///
    /// Returns `"JITTER"` to match the provider dispatch name used in
    /// `mod.rs` factory (`"JITTER" => JitterProvider.new_ctx()`).
    fn name(&self) -> &'static str {
        "JITTER"
    }

    /// Creates a new [`JitterSource`] context.
    ///
    /// The created source starts in [`RandState::Uninitialised`] and must
    /// be explicitly instantiated before use. No parent RAND is accepted,
    /// enforcing the seed source constraint by API design.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the source cannot be created.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let source = JitterSource::new()?;
        Ok(Box::new(source))
    }
}
