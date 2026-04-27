//! OS Entropy Seed Source for system-provided random bytes.
//!
//! Provides entropy from the operating system:
//! - Linux/macOS: `getrandom()` syscall / `/dev/urandom`
//! - Windows: `CryptGenRandom` / `BCryptGenRandom`
//!
//! This is the root of the DRBG chain — it MUST NOT have a parent RAND.
//! Typically wrapped by a CRNG test in FIPS mode.
//!
//! ## Rust Implementation
//!
//! Uses the `rand` crate's `OsRng` for cross-platform OS entropy access,
//! which delegates to the appropriate system API on each platform.
//!
//! Source: `providers/implementations/rands/seed_src.c`

use crate::implementations::rands::drbg::RandState;
use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{debug, error};
use zeroize::Zeroize;

/// Maximum security strength in bits provided by the OS entropy source.
///
/// The OS entropy source is assumed to provide 256 bits of security strength,
/// matching the strongest algorithms in the provider framework.
///
/// Replaces C `SEED_SRC_DEFAULT_SECURITY_STRENGTH` from `seed_src.c`.
pub const SEED_SRC_STRENGTH: u32 = 256;

/// Maximum number of bytes that can be requested per call to [`SeedSource::generate`].
///
/// Set to 256 bytes per request, matching the provider framework constraints
/// for individual entropy acquisition operations.
///
/// Replaces C `seed_src_get_ctx_params()` reported `max_request` from `seed_src.c`.
pub const SEED_SRC_MAX_REQUEST: usize = 256;

/// OS entropy seed source that provides true randomness from the operating system.
///
/// This is the root of the DRBG chain and MUST NOT have a parent RAND.
/// It acquires entropy directly from the OS via `getrandom(2)` (Linux/macOS)
/// or `BCryptGenRandom` (Windows) through the `rand` crate's `OsRng`.
///
/// Fixed capabilities:
/// - Strength: 256 bits (see [`SEED_SRC_STRENGTH`])
/// - Max request: 256 bytes per call (see [`SEED_SRC_MAX_REQUEST`])
///
/// ## State Machine
///
/// The seed source follows a simple lifecycle:
/// - `Uninitialised` → `Ready` (via [`instantiate`](SeedSource::instantiate))
/// - `Ready` → `Uninitialised` (via [`uninstantiate`](SeedSource::uninstantiate))
///
/// ## Locking
///
/// // LOCK-SCOPE: Optional lock for thread-safe access. The lock protects
/// // the state field only. Low contention — seed source is typically accessed
/// // infrequently (only during DRBG seeding/reseeding).
///
/// Replaces C `PROV_SEED_SRC` from `seed_src.c`.
#[derive(Debug)]
pub struct SeedSource {
    /// Current lifecycle state of the seed source.
    state: RandState,
    /// Optional mutex for thread-safe access to state.
    ///
    // LOCK-SCOPE: Protects `state` field transitions during concurrent
    // DRBG seeding/reseeding operations. Low contention expected — seed
    // source is accessed infrequently (only when a DRBG requests entropy).
    lock: Option<Mutex<()>>,
}

impl SeedSource {
    /// Creates a new OS entropy seed source.
    ///
    /// The seed source is created in the [`RandState::Uninitialised`] state.
    /// Call [`instantiate`](SeedSource::instantiate) before generating entropy.
    ///
    /// Seed sources MUST NOT have a parent RAND — they are the root entropy
    /// source in the DRBG chain. This constraint is enforced at construction
    /// time (matching C `seed_src_new()` which rejects non-NULL parent with
    /// `PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if construction fails (reserved for
    /// future constraint validation such as parent-rejection).
    pub fn new() -> ProviderResult<Self> {
        debug!("Creating new OS entropy seed source");
        Ok(Self {
            state: RandState::Uninitialised,
            lock: None,
        })
    }

    /// Instantiates the seed source, transitioning to the [`RandState::Ready`] state.
    ///
    /// For OS entropy sources, instantiation simply marks the source as ready.
    /// The underlying OS entropy mechanism is always available and does not
    /// require initialisation.
    ///
    /// Matches C `seed_src_instantiate()`.
    ///
    /// # Parameters
    ///
    /// - `_strength`: Requested security strength in bits (ignored; OS provides 256)
    /// - `_prediction_resistance`: Whether prediction resistance is required (ignored)
    /// - `_additional`: Additional input data (ignored for OS entropy sources)
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the seed source is already in the
    /// [`RandState::Ready`] state.
    pub fn instantiate(
        &mut self,
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        if self.state == RandState::Ready {
            error!("Seed source already instantiated");
            return Err(ProviderError::Init(
                "Seed source already instantiated".into(),
            ));
        }
        self.state = RandState::Ready;
        debug!("Seed source instantiated, state=Ready");
        Ok(())
    }

    /// Uninstantiates the seed source, transitioning back to
    /// [`RandState::Uninitialised`].
    ///
    /// After this call, the source must be re-instantiated before generating
    /// entropy.
    ///
    /// Matches C `seed_src_uninstantiate()`.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`Ok`] unconditionally.
    pub fn uninstantiate(&mut self) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        self.state = RandState::Uninitialised;
        debug!("Seed source uninstantiated, state=Uninitialised");
        Ok(())
    }

    /// Generates random bytes from the OS entropy source.
    ///
    /// Fills the `output` buffer with random bytes obtained directly from the
    /// operating system's entropy source. Uses `OsRng` which delegates to
    /// the platform's cryptographic RNG (`getrandom()`, `/dev/urandom`,
    /// `BCryptGenRandom`).
    ///
    /// Matches C `seed_src_generate()` which uses `ossl_pool_acquire_entropy()`
    /// through the `RAND_POOL` mechanism.
    ///
    /// # Parameters
    ///
    /// - `output`: Buffer to fill with random bytes
    /// - `_strength`: Requested security strength in bits (ignored; OS provides 256)
    /// - `_prediction_resistance`: Whether prediction resistance is required (ignored)
    /// - `_additional`: Additional input data (ignored for OS entropy sources)
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] if the seed source has not been instantiated
    /// - `ProviderError::Dispatch` if the request exceeds [`SEED_SRC_MAX_REQUEST`]
    pub fn generate(
        &mut self,
        output: &mut [u8],
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        self.check_ready("generate")?;

        if output.len() > SEED_SRC_MAX_REQUEST {
            error!(
                requested = output.len(),
                max = SEED_SRC_MAX_REQUEST,
                "Generate request exceeds maximum"
            );
            return Err(ProviderError::Dispatch(format!(
                "Requested {} bytes exceeds max {} bytes per request",
                output.len(),
                SEED_SRC_MAX_REQUEST
            )));
        }

        OsRng.fill_bytes(output);
        debug!(bytes = output.len(), "Generated OS entropy");
        Ok(())
    }

    /// Reseeds the seed source.
    ///
    /// This is a no-op for OS entropy sources — the operating system always
    /// provides fresh entropy, so there is nothing to reseed. Returns [`Ok`]
    /// as long as the source is instantiated.
    ///
    /// Matches C `seed_src_reseed()` which simply returns 1.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the seed source has not been
    /// instantiated.
    pub fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        self.check_ready("reseed")?;

        debug!("Reseed no-op for OS entropy source");
        Ok(())
    }

    /// Acquires a seed buffer filled with OS entropy.
    ///
    /// Allocates a buffer of `max_len` bytes and fills it with random bytes
    /// from the OS entropy source. The caller is responsible for clearing
    /// the buffer via [`clear_seed`](SeedSource::clear_seed) after use to
    /// prevent entropy leakage.
    ///
    /// Matches C `seed_get_seed()` which allocates a `RAND_POOL` and fills it
    /// with OS entropy via `ossl_pool_acquire_entropy()`.
    ///
    /// # Parameters
    ///
    /// - `min_len`: Minimum acceptable seed length in bytes
    /// - `max_len`: Maximum seed length in bytes (buffer will be this size)
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] if the seed source has not been instantiated
    /// - `ProviderError::Dispatch` if `min_len > max_len` or `min_len` is 0
    pub fn get_seed(&mut self, min_len: usize, max_len: usize) -> ProviderResult<Vec<u8>> {
        let _guard = self.lock.as_ref().map(|m| m.lock());

        self.check_ready("get_seed")?;

        if min_len == 0 {
            error!("get_seed: min_len must be greater than zero");
            return Err(ProviderError::Dispatch(
                "get_seed: min_len must be greater than zero".into(),
            ));
        }

        if min_len > max_len {
            error!(
                min_len = min_len,
                max_len = max_len,
                "get_seed: min_len exceeds max_len"
            );
            return Err(ProviderError::Dispatch(format!(
                "min_len ({min_len}) exceeds max_len ({max_len})"
            )));
        }

        let len = max_len;
        let mut seed = vec![0u8; len];
        OsRng.fill_bytes(&mut seed);
        debug!(seed_len = len, "Acquired OS entropy seed");
        Ok(seed)
    }

    /// Securely clears a seed buffer by zeroing its contents.
    ///
    /// Uses the `zeroize` crate to ensure the compiler does not optimise away
    /// the memory write, providing a strong guarantee that seed material is
    /// erased. This replaces C `seed_clear_seed()` which calls
    /// `OPENSSL_secure_clear_free()`.
    ///
    /// # Parameters
    ///
    /// - `seed`: Mutable reference to the seed buffer to clear
    pub fn clear_seed(&self, seed: &mut [u8]) {
        seed.zeroize();
        debug!(bytes = seed.len(), "Cleared seed buffer via zeroize");
    }

    /// Enables thread-safe locking for this seed source.
    ///
    /// Creates an internal mutex to protect state transitions during concurrent
    /// access. Subsequent operations will acquire the lock before proceeding.
    /// If the lock already exists, this is a no-op.
    ///
    /// Matches C `seed_src_enable_locking()` which creates a
    /// `CRYPTO_THREAD_lock`.
    ///
    /// # Errors
    ///
    /// Returns [`Ok`] unconditionally. The lock is created if not already
    /// present.
    pub fn enable_locking(&mut self) -> ProviderResult<()> {
        if self.lock.is_none() {
            // LOCK-SCOPE: Creating mutex for state field protection.
            // Low contention — seed source is accessed infrequently during
            // DRBG seeding/reseeding operations.
            self.lock = Some(Mutex::new(()));
            debug!("Locking enabled for seed source");
        }
        Ok(())
    }

    /// Returns the current parameters of the seed source.
    ///
    /// Reports:
    /// - `"state"`: Current lifecycle state name (e.g. `"Ready"`,
    ///   `"Uninitialised"`)
    /// - `"strength"`: Security strength in bits (`256`)
    /// - `"max_request"`: Maximum bytes per request (`256`)
    ///
    /// Matches C `seed_src_get_ctx_params()`.
    ///
    /// # Errors
    ///
    /// Returns [`Ok`] unconditionally with the populated parameter set.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("state", ParamValue::Utf8String(self.state.to_string()));
        params.set("strength", ParamValue::UInt32(SEED_SRC_STRENGTH));
        params.set(
            "max_request",
            ParamValue::UInt32(
                u32::try_from(SEED_SRC_MAX_REQUEST).unwrap_or(u32::MAX),
            ),
        );
        Ok(params)
    }

    // ------------------------------------------------------------------
    // Private helper methods
    // ------------------------------------------------------------------

    /// Verifies the seed source is in the [`RandState::Ready`] state.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] with a descriptive message including
    /// the operation name if the state is not `Ready`.
    fn check_ready(&self, operation: &str) -> ProviderResult<()> {
        if self.state != RandState::Ready {
            error!(operation = operation, "Seed source not instantiated");
            return Err(ProviderError::Init(format!(
                "Cannot {operation}: seed source not instantiated"
            )));
        }
        Ok(())
    }
}

/// [`RandContext`] trait implementation for [`SeedSource`].
///
/// Delegates all lifecycle methods to the corresponding inherent methods on
/// [`SeedSource`], providing the trait-based dispatch interface required by
/// the provider framework.
///
/// Replaces C `ossl_seed_src_functions[]` dispatch table entries from
/// `seed_src.c`.
impl RandContext for SeedSource {
    fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        SeedSource::instantiate(self, strength, prediction_resistance, additional)
    }

    fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        SeedSource::generate(self, output, strength, prediction_resistance, additional)
    }

    fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: &[u8],
        additional: &[u8],
    ) -> ProviderResult<()> {
        SeedSource::reseed(self, prediction_resistance, entropy, additional)
    }

    fn uninstantiate(&mut self) -> ProviderResult<()> {
        SeedSource::uninstantiate(self)
    }

    fn enable_locking(&mut self) -> ProviderResult<()> {
        SeedSource::enable_locking(self)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        SeedSource::get_params(self)
    }
}

/// Provider factory for creating [`SeedSource`] instances.
///
/// Implements the `RandProvider` trait to integrate with the provider
/// framework's algorithm dispatch system. Registered as the `"SEED-SRC"`
/// algorithm in the default provider.
///
/// ## Usage
///
/// ```rust,ignore
/// use openssl_provider::implementations::rands::seed_src::SeedSourceProvider;
/// use openssl_provider::traits::RandProvider;
///
/// let provider = SeedSourceProvider;
/// let ctx = provider.new_ctx().expect("create seed source");
/// ```
///
/// Replaces C `ossl_seed_src_functions[]` dispatch table from `seed_src.c`.
#[derive(Debug)]
pub struct SeedSourceProvider;

impl RandProvider for SeedSourceProvider {
    /// Returns the algorithm name for this provider.
    ///
    /// Returns `"SEED-SRC"` matching the C algorithm name used in
    /// provider registration.
    fn name(&self) -> &'static str {
        "SEED-SRC"
    }

    /// Creates a new [`SeedSource`] instance wrapped in a
    /// [`RandContext`] trait object.
    ///
    /// The seed source is created in the [`RandState::Uninitialised`] state.
    /// Call [`RandContext::instantiate`] on the returned context before
    /// generating entropy.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if seed source creation fails.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let source = SeedSource::new()?;
        debug!("SeedSourceProvider created new SeedSource context");
        Ok(Box::new(source))
    }
}
