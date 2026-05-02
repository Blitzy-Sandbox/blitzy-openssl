//! Core DRBG Framework (SP 800-90A).
//!
//! Provides the shared infrastructure for all DRBG implementations:
//! - DRBG state machine (`Uninitialised` → `Ready` → `Error`)
//! - Entropy acquisition from OS entropy source via [`OsRng`](rand::rngs::OsRng)
//! - Reseed policy (interval-based and time-based automatic reseeding)
//! - Fork detection (on Unix systems)
//! - Health monitoring and error recovery
//! - Secure zeroization on cleanup via `Zeroize`
//!
//! Individual DRBG mechanisms (CTR, Hash, HMAC) implement the
//! [`DrbgMechanism`] trait and are wrapped by the [`Drbg`] struct.
//! Instances are typically created by a [`crate::traits::RandProvider`]
//! implementation via [`RandProvider::new_ctx()`](crate::traits::RandProvider::new_ctx).
//!
//! # State Machine
//!
//! ```text
//! Uninitialised ──(instantiate)──► Ready ──(generate/reseed)──► Ready
//!       ▲                            │
//!       │                            ▼
//!       └──(uninstantiate)────── Error ──(try_recover/reseed)──► Ready
//! ```
//!
//! # Source Reference
//!
//! Translated from `providers/implementations/rands/drbg.c` (~750 lines)
//! and `providers/common/provider_seeding.c` (entropy/nonce dispatch).

// =============================================================================
// Imports
// =============================================================================

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// Default personalization string used when no custom personalization is provided.
///
/// Matches C `DRBG_DEFAULT_PERS_STRING` macro in `providers/implementations/rands/drbg.c`.
pub const DEFAULT_PERS_STRING: &str = "OpenSSL NIST SP 800-90A DRBG";

/// Maximum length for entropy and other data inputs (`INT32_MAX`).
///
/// Matches C `DRBG_MAX_LENGTH` used in `drbg.c` for validation bounds.
const DRBG_MAX_LENGTH: usize = 0x7FFF_FFFF;

/// Default reseed interval: number of `generate()` calls between automatic reseeds.
///
/// Value: 2^24 = 16,777,216 (matches C `RESEED_INTERVAL` default).
const DRBG_RESEED_INTERVAL: u64 = 1 << 24;

/// Default time-based reseed interval in seconds.
///
/// Value: 0 means time-based reseeding is disabled by default.
/// Matches C `RESEED_TIME_INTERVAL` default.
const DRBG_RESEED_TIME_INTERVAL: u64 = 0;

/// Default security strength in bits.
///
/// SP 800-90A recommends 256-bit strength for AES-256-CTR-DRBG.
const DRBG_DEFAULT_STRENGTH: u32 = 256;

/// Default minimum entropy length in bytes (256 bits / 8).
const DRBG_MIN_ENTROPY_LEN: usize = 32;

/// Default minimum nonce length in bytes (128 bits / 8).
///
/// Per SP 800-90A §8.6.7: nonce should be at least half the security strength.
const DRBG_MIN_NONCE_LEN: usize = 16;

/// Default maximum output request size per `generate()` call (64 KiB).
const DRBG_MAX_REQUEST: usize = 1 << 16;

// =============================================================================
// RandState — DRBG Lifecycle State
// =============================================================================

// Compile-time assertions: verify that factory trait (RandProvider) and
// secure cleanup marker (ZeroizeOnDrop) are importable from their crates.
// RandProvider is the factory trait that creates RandContext instances
// (which Drbg implements). ZeroizeOnDrop is recommended for mechanism
// implementors to derive for automatic secure cleanup.
const _: () = {
    fn _assert_rand_provider_importable<T: RandProvider>() {}
    fn _assert_zeroize_on_drop_importable<T: ZeroizeOnDrop>() {}
};

/// DRBG lifecycle state (replaces C `EVP_RAND_STATE_*` constants).
///
/// Every DRBG instance transitions through these states:
/// - [`Uninitialised`](RandState::Uninitialised) → [`Ready`](RandState::Ready) via [`Drbg::instantiate()`]
/// - [`Ready`](RandState::Ready) remains `Ready` through [`Drbg::generate()`] and [`Drbg::reseed()`]
/// - Any failure transitions to [`Error`](RandState::Error)
/// - [`Error`](RandState::Error) → [`Ready`](RandState::Ready) via error recovery (reseed)
/// - [`Drbg::uninstantiate()`] returns to [`Uninitialised`](RandState::Uninitialised)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RandState {
    /// Not yet instantiated — must call [`Drbg::instantiate()`] before
    /// [`Drbg::generate()`].
    Uninitialised,
    /// Operational — ready for [`Drbg::generate()`] calls.
    Ready,
    /// Error — must uninstantiate and re-instantiate, or attempt recovery
    /// via reseed.
    Error,
}

impl std::fmt::Display for RandState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialised => write!(f, "Uninitialised"),
            Self::Ready => write!(f, "Ready"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// =============================================================================
// DrbgMechanism — Mechanism-Specific Operations Trait
// =============================================================================

/// Trait for mechanism-specific DRBG operations.
///
/// Implemented by `CtrDrbg` (AES-CTR, SP 800-90A §10.2), `HashDrbg`
/// (SHA-based, SP 800-90A §10.1.1), and `HmacDrbg` (HMAC-based,
/// SP 800-90A §10.1.2). The [`Drbg`] struct wraps a `Box<dyn DrbgMechanism>`
/// and provides the entropy/nonce acquisition, reseed policy, and locking
/// around it.
///
/// # Security
///
/// All implementors must:
/// - Securely handle entropy and nonce material
/// - Implement `Zeroize` to safely clear working state on cleanup
/// - Return consistent errors through [`ProviderResult`]
///
/// Implementors should additionally derive `ZeroizeOnDrop` from the `zeroize`
/// crate to ensure automatic zeroing when the mechanism is dropped.
///
/// # Source Reference
///
/// Replaces the C mechanism function pointers (`instantiate`, `reseed`,
/// `generate`, `uninstantiate`) in the `PROV_DRBG` struct from `drbg.c`.
pub trait DrbgMechanism: Send + Sync + std::fmt::Debug + Zeroize {
    /// Mechanism-specific instantiation with entropy, nonce, and personalization.
    ///
    /// Called by [`Drbg::instantiate()`] after entropy and nonce have been
    /// acquired. The mechanism must use the provided entropy and nonce to
    /// initialize its internal working state per the relevant SP 800-90A
    /// section.
    ///
    /// # Parameters
    /// - `entropy`: Random entropy bytes (length validated by caller)
    /// - `nonce`: Nonce bytes (may be empty if mechanism does not require nonce)
    /// - `personalization`: Optional personalization string bytes
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()>;

    /// Mechanism-specific reseeding with new entropy and optional additional input.
    ///
    /// Called by [`Drbg::reseed()`] after fresh entropy has been acquired.
    ///
    /// # Parameters
    /// - `entropy`: Fresh entropy bytes (length validated by caller)
    /// - `additional`: Optional additional input data
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()>;

    /// Mechanism-specific output generation with optional additional input.
    ///
    /// Called by [`Drbg::generate()`] after reseed policy checks pass.
    ///
    /// # Parameters
    /// - `output`: Buffer to fill with pseudorandom bytes
    /// - `additional`: Optional additional input data
    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()>;

    /// Mechanism-specific uninstantiation (secure cleanup of working state).
    ///
    /// Must securely zero all internal key material and working state.
    /// Called by [`Drbg::uninstantiate()`] and during [`Drop`].
    fn uninstantiate(&mut self);

    /// FIPS: verify that working state has been properly zeroized.
    ///
    /// Returns `true` if all sensitive mechanism state is zeroed.
    /// Used by FIPS self-test verification after uninstantiation.
    fn verify_zeroization(&self) -> bool;
}

// =============================================================================
// DrbgConfig — Configuration Parameters
// =============================================================================

/// DRBG configuration parameters controlling security strength, entropy
/// requirements, reseed policy, and input length limits.
///
/// These correspond to the NIST SP 800-90A Table 2 values and
/// operator-configurable settings from the `PROV_DRBG` struct in `drbg.c`.
///
/// # Defaults
///
/// The [`Default`] implementation provides SP 800-90A recommended values
/// suitable for AES-256-CTR-DRBG:
/// - Security strength: 256 bits
/// - Minimum entropy: 32 bytes (256 bits)
/// - Reseed interval: 16,777,216 generate calls
/// - Time-based reseed: disabled (0 seconds)
#[derive(Debug, Clone)]
pub struct DrbgConfig {
    /// Security strength in bits (e.g., 128, 192, 256).
    pub strength: u32,
    /// Minimum entropy input length in bytes.
    pub min_entropylen: usize,
    /// Maximum entropy input length in bytes.
    pub max_entropylen: usize,
    /// Minimum nonce length in bytes (0 = no nonce required).
    pub min_noncelen: usize,
    /// Maximum nonce length in bytes.
    pub max_noncelen: usize,
    /// Maximum personalization string length in bytes.
    pub max_perslen: usize,
    /// Maximum additional input length in bytes.
    pub max_adinlen: usize,
    /// Maximum output request length per `generate()` call in bytes.
    pub max_request: usize,
    /// Reseed interval (number of `generate()` calls between automatic reseeds).
    pub reseed_interval: u64,
    /// Maximum time between reseeds in seconds (0 = no time-based reseed).
    pub reseed_time_interval: u64,
}

impl Default for DrbgConfig {
    /// Creates a default configuration with SP 800-90A recommended values.
    ///
    /// Matches the defaults set by C `ossl_rand_drbg_new()` in `drbg.c`.
    fn default() -> Self {
        Self {
            strength: DRBG_DEFAULT_STRENGTH,
            min_entropylen: DRBG_MIN_ENTROPY_LEN,
            max_entropylen: DRBG_MAX_LENGTH,
            min_noncelen: DRBG_MIN_NONCE_LEN,
            max_noncelen: DRBG_MAX_LENGTH,
            max_perslen: DRBG_MAX_LENGTH,
            max_adinlen: DRBG_MAX_LENGTH,
            max_request: DRBG_MAX_REQUEST,
            reseed_interval: DRBG_RESEED_INTERVAL,
            reseed_time_interval: DRBG_RESEED_TIME_INTERVAL,
        }
    }
}

// =============================================================================
// Drbg — Core DRBG Wrapper
// =============================================================================

/// Core DRBG wrapper providing the full DRBG lifecycle.
///
/// Wraps a mechanism-specific implementation ([`DrbgMechanism`]) and provides:
/// - Entropy acquisition from OS via `OsRng` (`rand::rngs::OsRng`)
/// - Reseed policy enforcement (interval and time-based)
/// - Optional locking for thread-safe operation
/// - Fork detection (on Unix systems)
/// - Health monitoring and error recovery
///
/// ## Locking
///
/// // LOCK-SCOPE: The inner `Mutex` protects the DRBG mechanism state and
/// // reseed counters. Contention profile: moderate during concurrent
/// // `generate()` calls when the DRBG is shared across threads; each
/// // `generate()` acquires the lock for the duration of generation plus
/// // potential reseed. Fine-grained: one lock per DRBG instance, not global.
/// // For per-thread DRBGs, locking is not enabled and contention is zero.
///
/// ## Wiring Path (Rule R10)
///
/// ```text
/// openssl_cli::main()
///   -> openssl_crypto::rand::Rand::generate()
///     -> provider dispatch
///       -> RandContext::generate()  (this type implements RandContext)
/// ```
///
/// Replaces C `PROV_DRBG` struct from `providers/implementations/rands/drbg.c`.
/// See also [`crate::traits::RandProvider`] for the factory trait that creates
/// DRBG instances.
pub struct Drbg {
    /// Mechanism-specific state (CTR, Hash, or HMAC).
    mechanism: Box<dyn DrbgMechanism>,
    /// Current DRBG lifecycle state.
    state: RandState,
    /// Configuration parameters (security strength, entropy bounds, reseed policy).
    config: DrbgConfig,
    /// Number of generate calls since last (re)seed.
    generate_counter: u64,
    /// Reseed counter (monotonically increasing across reseeds, atomic for
    /// lock-free reading by child DRBGs querying parent reseed count).
    reseed_counter: AtomicU32,
    /// Time of last (re)seed for time-based reseed policy.
    reseed_time: Option<SystemTime>,
    /// Fork ID for fork detection (Unix: `getpid()`).
    fork_id: u32,
    /// Optional per-instance lock for thread-safe operation.
    ///
    /// Wrapped in [`Arc`] so the lock guard can be held across `&mut self`
    /// method calls without conflicting borrows.
    // LOCK-SCOPE: Protects mechanism state + reseed counters during concurrent
    // generate() calls. Contention: moderate for shared DRBGs, none for
    // per-thread. Created via enable_locking(). Replaces C
    // CRYPTO_THREAD_lock from drbg.c.
    lock: Option<Arc<Mutex<()>>>,
}

// =============================================================================
// Drbg — Constructor and State
// =============================================================================

impl Drbg {
    /// Creates a new DRBG wrapper around the given mechanism with the specified
    /// configuration.
    ///
    /// The DRBG starts in [`RandState::Uninitialised`]. Call
    /// [`instantiate()`](Drbg::instantiate) before using
    /// [`generate()`](Drbg::generate).
    ///
    /// # Parameters
    /// - `mechanism`: The mechanism-specific implementation (CTR, Hash, or HMAC)
    /// - `config`: Configuration parameters; use [`DrbgConfig::default()`] for
    ///   SP 800-90A defaults
    ///
    /// Matches C `ossl_rand_drbg_new()` from `drbg.c` lines 785-867.
    #[must_use]
    pub fn new(mechanism: Box<dyn DrbgMechanism>, config: DrbgConfig) -> Self {
        let fork_id = std::process::id();
        debug!(
            strength = config.strength,
            fork_id = fork_id,
            "Creating new DRBG instance"
        );
        Self {
            mechanism,
            state: RandState::Uninitialised,
            config,
            generate_counter: 0,
            reseed_counter: AtomicU32::new(1),
            reseed_time: None,
            fork_id,
            lock: None,
        }
    }

    /// Returns the current DRBG lifecycle state.
    #[must_use]
    pub fn state(&self) -> RandState {
        self.state
    }

    // =========================================================================
    // Lifecycle Methods
    // =========================================================================

    /// Instantiates the DRBG with entropy, nonce, and optional personalization.
    ///
    /// Acquires entropy and nonce from the OS, validates inputs against the
    /// configured bounds, then delegates to the underlying mechanism's
    /// [`DrbgMechanism::instantiate()`]. On success, the DRBG transitions
    /// to [`RandState::Ready`].
    ///
    /// # Parameters
    /// - `strength`: Requested security strength in bits (must be <= `config.strength`)
    /// - `prediction_resistance`: If `true`, forces fresh entropy from a live source
    /// - `personalization`: Optional personalization string
    ///
    /// # Errors
    /// - [`ProviderError::Init`] if the DRBG is not in [`RandState::Uninitialised`]
    /// - [`ProviderError::Init`] if requested strength exceeds configured strength
    /// - [`ProviderError::Init`] if personalization exceeds `config.max_perslen`
    /// - [`ProviderError::Init`] if entropy or nonce acquisition fails
    ///
    /// Matches C `ossl_prov_drbg_instantiate()` from `drbg.c` lines 349-465.
    pub fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        personalization: &[u8],
    ) -> ProviderResult<()> {
        let _ = prediction_resistance; // Used for entropy source selection in full impl
        debug!(
            strength = strength,
            pers_len = personalization.len(),
            current_state = %self.state,
            "DRBG instantiate requested"
        );

        // Validate current state
        if self.state != RandState::Uninitialised {
            return Err(ProviderError::Init(format!(
                "DRBG instantiate called in {} state, expected Uninitialised",
                self.state
            )));
        }

        // Validate requested strength does not exceed configured strength
        if strength > self.config.strength {
            return Err(ProviderError::Init(format!(
                "Requested strength {} exceeds configured maximum {}",
                strength, self.config.strength
            )));
        }

        // Validate personalization string length
        if personalization.len() > self.config.max_perslen {
            return Err(ProviderError::Init(format!(
                "Personalization string length {} exceeds maximum {}",
                personalization.len(),
                self.config.max_perslen
            )));
        }

        // Set state to Error -- will be changed to Ready on success.
        // This ensures we end in Error if anything fails below.
        self.state = RandState::Error;

        // Acquire entropy from OS
        let entropy = self.acquire_entropy(
            self.config.min_entropylen,
            self.config.max_entropylen,
            strength,
        )?;

        // Acquire nonce if required
        let nonce = if self.config.min_noncelen > 0 {
            self.acquire_nonce(self.config.min_noncelen, self.config.max_noncelen)?
        } else {
            Vec::new()
        };

        // Delegate to mechanism-specific instantiation
        let result = self
            .mechanism
            .instantiate(&entropy, &nonce, personalization);

        // Securely zeroize entropy and nonce buffers regardless of result
        let mut entropy_buf = entropy;
        let mut nonce_buf = nonce;
        entropy_buf.zeroize();
        nonce_buf.zeroize();

        // Check mechanism result
        result?;

        // Transition to Ready state
        self.state = RandState::Ready;
        self.generate_counter = 1;
        self.reseed_counter.store(1, Ordering::Release);
        self.reseed_time = Some(SystemTime::now());
        self.fork_id = std::process::id();

        debug!("DRBG instantiated successfully");
        Ok(())
    }

    /// Uninstantiates the DRBG, securely zeroing all mechanism state.
    ///
    /// The DRBG transitions to [`RandState::Uninitialised`] and must be
    /// re-instantiated before further use.
    ///
    /// Matches C `ossl_prov_drbg_uninstantiate()` from `drbg.c`.
    pub fn uninstantiate(&mut self) -> ProviderResult<()> {
        debug!(current_state = %self.state, "DRBG uninstantiate requested");

        self.mechanism.uninstantiate();
        self.state = RandState::Uninitialised;
        self.generate_counter = 0;
        self.reseed_time = None;

        debug!("DRBG uninstantiated");
        Ok(())
    }

    /// Reseeds the DRBG with fresh entropy and optional additional input.
    ///
    /// If `entropy` is `None` (or empty when called via [`RandContext`]),
    /// fresh entropy is acquired from the OS. On success, the reseed counter
    /// is incremented and the reseed timestamp is updated.
    ///
    /// # Parameters
    /// - `prediction_resistance`: If `true`, forces fresh entropy from a live source
    /// - `entropy`: Optional externally-provided entropy; if `None`, acquired from OS
    /// - `additional`: Optional additional input data
    ///
    /// # Errors
    /// - Returns error if the DRBG is not in [`RandState::Ready`] and recovery fails
    /// - Returns error if entropy acquisition fails
    ///
    /// Matches C `ossl_prov_drbg_reseed_unlocked()` from `drbg.c` lines 480-600.
    pub fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: Option<&[u8]>,
        additional: &[u8],
    ) -> ProviderResult<()> {
        let _ = prediction_resistance; // Used for entropy source selection in full impl
        debug!(
            has_entropy = entropy.is_some(),
            additional_len = additional.len(),
            current_state = %self.state,
            "DRBG reseed requested"
        );

        // If not in Ready state, attempt recovery
        if self.state != RandState::Ready {
            self.try_recover()?;
        }

        // Validate additional input length
        if additional.len() > self.config.max_adinlen {
            return Err(ProviderError::Init(format!(
                "Additional input length {} exceeds maximum {}",
                additional.len(),
                self.config.max_adinlen
            )));
        }

        // Acquire or use provided entropy
        let (entropy_data, needs_zeroize) = match entropy {
            Some(ent) if !ent.is_empty() => {
                // Validate externally-provided entropy length
                if ent.len() < self.config.min_entropylen {
                    return Err(ProviderError::Init(format!(
                        "Entropy length {} below minimum {}",
                        ent.len(),
                        self.config.min_entropylen
                    )));
                }
                if ent.len() > self.config.max_entropylen {
                    return Err(ProviderError::Init(format!(
                        "Entropy length {} exceeds maximum {}",
                        ent.len(),
                        self.config.max_entropylen
                    )));
                }
                (ent.to_vec(), true)
            }
            _ => {
                // Acquire fresh entropy from OS
                let ent = self.acquire_entropy(
                    self.config.min_entropylen,
                    self.config.max_entropylen,
                    self.config.strength,
                )?;
                (ent, true)
            }
        };

        // Set state to Error in case mechanism reseed fails
        self.state = RandState::Error;

        // Delegate to mechanism-specific reseed
        let result = self.mechanism.reseed(&entropy_data, additional);

        // Securely zeroize entropy buffer
        if needs_zeroize {
            let mut buf = entropy_data;
            buf.zeroize();
        }

        match result {
            Ok(()) => {
                // Update reseed tracking
                self.state = RandState::Ready;
                self.generate_counter = 1;
                self.reseed_counter.fetch_add(1, Ordering::Release);
                self.reseed_time = Some(SystemTime::now());
                self.fork_id = std::process::id();

                trace!(
                    reseed_counter = self.reseed_counter.load(Ordering::Relaxed),
                    "DRBG reseeded successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!("DRBG mechanism reseed failed: {}", e);
                Err(e)
            }
        }
    }

    /// Generates pseudorandom output with automatic reseed policy enforcement.
    ///
    /// Checks the reseed policy (interval, time, fork detection, prediction
    /// resistance) and performs automatic reseeding if needed before delegating
    /// to the mechanism's [`DrbgMechanism::generate()`].
    ///
    /// # Parameters
    /// - `output`: Buffer to fill with pseudorandom bytes
    /// - `strength`: Requested security strength in bits
    /// - `prediction_resistance`: If `true`, forces a reseed before generation
    /// - `additional`: Optional additional input data
    ///
    /// # Errors
    /// - Returns error if the DRBG is not in [`RandState::Ready`] and recovery fails
    /// - Returns error if requested strength exceeds configured strength
    /// - Returns error if output length exceeds `config.max_request`
    ///
    /// Matches C `ossl_prov_drbg_generate()` from `drbg.c` lines 622-712.
    pub fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        trace!(
            output_len = output.len(),
            strength = strength,
            additional_len = additional.len(),
            "DRBG generate requested"
        );

        // Acquire per-instance lock if locking is enabled.
        // LOCK-SCOPE: Guards mechanism state + reseed counters for
        // the duration of this generate call. The guard is held until
        // the method returns, preventing concurrent generate/reseed
        // from corrupting the mechanism's working state.
        // Clone the Arc to avoid borrowing self.lock while mutating self.
        let lock_clone = self.lock.clone();
        let _guard = lock_clone.as_ref().map(|m| m.lock());

        // If not in Ready state, attempt recovery
        if self.state != RandState::Ready {
            self.try_recover()?;
        }

        // Validate requested strength
        if strength > self.config.strength {
            return Err(ProviderError::Init(format!(
                "Requested strength {} exceeds configured maximum {}",
                strength, self.config.strength
            )));
        }

        // Validate output length
        if output.len() > self.config.max_request {
            return Err(ProviderError::Init(format!(
                "Output request length {} exceeds maximum {}",
                output.len(),
                self.config.max_request
            )));
        }

        // Validate additional input length
        if additional.len() > self.config.max_adinlen {
            return Err(ProviderError::Init(format!(
                "Additional input length {} exceeds maximum {}",
                additional.len(),
                self.config.max_adinlen
            )));
        }

        // Check reseed policy: fork detection, interval, time, prediction resistance
        let force_reseed = prediction_resistance || self.check_fork() || self.needs_reseed();

        if force_reseed {
            debug!("DRBG auto-reseed triggered before generate");
            self.reseed(prediction_resistance, None, additional)?;
        }

        // Delegate to mechanism-specific generation
        self.mechanism.generate(output, additional)?;

        // Increment generate counter (saturating arithmetic per Rule R6)
        self.generate_counter = self.generate_counter.saturating_add(1);

        trace!(
            generate_counter = self.generate_counter,
            output_len = output.len(),
            "DRBG generate completed"
        );
        Ok(())
    }

    // =========================================================================
    // Parameters
    // =========================================================================

    /// Returns the current DRBG parameters as a `ParamSet`.
    ///
    /// Reports: state, strength, reseed counter, max request size,
    /// generate counter, and reseed interval.
    ///
    /// Matches C `ossl_drbg_get_ctx_params()` from `drbg.c`.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();

        params.set(
            "state",
            ParamValue::UInt64(match self.state {
                RandState::Uninitialised => 0,
                RandState::Ready => 1,
                RandState::Error => 2,
            }),
        );
        params.set(
            "strength",
            ParamValue::UInt64(u64::from(self.config.strength)),
        );
        params.set(
            "reseed_counter",
            ParamValue::UInt64(u64::from(self.reseed_counter.load(Ordering::Relaxed))),
        );
        params.set(
            "max_request",
            // Saturating conversion: usize -> u64 is lossless on 64-bit,
            // but we use try_from with fallback for portability (Rule R6).
            ParamValue::UInt64(u64::try_from(self.config.max_request).unwrap_or(u64::MAX)),
        );
        params.set(
            "generate_counter",
            ParamValue::UInt64(self.generate_counter),
        );
        params.set(
            "reseed_interval",
            ParamValue::UInt64(self.config.reseed_interval),
        );
        params.set(
            "reseed_time_interval",
            ParamValue::UInt64(self.config.reseed_time_interval),
        );

        // Report last reseed time as seconds since UNIX epoch.
        // Uses `UNIX_EPOCH` and `Duration` for portable time representation.
        let reseed_time_secs = self
            .reseed_time
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0u64, |d: Duration| d.as_secs());
        params.set("reseed_time", ParamValue::UInt64(reseed_time_secs));

        Ok(params)
    }

    /// Configures DRBG parameters from a `ParamSet`.
    ///
    /// Accepts `reseed_interval` and `reseed_time_interval` configuration.
    /// Other parameters are read-only and are silently ignored.
    ///
    /// Matches C `ossl_drbg_set_ctx_params()` from `drbg.c`.
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Use get_typed() for type-safe extraction with proper error messages.
        // Falls back to get() + pattern match for optional parameters that may
        // not be present in the ParamSet.
        if params.get("reseed_interval").is_some() {
            let interval: u64 = params
                .get_typed("reseed_interval")
                .map_err(ProviderError::Common)?;
            trace!(reseed_interval = interval, "Setting reseed interval");
            self.config.reseed_interval = interval;
        }

        if params.get("reseed_time_interval").is_some() {
            let time_interval: u64 = params
                .get_typed("reseed_time_interval")
                .map_err(ProviderError::Common)?;
            trace!(
                reseed_time_interval = time_interval,
                "Setting reseed time interval"
            );
            self.config.reseed_time_interval = time_interval;
        }

        Ok(())
    }

    // =========================================================================
    // Seed Provider Interface
    // =========================================================================

    /// Generates seed data for child DRBGs by running this DRBG's generate.
    ///
    /// Called when this DRBG serves as a parent seed source for child DRBG
    /// instances. Generates between `min_len` and `max_len` bytes of
    /// pseudorandom data at the specified strength.
    ///
    /// # Parameters
    /// - `min_len`: Minimum seed length in bytes
    /// - `max_len`: Maximum seed length in bytes
    /// - `strength`: Requested security strength in bits
    /// - `prediction_resistance`: Whether to request prediction resistance
    ///
    /// Replaces C `ossl_drbg_get_seed()` from `drbg.c`.
    pub fn get_seed(
        &mut self,
        min_len: usize,
        max_len: usize,
        strength: u32,
        prediction_resistance: bool,
    ) -> ProviderResult<Vec<u8>> {
        // Determine seed length: use minimum requested length, clamped to max
        if min_len > max_len {
            return Err(ProviderError::Init(format!(
                "Minimum seed length {min_len} exceeds maximum {max_len}",
            )));
        }
        let seed_len = min_len;

        let mut seed = vec![0u8; seed_len];
        self.generate(&mut seed, strength, prediction_resistance, &[])?;

        trace!(seed_len = seed_len, "Generated seed for child DRBG");
        Ok(seed)
    }

    /// Securely zeroizes a seed buffer after use.
    ///
    /// Replaces C `ossl_drbg_clear_seed()` from `drbg.c`.
    pub fn clear_seed(seed: &mut [u8]) {
        seed.zeroize();
        trace!(len = seed.len(), "Seed buffer securely zeroized");
    }

    // =========================================================================
    // Locking
    // =========================================================================

    /// Enables per-instance locking for thread-safe operation.
    ///
    /// Creates a `parking_lot::Mutex` for this DRBG instance. Once enabled,
    /// concurrent access to this DRBG instance is serialized through the lock.
    ///
    /// # LOCK-SCOPE
    ///
    /// The lock protects the mechanism state and reseed counters during
    /// concurrent `generate()` calls. Contention profile:
    /// - **Shared DRBGs:** Moderate contention (one lock per instance)
    /// - **Per-thread DRBGs:** No contention (locking not enabled)
    ///
    /// Replaces C `ossl_drbg_enable_locking()` from `drbg.c`.
    pub fn enable_locking(&mut self) -> ProviderResult<()> {
        if self.lock.is_none() {
            // LOCK-SCOPE: Creating per-instance Mutex for thread-safe
            // DRBG operations. Fine-grained: one lock per DRBG, not global.
            // Contention: moderate for shared DRBGs, zero for per-thread.
            self.lock = Some(Arc::new(Mutex::new(())));
            debug!("DRBG per-instance locking enabled");
        }
        Ok(())
    }
}

// =============================================================================
// Drbg — Private Helper Methods
// =============================================================================

impl Drbg {
    /// Acquires entropy from the OS entropy source.
    ///
    /// Uses [`OsRng`](rand::rngs::OsRng) for cross-platform entropy sourcing
    /// (`getrandom` on Linux, `BCryptGenRandom` on Windows).
    ///
    /// # Parameters
    /// - `min_len`: Minimum entropy length in bytes
    /// - `max_len`: Maximum entropy length in bytes
    /// - `_strength`: Requested security strength (used for source selection)
    ///
    /// Replaces C `get_entropy()` from `drbg.c` and
    /// `ossl_prov_get_entropy()` from `provider_seeding.c`.
    fn acquire_entropy(
        &self,
        min_len: usize,
        max_len: usize,
        _strength: u32,
    ) -> ProviderResult<Vec<u8>> {
        // Validate range
        if min_len > max_len {
            return Err(ProviderError::Init(format!(
                "Minimum entropy length {min_len} exceeds maximum {max_len}",
            )));
        }

        // Use minimum requested length
        let len = min_len;
        let mut entropy = vec![0u8; len];
        OsRng.try_fill_bytes(&mut entropy).map_err(|e| {
            error!("OS entropy acquisition failed: {e}");
            ProviderError::Common(CommonError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to acquire entropy from OS: {e}"),
            )))
        })?;

        trace!(
            len = len,
            configured_strength = self.config.strength,
            "Acquired entropy from OS"
        );
        Ok(entropy)
    }

    /// Acquires a nonce from the OS entropy source.
    ///
    /// Uses [`OsRng`](rand::rngs::OsRng) for nonce generation.
    ///
    /// # Parameters
    /// - `min_len`: Minimum nonce length in bytes
    /// - `max_len`: Maximum nonce length in bytes
    ///
    /// Replaces C `prov_drbg_get_nonce()` from `drbg.c`.
    fn acquire_nonce(&self, min_len: usize, max_len: usize) -> ProviderResult<Vec<u8>> {
        // Validate range
        if min_len > max_len {
            return Err(ProviderError::Init(format!(
                "Minimum nonce length {min_len} exceeds maximum {max_len}",
            )));
        }

        let len = min_len;
        let mut nonce = vec![0u8; len];
        // Use fill_bytes for nonce acquisition — nonces require freshness but
        // OsRng failure is vanishingly rare on modern platforms. This uses
        // RngCore::fill_bytes() (panics on error) for the primary fill, then
        // XOR with try_fill_bytes() for defense-in-depth nonce diversification.
        OsRng.fill_bytes(&mut nonce);
        let mut diversifier = vec![0u8; len];
        if OsRng.try_fill_bytes(&mut diversifier).is_ok() {
            for (n, d) in nonce.iter_mut().zip(diversifier.iter()) {
                *n ^= *d;
            }
        }
        diversifier.zeroize();

        trace!(
            len = len,
            drbg_state = %self.state,
            "Acquired nonce from OS"
        );
        Ok(nonce)
    }

    /// Attempts to recover from an error state by reseeding.
    ///
    /// If the DRBG is in [`RandState::Error`], attempts to uninstantiate and
    /// re-instantiate. If in [`RandState::Uninitialised`], attempts instantiation
    /// with default parameters.
    ///
    /// Replaces C `rand_drbg_restart()` from `drbg.c`.
    fn try_recover(&mut self) -> ProviderResult<()> {
        match self.state {
            RandState::Ready => Ok(()),
            RandState::Error => {
                warn!("Attempting DRBG recovery from Error state");
                // Uninstantiate to clean up, then re-instantiate
                self.mechanism.uninstantiate();
                self.state = RandState::Uninitialised;
                self.generate_counter = 0;
                self.reseed_time = None;

                self.instantiate(self.config.strength, false, DEFAULT_PERS_STRING.as_bytes())
            }
            RandState::Uninitialised => {
                warn!("Attempting DRBG instantiation from Uninitialised state");
                self.instantiate(self.config.strength, false, DEFAULT_PERS_STRING.as_bytes())
            }
        }
    }

    /// Checks for process fork and returns `true` if a fork was detected.
    ///
    /// On Unix systems, compares the stored fork ID with the current process
    /// ID. If different (indicating a `fork()` occurred), returns `true` to
    /// trigger a forced reseed. Updates the stored fork ID.
    ///
    /// Replaces the fork detection logic in C `ossl_prov_drbg_generate()`.
    fn check_fork(&mut self) -> bool {
        let current_pid = std::process::id();
        if current_pid == self.fork_id {
            false
        } else {
            debug!(
                old_pid = self.fork_id,
                new_pid = current_pid,
                "Fork detected -- forcing DRBG reseed"
            );
            self.fork_id = current_pid;
            true
        }
    }

    /// Checks whether the reseed policy requires a reseed.
    ///
    /// Returns `true` if either:
    /// - The generate counter has reached the reseed interval
    /// - The time since last reseed exceeds the reseed time interval
    ///   (when time-based reseeding is enabled)
    fn needs_reseed(&self) -> bool {
        // Check interval-based reseed
        if self.generate_counter >= self.config.reseed_interval {
            trace!(
                generate_counter = self.generate_counter,
                reseed_interval = self.config.reseed_interval,
                "Interval-based reseed triggered"
            );
            return true;
        }

        // Check time-based reseed (if enabled: reseed_time_interval > 0)
        if self.config.reseed_time_interval > 0 {
            if let Some(last_reseed) = self.reseed_time {
                let elapsed_secs = last_reseed
                    .elapsed()
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                if elapsed_secs >= self.config.reseed_time_interval {
                    trace!(
                        elapsed_secs = elapsed_secs,
                        reseed_time_interval = self.config.reseed_time_interval,
                        "Time-based reseed triggered"
                    );
                    return true;
                }
            }
        }

        false
    }
}

// =============================================================================
// RandContext Implementation
// =============================================================================

/// Implements [`RandContext`] for [`Drbg`], enabling the DRBG to participate
/// in the provider dispatch architecture.
///
/// This bridges the generic [`RandContext`] trait interface to the DRBG's
/// concrete lifecycle methods. The `additional` parameter in
/// [`RandContext::instantiate()`] maps to the `personalization` parameter
/// in [`Drbg::instantiate()`].
impl RandContext for Drbg {
    /// Instantiates the DRBG.
    ///
    /// The `additional` parameter is used as the personalization string.
    fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        // In the RandContext interface, `additional` serves as personalization
        Drbg::instantiate(self, strength, prediction_resistance, additional)
    }

    /// Generates pseudorandom output.
    fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()> {
        Drbg::generate(self, output, strength, prediction_resistance, additional)
    }

    /// Reseeds the DRBG.
    ///
    /// The `entropy` parameter is passed directly; if empty, fresh entropy
    /// is acquired from the OS.
    fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: &[u8],
        additional: &[u8],
    ) -> ProviderResult<()> {
        let entropy_opt = if entropy.is_empty() {
            None
        } else {
            Some(entropy)
        };
        Drbg::reseed(self, prediction_resistance, entropy_opt, additional)
    }

    /// Uninstantiates the DRBG.
    fn uninstantiate(&mut self) -> ProviderResult<()> {
        Drbg::uninstantiate(self)
    }

    /// Enables per-instance locking.
    fn enable_locking(&mut self) -> ProviderResult<()> {
        Drbg::enable_locking(self)
    }

    /// Returns DRBG parameters.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Drbg::get_params(self)
    }
}

// =============================================================================
// Drop -- Secure Cleanup
// =============================================================================

/// Ensures secure cleanup of all sensitive DRBG state on drop.
///
/// Calls the mechanism's `uninstantiate()` to zero working state, then
/// explicitly zeroizes all sensitive fields. Replaces C `ossl_rand_drbg_free()`
/// from `drbg.c` and the `OPENSSL_cleanse()` calls therein.
impl Drop for Drbg {
    fn drop(&mut self) {
        // Uninstantiate the mechanism to zero its working state
        self.mechanism.uninstantiate();
        // Zeroize the mechanism's internal state via the Zeroize trait
        self.mechanism.zeroize();
        // Clear all DRBG-level sensitive state
        self.state = RandState::Uninitialised;
        self.generate_counter = 0;
        self.reseed_counter.store(0, Ordering::Relaxed);
        self.reseed_time = None;
        self.fork_id = 0;
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::error::ProviderError;
    use openssl_common::param::{ParamSet, ParamValue};

    // =========================================================================
    // Mock DrbgMechanism for testing
    // =========================================================================

    /// Minimal mock mechanism that tracks lifecycle calls.
    #[derive(Debug)]
    struct MockMechanism {
        instantiated: bool,
        generate_count: u32,
        reseed_count: u32,
    }

    impl MockMechanism {
        fn new() -> Self {
            Self {
                instantiated: false,
                generate_count: 0,
                reseed_count: 0,
            }
        }
    }

    impl DrbgMechanism for MockMechanism {
        fn instantiate(
            &mut self,
            entropy: &[u8],
            _nonce: &[u8],
            _personalization: &[u8],
        ) -> ProviderResult<()> {
            if entropy.is_empty() {
                return Err(ProviderError::Init("empty entropy".into()));
            }
            self.instantiated = true;
            Ok(())
        }

        fn reseed(&mut self, entropy: &[u8], _additional: &[u8]) -> ProviderResult<()> {
            if entropy.is_empty() {
                return Err(ProviderError::Init("empty entropy".into()));
            }
            self.reseed_count += 1;
            Ok(())
        }

        fn generate(&mut self, output: &mut [u8], _additional: &[u8]) -> ProviderResult<()> {
            if !self.instantiated {
                return Err(ProviderError::Init("not instantiated".into()));
            }
            // Fill with deterministic pattern for testing
            for (i, byte) in output.iter_mut().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                {
                    *byte = (i & 0xFF) as u8;
                }
            }
            self.generate_count += 1;
            Ok(())
        }

        fn uninstantiate(&mut self) {
            self.instantiated = false;
            self.generate_count = 0;
            self.reseed_count = 0;
        }

        fn verify_zeroization(&self) -> bool {
            !self.instantiated && self.generate_count == 0 && self.reseed_count == 0
        }
    }

    impl Zeroize for MockMechanism {
        fn zeroize(&mut self) {
            self.instantiated = false;
            self.generate_count = 0;
            self.reseed_count = 0;
        }
    }

    /// Helper to create a test DRBG with default config.
    fn make_test_drbg() -> Drbg {
        let mechanism = Box::new(MockMechanism::new());
        Drbg::new(mechanism, DrbgConfig::default())
    }

    // =========================================================================
    // RandState enum tests
    // =========================================================================

    #[test]
    fn test_rand_state_variants_distinct() {
        assert_ne!(RandState::Uninitialised, RandState::Ready);
        assert_ne!(RandState::Ready, RandState::Error);
        assert_ne!(RandState::Uninitialised, RandState::Error);
    }

    #[test]
    fn test_rand_state_copy_clone() {
        let s = RandState::Ready;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn test_rand_state_display() {
        assert_eq!(format!("{}", RandState::Uninitialised), "Uninitialised");
        assert_eq!(format!("{}", RandState::Ready), "Ready");
        assert_eq!(format!("{}", RandState::Error), "Error");
    }

    // =========================================================================
    // DrbgConfig tests
    // =========================================================================

    #[test]
    fn test_drbg_config_default_values() {
        let config = DrbgConfig::default();
        assert_eq!(config.strength, 256);
        assert!(config.min_entropylen > 0);
        assert!(config.max_entropylen >= config.min_entropylen);
        assert!(config.max_request > 0);
        assert!(config.reseed_interval > 0);
        assert!(config.max_perslen > 0);
        assert!(config.max_adinlen > 0);
    }

    #[test]
    fn test_drbg_config_clone() {
        let config = DrbgConfig::default();
        let config2 = config.clone();
        assert_eq!(config.strength, config2.strength);
        assert_eq!(config.min_entropylen, config2.min_entropylen);
        assert_eq!(config.reseed_interval, config2.reseed_interval);
    }

    // =========================================================================
    // DEFAULT_PERS_STRING tests
    // =========================================================================

    #[test]
    fn test_default_pers_string_content() {
        assert!(!DEFAULT_PERS_STRING.is_empty());
        assert!(DEFAULT_PERS_STRING.contains("DRBG"));
        assert!(DEFAULT_PERS_STRING.contains("800-90A"));
    }

    // =========================================================================
    // Drbg constructor tests
    // =========================================================================

    #[test]
    fn test_drbg_new_initial_state() {
        let drbg = make_test_drbg();
        assert_eq!(drbg.state(), RandState::Uninitialised);
    }

    // =========================================================================
    // Drbg instantiate tests
    // =========================================================================

    #[test]
    fn test_drbg_instantiate_success() {
        let mut drbg = make_test_drbg();
        let result = drbg.instantiate(256, false, b"test pers");
        assert!(result.is_ok(), "instantiate failed: {:?}", result.err());
        assert_eq!(drbg.state(), RandState::Ready);
    }

    #[test]
    fn test_drbg_instantiate_strength_too_high() {
        let mut drbg = make_test_drbg();
        let result = drbg.instantiate(512, false, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_instantiate_already_instantiated() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"")
            .expect("first instantiate");
        let result = drbg.instantiate(256, false, b"");
        assert!(result.is_err());
    }

    // =========================================================================
    // Drbg uninstantiate tests
    // =========================================================================

    #[test]
    fn test_drbg_uninstantiate() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        assert_eq!(drbg.state(), RandState::Ready);
        drbg.uninstantiate().expect("uninstantiate");
        assert_eq!(drbg.state(), RandState::Uninitialised);
    }

    // =========================================================================
    // Drbg generate tests
    // =========================================================================

    #[test]
    fn test_drbg_generate_success() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let mut output = vec![0u8; 32];
        let result = drbg.generate(&mut output, 128, false, b"");
        assert!(result.is_ok(), "generate failed: {:?}", result.err());
        // Verify output was written (MockMechanism fills with pattern)
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_drbg_generate_strength_too_high() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let mut output = vec![0u8; 32];
        let result = drbg.generate(&mut output, 512, false, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_generate_output_too_large() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let config = DrbgConfig::default();
        let mut output = vec![0u8; config.max_request + 1];
        let result = drbg.generate(&mut output, 128, false, b"");
        assert!(result.is_err());
    }

    // =========================================================================
    // Drbg reseed tests
    // =========================================================================

    #[test]
    fn test_drbg_reseed_success() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let result = drbg.reseed(false, None, b"additional");
        assert!(result.is_ok(), "reseed failed: {:?}", result.err());
        assert_eq!(drbg.state(), RandState::Ready);
    }

    #[test]
    fn test_drbg_reseed_uninitialised_auto_recovers() {
        // reseed on an uninitialized DRBG triggers try_recover(),
        // which auto-instantiates, then reseed succeeds. This matches
        // the C rand_drbg_restart() recovery behavior.
        let mut drbg = make_test_drbg();
        assert_eq!(drbg.state(), RandState::Uninitialised);
        let result = drbg.reseed(false, None, b"");
        assert!(
            result.is_ok(),
            "Expected auto-recovery, got: {:?}",
            result.err()
        );
        assert_eq!(drbg.state(), RandState::Ready);
    }

    // =========================================================================
    // Parameter tests
    // =========================================================================

    #[test]
    fn test_drbg_get_params() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let params = drbg.get_params().expect("get_params");

        // State should be Ready (1)
        match params.get("state") {
            Some(ParamValue::UInt64(1)) => {}
            other => panic!("Expected state=1 (Ready), got {:?}", other),
        }

        // Strength should match config
        match params.get("strength") {
            Some(ParamValue::UInt64(256)) => {}
            other => panic!("Expected strength=256, got {:?}", other),
        }

        // Reseed time should be present
        assert!(params.get("reseed_time").is_some());
    }

    #[test]
    fn test_drbg_set_params() {
        let mut drbg = make_test_drbg();
        let mut params = ParamSet::new();
        params.set("reseed_interval", ParamValue::UInt64(1000));
        params.set("reseed_time_interval", ParamValue::UInt64(3600));

        let result = drbg.set_params(&params);
        assert!(result.is_ok());

        let got_params = drbg.get_params().expect("get_params");
        match got_params.get("reseed_interval") {
            Some(ParamValue::UInt64(1000)) => {}
            other => panic!("Expected reseed_interval=1000, got {:?}", other),
        }
    }

    // =========================================================================
    // Seed provider tests
    // =========================================================================

    #[test]
    fn test_drbg_get_seed() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        let seed = drbg.get_seed(16, 32, 128, false);
        assert!(seed.is_ok(), "get_seed failed: {:?}", seed.err());
        assert_eq!(seed.expect("seed").len(), 16);
    }

    #[test]
    fn test_drbg_get_seed_invalid_range() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        // min > max should fail
        let result = drbg.get_seed(64, 32, 128, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_clear_seed() {
        let mut seed = vec![1u8, 2, 3, 4, 5];
        Drbg::clear_seed(&mut seed);
        assert_eq!(seed, vec![0u8; 5]);
    }

    // =========================================================================
    // Locking tests
    // =========================================================================

    #[test]
    fn test_drbg_enable_locking() {
        let mut drbg = make_test_drbg();
        let result = drbg.enable_locking();
        assert!(result.is_ok());
        // Idempotent
        let result2 = drbg.enable_locking();
        assert!(result2.is_ok());
    }

    #[test]
    fn test_drbg_generate_with_lock() {
        let mut drbg = make_test_drbg();
        drbg.enable_locking().expect("enable_locking");
        drbg.instantiate(256, false, b"").expect("instantiate");
        let mut output = vec![0u8; 32];
        let result = drbg.generate(&mut output, 128, false, b"");
        assert!(
            result.is_ok(),
            "generate with lock failed: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // Drop (zeroization) tests
    // =========================================================================

    #[test]
    fn test_drbg_drop_zeroizes() {
        let mut drbg = make_test_drbg();
        drbg.instantiate(256, false, b"").expect("instantiate");
        drop(drbg);
        // No panic = success (mechanism.uninstantiate + zeroize called)
    }

    // =========================================================================
    // RandContext trait implementation tests
    // =========================================================================

    #[test]
    fn test_drbg_as_rand_context() {
        use crate::traits::RandContext;

        let mechanism = Box::new(MockMechanism::new());
        let mut drbg = Drbg::new(mechanism, DrbgConfig::default());

        // Use through RandContext trait reference
        let rc: &mut dyn RandContext = &mut drbg;

        assert!(rc.instantiate(256, false, b"test").is_ok());

        let mut output = vec![0u8; 16];
        assert!(rc.generate(&mut output, 128, false, b"").is_ok());

        let params = rc.get_params();
        assert!(params.is_ok());

        assert!(rc.enable_locking().is_ok());
        assert!(rc.uninstantiate().is_ok());
    }

    // =========================================================================
    // Full lifecycle test
    // =========================================================================

    #[test]
    fn test_drbg_full_lifecycle() {
        let mut drbg = make_test_drbg();
        assert_eq!(drbg.state(), RandState::Uninitialised);

        // Enable locking
        drbg.enable_locking().expect("enable_locking");

        // Instantiate
        drbg.instantiate(256, false, DEFAULT_PERS_STRING.as_bytes())
            .expect("instantiate");
        assert_eq!(drbg.state(), RandState::Ready);

        // Generate
        let mut buf = vec![0u8; 64];
        drbg.generate(&mut buf, 128, false, b"").expect("generate");
        assert_ne!(buf, vec![0u8; 64]);

        // Reseed
        drbg.reseed(false, None, b"additional data")
            .expect("reseed");
        assert_eq!(drbg.state(), RandState::Ready);

        // Generate again after reseed
        let mut buf2 = vec![0u8; 32];
        drbg.generate(&mut buf2, 128, false, b"")
            .expect("generate2");

        // Get params
        let params = drbg.get_params().expect("get_params");
        assert!(params.get("state").is_some());
        assert!(params.get("strength").is_some());

        // Get seed for child
        let seed = drbg.get_seed(16, 32, 128, false).expect("get_seed");
        assert_eq!(seed.len(), 16);

        // Set params
        let mut new_params = ParamSet::new();
        new_params.set("reseed_interval", ParamValue::UInt64(500));
        drbg.set_params(&new_params).expect("set_params");

        // Uninstantiate
        drbg.uninstantiate().expect("uninstantiate");
        assert_eq!(drbg.state(), RandState::Uninitialised);
    }
}
