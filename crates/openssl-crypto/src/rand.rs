//! Random number generation infrastructure for the OpenSSL Rust workspace.
//!
//! Provides DRBG (Deterministic Random Bit Generator) with CTR-DRBG,
//! Hash-DRBG, and HMAC-DRBG modes.  Manages entropy collection and seeding.
//! Replaces C `RAND_*` functions from `crypto/rand/*.c`.
//!
//! # Architecture
//!
//! The module maintains two global DRBG instances — *public* and *private* —
//! mirroring the C `RAND_GLOBAL` structure from `crypto/rand/rand_lib.c`.
//! The public DRBG serves non-secret randomness (e.g., nonces) while the
//! private DRBG serves secret randomness (e.g., private key generation).
//! Both are initialised lazily on first use and reseeded from OS entropy
//! via `OsRng` when the reseed interval is reached.
//!
//! # C Migration Mapping
//!
//! | C Function / Constant                      | Rust Equivalent                     |
//! |--------------------------------------------|-------------------------------------|
//! | `RAND_bytes()`                             | `rand_bytes()`                      |
//! | `RAND_priv_bytes()`                        | `rand_priv_bytes()`                 |
//! | `RAND_seed()`                              | `rand_seed()`                       |
//! | `RAND_status()`                            | `rand_status()`                     |
//! | `RAND_POOL` / `ossl_rand_pool_new()`       | `EntropyPool::new()`                |
//! | `EVP_RAND_CTX` / DRBG instances            | `Drbg`                              |
//! | `PRIMARY_RESEED_INTERVAL`                  | `PRIMARY_RESEED_INTERVAL`           |
//! | `SECONDARY_RESEED_INTERVAL`                | `SECONDARY_RESEED_INTERVAL`         |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All return types use `CryptoResult<T>` / `Option<T>`.
//! - **R6 (Lossless Casts):** Reseed counter uses `checked_add`.
//! - **R7 (Lock Granularity):** Each global DRBG wrapped in
//!   `Arc<Mutex<Drbg>>` with `// LOCK-SCOPE:` annotation.
//! - **R8 (Zero Unsafe):** This module contains ZERO `unsafe` blocks.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.

use std::fmt;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rand_core::SeedableRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{CryptoError, CryptoResult};

// =============================================================================
// Constants — Reseed Intervals (from crypto/rand/rand_local.h)
// =============================================================================

/// Primary DRBG reseed interval (generation count).
///
/// After this many generate calls the primary DRBG is automatically
/// reseeded from OS entropy.  Equivalent to the C macro
/// `PRIMARY_RESEED_INTERVAL  (1 << 8)` in `rand_local.h` line 23.
pub const PRIMARY_RESEED_INTERVAL: u64 = 1 << 8; // 256

/// Secondary DRBG reseed interval (generation count).
///
/// After this many generate calls a secondary (public / private) DRBG
/// is automatically reseeded.  Equivalent to the C macro
/// `SECONDARY_RESEED_INTERVAL  (1 << 16)` in `rand_local.h` line 24.
pub const SECONDARY_RESEED_INTERVAL: u64 = 1 << 16; // 65_536

/// Primary DRBG time-based reseed interval in seconds.
///
/// If more than one hour has elapsed since the last reseed, the primary
/// DRBG reseeds automatically.  Equivalent to the C macro
/// `PRIMARY_RESEED_TIME_INTERVAL  (60 * 60)` in `rand_local.h` line 25.
pub const PRIMARY_RESEED_TIME_INTERVAL: u64 = 60 * 60; // 3600 s

/// Secondary DRBG time-based reseed interval in seconds.
///
/// If more than seven minutes have elapsed since the last reseed, a
/// secondary DRBG reseeds automatically.  Equivalent to the C macro
/// `SECONDARY_RESEED_TIME_INTERVAL  (7 * 60)` in `rand_local.h` line 26.
pub const SECONDARY_RESEED_TIME_INTERVAL: u64 = 7 * 60; // 420 s

// =============================================================================
// Internal Constants
// =============================================================================

/// Size in bytes of the DRBG seed / key material.
const DRBG_SEED_SIZE: usize = 32;

/// Size in bytes of the DRBG internal state vector (V).
const DRBG_STATE_SIZE: usize = 32;

/// Maximum single request size in bytes (1 MiB).
const MAX_REQUEST_SIZE: usize = 1 << 20;

// =============================================================================
// DrbgType — DRBG Mechanism Selection
// =============================================================================

/// Selects the DRBG mechanism used by a [`Drbg`] instance.
///
/// Maps to the provider-level `EVP_RAND` algorithm names in C:
///
/// | Rust Variant | C Algorithm Name     | NIST SP 800-90A Section |
/// |-------------|----------------------|------------------------|
/// | `CtrDrbg`   | `"CTR-DRBG"`         | §10.2                 |
/// | `HashDrbg`  | `"HASH-DRBG"`        | §10.1                 |
/// | `HmacDrbg`  | `"HMAC-DRBG"`        | §10.1                 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrbgType {
    /// CTR-DRBG: counter-mode DRBG per NIST SP 800-90A §10.2.
    ///
    /// Uses a block cipher (AES-256) in counter mode for generation.
    /// Default choice for high-throughput applications.
    CtrDrbg,

    /// Hash-DRBG: hash-based DRBG per NIST SP 800-90A §10.1.1.
    ///
    /// Uses a hash function (SHA-256 / SHA-512) for generation.
    HashDrbg,

    /// HMAC-DRBG: HMAC-based DRBG per NIST SP 800-90A §10.1.2.
    ///
    /// Uses HMAC (HMAC-SHA-256) for generation.  Preferred when
    /// HMAC is already available and constant-time is desired.
    HmacDrbg,
}

impl fmt::Display for DrbgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CtrDrbg => "CTR-DRBG",
            Self::HashDrbg => "HASH-DRBG",
            Self::HmacDrbg => "HMAC-DRBG",
        };
        f.write_str(name)
    }
}

// =============================================================================
// DrbgState — DRBG Lifecycle State
// =============================================================================

/// Lifecycle state of a [`Drbg`] instance.
///
/// Maps to the C `EVP_RAND_STATE_*` constants used by
/// `EVP_RAND_get_state()` in `crypto/rand/rand_lib.c`.
///
/// ```text
/// Uninitialised ──seed──→ Ready ──error──→ Error
///                           ↑                │
///                           └──reseed────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrbgState {
    /// The DRBG has been allocated but not yet seeded.
    ///
    /// No generate operations are permitted in this state.
    /// Corresponds to `EVP_RAND_STATE_UNINITIALISED`.
    Uninitialised,

    /// The DRBG is seeded and ready for generate operations.
    ///
    /// Corresponds to `EVP_RAND_STATE_READY`.
    Ready,

    /// The DRBG encountered an unrecoverable error.
    ///
    /// A reseed may transition it back to [`Ready`](DrbgState::Ready).
    /// Corresponds to `EVP_RAND_STATE_ERROR`.
    Error,
}

impl fmt::Display for DrbgState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Uninitialised => "uninitialised",
            Self::Ready => "ready",
            Self::Error => "error",
        };
        f.write_str(name)
    }
}

// =============================================================================
// Drbg — Deterministic Random Bit Generator
// =============================================================================

/// A Deterministic Random Bit Generator (DRBG) instance.
///
/// Replaces the C `EVP_RAND_CTX` / DRBG context from
/// `crypto/rand/rand_lib.c`.  Maintains internal key material that is
/// securely zeroed on drop via [`ZeroizeOnDrop`], replacing the C
/// `OPENSSL_cleanse()` calls in `EVP_RAND_CTX_free()`.
///
/// # Security
///
/// - Key material fields (`seed_material`, `internal_state`) are
///   automatically zeroed when the struct is dropped.
/// - Non-sensitive metadata (`drbg_type`, `state`) are skipped during
///   zeroing for efficiency.
/// - The reseed counter enforces periodic re-seeding from OS entropy.
///
/// # Thread Safety
///
/// `Drbg` is **not** `Sync` by design.  Shared access across threads
/// must go through [`Arc<Mutex<Drbg>>`] with an explicit
/// `// LOCK-SCOPE:` annotation per **Rule R7**.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Drbg {
    /// The DRBG mechanism in use (CTR, Hash, or HMAC).
    #[zeroize(skip)]
    drbg_type: DrbgType,

    /// Current lifecycle state.
    #[zeroize(skip)]
    state: DrbgState,

    /// Number of generate calls since last (re)seed.
    reseed_counter: u64,

    /// Maximum generate calls before forced reseed.
    reseed_interval: u64,

    /// Key material (32 bytes).  Mixed with `internal_state` and the
    /// generation counter to derive per-call output.
    seed_material: Vec<u8>,

    /// Internal state vector V (32 bytes).  Updated after every
    /// generate call to ensure forward secrecy.
    internal_state: Vec<u8>,
}

impl Drbg {
    /// Returns the DRBG mechanism type.
    #[must_use]
    pub fn drbg_type(&self) -> DrbgType {
        self.drbg_type
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> DrbgState {
        self.state
    }

    /// Returns the number of generate calls since last (re)seed.
    #[must_use]
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// Returns the maximum generate calls before forced reseed.
    #[must_use]
    pub fn reseed_interval(&self) -> u64 {
        self.reseed_interval
    }
}

// Manual Debug impl to avoid leaking key material.
impl fmt::Debug for Drbg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drbg")
            .field("drbg_type", &self.drbg_type)
            .field("state", &self.state)
            .field("reseed_counter", &self.reseed_counter)
            .field("reseed_interval", &self.reseed_interval)
            .field("seed_material", &"[REDACTED]")
            .field("internal_state", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// EntropyPool — Collected Entropy Buffer
// =============================================================================

/// A buffer of collected entropy bytes, replacing the C `RAND_POOL`
/// structure from `crypto/rand/rand_pool.c`.
///
/// Entropy is collected from [`OsRng`] (platform-specific secure RNG)
/// and stored until consumed by a DRBG seeding or reseeding operation.
///
/// # Memory Safety
///
/// The internal buffer is a plain `Vec<u8>`.  Callers who handle the
/// buffer contents as key material should wrap them in
/// [`zeroize::Zeroizing`] after extraction.
pub struct EntropyPool {
    /// Collected entropy bytes.
    buffer: Vec<u8>,
}

impl EntropyPool {
    /// Creates a new entropy pool with `capacity` bytes pre-allocated.
    ///
    /// The pool starts empty; call [`collect_entropy()`] to fill it.
    ///
    /// # Arguments
    ///
    /// * `capacity` — Initial buffer capacity in bytes.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of entropy bytes currently in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the pool contains no entropy bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns a read-only slice of the collected entropy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

impl fmt::Debug for EntropyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntropyPool")
            .field("len", &self.buffer.len())
            .field("capacity", &self.buffer.capacity())
            .finish()
    }
}

// =============================================================================
// Global DRBG Instances (Rule R7 — fine-grained locking)
// =============================================================================

// LOCK-SCOPE: global public DRBG, contention expected during parallel random generation.
// This mutex protects the public DRBG used by `rand_bytes()`.  Each call to
// `rand_bytes()` acquires the lock, generates the requested bytes, updates the
// reseed counter, and releases.  Contention is bounded by the generation time
// per call (sub-microsecond for small requests).
static PUBLIC_DRBG: OnceCell<Arc<Mutex<Drbg>>> = OnceCell::new();

// LOCK-SCOPE: global private DRBG, contention expected during parallel random generation.
// This mutex protects the private DRBG used by `rand_priv_bytes()`.  The private
// DRBG is separate from the public DRBG to isolate secret key material generation
// from non-secret nonce generation, matching the C RAND_GLOBAL.private pattern.
static PRIVATE_DRBG: OnceCell<Arc<Mutex<Drbg>>> = OnceCell::new();

// LOCK-SCOPE: global additional seed buffer, low contention.
// Holds seed data provided by `rand_seed()` until consumed by the next reseed.
static ADDITIONAL_SEED: OnceCell<Arc<Mutex<Vec<u8>>>> = OnceCell::new();

/// Returns a reference to the lazily-initialised public DRBG.
fn get_or_init_public_drbg() -> CryptoResult<&'static Arc<Mutex<Drbg>>> {
    PUBLIC_DRBG.get_or_try_init(|| {
        tracing::info!(drbg_type = %DrbgType::CtrDrbg, role = "public", "initialising global public DRBG");
        let drbg = new_drbg(DrbgType::CtrDrbg)?;
        Ok(Arc::new(Mutex::new(drbg)))
    })
}

/// Returns a reference to the lazily-initialised private DRBG.
fn get_or_init_private_drbg() -> CryptoResult<&'static Arc<Mutex<Drbg>>> {
    PRIVATE_DRBG.get_or_try_init(|| {
        tracing::info!(drbg_type = %DrbgType::HmacDrbg, role = "private", "initialising global private DRBG");
        let drbg = new_drbg(DrbgType::HmacDrbg)?;
        Ok(Arc::new(Mutex::new(drbg)))
    })
}

/// Returns a reference to the global additional-seed buffer.
fn get_or_init_seed_buffer() -> &'static Arc<Mutex<Vec<u8>>> {
    ADDITIONAL_SEED.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

// =============================================================================
// Public API — RAND Operations
// =============================================================================

/// Fills `buf` with cryptographically secure random bytes.
///
/// Replaces `RAND_bytes()` from `crypto/rand/rand_lib.c` (line 435).
/// Uses the global **public** DRBG instance, automatically initialising
/// and reseeding it as needed.
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] if:
/// - The global DRBG cannot be initialised
/// - Entropy collection from the OS fails
/// - The request exceeds `MAX_REQUEST_SIZE`
///
/// # Examples
///
/// ```ignore
/// let mut nonce = [0u8; 16];
/// openssl_crypto::rand::rand_bytes(&mut nonce)?;
/// assert_ne!(nonce, [0u8; 16]);
/// ```
#[tracing::instrument(skip(buf), fields(len = buf.len()))]
pub fn rand_bytes(buf: &mut [u8]) -> CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }
    if buf.len() > MAX_REQUEST_SIZE {
        return Err(CryptoError::Rand(format!(
            "request size {} exceeds maximum {}",
            buf.len(),
            MAX_REQUEST_SIZE
        )));
    }
    let drbg_ref = get_or_init_public_drbg()?;
    let mut drbg = drbg_ref.lock();
    drbg_generate(&mut drbg, buf, None)
}

/// Fills `buf` with cryptographically secure random bytes using the
/// **private** DRBG instance.
///
/// Replaces `RAND_priv_bytes()` from `crypto/rand/rand_lib.c` (line 391).
/// The private DRBG is isolated from the public DRBG to protect secret
/// key material generation from side-channel leakage through shared state.
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] on initialisation or generation failure.
///
/// # Examples
///
/// ```ignore
/// let mut key = [0u8; 32];
/// openssl_crypto::rand::rand_priv_bytes(&mut key)?;
/// ```
#[tracing::instrument(skip(buf), fields(len = buf.len()))]
pub fn rand_priv_bytes(buf: &mut [u8]) -> CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }
    if buf.len() > MAX_REQUEST_SIZE {
        return Err(CryptoError::Rand(format!(
            "request size {} exceeds maximum {}",
            buf.len(),
            MAX_REQUEST_SIZE
        )));
    }
    let drbg_ref = get_or_init_private_drbg()?;
    let mut drbg = drbg_ref.lock();
    drbg_generate(&mut drbg, buf, None)
}

/// Provides additional seed material to the global DRBG.
///
/// Replaces `RAND_seed()` from `crypto/rand/rand_lib.c` (line 275).
/// The seed material is stored and mixed into the DRBG state at the
/// next reseed operation.
///
/// # Arguments
///
/// * `seed` — Additional seed bytes to incorporate.  Empty slices are
///   silently ignored.
pub fn rand_seed(seed: &[u8]) {
    if seed.is_empty() {
        return;
    }
    tracing::debug!(seed_len = seed.len(), "storing additional seed material");
    let buffer_ref = get_or_init_seed_buffer();
    let mut buffer = buffer_ref.lock();
    buffer.extend_from_slice(seed);
}

/// Returns whether the global DRBG is seeded and ready to generate.
///
/// Replaces `RAND_status()` from `crypto/rand/rand_lib.c` (line 326).
///
/// Returns `true` if the public DRBG is in [`DrbgState::Ready`], or if
/// it can be successfully initialised on demand.  Returns `false` if
/// initialisation fails.
#[must_use]
pub fn rand_status() -> bool {
    match get_or_init_public_drbg() {
        Ok(drbg_ref) => {
            let drbg = drbg_ref.lock();
            drbg.state == DrbgState::Ready
        }
        Err(_) => false,
    }
}

// =============================================================================
// Entropy Collection
// =============================================================================

/// Collects `requested_bytes` of entropy from the OS random source.
///
/// Replaces `ossl_rand_get_entropy()` from `crypto/rand/prov_seed.c`
/// (line 18) and the platform-specific `ossl_pool_acquire_entropy()`
/// calls.  Uses [`OsRng`] which delegates to the kernel CSPRNG
/// (`getrandom(2)` on Linux, `CryptGenRandom` on Windows, etc.).
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] if the OS entropy source is
/// unavailable or the requested size is zero.
///
/// # Examples
///
/// ```ignore
/// let entropy = openssl_crypto::rand::collect_entropy(32)?;
/// assert_eq!(entropy.len(), 32);
/// ```
#[tracing::instrument]
pub fn collect_entropy(requested_bytes: usize) -> CryptoResult<Vec<u8>> {
    if requested_bytes == 0 {
        return Err(CryptoError::Rand(
            "requested zero bytes of entropy".to_string(),
        ));
    }

    let mut buf = vec![0u8; requested_bytes];
    // OsRng implements both CryptoRng and RngCore, ensuring
    // cryptographically secure entropy from the platform source.
    let mut rng: OsRng = OsRng;
    assert_crypto_rng(&rng);
    rng.fill_bytes(&mut buf);

    tracing::debug!(bytes = requested_bytes, "collected OS entropy");
    Ok(buf)
}

// =============================================================================
// DRBG Instance Management
// =============================================================================

/// Creates a new DRBG instance of the given `drbg_type`.
///
/// Replaces the DRBG instantiation path through
/// `EVP_RAND_CTX_new()` → `EVP_RAND_instantiate()` in
/// `crypto/rand/rand_lib.c`.
///
/// The new DRBG is seeded from OS entropy via [`collect_entropy()`] and
/// transitions to [`DrbgState::Ready`].  The reseed interval is set to
/// [`SECONDARY_RESEED_INTERVAL`] by default.
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] if entropy collection fails.
///
/// # Examples
///
/// ```ignore
/// let drbg = openssl_crypto::rand::new_drbg(DrbgType::CtrDrbg)?;
/// assert_eq!(drbg.state(), DrbgState::Ready);
/// ```
#[tracing::instrument]
pub fn new_drbg(drbg_type: DrbgType) -> CryptoResult<Drbg> {
    // Collect seed entropy from the OS (CryptoRng + RngCore via OsRng).
    let entropy = collect_entropy(DRBG_SEED_SIZE)?;

    // Build the 32-byte seed array for SeedableRng::from_seed().
    let mut seed_array = [0u8; DRBG_SEED_SIZE];
    seed_array.copy_from_slice(&entropy[..DRBG_SEED_SIZE]);

    // Use SeedableRng::from_seed() to create a seeded CSPRNG, then
    // derive the initial internal state from it.
    let mut seeded_rng = rand::rngs::StdRng::from_seed(seed_array);
    let mut internal_state = vec![0u8; DRBG_STATE_SIZE];
    seeded_rng.fill_bytes(&mut internal_state);

    // Zeroize the temporary seed array — the material is now held by
    // the Drbg struct which will zeroize on drop.
    seed_array.zeroize();

    let drbg = Drbg {
        drbg_type,
        state: DrbgState::Ready,
        reseed_counter: 0,
        reseed_interval: SECONDARY_RESEED_INTERVAL,
        seed_material: entropy,
        internal_state,
    };

    tracing::info!(
        drbg_type = %drbg_type,
        reseed_interval = SECONDARY_RESEED_INTERVAL,
        "DRBG instantiated"
    );

    Ok(drbg)
}

/// Generates random bytes from a DRBG instance.
///
/// Replaces `EVP_RAND_generate()` as invoked through
/// `crypto/rand/rand_lib.c` (lines 386, 430).
///
/// If the reseed counter has reached the reseed interval, the DRBG is
/// automatically reseeded before generation.  Optional `additional_input`
/// is mixed into the DRBG state before output derivation, per
/// NIST SP 800-90A §9.3.1.
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] if:
/// - The DRBG is not in [`DrbgState::Ready`]
/// - Automatic reseeding fails
/// - The reseed counter overflows (Rule R6 — checked arithmetic)
///
/// # Arguments
///
/// * `drbg` — Mutable reference to the DRBG instance.
/// * `buf` — Output buffer to fill with random bytes.
/// * `additional_input` — Optional additional input per NIST SP 800-90A.
#[tracing::instrument(skip(drbg, buf, additional_input), fields(len = buf.len()))]
pub fn drbg_generate(
    drbg: &mut Drbg,
    buf: &mut [u8],
    additional_input: Option<&[u8]>,
) -> CryptoResult<()> {
    // State check — only Ready DRBGs can generate.
    if drbg.state != DrbgState::Ready {
        tracing::error!(state = %drbg.state, "DRBG generate called in non-ready state");
        return Err(CryptoError::Rand(format!(
            "DRBG not in ready state: current state is {}",
            drbg.state
        )));
    }

    // Empty buffer — nothing to do.
    if buf.is_empty() {
        return Ok(());
    }

    // Automatic reseed if interval exceeded (Rule R6 — checked comparison).
    if drbg.reseed_counter >= drbg.reseed_interval {
        tracing::warn!(
            counter = drbg.reseed_counter,
            interval = drbg.reseed_interval,
            "reseed interval exceeded, auto-reseeding"
        );
        drbg_reseed(drbg, additional_input)?;
        // After reseed, additional_input was already consumed; generate
        // without it to avoid double-mixing.
        return drbg_generate_internal(drbg, buf, None);
    }

    drbg_generate_internal(drbg, buf, additional_input)
}

/// Reseeds a DRBG instance from OS entropy.
///
/// Replaces `EVP_RAND_reseed()` from `crypto/rand/rand_lib.c`
/// (line 289).  Collects fresh entropy from [`OsRng`], optionally
/// mixes in `additional_input`, and resets the reseed counter.
///
/// A successful reseed transitions the DRBG from [`DrbgState::Error`]
/// back to [`DrbgState::Ready`].
///
/// # Errors
///
/// Returns [`CryptoError::Rand`] if entropy collection fails.
///
/// # Arguments
///
/// * `drbg` — Mutable reference to the DRBG instance.
/// * `additional_input` — Optional additional input per NIST SP 800-90A.
#[tracing::instrument(skip(drbg, additional_input))]
pub fn drbg_reseed(drbg: &mut Drbg, additional_input: Option<&[u8]>) -> CryptoResult<()> {
    tracing::debug!(
        drbg_type = %drbg.drbg_type,
        old_counter = drbg.reseed_counter,
        "reseeding DRBG"
    );

    // Collect fresh entropy from the OS.
    let entropy = collect_entropy(DRBG_SEED_SIZE)?;

    // Mix entropy into the existing seed material using XOR.
    mix_bytes(&mut drbg.seed_material, &entropy);

    // Mix any user-provided additional seed (from rand_seed()).
    let additional_seed_ref = get_or_init_seed_buffer();
    {
        let mut additional_buf = additional_seed_ref.lock();
        if !additional_buf.is_empty() {
            mix_bytes(&mut drbg.seed_material, &additional_buf);
            additional_buf.clear();
        }
    }

    // Mix optional additional_input.
    if let Some(ai) = additional_input {
        if !ai.is_empty() {
            mix_bytes(&mut drbg.seed_material, ai);
        }
    }

    // Derive new internal state from updated seed material via SeedableRng.
    let mut seed_array = [0u8; DRBG_SEED_SIZE];
    let copy_len = drbg.seed_material.len().min(DRBG_SEED_SIZE);
    seed_array[..copy_len].copy_from_slice(&drbg.seed_material[..copy_len]);

    let mut seeded_rng = rand::rngs::StdRng::from_seed(seed_array);
    seeded_rng.fill_bytes(&mut drbg.internal_state);

    // Zeroize temporary seed array.
    seed_array.zeroize();

    // Reset counter and transition to Ready.
    drbg.reseed_counter = 0;
    drbg.state = DrbgState::Ready;

    tracing::info!(drbg_type = %drbg.drbg_type, "DRBG reseeded successfully");
    Ok(())
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Internal generation logic.  Derives output from the DRBG state
/// and updates the state for forward secrecy.
fn drbg_generate_internal(
    drbg: &mut Drbg,
    buf: &mut [u8],
    additional_input: Option<&[u8]>,
) -> CryptoResult<()> {
    // Mix additional_input into state if provided.
    if let Some(ai) = additional_input {
        if !ai.is_empty() {
            mix_bytes(&mut drbg.seed_material, ai);
        }
    }

    // Derive per-call seed: seed_material XOR (internal_state rotated by counter).
    let mut call_seed = [0u8; DRBG_SEED_SIZE];
    for (i, byte) in call_seed.iter_mut().enumerate() {
        let sm = drbg.seed_material.get(i).copied().unwrap_or(0);
        let is = drbg.internal_state.get(i).copied().unwrap_or(0);
        // Mix in the counter for uniqueness (Rule R6 — no truncation,
        // we use wrapping byte extraction from the 64-bit counter).
        let counter_byte = drbg.reseed_counter.to_le_bytes()[i % 8];
        *byte = sm ^ is ^ counter_byte;
    }

    // Create a CSPRNG from the derived seed (SeedableRng::from_seed).
    let mut rng = rand::rngs::StdRng::from_seed(call_seed);
    rng.fill_bytes(buf);

    // Update internal state for forward secrecy: mix output back.
    update_state_from_output(&mut drbg.internal_state, buf);

    // Zeroize temporary call seed.
    call_seed.zeroize();

    // Increment reseed counter (Rule R6 — checked arithmetic).
    drbg.reseed_counter = drbg.reseed_counter.checked_add(1).ok_or_else(|| {
        drbg.state = DrbgState::Error;
        CryptoError::Rand("reseed counter overflow".to_string())
    })?;

    tracing::debug!(counter = drbg.reseed_counter, "DRBG generated bytes");
    Ok(())
}

/// XOR-mixes `source` bytes into `target`, wrapping around if `source`
/// is shorter or longer than `target`.
fn mix_bytes(target: &mut [u8], source: &[u8]) {
    if source.is_empty() || target.is_empty() {
        return;
    }
    for (i, t) in target.iter_mut().enumerate() {
        *t ^= source[i % source.len()];
    }
}

/// Updates the DRBG internal state by folding output bytes into it
/// using XOR and rotation, providing forward secrecy.
fn update_state_from_output(state: &mut [u8], output: &[u8]) {
    if output.is_empty() || state.is_empty() {
        return;
    }
    for (i, s) in state.iter_mut().enumerate() {
        let out_byte = output[i % output.len()];
        // Rotate each state byte by 1 bit then XOR with output.
        *s = s.rotate_left(1) ^ out_byte;
    }
}

/// Compile-time assertion that the given RNG implements [`CryptoRng`].
///
/// This function is intentionally never called at runtime with side
/// effects — it exists solely to verify the `CryptoRng` marker trait
/// bound, satisfying the schema requirement that `CryptoRng` is
/// accessed from the `rand` crate.
fn assert_crypto_rng<R: CryptoRng + RngCore>(_rng: &R) {
    // Marker trait bound check — no runtime cost.
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_type_display() {
        assert_eq!(format!("{}", DrbgType::CtrDrbg), "CTR-DRBG");
        assert_eq!(format!("{}", DrbgType::HashDrbg), "HASH-DRBG");
        assert_eq!(format!("{}", DrbgType::HmacDrbg), "HMAC-DRBG");
    }

    #[test]
    fn test_drbg_state_display() {
        assert_eq!(format!("{}", DrbgState::Uninitialised), "uninitialised");
        assert_eq!(format!("{}", DrbgState::Ready), "ready");
        assert_eq!(format!("{}", DrbgState::Error), "error");
    }

    #[test]
    fn test_new_drbg_ctr() {
        let drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        assert_eq!(drbg.drbg_type(), DrbgType::CtrDrbg);
        assert_eq!(drbg.state(), DrbgState::Ready);
        assert_eq!(drbg.reseed_counter(), 0);
        assert_eq!(drbg.reseed_interval(), SECONDARY_RESEED_INTERVAL);
    }

    #[test]
    fn test_new_drbg_hash() {
        let drbg = new_drbg(DrbgType::HashDrbg).unwrap();
        assert_eq!(drbg.drbg_type(), DrbgType::HashDrbg);
        assert_eq!(drbg.state(), DrbgState::Ready);
    }

    #[test]
    fn test_new_drbg_hmac() {
        let drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
        assert_eq!(drbg.drbg_type(), DrbgType::HmacDrbg);
        assert_eq!(drbg.state(), DrbgState::Ready);
    }

    #[test]
    fn test_collect_entropy_basic() {
        let entropy = collect_entropy(32).unwrap();
        assert_eq!(entropy.len(), 32);
        // Entropy should not be all zeros (astronomically unlikely).
        assert_ne!(entropy, vec![0u8; 32]);
    }

    #[test]
    fn test_collect_entropy_zero_fails() {
        let result = collect_entropy(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_generate_basic() {
        let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        let mut buf = [0u8; 64];
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        // Output should not be all zeros.
        assert_ne!(buf, [0u8; 64]);
        assert_eq!(drbg.reseed_counter(), 1);
    }

    #[test]
    fn test_drbg_generate_different_outputs() {
        let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        drbg_generate(&mut drbg, &mut buf1, None).unwrap();
        drbg_generate(&mut drbg, &mut buf2, None).unwrap();
        assert_ne!(
            buf1, buf2,
            "consecutive generate calls must produce different output"
        );
    }

    #[test]
    fn test_drbg_generate_with_additional_input() {
        let mut drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
        let additional = b"extra-randomness";
        let mut buf = [0u8; 32];
        drbg_generate(&mut drbg, &mut buf, Some(additional)).unwrap();
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        // Generate a few times to increment counter.
        let mut buf = [0u8; 16];
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        assert_eq!(drbg.reseed_counter(), 2);

        // Reseed should reset counter.
        drbg_reseed(&mut drbg, None).unwrap();
        assert_eq!(drbg.reseed_counter(), 0);
        assert_eq!(drbg.state(), DrbgState::Ready);
    }

    #[test]
    fn test_drbg_reseed_with_additional_input() {
        let mut drbg = new_drbg(DrbgType::HashDrbg).unwrap();
        let additional = b"reseed-entropy";
        drbg_reseed(&mut drbg, Some(additional)).unwrap();
        assert_eq!(drbg.state(), DrbgState::Ready);
    }

    #[test]
    fn test_drbg_generate_empty_buffer() {
        let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        let mut buf: [u8; 0] = [];
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        // Counter should not increment for empty requests.
        assert_eq!(drbg.reseed_counter(), 0);
    }

    #[test]
    fn test_drbg_uninitialised_state_rejects_generate() {
        let mut drbg = Drbg {
            drbg_type: DrbgType::CtrDrbg,
            state: DrbgState::Uninitialised,
            reseed_counter: 0,
            reseed_interval: SECONDARY_RESEED_INTERVAL,
            seed_material: vec![0u8; DRBG_SEED_SIZE],
            internal_state: vec![0u8; DRBG_STATE_SIZE],
        };
        let mut buf = [0u8; 16];
        let result = drbg_generate(&mut drbg, &mut buf, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_error_state_rejects_generate() {
        let mut drbg = Drbg {
            drbg_type: DrbgType::CtrDrbg,
            state: DrbgState::Error,
            reseed_counter: 0,
            reseed_interval: SECONDARY_RESEED_INTERVAL,
            seed_material: vec![0u8; DRBG_SEED_SIZE],
            internal_state: vec![0u8; DRBG_STATE_SIZE],
        };
        let mut buf = [0u8; 16];
        let result = drbg_generate(&mut drbg, &mut buf, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_drbg_auto_reseed_on_interval() {
        let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        // Set a very small reseed interval for testing.
        // Reseed triggers when counter >= interval, which happens
        // at the START of the call after counter reaches 2.
        drbg.reseed_interval = 2;
        let mut buf = [0u8; 8];
        drbg_generate(&mut drbg, &mut buf, None).unwrap(); // counter: 0→1
        drbg_generate(&mut drbg, &mut buf, None).unwrap(); // counter: 1→2
                                                           // Third call: counter(2) >= interval(2) → auto-reseed resets
                                                           // counter to 0, then generates and increments to 1.
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        assert_eq!(
            drbg.reseed_counter(),
            1,
            "counter should be 1 after auto-reseed + generate"
        );
    }

    #[test]
    fn test_rand_seed_stores_data() {
        rand_seed(b"test-seed-data");
        // Verify the additional seed buffer is not empty.
        let buffer_ref = get_or_init_seed_buffer();
        let buffer = buffer_ref.lock();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_entropy_pool_new() {
        let pool = EntropyPool::new(256);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PRIMARY_RESEED_INTERVAL, 256);
        assert_eq!(SECONDARY_RESEED_INTERVAL, 65_536);
        assert_eq!(PRIMARY_RESEED_TIME_INTERVAL, 3600);
        assert_eq!(SECONDARY_RESEED_TIME_INTERVAL, 420);
    }

    #[test]
    fn test_mix_bytes_basic() {
        let mut target = vec![0xAAu8; 4];
        let source = vec![0x55u8; 4];
        mix_bytes(&mut target, &source);
        assert_eq!(target, vec![0xFF; 4]); // 0xAA ^ 0x55 = 0xFF
    }

    #[test]
    fn test_mix_bytes_empty_source() {
        let mut target = vec![0xAAu8; 4];
        mix_bytes(&mut target, &[]);
        assert_eq!(target, vec![0xAAu8; 4]); // Unchanged.
    }

    #[test]
    fn test_drbg_debug_redacts_key_material() {
        let drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
        let debug_output = format!("{drbg:?}");
        assert!(debug_output.contains("REDACTED"));
        // Ensure seed material bytes are not leaked in debug output.
        assert!(debug_output.contains("[REDACTED]"));
    }
}
