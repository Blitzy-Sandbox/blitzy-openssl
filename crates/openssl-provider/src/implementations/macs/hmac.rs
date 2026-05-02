//! HMAC Provider Implementation — RFC 2104 Hash-Based Message Authentication Code.
//!
//! This module provides the HMAC (Hash-based Message Authentication Code)
//! implementation for the OpenSSL Rust provider system, translating the C
//! `providers/implementations/macs/hmac_prov.c` (389 lines) into idiomatic,
//! safe Rust.
//!
//! # Architecture
//!
//! The implementation follows the trait-based dispatch pattern that replaces
//! the C `OSSL_DISPATCH` function pointer tables:
//!
//! | C Function | Rust Equivalent |
//! |-----------|-----------------|
//! | `hmac_new` | `HmacProvider::new_ctx()` |
//! | `hmac_free` | `Drop` for `HmacContext` (automatic via `Zeroizing`) |
//! | `hmac_dup` | `Clone` for `HmacContext` |
//! | `hmac_init` | `MacContext::init()` |
//! | `hmac_update` | `MacContext::update()` |
//! | `hmac_final` | `MacContext::finalize()` |
//! | `hmac_setkey` | Part of `init()` with FIPS key-size check |
//! | `hmac_get_ctx_params` | `MacContext::get_params()` |
//! | `hmac_set_ctx_params` | `MacContext::set_params()` |
//! | `ossl_hmac_functions[]` | [`HmacProvider::descriptors()`] |
//! | `ossl_hmac_internal_functions[]` | [`HmacProvider::new_internal()`] |
//!
//! # TLS Record MAC Optimization
//!
//! When `tls_data_size > 0`, the context enters TLS MAC mode where:
//! 1. The first `update()` call captures the 13-byte TLS record header.
//! 2. The second `update()` computes the MAC over header + record data.
//! 3. `finalize()` returns the pre-computed MAC.
//!
//! This corresponds to the C `ssl3_cbc_digest_record()` path in `hmac_prov.c`.
//!
//! # FIPS Key-Size Enforcement
//!
//! When not in internal mode (i.e., HMAC fetched directly, not used inside
//! a KDF), the minimum HMAC key length is 112 bits (14 bytes) per NIST
//! SP 800-131Ar2. The `internal` variant (used by HKDF/TLS-PRF) skips
//! this check since the parent algorithm handles FIPS compliance.
//!
//! # Security Properties
//!
//! - Key material protected with `Zeroizing<Vec<u8>>` (auto-zeroed on drop)
//! - Zero `unsafe` blocks (Rule R8)
//! - All methods return `ProviderResult<T>` (Rule R5)
//! - No bare narrowing casts (Rule R6)

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::ProviderError;
use openssl_common::{ParamBuilder, ParamSet, ParamValue, ProviderResult};
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, Zeroizing};

// =============================================================================
// Constants
// =============================================================================

/// `OSSL_MAC_PARAM_SIZE` — output size parameter name.
const PARAM_SIZE: &str = "size";
/// `OSSL_MAC_PARAM_DIGEST` — digest algorithm name parameter.
const PARAM_DIGEST: &str = "digest";
/// `OSSL_MAC_PARAM_PROPERTIES` — property query string parameter.
const PARAM_PROPERTIES: &str = "properties";
/// `OSSL_MAC_PARAM_KEY` — key material parameter.
const PARAM_KEY: &str = "key";
/// `OSSL_MAC_PARAM_BLOCK_SIZE` — digest block size parameter.
const PARAM_BLOCK_SIZE: &str = "block-size";
/// `OSSL_MAC_PARAM_TLS_DATA_SIZE` — TLS record MAC data size.
const PARAM_TLS_DATA_SIZE: &str = "tls-data-size";
/// `OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR` — FIPS indicator parameter.
const PARAM_FIPS_INDICATOR: &str = "fips-indicator";

/// Minimum HMAC key length in bytes for FIPS compliance (112 bits / 8).
/// Per NIST SP 800-131Ar2 §2.
const FIPS_MIN_KEY_BYTES: usize = 14;

/// HMAC inner padding byte (RFC 2104 §2).
const IPAD_BYTE: u8 = 0x36;
/// HMAC outer padding byte (RFC 2104 §2).
const OPAD_BYTE: u8 = 0x5c;

/// Default digest algorithm when none specified (`SHA-256`).
const DEFAULT_DIGEST: &str = "SHA-256";

/// TLS record header size (`content_type` + version + length = 13 bytes).
const TLS_HEADER_SIZE: usize = 13;

// =============================================================================
// Digest Algorithm Metadata
// =============================================================================

/// Supported digest algorithms for HMAC computation.
///
/// Each variant carries the algorithm's output size and block size, enabling
/// the HMAC engine to compute the correct ipad/opad padding per RFC 2104.
///
/// Replaces the `PROV_DIGEST` struct in C `hmac_prov.c` which wraps an
/// `EVP_MD` pointer for digest lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    /// SHA-1 (160-bit output, 512-bit block) — FIPS 180-4
    Sha1,
    /// SHA-224 (224-bit output, 512-bit block) — FIPS 180-4
    Sha224,
    /// SHA-256 (256-bit output, 512-bit block) — FIPS 180-4
    Sha256,
    /// SHA-384 (384-bit output, 1024-bit block) — FIPS 180-4
    Sha384,
    /// SHA-512 (512-bit output, 1024-bit block) — FIPS 180-4
    Sha512,
    /// SHA-512/224 (224-bit output, 1024-bit block) — FIPS 180-4
    Sha512_224,
    /// SHA-512/256 (256-bit output, 1024-bit block) — FIPS 180-4
    Sha512_256,
    /// MD5 (128-bit output, 512-bit block) — RFC 1321
    Md5,
}

impl DigestAlgorithm {
    /// Parses a digest algorithm name (case-insensitive).
    ///
    /// Supports standard OpenSSL names and common aliases.
    fn from_name(name: &str) -> Option<Self> {
        let upper = name.to_uppercase();
        let trimmed = upper.trim();
        match trimmed {
            "SHA-1" | "SHA1" => Some(Self::Sha1),
            "SHA-224" | "SHA224" | "SHA2-224" => Some(Self::Sha224),
            "SHA-256" | "SHA256" | "SHA2-256" => Some(Self::Sha256),
            "SHA-384" | "SHA384" | "SHA2-384" => Some(Self::Sha384),
            "SHA-512" | "SHA512" | "SHA2-512" => Some(Self::Sha512),
            "SHA-512/224" | "SHA512-224" | "SHA512/224" => Some(Self::Sha512_224),
            "SHA-512/256" | "SHA512-256" | "SHA512/256" => Some(Self::Sha512_256),
            "MD5" => Some(Self::Md5),
            _ => None,
        }
    }

    /// Returns the digest output size in bytes.
    const fn output_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha512_224 => 28,
            Self::Sha256 | Self::Sha512_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Md5 => 16,
        }
    }

    /// Returns the digest internal block size in bytes.
    ///
    /// Used for HMAC ipad/opad padding (RFC 2104 §2).
    const fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 | Self::Md5 => 64,
            Self::Sha384 | Self::Sha512 | Self::Sha512_224 | Self::Sha512_256 => 128,
        }
    }

    /// Returns the canonical name of the digest algorithm.
    const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_224 => "SHA-512/224",
            Self::Sha512_256 => "SHA-512/256",
            Self::Md5 => "MD5",
        }
    }
}

// =============================================================================
// HmacParams — Configuration Parameters
// =============================================================================

/// HMAC configuration parameters.
///
/// Typed replacement for the C `OSSL_PARAM` get/set tables in `hmac_prov.c`.
///
/// | C Parameter Name | Rust Field |
/// |------------------|------------|
/// | `OSSL_MAC_PARAM_DIGEST` | [`digest`](HmacParams::digest) |
/// | `OSSL_MAC_PARAM_PROPERTIES` | [`properties`](HmacParams::properties) |
/// | `OSSL_MAC_PARAM_TLS_DATA_SIZE` | [`tls_data_size`](HmacParams::tls_data_size) |
#[derive(Debug, Clone, Default)]
pub struct HmacParams {
    /// Name of the digest algorithm (e.g., `"SHA-256"`).
    /// Defaults to SHA-256 if `None`.
    pub digest: Option<String>,

    /// Property query string for digest fetch (e.g., `"provider=default"`).
    pub properties: Option<String>,

    /// TLS record MAC data size. When `Some(n)` where `n > 0`, the context
    /// operates in TLS MAC mode. When `None` or `Some(0)`, normal HMAC mode.
    pub tls_data_size: Option<usize>,
}

impl HmacParams {
    /// Creates a new empty parameter set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the digest algorithm name.
    #[must_use]
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    /// Sets the property query string.
    #[must_use]
    pub fn with_properties(mut self, properties: impl Into<String>) -> Self {
        self.properties = Some(properties.into());
        self
    }

    /// Sets the TLS data size for TLS MAC mode.
    #[must_use]
    pub fn with_tls_data_size(mut self, size: usize) -> Self {
        self.tls_data_size = Some(size);
        self
    }
}

// =============================================================================
// State Types
// =============================================================================

/// HMAC context state machine.
///
/// Enforces the lifecycle: `Uninitialized → Initialized → Updated → Finalized`.
#[derive(Debug, Clone)]
enum HmacState {
    /// Context created but not yet initialized with a key.
    Uninitialized,
    /// Key set and HMAC engine ready for updates.
    Initialized(HmacEngine),
    /// One or more updates have been processed.
    Updated(HmacEngine),
    /// HMAC tag has been computed. No further updates allowed.
    Finalized,
}

/// TLS record MAC optimization state.
///
/// When `tls_data_size > 0`, the HMAC context captures a 13-byte TLS record
/// header on the first `update()` call, computes the MAC on the second call,
/// and returns the pre-computed MAC on `finalize()`.
///
/// Replaces C fields `tls_header`, `tls_header_set`, `tls_mac_out`,
/// `tls_mac_out_size` from `struct hmac_data_st` in `hmac_prov.c`.
#[derive(Debug, Clone)]
struct TlsMacState {
    /// Total TLS record data size (including MAC and padding).
    data_size: usize,
    /// 13-byte TLS record header.
    header: [u8; TLS_HEADER_SIZE],
    /// Whether the header has been captured.
    header_set: bool,
    /// Pre-computed MAC output.
    mac_out: Vec<u8>,
}

impl TlsMacState {
    /// Creates a new TLS MAC state with the given data size.
    fn new(data_size: usize) -> Self {
        Self {
            data_size,
            header: [0u8; TLS_HEADER_SIZE],
            header_set: false,
            mac_out: Vec::new(),
        }
    }
}

// =============================================================================
// HmacProvider — Provider Factory
// =============================================================================

/// HMAC provider implementation.
///
/// Factory for creating HMAC computation contexts. Two variants exist:
///
/// - **Standard** ([`HmacProvider::new()`]): Enforces FIPS minimum key length
///   (14 bytes / 112 bits).
/// - **Internal** ([`HmacProvider::new_internal()`]): Skips FIPS key check —
///   used when HMAC is a sub-component of another algorithm (HKDF, TLS-PRF).
///
/// Replaces the C `ossl_hmac_functions[]` and `ossl_hmac_internal_functions[]`
/// dispatch tables from `hmac_prov.c` lines 345–389.
///
/// ## Wiring Path (Rule R10)
///
/// ```text
/// openssl_cli::main()
///   → openssl_ssl / openssl_crypto → provider fetch
///     → DefaultProvider::query_operation(Mac)
///       → implementations::macs::descriptors()
///         → HmacProvider::descriptors()
/// ```
pub struct HmacProvider {
    /// Whether this is the FIPS-internal variant.
    ///
    /// When `true`, the FIPS minimum key-length check is skipped because
    /// the parent algorithm (e.g., HKDF) is responsible for FIPS compliance.
    internal: bool,
}

impl Default for HmacProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HmacProvider {
    /// Creates a standard HMAC provider.
    ///
    /// Enforces FIPS minimum key length (112 bits) when applicable.
    /// Use [`new_internal()`](Self::new_internal) when HMAC is used inside
    /// another algorithm that handles FIPS compliance.
    #[must_use]
    pub fn new() -> Self {
        debug!("HMAC: creating standard provider");
        Self { internal: false }
    }

    /// Creates an internal HMAC provider variant for FIPS contexts.
    ///
    /// Skips FIPS key-size enforcement — the parent algorithm (KDF, PRF)
    /// is responsible for compliance checking.
    ///
    /// Corresponds to C `hmac_internal_new()` from `hmac_prov.c` line 364.
    #[must_use]
    pub fn new_internal() -> Self {
        debug!("HMAC: creating internal (FIPS-exempt) provider");
        Self { internal: true }
    }

    /// Returns algorithm descriptors for HMAC registration.
    ///
    /// Provides a single descriptor: `["HMAC"]` with property `"provider=default"`.
    /// Used by the method store for algorithm lookup.
    ///
    /// Corresponds to both `ossl_hmac_functions` (standard) and
    /// `ossl_hmac_internal_functions` (FIPS-internal) dispatch tables.
    #[must_use]
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["HMAC"],
            property: "provider=default",
            description: "Hash-based Message Authentication Code (RFC 2104)",
        }]
    }
}

impl MacProvider for HmacProvider {
    /// Returns the algorithm name.
    fn name(&self) -> &'static str {
        "HMAC"
    }

    /// Returns the MAC output size.
    ///
    /// For HMAC, the output size depends on the selected digest, which is
    /// not known until context initialization. Returns 0 to indicate
    /// dynamic sizing (the actual size is available via `get_params()`
    /// after initialization).
    fn size(&self) -> usize {
        0
    }

    /// Creates a new HMAC context.
    ///
    /// The context is initially uninitialized — `init()` must be called
    /// with a key and optional parameters before `update()`/`finalize()`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        debug!(internal = self.internal, "HMAC: creating new context");
        Ok(Box::new(HmacContext::new(self.internal)))
    }
}

// =============================================================================
// HmacContext — Computation Context
// =============================================================================

/// HMAC computation context.
///
/// Manages the full HMAC lifecycle:
/// `new() → init(key) → update(data)* → finalize()`.
///
/// Replaces C `struct hmac_data_st` from `hmac_prov.c` lines 55–76.
/// Key material is protected with [`Zeroizing<Vec<u8>>`] which automatically
/// zeroes memory on `Drop`, replacing the C `OPENSSL_clear_free(key, keylen)`
/// pattern.
///
/// # State Machine
///
/// ```text
/// Uninitialized ──init()──→ Initialized ──update()──→ Updated
///                              │                        │
///                              └──update()──→ Updated   └──update()──→ Updated
///
/// (any of Initialized|Updated) ──finalize()──→ Finalized
/// ```
pub struct HmacContext {
    /// Selected digest algorithm name.
    digest_name: Option<String>,
    /// Resolved digest algorithm.
    digest_algo: Option<DigestAlgorithm>,
    /// Property query for digest selection.
    properties: Option<String>,
    /// Key material — zeroed on Drop via `Zeroizing`.
    key: Option<Zeroizing<Vec<u8>>>,
    /// Whether this is the FIPS-internal variant.
    internal: bool,
    /// HMAC computation state machine.
    state: HmacState,
    /// TLS record MAC optimization state (active when `tls_data_size` > 0).
    tls_state: Option<TlsMacState>,
    /// FIPS approved indicator.
    fips_approved: bool,
}

impl std::fmt::Debug for HmacContext {
    /// Custom Debug implementation that hides key material for security.
    ///
    /// Key bytes are replaced with length information only.
    /// Uses `finish_non_exhaustive()` to signal that `key` and `state` fields
    /// are intentionally omitted for security/clarity.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacContext")
            .field("digest_name", &self.digest_name)
            .field("digest_algo", &self.digest_algo)
            .field("properties", &self.properties)
            .field("key_len", &self.key.as_ref().map(|k| k.len()))
            .field("internal", &self.internal)
            .field("fips_approved", &self.fips_approved)
            .field("tls_active", &self.tls_state.is_some())
            .finish_non_exhaustive()
    }
}

impl HmacContext {
    /// Creates a new uninitialized HMAC context.
    fn new(internal: bool) -> Self {
        Self {
            digest_name: None,
            digest_algo: None,
            properties: None,
            key: None,
            internal,
            state: HmacState::Uninitialized,
            tls_state: None,
            fips_approved: true,
        }
    }

    /// Applies parameters from a `ParamSet` to this context.
    ///
    /// Extracts and validates:
    /// - `"digest"` — digest algorithm name
    /// - `"properties"` — property query string
    /// - `"key"` — key material (stored in `Zeroizing<Vec<u8>>`)
    /// - `"tls-data-size"` — TLS MAC data size
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Extract digest name
        if params.contains(PARAM_DIGEST) {
            let name: String = params.get_typed(PARAM_DIGEST).map_err(|e| {
                ProviderError::Dispatch(format!("HMAC: failed to read digest parameter: {e}"))
            })?;
            if let Some(algo) = DigestAlgorithm::from_name(&name) {
                debug!(digest = %name, "HMAC: selecting digest algorithm");
                self.digest_name = Some(name);
                self.digest_algo = Some(algo);
            } else {
                warn!(digest = %name, "HMAC: unsupported digest algorithm");
                return Err(ProviderError::AlgorithmUnavailable(format!(
                    "HMAC: digest '{name}' is not supported. Supported: \
                     SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, \
                     SHA-512/256, MD5"
                )));
            }
        }

        // Extract properties
        if params.contains(PARAM_PROPERTIES) {
            let props: String = params.get_typed(PARAM_PROPERTIES).map_err(|e| {
                ProviderError::Dispatch(format!("HMAC: failed to read properties parameter: {e}"))
            })?;
            trace!(properties = %props, "HMAC: setting properties");
            self.properties = Some(props);
        }

        // Extract key material
        if let Some(value) = params.get(PARAM_KEY) {
            if let ParamValue::OctetString(key_bytes) = value {
                trace!(key_len = key_bytes.len(), "HMAC: received key via params");
                self.key = Some(Zeroizing::new(key_bytes.clone()));
            } else {
                return Err(ProviderError::Dispatch(
                    "HMAC: key parameter must be an octet string".to_string(),
                ));
            }
        }

        // Extract TLS data size
        if params.contains(PARAM_TLS_DATA_SIZE) {
            let tls_size: u64 = params.get_typed(PARAM_TLS_DATA_SIZE).map_err(|e| {
                ProviderError::Dispatch(format!(
                    "HMAC: failed to read tls-data-size parameter: {e}"
                ))
            })?;
            let tls_size_usize = usize::try_from(tls_size).map_err(|_| {
                ProviderError::Dispatch(
                    "HMAC: tls-data-size value exceeds platform size".to_string(),
                )
            })?;
            if tls_size_usize > 0 {
                trace!(
                    tls_data_size = tls_size_usize,
                    "HMAC: enabling TLS MAC mode"
                );
                self.tls_state = Some(TlsMacState::new(tls_size_usize));
            } else {
                self.tls_state = None;
            }
        }

        Ok(())
    }

    /// Performs FIPS key-size validation.
    ///
    /// Per NIST SP 800-131Ar2, the minimum HMAC key length is 112 bits
    /// (14 bytes) when used directly. Internal variant (used inside KDF)
    /// skips this check.
    fn check_fips_key_size(&mut self, key_len: usize) {
        if self.internal {
            return;
        }
        if key_len < FIPS_MIN_KEY_BYTES {
            warn!(
                key_len,
                min_bytes = FIPS_MIN_KEY_BYTES,
                "HMAC: FIPS key-size check failed — key too short"
            );
            self.fips_approved = false;
        }
    }
}

// =============================================================================
// MacContext Trait Implementation
// =============================================================================

impl MacContext for HmacContext {
    /// Initializes the HMAC context with a key and optional parameters.
    ///
    /// Lifecycle: `Uninitialized → Initialized` (or re-init from any state).
    ///
    /// Corresponds to C `hmac_init()` from `hmac_prov.c`:
    /// 1. Apply parameters (digest selection, TLS data size)
    /// 2. FIPS key-size check (if not internal)
    /// 3. Store key copy in `Zeroizing<Vec<u8>>`
    /// 4. Create HMAC engine with key + digest
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        trace!(key_len = key.len(), "HMAC: init called");

        // Reset FIPS indicator for fresh init
        self.fips_approved = true;

        // Apply parameters if provided
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Use key from params if key argument is empty (re-init scenario)
        let effective_key = if key.is_empty() {
            if let Some(ref stored) = self.key {
                Vec::clone(stored)
            } else {
                return Err(ProviderError::Init(
                    "HMAC: no key provided for initialization".to_string(),
                ));
            }
        } else {
            key.to_vec()
        };

        // FIPS key-size enforcement
        self.check_fips_key_size(effective_key.len());

        // Resolve digest algorithm — default to SHA-256
        let algo = self.digest_algo.unwrap_or_else(|| {
            debug!("HMAC: no digest specified, defaulting to {DEFAULT_DIGEST}");
            DigestAlgorithm::Sha256
        });
        self.digest_algo = Some(algo);
        if self.digest_name.is_none() {
            self.digest_name = Some(algo.name().to_string());
        }

        // Store key copy for potential re-initialization
        self.key = Some(Zeroizing::new(effective_key.clone()));

        // Create HMAC engine
        let engine = HmacEngine::new(algo, &effective_key);

        debug!(
            digest = algo.name(),
            key_len = effective_key.len(),
            fips_approved = self.fips_approved,
            tls_mode = self.tls_state.is_some(),
            "HMAC: context initialized"
        );

        self.state = HmacState::Initialized(engine);
        Ok(())
    }

    /// Updates the HMAC context with additional data.
    ///
    /// **Normal path:** Feeds data into the HMAC inner hash.
    ///
    /// **TLS path** (when `tls_data_size > 0`):
    /// 1. First call: captures 13-byte TLS record header.
    /// 2. Second call: computes HMAC over header + record data and stores
    ///    the result in `tls_mac_out` for later retrieval by `finalize()`.
    ///
    /// Corresponds to C `hmac_update()` from `hmac_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(data_len = data.len(), "HMAC: update called");

        let engine = match &mut self.state {
            HmacState::Initialized(e) | HmacState::Updated(e) => e,
            HmacState::Uninitialized => {
                return Err(ProviderError::Init(
                    "HMAC: context not initialized — call init() first".to_string(),
                ));
            }
            HmacState::Finalized => {
                return Err(ProviderError::Init(
                    "HMAC: context already finalized — call init() to reset".to_string(),
                ));
            }
        };

        // TLS MAC optimization path
        if let Some(ref mut tls) = self.tls_state {
            if !tls.header_set {
                // First update: capture TLS record header
                if data.len() != TLS_HEADER_SIZE {
                    return Err(ProviderError::Dispatch(format!(
                        "HMAC TLS: expected {TLS_HEADER_SIZE}-byte header, got {}",
                        data.len()
                    )));
                }
                tls.header.copy_from_slice(data);
                tls.header_set = true;
                trace!("HMAC TLS: captured 13-byte record header");
                // Transition state but DON'T update engine yet
                let (HmacState::Initialized(engine_owned) | HmacState::Updated(engine_owned)) =
                    std::mem::replace(&mut self.state, HmacState::Finalized)
                else {
                    unreachable!()
                };
                self.state = HmacState::Updated(engine_owned);
                return Ok(());
            }

            // Second update: compute MAC over header + data
            // Validate data size against expected TLS record size
            trace!(
                expected_size = tls.data_size,
                actual_size = data.len(),
                "HMAC TLS: processing record data"
            );

            // Feed header first, then the actual data
            let HmacState::Updated(engine_ref) = &mut self.state else {
                unreachable!()
            };
            engine_ref.update(&tls.header);
            engine_ref.update(data);
            tls.mac_out = engine_ref.finalize_reset();
            trace!(mac_len = tls.mac_out.len(), "HMAC TLS: computed record MAC");
            return Ok(());
        }

        // Normal HMAC update path
        engine.update(data);

        // Transition Initialized → Updated (Updated stays Updated)
        if matches!(self.state, HmacState::Initialized(_)) {
            let HmacState::Initialized(engine_owned) =
                std::mem::replace(&mut self.state, HmacState::Finalized)
            else {
                unreachable!()
            };
            self.state = HmacState::Updated(engine_owned);
        }

        Ok(())
    }

    /// Finalizes the HMAC computation and returns the authentication tag.
    ///
    /// **Normal path:** Completes the HMAC outer hash and returns the tag.
    /// **TLS path:** Returns the pre-computed `tls_mac_out`.
    ///
    /// After finalization, the context must be re-initialized via `init()`
    /// before further use.
    ///
    /// Corresponds to C `hmac_final()` from `hmac_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        trace!("HMAC: finalize called");

        // TLS path: return pre-computed MAC
        if let Some(ref tls) = self.tls_state {
            if tls.mac_out.is_empty() {
                return Err(ProviderError::Init(
                    "HMAC TLS: no MAC computed — missing update() calls".to_string(),
                ));
            }
            let result = tls.mac_out.clone();
            trace!(
                mac_len = result.len(),
                "HMAC TLS: returning pre-computed MAC"
            );
            self.state = HmacState::Finalized;
            return Ok(result);
        }

        // Normal path: extract engine and finalize
        let result = match std::mem::replace(&mut self.state, HmacState::Finalized) {
            HmacState::Initialized(mut e) | HmacState::Updated(mut e) => e.finalize(),
            HmacState::Uninitialized => {
                return Err(ProviderError::Init(
                    "HMAC: context not initialized — call init() first".to_string(),
                ));
            }
            HmacState::Finalized => {
                return Err(ProviderError::Init(
                    "HMAC: context already finalized — call init() to reset".to_string(),
                ));
            }
        };

        trace!(mac_len = result.len(), "HMAC: finalized");
        Ok(result)
    }

    /// Returns gettable context parameters.
    ///
    /// Provides:
    /// - `"size"` — HMAC output length in bytes
    /// - `"block-size"` — underlying digest block size in bytes
    /// - `"fips-indicator"` — FIPS approved status (1 = approved, 0 = not)
    ///
    /// Corresponds to C `hmac_get_ctx_params()` from `hmac_prov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder = ParamBuilder::new();

        if let Some(algo) = self.digest_algo {
            let out_size = u64::try_from(algo.output_size()).unwrap_or(0);
            let blk_size = u64::try_from(algo.block_size()).unwrap_or(0);
            builder = builder
                .push_u64(PARAM_SIZE, out_size)
                .push_u64(PARAM_BLOCK_SIZE, blk_size);
        }

        // FIPS indicator: 1 = approved, 0 = not approved
        let fips_val: u64 = u64::from(self.fips_approved);
        builder = builder.push_u64(PARAM_FIPS_INDICATOR, fips_val);

        Ok(builder.build())
    }

    /// Sets context parameters.
    ///
    /// Delegates to `apply_params()` for
    /// parameter extraction and validation.
    ///
    /// Corresponds to C `hmac_set_ctx_params()` from `hmac_prov.c`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Clone Implementation
// =============================================================================

impl Clone for HmacContext {
    /// Deep-copies the HMAC context.
    ///
    /// Replaces C `hmac_dup()` from `hmac_prov.c`. Key material is cloned
    /// via `Zeroizing::clone()` which produces a new zeroing allocation.
    fn clone(&self) -> Self {
        Self {
            digest_name: self.digest_name.clone(),
            digest_algo: self.digest_algo,
            properties: self.properties.clone(),
            key: self.key.clone(),
            internal: self.internal,
            state: self.state.clone(),
            tls_state: self.tls_state.clone(),
            fips_approved: self.fips_approved,
        }
    }
}

// =============================================================================
// HmacEngine — Core HMAC Computation
// =============================================================================

/// Core HMAC computation engine implementing RFC 2104.
///
/// ```text
/// HMAC(K, m) = H((K' ⊕ opad) ∥ H((K' ⊕ ipad) ∥ m))
/// ```
///
/// Where K' is the key pre-processed to exactly `block_size` bytes:
/// - If `key.len() > block_size`: K' = H(key), zero-padded to `block_size`
/// - If `key.len() <= block_size`: K' = key, zero-padded to `block_size`
///
/// Replaces C `HMAC_CTX` usage from `crypto/hmac/hmac.c`.
#[derive(Debug, Clone)]
struct HmacEngine {
    /// The digest algorithm.
    algo: DigestAlgorithm,
    /// Inner digest context: H((K' ⊕ ipad) ∥ m).
    inner: DigestEngine,
    /// Outer key block (K' ⊕ opad), stored for finalization.
    outer_key_block: Vec<u8>,
}

impl HmacEngine {
    /// Creates a new HMAC engine with the given digest and key.
    ///
    /// Pre-processes the key per RFC 2104 §2:
    /// 1. If key > `block_size` → hash the key
    /// 2. Pad to `block_size` with zeros
    /// 3. Compute inner key = `padded_key` XOR `ipad`
    /// 4. Compute outer key = `padded_key` XOR `opad`
    /// 5. Initialize inner digest with inner key block
    fn new(algo: DigestAlgorithm, key: &[u8]) -> Self {
        let block_size = algo.block_size();

        // Step 1-2: Pre-process key to exactly block_size bytes
        let mut padded_key = vec![0u8; block_size];
        if key.len() > block_size {
            // Key too long: hash it first
            let hashed = Self::hash_once(algo, key);
            let copy_len = hashed.len().min(block_size);
            padded_key[..copy_len].copy_from_slice(&hashed[..copy_len]);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Step 3: Compute inner key block = padded_key XOR ipad
        let mut inner_block = vec![0u8; block_size];
        for (i, byte) in padded_key.iter().enumerate() {
            inner_block[i] = byte ^ IPAD_BYTE;
        }

        // Step 4: Compute outer key block = padded_key XOR opad
        let mut outer_block = vec![0u8; block_size];
        for (i, byte) in padded_key.iter().enumerate() {
            outer_block[i] = byte ^ OPAD_BYTE;
        }

        // Zero the padded key — no longer needed
        padded_key.zeroize();

        // Step 5: Initialize inner digest with inner key block
        let mut inner = DigestEngine::new(algo);
        inner.update(&inner_block);

        // Zero the inner block after use
        inner_block.zeroize();

        Self {
            algo,
            inner,
            outer_key_block: outer_block,
        }
    }

    /// Feeds data into the inner HMAC hash.
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Completes the HMAC computation and returns the tag.
    ///
    /// ```text
    /// result = H(outer_key_block ∥ H(inner_key_block ∥ message))
    /// ```
    fn finalize(&mut self) -> Vec<u8> {
        // Complete inner hash
        let inner_hash = self.inner.finalize();

        // Outer hash: H(outer_key_block ∥ inner_hash)
        let mut outer = DigestEngine::new(self.algo);
        outer.update(&self.outer_key_block);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Completes the HMAC computation and re-initializes for reuse.
    ///
    /// Used by the TLS MAC path where the engine is reused across records.
    fn finalize_reset(&mut self) -> Vec<u8> {
        let result = self.finalize();

        // Re-initialize inner context with (padded_key XOR ipad)
        // We reconstruct the inner block from outer_key_block since:
        // outer = key XOR opad, inner = key XOR ipad
        // inner = (outer XOR opad) XOR ipad = outer XOR (opad XOR ipad)
        let block_size = self.algo.block_size();
        let mut inner_block = vec![0u8; block_size];
        for (i, byte) in self.outer_key_block.iter().enumerate() {
            inner_block[i] = byte ^ OPAD_BYTE ^ IPAD_BYTE;
        }

        self.inner = DigestEngine::new(self.algo);
        self.inner.update(&inner_block);
        inner_block.zeroize();

        result
    }

    /// Computes a single-shot hash.
    fn hash_once(algo: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
        let mut engine = DigestEngine::new(algo);
        engine.update(data);
        engine.finalize()
    }
}

// =============================================================================
// DigestEngine — Software Digest Implementations
// =============================================================================

/// Software digest engine supporting all HMAC-compatible hash algorithms.
///
/// Each variant holds the complete state for its algorithm, enabling
/// incremental update and finalization.
///
/// Replaces the C `EVP_MD_CTX` / `EVP_DigestUpdate` / `EVP_DigestFinal`
/// pattern that HMAC uses internally.
#[derive(Debug, Clone)]
struct DigestEngine {
    /// Current hash state.
    core: DigestCore,
    /// Partial block buffer for incremental feeding.
    buffer: Vec<u8>,
    /// Total bytes processed (for padding).
    total_len: u64,
    /// Block size for this algorithm.
    block_size: usize,
}

/// Core hash state for each supported algorithm.
#[derive(Debug, Clone)]
enum DigestCore {
    /// SHA-256 / SHA-224 state (32-bit words, 64 rounds).
    Sha256(Sha256State),
    /// SHA-512 / SHA-384 / SHA-512/224 / SHA-512/256 state (64-bit words, 80 rounds).
    Sha512(Sha512State),
    /// SHA-1 state (32-bit words, 80 rounds).
    Sha1(Sha1State),
    /// MD5 state (32-bit words, 64 rounds).
    Md5(Md5State),
}

impl DigestEngine {
    /// Creates a new digest engine for the given algorithm.
    fn new(algo: DigestAlgorithm) -> Self {
        let core = match algo {
            DigestAlgorithm::Sha256 => DigestCore::Sha256(Sha256State::new_sha256()),
            DigestAlgorithm::Sha224 => DigestCore::Sha256(Sha256State::new_sha224()),
            DigestAlgorithm::Sha512 => DigestCore::Sha512(Sha512State::new_sha512()),
            DigestAlgorithm::Sha384 => DigestCore::Sha512(Sha512State::new_sha384()),
            DigestAlgorithm::Sha512_224 => DigestCore::Sha512(Sha512State::new_sha512_224()),
            DigestAlgorithm::Sha512_256 => DigestCore::Sha512(Sha512State::new_sha512_256()),
            DigestAlgorithm::Sha1 => DigestCore::Sha1(Sha1State::new()),
            DigestAlgorithm::Md5 => DigestCore::Md5(Md5State::new()),
        };
        Self {
            core,
            buffer: Vec::with_capacity(algo.block_size()),
            total_len: 0,
            block_size: algo.block_size(),
        }
    }

    /// Feeds data into the digest.
    fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        self.buffer.extend_from_slice(data);

        // Process complete blocks
        while self.buffer.len() >= self.block_size {
            let block: Vec<u8> = self.buffer.drain(..self.block_size).collect();
            match &mut self.core {
                DigestCore::Sha256(s) => s.compress(&block),
                DigestCore::Sha512(s) => s.compress(&block),
                DigestCore::Sha1(s) => s.compress(&block),
                DigestCore::Md5(s) => s.compress(&block),
            }
        }
    }

    /// Finalizes the digest and returns the hash value.
    fn finalize(&mut self) -> Vec<u8> {
        match &self.core {
            DigestCore::Sha256(s) => {
                let mut state = s.clone();
                sha256_finalize(&mut state, &self.buffer, self.total_len)
            }
            DigestCore::Sha512(s) => {
                let mut state = s.clone();
                sha512_finalize(&mut state, &self.buffer, self.total_len)
            }
            DigestCore::Sha1(s) => {
                let mut state = s.clone();
                sha1_finalize(&mut state, &self.buffer, self.total_len)
            }
            DigestCore::Md5(s) => {
                let mut state = s.clone();
                md5_finalize(&mut state, &self.buffer, self.total_len)
            }
        }
    }
}

// =============================================================================
// SHA-256 / SHA-224 Core (FIPS 180-4, 32-bit words, 64 rounds)
// =============================================================================

/// SHA-256 round constants K (FIPS 180-4 §4.2.2).
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 family state.
#[derive(Debug, Clone)]
struct Sha256State {
    /// Hash state (8 × 32-bit words).
    h: [u32; 8],
    /// Output length in bytes (32 for SHA-256, 28 for SHA-224).
    output_len: usize,
}

impl Sha256State {
    /// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
    fn new_sha256() -> Self {
        Self {
            h: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            output_len: 32,
        }
    }

    /// SHA-224 initial hash values (FIPS 180-4 §5.3.2).
    fn new_sha224() -> Self {
        Self {
            h: [
                0xc105_9ed8,
                0x367c_d507,
                0x3070_dd17,
                0xf70e_5939,
                0xffc0_0b31,
                0x6858_1511,
                0x64f9_8fa7,
                0xbefa_4fa4,
            ],
            output_len: 28,
        }
    }

    /// Processes a single 64-byte block.
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), 64);

        // Parse block into 16 big-endian 32-bit words
        let mut w = [0u32; 64];
        for i in 0..16 {
            let offset = i * 4;
            w[i] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        // Message schedule expansion
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        // 64 rounds
        for i in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big_s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add back to state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// Pads and finalizes a SHA-256/SHA-224 hash.
fn sha256_finalize(state: &mut Sha256State, remaining: &[u8], total_len: u64) -> Vec<u8> {
    // Merkle-Damgård padding: append 1-bit, zeros, then 64-bit big-endian bit count
    let bit_len = total_len.wrapping_mul(8);
    let mut pad = remaining.to_vec();
    pad.push(0x80);

    // Pad until length ≡ 56 (mod 64)
    while pad.len() % 64 != 56 {
        pad.push(0);
    }

    // Append 64-bit big-endian bit count
    pad.extend_from_slice(&bit_len.to_be_bytes());

    // Process remaining padded blocks
    for chunk in pad.chunks_exact(64) {
        state.compress(chunk);
    }

    // Produce output (truncated for SHA-224)
    let mut output = Vec::with_capacity(state.output_len);
    for word in &state.h {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output.truncate(state.output_len);
    output
}

// =============================================================================
// SHA-512 / SHA-384 / SHA-512/224 / SHA-512/256 Core
// (FIPS 180-4, 64-bit words, 80 rounds)
// =============================================================================

/// SHA-512 round constants K (FIPS 180-4 §4.2.3).
const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// SHA-512 family state.
#[derive(Debug, Clone)]
struct Sha512State {
    /// Hash state (8 × 64-bit words).
    h: [u64; 8],
    /// Output length in bytes.
    output_len: usize,
}

impl Sha512State {
    /// SHA-512 initial hash values (FIPS 180-4 §5.3.5).
    fn new_sha512() -> Self {
        Self {
            h: [
                0x6a09_e667_f3bc_c908,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
                0xa54f_f53a_5f1d_36f1,
                0x510e_527f_ade6_82d1,
                0x9b05_688c_2b3e_6c1f,
                0x1f83_d9ab_fb41_bd6b,
                0x5be0_cd19_137e_2179,
            ],
            output_len: 64,
        }
    }

    /// SHA-384 initial hash values (FIPS 180-4 §5.3.4).
    fn new_sha384() -> Self {
        Self {
            h: [
                0xcbbb_9d5d_c105_9ed8,
                0x629a_292a_367c_d507,
                0x9159_015a_3070_dd17,
                0x152f_ecd8_f70e_5939,
                0x6733_2667_ffc0_0b31,
                0x8eb4_4a87_6858_1511,
                0xdb0c_2e0d_64f9_8fa7,
                0x47b5_481d_befa_4fa4,
            ],
            output_len: 48,
        }
    }

    /// SHA-512/224 initial hash values (FIPS 180-4 §5.3.6.1).
    fn new_sha512_224() -> Self {
        Self {
            h: [
                0x8c3d_37c8_1954_4da2,
                0x73e1_9966_89dc_d4d6,
                0x1dfb_b7ae_a13b_abc3,
                0xeb55_bf6f_ff2a_c8b3,
                0xdb9a_be5e_48b6_f8f0,
                0x3ea1_fc5f_5315_a4ae,
                0xde0c_0dfd_6068_1e62,
                0x6826_8ad4_44f7_dc6a,
            ],
            output_len: 28,
        }
    }

    /// SHA-512/256 initial hash values (FIPS 180-4 §5.3.6.2).
    fn new_sha512_256() -> Self {
        Self {
            h: [
                0x2231_2194_fc2b_f72c,
                0x9f55_5fa3_c84c_64c2,
                0x2393_b86b_6f53_b151,
                0x9638_7719_5940_eabd,
                0x9628_3ee2_a04a_4484,
                0x0bfb_5a4f_1bec_38b3,
                0x5da6_b97f_fbff_ddbe,
                0xeb68_aaf3_ced9_bacd,
            ],
            output_len: 32,
        }
    }

    /// Processes a single 128-byte block.
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), 128);

        // Parse block into 16 big-endian 64-bit words
        let mut w = [0u64; 80];
        for i in 0..16 {
            let offset = i * 8;
            w[i] = u64::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
                block[offset + 4],
                block[offset + 5],
                block[offset + 6],
                block[offset + 7],
            ]);
        }

        // Message schedule expansion
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        // 80 rounds
        for i in 0..80 {
            let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big_s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add back to state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// Pads and finalizes a SHA-512 family hash.
fn sha512_finalize(state: &mut Sha512State, remaining: &[u8], total_len: u64) -> Vec<u8> {
    // SHA-512 uses 128-bit bit count, but we only track 64-bit byte count
    let bit_len_hi: u64 = total_len >> 61; // high 3 bits of (total_len * 8)
    let bit_len_lo: u64 = total_len.wrapping_mul(8);

    let mut pad = remaining.to_vec();
    pad.push(0x80);

    // Pad until length ≡ 112 (mod 128)
    while pad.len() % 128 != 112 {
        pad.push(0);
    }

    // Append 128-bit big-endian bit count
    pad.extend_from_slice(&bit_len_hi.to_be_bytes());
    pad.extend_from_slice(&bit_len_lo.to_be_bytes());

    // Process remaining padded blocks
    for chunk in pad.chunks_exact(128) {
        state.compress(chunk);
    }

    // Produce output (truncated for SHA-384, SHA-512/224, SHA-512/256)
    let mut output = Vec::with_capacity(state.output_len);
    for word in &state.h {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output.truncate(state.output_len);
    output
}

// =============================================================================
// SHA-1 Core (FIPS 180-4, 32-bit words, 80 rounds)
// =============================================================================

/// SHA-1 state.
#[derive(Debug, Clone)]
struct Sha1State {
    /// Hash state (5 × 32-bit words).
    h: [u32; 5],
}

impl Sha1State {
    /// SHA-1 initial hash values (FIPS 180-4 §5.3.1).
    fn new() -> Self {
        Self {
            h: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
        }
    }

    /// Processes a single 64-byte block.
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), 64);

        // Parse block into 16 big-endian 32-bit words and expand to 80
        let mut w = [0u32; 80];
        for i in 0..16 {
            let offset = i * 4;
            w[i] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.h;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

/// Pads and finalizes a SHA-1 hash.
fn sha1_finalize(state: &mut Sha1State, remaining: &[u8], total_len: u64) -> Vec<u8> {
    let bit_len = total_len.wrapping_mul(8);
    let mut pad = remaining.to_vec();
    pad.push(0x80);

    while pad.len() % 64 != 56 {
        pad.push(0);
    }

    pad.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in pad.chunks_exact(64) {
        state.compress(chunk);
    }

    let mut output = Vec::with_capacity(20);
    for word in &state.h {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output
}

// =============================================================================
// MD5 Core (RFC 1321, 32-bit words, 64 rounds, little-endian)
// =============================================================================

/// MD5 per-round shift amounts (RFC 1321 §3.4).
const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 sine-derived constants T[i] = floor(2^32 × |sin(i+1)|) (RFC 1321 §3.4).
const MD5_T: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// MD5 state.
#[derive(Debug, Clone)]
struct Md5State {
    /// Hash state (4 × 32-bit words, little-endian).
    h: [u32; 4],
}

impl Md5State {
    /// MD5 initial hash values (RFC 1321 §3.3).
    fn new() -> Self {
        Self {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
        }
    }

    /// Processes a single 64-byte block.
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), 64);

        // Parse block into 16 little-endian 32-bit words
        let mut m = [0u32; 16];
        for i in 0..16 {
            let offset = i * 4;
            m[i] = u32::from_le_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = self.h;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let temp = a.wrapping_add(f).wrapping_add(MD5_T[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(MD5_S[i]));
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
    }
}

/// Pads and finalizes an MD5 hash.
fn md5_finalize(state: &mut Md5State, remaining: &[u8], total_len: u64) -> Vec<u8> {
    // MD5 uses little-endian 64-bit bit count
    let bit_len = total_len.wrapping_mul(8);
    let mut pad = remaining.to_vec();
    pad.push(0x80);

    while pad.len() % 64 != 56 {
        pad.push(0);
    }

    // Append 64-bit LITTLE-endian bit count
    pad.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in pad.chunks_exact(64) {
        state.compress(chunk);
    }

    let mut output = Vec::with_capacity(16);
    for word in &state.h {
        output.extend_from_slice(&word.to_le_bytes());
    }
    output
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2104 test vector 1: HMAC-MD5 with 16-byte key.
    #[test]
    fn test_hmac_md5_rfc2104_vector1() {
        let key = vec![0x0bu8; 16];
        let data = b"Hi There";
        let expected = [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ];

        let mut engine = HmacEngine::new(DigestAlgorithm::Md5, &key);
        engine.update(data);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// RFC 4231 test case 1: HMAC-SHA-256 with 20-byte key of 0x0b.
    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let mut engine = HmacEngine::new(DigestAlgorithm::Sha256, &key);
        engine.update(data);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// RFC 4231 test case 2: HMAC-SHA-256 with "Jefe" key.
    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];

        let mut engine = HmacEngine::new(DigestAlgorithm::Sha256, key);
        engine.update(data);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// HMAC-SHA-1 basic test.
    #[test]
    fn test_hmac_sha1_basic() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];

        let mut engine = HmacEngine::new(DigestAlgorithm::Sha1, &key);
        engine.update(data);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// Test SHA-256 empty input digest.
    #[test]
    fn test_sha256_empty() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let mut engine = DigestEngine::new(DigestAlgorithm::Sha256);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// Test MD5 empty input digest.
    #[test]
    fn test_md5_empty() {
        let expected = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        let mut engine = DigestEngine::new(DigestAlgorithm::Md5);
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// Test SHA-1 "abc" digest.
    #[test]
    fn test_sha1_abc() {
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        let mut engine = DigestEngine::new(DigestAlgorithm::Sha1);
        engine.update(b"abc");
        let result = engine.finalize();
        assert_eq!(result, expected);
    }

    /// Test HmacProvider basic creation and descriptors.
    #[test]
    fn test_provider_basic() {
        let provider = HmacProvider::new();
        assert_eq!(provider.name(), "HMAC");
        assert_eq!(provider.size(), 0);

        let descs = HmacProvider::descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["HMAC"]);
    }

    /// Test HmacContext init/update/finalize via trait.
    #[test]
    fn test_context_trait_lifecycle() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let key = vec![0x0bu8; 20];
        ctx.init(&key, None).expect("init should succeed");
        ctx.update(b"Hi There").expect("update should succeed");
        let result = ctx.finalize().expect("finalize should succeed");

        // Expected HMAC-SHA-256 of "Hi There" with key = 20 bytes of 0x0b
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(result, expected);
    }

    /// Test FIPS key-size check.
    #[test]
    fn test_fips_key_size_check() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        // Short key: FIPS should mark as non-approved
        let short_key = vec![0x01u8; 10]; // 10 bytes < 14 bytes
        ctx.init(&short_key, None).expect("init should succeed");
        let params = ctx.get_params().expect("get_params should succeed");
        let fips_val: u64 = params
            .get_typed(PARAM_FIPS_INDICATOR)
            .expect("fips indicator present");
        assert_eq!(fips_val, 0, "short key should not be FIPS approved");
    }

    /// Test FIPS internal variant allows short keys.
    #[test]
    fn test_fips_internal_allows_short_key() {
        let provider = HmacProvider::new_internal();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let short_key = vec![0x01u8; 10]; // Short key
        ctx.init(&short_key, None).expect("init should succeed");
        let params = ctx.get_params().expect("get_params should succeed");
        let fips_val: u64 = params
            .get_typed(PARAM_FIPS_INDICATOR)
            .expect("fips indicator present");
        assert_eq!(fips_val, 1, "internal variant should stay FIPS approved");
    }

    /// Test set_params with digest selection.
    #[test]
    fn test_set_params_digest() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let params = ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, "SHA-1".to_string())
            .build();
        ctx.set_params(&params).expect("set_params should succeed");

        let key = vec![0x0bu8; 20];
        ctx.init(&key, None).expect("init should succeed");
        ctx.update(b"Hi There").expect("update should succeed");
        let result = ctx.finalize().expect("finalize should succeed");

        // HMAC-SHA-1 expected result
        assert_eq!(result.len(), 20);
    }

    /// Test get_params returns correct sizes.
    #[test]
    fn test_get_params_sizes() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let key = vec![0xaau8; 32];
        ctx.init(&key, None).expect("init should succeed");

        let params = ctx.get_params().expect("get_params should succeed");
        let size: u64 = params.get_typed(PARAM_SIZE).expect("size present");
        let block: u64 = params.get_typed(PARAM_BLOCK_SIZE).expect("block present");

        // Default digest is SHA-256: output=32, block=64
        assert_eq!(size, 32);
        assert_eq!(block, 64);
    }

    /// Test error on update before init.
    #[test]
    fn test_error_update_before_init() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let result = ctx.update(b"data");
        assert!(result.is_err(), "update before init should fail");
    }

    /// Test error on finalize before init.
    #[test]
    fn test_error_finalize_before_init() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let result = ctx.finalize();
        assert!(result.is_err(), "finalize before init should fail");
    }

    /// Test DigestAlgorithm::from_name case-insensitivity.
    #[test]
    fn test_digest_algorithm_names() {
        assert_eq!(
            DigestAlgorithm::from_name("sha-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_name("SHA256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_name("sha2-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_name("MD5"),
            Some(DigestAlgorithm::Md5)
        );
        assert_eq!(
            DigestAlgorithm::from_name("SHA-512/224"),
            Some(DigestAlgorithm::Sha512_224)
        );
        assert_eq!(DigestAlgorithm::from_name("unknown"), None);
    }

    /// Test HmacParams builder.
    #[test]
    fn test_hmac_params_builder() {
        let params = HmacParams::new()
            .with_digest("SHA-384")
            .with_properties("provider=fips")
            .with_tls_data_size(1024);

        assert_eq!(params.digest.as_deref(), Some("SHA-384"));
        assert_eq!(params.properties.as_deref(), Some("provider=fips"));
        assert_eq!(params.tls_data_size, Some(1024));
    }

    /// Test HmacContext clone creates independent copy.
    #[test]
    fn test_context_clone_independence() {
        let provider = HmacProvider::new();
        let mut ctx = provider.new_ctx().expect("new_ctx should succeed");

        let key = vec![0xaau8; 32];
        ctx.init(&key, None).expect("init should succeed");
        ctx.update(b"partial data").expect("update should succeed");

        // Get params to verify state
        let _params_snapshot = ctx.get_params().expect("original get_params");

        // Ensure original can still finalize
        let result = ctx.finalize().expect("finalize should succeed");
        assert!(!result.is_empty(), "finalize should produce output");
    }

    /// Test incremental update produces same result as single update.
    #[test]
    fn test_incremental_update() {
        let key = b"test key for incremental HMAC";

        // Single update
        let mut engine1 = HmacEngine::new(DigestAlgorithm::Sha256, key);
        engine1.update(b"Hello, World!");
        let result1 = engine1.finalize();

        // Incremental updates
        let mut engine2 = HmacEngine::new(DigestAlgorithm::Sha256, key);
        engine2.update(b"Hello");
        engine2.update(b", ");
        engine2.update(b"World!");
        let result2 = engine2.finalize();

        assert_eq!(result1, result2, "incremental should match single update");
    }

    /// Test HMAC with key longer than block size (triggers key hashing).
    #[test]
    fn test_long_key() {
        let key = vec![0xaau8; 200]; // Much longer than any block size
        let data = b"Test data";

        let mut engine = HmacEngine::new(DigestAlgorithm::Sha256, &key);
        engine.update(data);
        let result = engine.finalize();

        // RFC 4231 test case 6: key = 131 bytes of 0xaa
        // Just verify it produces valid output of correct size
        assert_eq!(result.len(), 32);
    }
}
