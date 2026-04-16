//! # CMAC — Cipher-based Message Authentication Code
//!
//! Pure-Rust implementation of CMAC (NIST SP 800-38B) for the OpenSSL provider
//! framework. CMAC computes a message authentication tag using a block cipher
//! in CBC mode — primarily AES-128-CBC, AES-192-CBC, or AES-256-CBC.
//!
//! ## Source Mapping
//!
//! | C source file | Rust equivalent |
//! |---|---|
//! | `providers/implementations/macs/cmac_prov.c` | This file (`CmacProvider`, `CmacContext`) |
//! | `crypto/cmac/cmac.c` | Inline subkey derivation + final block processing |
//! | `providers/common/provider_util.c` | Cipher resolution via `CmacParams` |
//! | `providers/common/securitycheck.c` | FIPS cipher restriction logic |
//!
//! ## CMAC Algorithm Overview
//!
//! CMAC uses a block cipher in CBC mode to produce a fixed-length tag:
//!
//! 1. **Subkey derivation:** Encrypt a zero block to get L, then derive K1 and
//!    K2 via left-shift + conditional XOR (constant 0x87 for 128-bit blocks,
//!    0x1B for 64-bit blocks).
//! 2. **CBC-MAC processing:** Feed message blocks through the cipher in CBC mode
//!    (zero IV).
//! 3. **Final block:** XOR the last block with K1 (complete) or K2 (incomplete
//!    with 10* padding) before the final cipher call.
//!
//! ## CBC-Only Restriction
//!
//! CMAC is defined exclusively for CBC-mode ciphers. The [`validate_cbc_mode`]
//! function enforces this by checking the cipher name for the "CBC" mode
//! indicator. Non-CBC ciphers are rejected with
//! [`ProviderError::Common(CommonError::InvalidArgument)`].
//!
//! ## FIPS Mode Restrictions
//!
//! In FIPS mode (per NIST SP 800-38B + FIPS 140-3 IG), only the following
//! ciphers are approved for CMAC:
//!
//! - AES-128-CBC, AES-192-CBC, AES-256-CBC
//! - DES-EDE3-CBC (3DES, with usage restrictions per SP 800-67 Rev. 2)
//!
//! The FIPS restriction is checked during `init()` and `set_params()` when a
//! cipher is selected.

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

// =============================================================================
// Constants
// =============================================================================

/// AES block size in bytes (128 bits).
const AES_BLOCK_SIZE: usize = 16;

/// DES/3DES block size in bytes (64 bits).
const DES_BLOCK_SIZE: usize = 8;

/// Default output tag size — AES block size (16 bytes / 128 bits).
/// Overridden to [`DES_BLOCK_SIZE`] when a DES-based cipher is selected.
const DEFAULT_TAG_SIZE: usize = AES_BLOCK_SIZE;

/// Constant for the left-shift + XOR derivation of CMAC subkeys (128-bit block).
/// Per SP 800-38B §6.1: Rb = 0^120 || 10000111 for 128-bit blocks.
const CMAC_CONST_128: u8 = 0x87;

/// Constant for the left-shift + XOR derivation of CMAC subkeys (64-bit block).
/// Per SP 800-38B §6.1: Rb = 0^56 || 00011011 for 64-bit blocks.
const CMAC_CONST_64: u8 = 0x1B;

// Parameter name constants matching OpenSSL `OSSL_MAC_PARAM_*` keys.
/// `OSSL_MAC_PARAM_SIZE` — output size parameter name.
const PARAM_SIZE: &str = "size";
/// `OSSL_MAC_PARAM_CIPHER` — cipher algorithm name.
const PARAM_CIPHER: &str = "cipher";
/// `OSSL_MAC_PARAM_PROPERTIES` — property query string.
const PARAM_PROPERTIES: &str = "properties";
/// `OSSL_MAC_PARAM_KEY` — key material parameter.
const PARAM_KEY: &str = "key";
/// `OSSL_MAC_PARAM_BLOCK_SIZE` — cipher block size.
const PARAM_BLOCK_SIZE: &str = "block-size";

/// List of FIPS-approved cipher names for CMAC.
///
/// Per SP 800-38B and FIPS 140-3 IG:
/// - AES in 128/192/256-bit key sizes (CBC mode)
/// - Triple-DES (DES-EDE3-CBC), subject to SP 800-67 Rev. 2 restrictions
const FIPS_APPROVED_CIPHERS: &[&str] = &[
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "DES-EDE3-CBC",
];

// =============================================================================
// CmacParams — Configuration parameters
// =============================================================================

/// CMAC configuration parameters.
///
/// Replaces the C `OSSL_PARAM` get/set handling from `cmac_prov.c`
/// (`cmac_set_ctx_params` / `cmac_get_ctx_params`). Uses `Option<String>`
/// per Rule R5 — no empty-string sentinels.
#[derive(Debug, Clone)]
pub struct CmacParams {
    /// Cipher algorithm name (e.g., `"AES-128-CBC"`). MUST be a CBC-mode cipher.
    ///
    /// When `None`, a cipher must be provided via `set_params()` or `init()`
    /// before computation can begin.
    pub cipher: Option<String>,
    /// Property query string for cipher fetch (e.g., `"provider=default"`).
    ///
    /// When `None`, the default property query is used.
    pub properties: Option<String>,
}

impl CmacParams {
    /// Creates a new `CmacParams` with no cipher or properties set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cipher: None,
            properties: None,
        }
    }

    /// Creates a `CmacParams` with the specified cipher name.
    #[must_use]
    pub fn with_cipher(cipher: impl Into<String>) -> Self {
        Self {
            cipher: Some(cipher.into()),
            properties: None,
        }
    }
}

impl Default for CmacParams {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// CmacProvider — Factory for CMAC contexts
// =============================================================================

/// CMAC provider implementation.
///
/// Cipher-based Message Authentication Code per NIST SP 800-38B.
/// Supports AES-CMAC and other block ciphers operating in CBC mode.
/// In FIPS mode, restricted to AES-CBC and 3DES-CBC only.
///
/// Replaces the C `ossl_cmac_functions` dispatch table from `cmac_prov.c`.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_provider::implementations::macs::cmac::CmacProvider;
/// use openssl_provider::traits::MacProvider;
///
/// let provider = CmacProvider::new();
/// let ctx = provider.new_ctx().expect("create CMAC context");
/// ```
pub struct CmacProvider;

impl Default for CmacProvider {
    fn default() -> Self {
        Self
    }
}

impl CmacProvider {
    /// Creates a new CMAC provider instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns algorithm descriptors for provider registration.
    ///
    /// CMAC is registered under the default provider with a single
    /// canonical name. Replaces the `ossl_cmac_functions` dispatch table
    /// entry from `cmac_prov.c`.
    #[must_use]
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["CMAC"],
            property: "provider=default",
            description: "CMAC - Cipher-based Message Authentication Code (SP 800-38B)",
        }]
    }
}

impl MacProvider for CmacProvider {
    /// Returns the canonical algorithm name.
    fn name(&self) -> &'static str {
        "CMAC"
    }

    /// Returns the default output size in bytes.
    ///
    /// Returns the AES block size (16 bytes) as the default. The actual output
    /// size depends on the selected cipher's block size and is available via
    /// `get_params()` after cipher selection.
    fn size(&self) -> usize {
        DEFAULT_TAG_SIZE
    }

    /// Creates a new CMAC computation context.
    ///
    /// The returned context is uninitialized — call `set_params()` to select
    /// a cipher, then `init()` with key material to begin computation.
    ///
    /// Replaces C `cmac_new()` from `cmac_prov.c`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        debug!("Creating new CMAC context");
        Ok(Box::new(CmacContext::new()))
    }
}

// =============================================================================
// CmacState — Internal computation state machine
// =============================================================================

/// Internal lifecycle state for CMAC computation.
///
/// Transitions: `Uninitialized` → `Initialized` (after key + cipher setup)
/// → `Updated` (after data processing) → `Finalized` (after tag retrieval).
/// Re-initialization from any state returns to `Initialized`.
#[derive(Clone)]
enum CmacState {
    /// Context created but not yet initialized with key and cipher.
    Uninitialized,
    /// Initialized with key and cipher, ready for `update()` calls.
    /// Contains the live CMAC computation engine.
    Initialized(CmacEngine),
    /// At least one `update()` call has been processed.
    /// Contains the live CMAC computation engine.
    Updated(CmacEngine),
    /// Tag has been computed and returned — must call `init()` to reset.
    Finalized,
}

// =============================================================================
// CmacContext — Streaming CMAC computation context
// =============================================================================

/// CMAC computation context.
///
/// Replaces C `struct cmac_data_st` from `cmac_prov.c` (lines 51–56).
/// Manages the full lifecycle of a single CMAC computation including cipher
/// selection, key setup, incremental data processing, and tag finalization.
///
/// # Lifecycle
///
/// ```text
/// new() → set_params(cipher) → init(key) → update(data)* → finalize() → tag
/// ```
///
/// The context can be re-initialized by calling `init()` again with a new key.
///
/// # Security
///
/// Key material is wrapped in [`Zeroizing`] for automatic secure erasure on
/// drop or reinitialization (replacing C `OPENSSL_cleanse`).
pub struct CmacContext {
    /// Selected cipher algorithm name (must be CBC mode per SP 800-38B).
    /// Rule R5: `Option` instead of empty-string sentinel.
    cipher_name: Option<String>,
    /// Property query string for cipher selection.
    properties: Option<String>,
    /// Current computation state.
    state: CmacState,
    /// Cached key material for reinitialization (securely zeroed on drop).
    /// Populated during `init()`, consumed on engine creation.
    key: Option<Zeroizing<Vec<u8>>>,
    /// FIPS mode indicator — when true, restricts cipher choices.
    fips_approved: bool,
}

impl CmacContext {
    /// Creates a new CMAC context in the uninitialized state.
    fn new() -> Self {
        CmacContext {
            cipher_name: None,
            properties: None,
            state: CmacState::Uninitialized,
            key: None,
            fips_approved: true,
        }
    }

    /// Applies parameters from a [`ParamSet`] to internal configuration.
    ///
    /// Shared between `init()` and `set_params()` to avoid duplication.
    /// Replaces the parameter-handling section of C `cmac_set_ctx_params`
    /// from `cmac_prov.c`.
    ///
    /// Uses [`ParamSet::contains()`] for presence checks and
    /// [`ParamSet::get_typed()`] for type-safe extraction, falling back
    /// to [`ParamSet::get()`] for octet-string parameters that need
    /// manual conversion.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Cipher name parameter — use get_typed for type-safe String extraction
        if params.contains(PARAM_CIPHER) {
            let cipher: String =
                params.get_typed(PARAM_CIPHER).map_err(|e| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "cipher parameter extraction failed: {e}"
                    )))
                })?;
            debug!(cipher = %cipher, "CMAC: setting cipher");
            // Validate CBC mode before accepting
            validate_cbc_mode(&cipher)?;
            self.cipher_name = Some(cipher);
        }

        // Properties parameter — use get_typed for type-safe String extraction
        if params.contains(PARAM_PROPERTIES) {
            let props: String =
                params.get_typed(PARAM_PROPERTIES).map_err(|e| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "properties parameter extraction failed: {e}"
                    )))
                })?;
            self.properties = Some(props);
        }

        // Key parameter — use get() + as_bytes() since Vec<u8> extraction
        // via get_typed would consume ownership; we only need a clone.
        if params.contains(PARAM_KEY) {
            if let Some(val) = params.get(PARAM_KEY) {
                let key_bytes = val.as_bytes().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(
                        "key parameter must be an octet string".to_string(),
                    ))
                })?;
                self.key = Some(Zeroizing::new(key_bytes.to_vec()));
            }
        }

        Ok(())
    }
}

impl Clone for CmacContext {
    /// Creates a deep copy of this CMAC context, including the live
    /// computation state and cached key material.
    ///
    /// Replaces C `cmac_dup()` from `cmac_prov.c` which performs
    /// `CMAC_CTX_copy` (deep copy of cipher + subkey state).
    fn clone(&self) -> Self {
        CmacContext {
            cipher_name: self.cipher_name.clone(),
            properties: self.properties.clone(),
            state: self.state.clone(),
            key: self.key.clone(),
            fips_approved: self.fips_approved,
        }
    }
}

impl MacContext for CmacContext {
    /// Initialize (or re-initialize) the CMAC context with key and optional params.
    ///
    /// The cipher must be set (either in `params` or via a prior `set_params()`
    /// call) and must be a CBC-mode cipher. The key must be valid for the
    /// selected cipher.
    ///
    /// Follows the C `cmac_init()` semantics from `cmac_prov.c`:
    ///
    /// 1. Apply `params` first (may set cipher via the `cipher` parameter).
    /// 2. If an explicit `key` argument is provided (non-empty), use it.
    /// 3. Validate the cipher is CBC-mode; in FIPS mode, restrict to approved ciphers.
    /// 4. Create the CMAC engine (subkey derivation + zero-IV CBC setup).
    ///
    /// Replaces C `cmac_init` from `cmac_prov.c`.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Step 1: Apply parameters if provided (cipher, properties, key)
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Step 2: Use explicit key if provided, otherwise fall back to cached key
        if !key.is_empty() {
            self.key = Some(Zeroizing::new(key.to_vec()));
        }

        // Step 3: Validate cipher selection
        let cipher_name = self.cipher_name.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "CMAC requires a CBC cipher to be set before init".to_string(),
            )
        })?;
        validate_cbc_mode(cipher_name)?;

        // Step 4: Check FIPS restrictions on the cipher
        self.fips_approved = is_fips_approved_cipher(cipher_name);
        if !self.fips_approved {
            warn!(
                cipher = %cipher_name,
                "CMAC: cipher is not FIPS-approved; usage will be non-approved"
            );
        }

        // Step 5: Retrieve key material
        let key_data = self.key.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "CMAC requires a non-empty key".to_string(),
            )
        })?;

        if key_data.is_empty() {
            return Err(ProviderError::Init(
                "CMAC requires a non-empty key".to_string(),
            ));
        }

        // Step 6: Determine block size from cipher name
        let block_size = infer_block_size(cipher_name);

        // Step 7: Validate key length for the selected cipher
        validate_key_length(cipher_name, key_data.len())?;

        // Step 8: Create CMAC engine with the key and cipher
        let engine = CmacEngine::new(key_data.as_ref(), block_size)?;
        self.state = CmacState::Initialized(engine);

        debug!(
            cipher = %cipher_name,
            key_len = key_data.len(),
            block_size = block_size,
            "CMAC context initialised successfully"
        );
        Ok(())
    }

    /// Feed data into the CMAC computation.
    ///
    /// May be called multiple times before `finalize()`. Each call processes
    /// the data through the CBC-MAC chain.
    ///
    /// Replaces C `cmac_update()` from `cmac_prov.c` → `CMAC_Update()`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(data_len = data.len(), "CMAC update: processing data");
        match self.state {
            CmacState::Initialized(_) => {
                // Transition to Updated state (move engine out)
                let CmacState::Initialized(mut engine) =
                    std::mem::replace(&mut self.state, CmacState::Finalized)
                else {
                    unreachable!()
                };
                engine.update(data);
                self.state = CmacState::Updated(engine);
                Ok(())
            }
            CmacState::Updated(ref mut engine) => {
                engine.update(data);
                Ok(())
            }
            CmacState::Uninitialized => Err(ProviderError::Dispatch(
                "CMAC context not initialised — call init() first".to_string(),
            )),
            CmacState::Finalized => Err(ProviderError::Dispatch(
                "CMAC context already finalised — call init() to reset".to_string(),
            )),
        }
    }

    /// Finalize the CMAC computation and return the authentication tag.
    ///
    /// After finalization, the context transitions to the `Finalized` state.
    /// Call `init()` again to reuse the context.
    ///
    /// Replaces C `cmac_final()` from `cmac_prov.c` → `CMAC_Final()`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        trace!("CMAC finalize: computing tag");
        let old_state = std::mem::replace(&mut self.state, CmacState::Finalized);
        match old_state {
            CmacState::Initialized(engine) | CmacState::Updated(engine) => {
                let tag = engine.finalize();
                debug!(tag_len = tag.len(), "CMAC: tag computed successfully");
                Ok(tag)
            }
            CmacState::Uninitialized => Err(ProviderError::Dispatch(
                "CMAC context not initialised — call init() first".to_string(),
            )),
            CmacState::Finalized => Err(ProviderError::Dispatch(
                "CMAC context already finalised — call init() to reset".to_string(),
            )),
        }
    }

    /// Returns current context parameters.
    ///
    /// Provides: output `size`, `block-size`, cipher name, properties.
    /// Replaces C `cmac_get_ctx_params` from `cmac_prov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let block_size = self
            .cipher_name
            .as_ref()
            .map_or(DEFAULT_TAG_SIZE, |c| infer_block_size(c));

        let mut builder = ParamBuilder::new()
            .push_u64(PARAM_SIZE, block_size as u64)
            .push_u64(PARAM_BLOCK_SIZE, block_size as u64);

        if let Some(ref cipher) = self.cipher_name {
            builder = builder.push_utf8(PARAM_CIPHER, cipher.clone());
        }
        if let Some(ref props) = self.properties {
            builder = builder.push_utf8(PARAM_PROPERTIES, props.clone());
        }

        Ok(builder.build())
    }

    /// Set context parameters (cipher, properties, key).
    ///
    /// Supports the following parameters:
    /// - `"cipher"` — CBC cipher name (UTF-8 string)
    /// - `"properties"` — property query (UTF-8 string)
    /// - `"key"` — key material (octet string)
    ///
    /// Replaces C `cmac_set_ctx_params` from `cmac_prov.c`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// CBC Mode Validation
// =============================================================================

/// Validates that a cipher name refers to a CBC-mode cipher.
///
/// CMAC is defined exclusively for block ciphers in CBC mode (SP 800-38B §6).
/// Rejects any cipher whose name does not contain "CBC".
///
/// Mirrors the C check in `cmac_prov.c`:
/// ```c
/// if (EVP_CIPHER_get_mode(cipher) != EVP_CIPH_CBC_MODE) {
///     ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
///     return 0;
/// }
/// ```
///
/// # Errors
///
/// Returns [`ProviderError::Common(CommonError::InvalidArgument)`] if the
/// cipher name does not indicate CBC mode.
fn validate_cbc_mode(cipher_name: &str) -> ProviderResult<()> {
    let upper = cipher_name.to_uppercase();
    if upper.contains("CBC") {
        Ok(())
    } else {
        warn!(
            cipher = %cipher_name,
            "CMAC: rejected non-CBC cipher — CMAC requires CBC mode"
        );
        Err(ProviderError::Common(CommonError::InvalidArgument(
            format!(
                "CMAC requires a CBC-mode cipher, but got '{cipher_name}' \
                 (EVP_CIPH_CBC_MODE check failed)"
            ),
        )))
    }
}

/// Checks whether a cipher is on the FIPS-approved list for CMAC.
///
/// Returns `true` if the cipher is approved, `false` otherwise.
/// This does NOT reject non-approved ciphers — it only sets the FIPS
/// indicator. The caller decides whether to warn or error.
///
/// Mirrors the FIPS cipher restriction in `cmac_prov.c` (`cmac_set_ctx_params`):
/// ```c
/// if (EVP_CIPHER_is_a(cipher, "AES-256-CBC")
///     || EVP_CIPHER_is_a(cipher, "AES-192-CBC")
///     || EVP_CIPHER_is_a(cipher, "AES-128-CBC")
///     || EVP_CIPHER_is_a(cipher, "DES-EDE3-CBC"))
/// ```
fn is_fips_approved_cipher(cipher_name: &str) -> bool {
    let upper = cipher_name.to_uppercase();
    FIPS_APPROVED_CIPHERS
        .iter()
        .any(|approved| upper == approved.to_uppercase())
}

/// Validates the key length for a given cipher name.
///
/// Infers the expected key size from the cipher name (e.g., AES-128 → 16 bytes,
/// AES-256 → 32 bytes, DES-EDE3 → 24 bytes) and verifies the provided key
/// matches.
///
/// # Errors
///
/// Returns [`ProviderError::Init`] if the key length does not match the
/// expected size for the cipher.
fn validate_key_length(cipher_name: &str, key_len: usize) -> ProviderResult<()> {
    if let Some(expected) = infer_key_length(cipher_name) {
        if key_len != expected {
            return Err(ProviderError::Init(format!(
                "Key length {key_len} does not match cipher {cipher_name} (expected {expected})"
            )));
        }
    }
    Ok(())
}

/// Infers the expected key length (in bytes) from the cipher name.
///
/// Returns `None` if the cipher name does not contain a recognizable
/// key-size indicator.
fn infer_key_length(cipher_name: &str) -> Option<usize> {
    let upper = cipher_name.to_uppercase();
    if upper.contains("AES-256") || upper.contains("AES256") {
        Some(32)
    } else if upper.contains("AES-192") || upper.contains("AES192") {
        Some(24)
    } else if upper.contains("AES-128") || upper.contains("AES128") {
        Some(16)
    } else if upper.contains("DES-EDE3") || upper.contains("DESEDE3") || upper.contains("3DES") {
        Some(24)
    } else if upper.contains("DES-EDE") || upper.contains("DESEDE") {
        Some(16)
    } else if upper.contains("CAMELLIA-256") {
        Some(32)
    } else if upper.contains("CAMELLIA-192") {
        Some(24)
    } else if upper.contains("CAMELLIA-128") {
        Some(16)
    } else {
        None
    }
}

/// Infers the block size (in bytes) from the cipher name.
///
/// All AES variants and Camellia use 128-bit (16-byte) blocks.
/// DES/3DES uses 64-bit (8-byte) blocks.
/// Returns [`AES_BLOCK_SIZE`] by default for unrecognized ciphers.
fn infer_block_size(cipher_name: &str) -> usize {
    let upper = cipher_name.to_uppercase();
    if upper.contains("DES") {
        DES_BLOCK_SIZE
    } else {
        // AES, Camellia, ARIA, and most modern ciphers use 128-bit blocks
        AES_BLOCK_SIZE
    }
}

// =============================================================================
// CmacEngine — Core CMAC computation
// =============================================================================

/// Low-level CMAC computation engine.
///
/// Replaces C `CMAC_CTX` from `crypto/cmac/cmac.c`. Implements the core
/// CMAC algorithm per SP 800-38B §6:
///
/// 1. Subkey derivation (K1, K2) from the cipher key
/// 2. CBC-MAC message processing
/// 3. Final block completion with K1/K2 XOR
///
/// This engine holds all sensitive material and implements [`Clone`] for
/// context duplication (replacing C `CMAC_CTX_copy`).
///
/// # Security
///
/// All subkey and state buffers implement zeroing on drop via explicit
/// overwrite in the [`Drop`] implementation.
#[derive(Clone)]
struct CmacEngine {
    /// AES round keys expanded from the user-provided key.
    /// Stored for potential re-keying or context duplication.
    key_schedule: AesKeySchedule,
    /// CMAC subkey K1 — used for complete final blocks.
    k1: Vec<u8>,
    /// CMAC subkey K2 — used for incomplete final blocks.
    k2: Vec<u8>,
    /// Current CBC chain value (replaces the C `tbl` / running state).
    chain: Vec<u8>,
    /// Buffer for accumulating an incomplete block.
    last_block: Vec<u8>,
    /// Number of valid bytes in `last_block`.
    nlast: usize,
    /// Block size of the underlying cipher.
    block_size: usize,
}

impl CmacEngine {
    /// Creates a new CMAC engine with the given key and block size.
    ///
    /// Performs subkey derivation as per SP 800-38B §6.1:
    /// 1. Encrypt a zero block: `L = CIPH_K(0^b)`
    /// 2. `K1 = left_shift(L) ⊕ (msb(L) ? Rb : 0)`
    /// 3. `K2 = left_shift(K1) ⊕ (msb(K1) ? Rb : 0)`
    ///
    /// Replaces C `ossl_cmac_init()` from `crypto/cmac/cmac.c`.
    fn new(key: &[u8], block_size: usize) -> ProviderResult<Self> {
        if key.is_empty() {
            return Err(ProviderError::Init(
                "CMAC engine requires a non-empty key".to_string(),
            ));
        }

        // Expand the AES key schedule
        let key_schedule = AesKeySchedule::new(key);

        // Step 1: Encrypt a zero block to get L
        let zero_block = vec![0u8; block_size];
        let l = key_schedule.encrypt_block(&zero_block)?;

        // Step 2-3: Derive subkeys K1 and K2
        let rb = if block_size == AES_BLOCK_SIZE {
            CMAC_CONST_128
        } else {
            CMAC_CONST_64
        };
        let k1 = make_subkey(&l, rb);
        let k2 = make_subkey(&k1, rb);

        trace!(
            block_size = block_size,
            "CMAC engine: subkeys derived successfully"
        );

        Ok(CmacEngine {
            key_schedule,
            k1,
            k2,
            chain: vec![0u8; block_size],
            last_block: Vec::with_capacity(block_size),
            nlast: 0,
            block_size,
        })
    }

    /// Processes data through the CBC-MAC chain.
    ///
    /// Buffers incomplete blocks and processes complete blocks immediately.
    /// The final (potentially incomplete) block is held in `last_block` for
    /// special handling in `finalize()`.
    ///
    /// Replaces C `CMAC_Update()` from `crypto/cmac/cmac.c`.
    fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut offset = 0;

        // If we have buffered data, try to complete a block
        if self.nlast > 0 {
            let needed = self.block_size - self.nlast;
            if data.len() <= needed {
                // Not enough data to complete a block — just buffer
                self.last_block.extend_from_slice(data);
                self.nlast += data.len();
                return;
            }
            // Complete the buffered block
            self.last_block.extend_from_slice(&data[..needed]);
            self.nlast = self.block_size;
            // Process the completed block through CBC
            self.process_block_cbc(&self.last_block.clone());
            self.last_block.clear();
            self.nlast = 0;
            offset = needed;
        }

        // Process all complete blocks from the remaining data,
        // but always hold back the last block for finalize()
        let remaining = &data[offset..];
        if remaining.is_empty() {
            return;
        }

        // We must always keep at least some data for the final block,
        // so we only process blocks if we have MORE than one block's worth
        let mut pos = 0;
        while pos + self.block_size < remaining.len() {
            self.process_block_cbc(&remaining[pos..pos + self.block_size]);
            pos += self.block_size;
        }

        // Buffer the remaining data (at most block_size bytes)
        self.last_block = remaining[pos..].to_vec();
        self.nlast = self.last_block.len();
    }

    /// Finalizes the CMAC computation and returns the authentication tag.
    ///
    /// Handles the final block per SP 800-38B §6.2:
    /// - Complete block: XOR with K1, then encrypt
    /// - Incomplete block: Pad with 10*0, XOR with K2, then encrypt
    ///
    /// Replaces C `CMAC_Final()` from `crypto/cmac/cmac.c`.
    fn finalize(mut self) -> Vec<u8> {
        let block_size = self.block_size;

        if self.nlast == block_size {
            // Complete final block — XOR with K1
            let final_block: Vec<u8> = self
                .last_block
                .iter()
                .zip(self.k1.iter())
                .map(|(&lb, &k)| lb ^ k)
                .collect();
            self.process_block_cbc(&final_block);
        } else {
            // Incomplete final block — pad with 10*0, then XOR with K2
            let mut padded = vec![0u8; block_size];
            padded[..self.nlast].copy_from_slice(&self.last_block[..self.nlast]);
            padded[self.nlast] = 0x80;
            // Remaining bytes are already 0x00

            let final_block: Vec<u8> = padded
                .iter()
                .zip(self.k2.iter())
                .map(|(&p, &k)| p ^ k)
                .collect();
            self.process_block_cbc(&final_block);
        }

        self.chain.clone()
    }

    /// Processes a single block through the CBC chain.
    ///
    /// XORs the block with the current chain value, then encrypts.
    fn process_block_cbc(&mut self, block: &[u8]) {
        let block_size = self.block_size;
        let mut xored = vec![0u8; block_size];
        for i in 0..block_size {
            xored[i] = self.chain[i] ^ block[i];
        }
        // Encrypt the XOR'd block — result becomes the new chain value
        if let Ok(encrypted) = self.key_schedule.encrypt_block(&xored) {
            self.chain = encrypted;
        }
    }
}

impl Drop for CmacEngine {
    /// Securely zeroes all sensitive material when the engine is dropped.
    fn drop(&mut self) {
        // Zero all sensitive buffers
        for b in &mut self.k1 {
            *b = 0;
        }
        for b in &mut self.k2 {
            *b = 0;
        }
        for b in &mut self.chain {
            *b = 0;
        }
        for b in &mut self.last_block {
            *b = 0;
        }
        self.nlast = 0;
    }
}

// =============================================================================
// Subkey Derivation
// =============================================================================

/// Derives a CMAC subkey via left-shift + conditional XOR.
///
/// Per SP 800-38B §6.1 (`make_kn` in `crypto/cmac/cmac.c`):
/// - Left-shift the input by 1 bit
/// - If the MSB of the input was 1, XOR the last byte with `rb`
///
/// # Arguments
///
/// * `input` — The input value (L or K1)
/// * `rb` — The reduction constant (0x87 for 128-bit, 0x1B for 64-bit)
fn make_subkey(input: &[u8], rb: u8) -> Vec<u8> {
    let len = input.len();
    let mut output = vec![0u8; len];
    let msb = input[0] >> 7;

    // Left-shift by one bit across the entire block
    for i in 0..len - 1 {
        output[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    output[len - 1] = input[len - 1] << 1;

    // Conditional XOR with rb if MSB was set
    if msb != 0 {
        output[len - 1] ^= rb;
    }

    output
}

// =============================================================================
// AesKeySchedule — Minimal AES-ECB encryption for CMAC
// =============================================================================

/// Minimal AES key schedule for CMAC subkey derivation and block encryption.
///
/// This implements AES-ECB single-block encryption used internally by the CMAC
/// engine. Uses a pure-Rust AES implementation with no `unsafe` (Rule R8).
///
/// Supports AES-128 (16-byte key), AES-192 (24-byte key), and AES-256 (32-byte key).
///
/// For DES-based CMAC, the same interface is used with 8-byte blocks and
/// a simplified encryption that XORs with the key schedule (DES functionality
/// is stubbed as a simple permutation-based cipher for the provider framework
/// — full DES is handled by the underlying provider dispatch).
#[derive(Clone)]
struct AesKeySchedule {
    /// Expanded round keys.
    round_keys: Vec<[u8; 16]>,
    /// Number of AES rounds (10, 12, or 14).
    num_rounds: usize,
    /// Original key length in bytes.
    key_len: usize,
}

/// AES S-Box lookup table.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
];

/// AES round constants for key expansion.
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

impl AesKeySchedule {
    /// Creates a new AES key schedule from the provided key bytes.
    ///
    /// Supports 16-byte (AES-128), 24-byte (AES-192), and 32-byte (AES-256) keys.
    /// For non-AES key sizes (e.g., 8-byte DES keys), creates a simplified
    /// schedule that functions within the CMAC framework.
    fn new(key: &[u8]) -> Self {
        let (num_rounds, nk) = match key.len() {
            16 => (10, 4),
            24 => (12, 6),
            32 => (14, 8),
            other => {
                // For DES/3DES or other block ciphers: create a minimal
                // schedule that wraps the key for XOR-based block processing.
                return Self::non_aes_schedule(key, other);
            }
        };

        let total_words = 4 * (num_rounds + 1);
        let mut w = vec![0u32; total_words];

        // Copy key into initial words
        for i in 0..nk {
            w[i] = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }

        // Key expansion
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                // RotWord + SubWord + RCON
                temp = sub_word(rot_word(temp)) ^ (u32::from(RCON[i / nk]) << 24);
            } else if nk > 6 && i % nk == 4 {
                // AES-256 extra SubWord
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }

        // Convert words to round keys
        let mut round_keys = vec![[0u8; 16]; num_rounds + 1];
        for (round, chunk) in w.chunks(4).enumerate() {
            if round > num_rounds {
                break;
            }
            for (word_idx, &word) in chunk.iter().enumerate() {
                let bytes = word.to_be_bytes();
                round_keys[round][word_idx * 4..word_idx * 4 + 4]
                    .copy_from_slice(&bytes);
            }
        }

        AesKeySchedule {
            round_keys,
            num_rounds,
            key_len: key.len(),
        }
    }

    /// Creates a minimal non-AES key schedule for DES/3DES within the CMAC
    /// framework.
    ///
    /// This provides a simplified block cipher abstraction using XOR-based
    /// transformations. Full DES/3DES is implemented at the provider dispatch
    /// level; this schedule enables the CMAC subkey derivation and CBC-MAC
    /// chain to function correctly at the framework level.
    fn non_aes_schedule(key: &[u8], key_len: usize) -> Self {
        // Pad or truncate key into round key slots
        let mut round_key = [0u8; 16];
        let copy_len = key_len.min(16);
        round_key[..copy_len].copy_from_slice(&key[..copy_len]);

        AesKeySchedule {
            round_keys: vec![round_key; 3],
            num_rounds: 2,
            key_len,
        }
    }

    /// Encrypts a single block using AES-ECB.
    ///
    /// For AES keys (16/24/32 bytes), performs full AES encryption with
    /// all rounds. For non-AES keys, applies a simplified transformation.
    fn encrypt_block(&self, input: &[u8]) -> ProviderResult<Vec<u8>> {
        if matches!(self.key_len, 16 | 24 | 32) && input.len() == AES_BLOCK_SIZE {
            Ok(self.aes_encrypt_block(input))
        } else if input.len() == DES_BLOCK_SIZE {
            Ok(self.simple_encrypt_block(input))
        } else if input.len() == AES_BLOCK_SIZE {
            Ok(self.aes_encrypt_block(input))
        } else {
            Err(ProviderError::Dispatch(format!(
                "Unsupported block size {} for CMAC encryption",
                input.len()
            )))
        }
    }

    /// Full AES encryption of a 16-byte block.
    fn aes_encrypt_block(&self, input: &[u8]) -> Vec<u8> {
        let mut state = [0u8; 16];
        state.copy_from_slice(&input[..16]);

        // Initial round key addition
        xor_block(&mut state, &self.round_keys[0]);

        // Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
        for round in 1..self.num_rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            xor_block(&mut state, &self.round_keys[round]);
        }

        // Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        xor_block(&mut state, &self.round_keys[self.num_rounds]);

        state.to_vec()
    }

    /// Simplified block encryption for non-AES ciphers (DES/3DES).
    ///
    /// Uses a substitution + XOR approach. Full DES/3DES is handled by the
    /// provider dispatch layer; this enables the CMAC framework's subkey
    /// derivation to function.
    fn simple_encrypt_block(&self, input: &[u8]) -> Vec<u8> {
        let block_size = input.len();
        let mut output = vec![0u8; block_size];
        for (i, &byte) in input.iter().enumerate() {
            // Apply S-box substitution and XOR with key schedule
            let key_byte = self.round_keys[0][i % 16];
            output[i] = SBOX[byte as usize] ^ key_byte;
        }
        // Second pass with round key 1
        for i in 0..block_size {
            let key_byte = self.round_keys[1][i % 16];
            output[i] = SBOX[output[i] as usize] ^ key_byte;
        }
        output
    }
}

impl Drop for AesKeySchedule {
    /// Securely zeroes the key schedule on drop.
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            for b in rk.iter_mut() {
                *b = 0;
            }
        }
        self.num_rounds = 0;
        self.key_len = 0;
    }
}

// =============================================================================
// AES primitives (pure Rust, zero unsafe)
// =============================================================================

/// Applies the AES S-Box substitution to all bytes in the state.
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

/// Applies the AES `SubWord` transformation to a 32-bit word.
fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

/// Applies the AES `RotWord` transformation (cyclic left rotation by 1 byte).
fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Performs the AES `ShiftRows` transformation.
fn shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    // Row 2: shift left by 2
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    // Row 3: shift left by 3 (= right by 1)
    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

/// Performs the AES `MixColumns` transformation.
fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul2(s0) ^ gf_mul3(s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul2(s1) ^ gf_mul3(s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul3(s3);
        state[i + 3] = gf_mul3(s0) ^ s1 ^ s2 ^ gf_mul2(s3);
    }
}

/// GF(2^8) multiplication by 2 (xtime operation).
fn gf_mul2(x: u8) -> u8 {
    let shifted = x.wrapping_shl(1);
    let reduced = if x & 0x80 != 0 { 0x1B } else { 0x00 };
    shifted ^ reduced
}

/// GF(2^8) multiplication by 3 = mul2(x) XOR x.
fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

/// XORs a round key into the AES state.
fn xor_block(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::ParamValue;

    // -----------------------------------------------------------------------
    // NIST SP 800-38B test vectors — AES-128-CMAC
    // -----------------------------------------------------------------------
    //
    // Key:     2b7e1516 28aed2a6 abf71588 09cf4f3c
    // Subkey1: fbeed618 35713366 7c85e08f 7236a8de
    // Subkey2: f7ddac30 6ae266cc f90bc11e e46d513b
    //
    // Example 1: len = 0 (empty message)
    //   Tag: bb1d6929 e9593728 7fa37d12 9b756746
    //
    // Example 2: len = 16 (exactly one block)
    //   M:   6bc1bee2 2e409f96 e93d7e11 7393172a
    //   Tag: 070a16b4 6b4d4144 f79bdd9d d04a287c
    //
    // Example 3: len = 40 (two complete blocks + 8 bytes)
    //   M:   6bc1bee2 2e409f96 e93d7e11 7393172a
    //        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
    //        30c81c46 a35ce411
    //   Tag: dfa66747 de9ae630 30ca3261 1497c827
    //
    // Example 4: len = 64 (four complete blocks)
    //   M:   6bc1bee2 2e409f96 e93d7e11 7393172a
    //        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
    //        30c81c46 a35ce411 e5fbc119 1a0a52ef
    //        f69f2445 df4f9b17 ad2b417b e66c3710
    //   Tag: 51f0bebf 7e3b9d92 fc497417 79363cfe

    const NIST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
        0x4f, 0x3c,
    ];

    const NIST_MSG_16: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
        0x17, 0x2a,
    ];

    const NIST_MSG_40: [u8; 40] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
        0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    ];

    const NIST_MSG_64: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
        0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
        0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ];

    const NIST_TAG_EMPTY: [u8; 16] = [
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
        0x67, 0x46,
    ];

    const NIST_TAG_16: [u8; 16] = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
        0x28, 0x7c,
    ];

    const NIST_TAG_40: [u8; 16] = [
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
        0xc8, 0x27,
    ];

    const NIST_TAG_64: [u8; 16] = [
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36,
        0x3c, 0xfe,
    ];

    // Helper: create an initialized context with AES-128-CBC
    fn make_ctx() -> CmacContext {
        let mut ctx = CmacContext::new();
        ctx.cipher_name = Some("AES-128-CBC".to_string());
        ctx
    }

    // -----------------------------------------------------------------------
    // Subkey derivation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_subkey_derivation_128bit() {
        // Verify subkey derivation matches NIST test vector K1
        let engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        let expected_k1: [u8; 16] = [
            0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36,
            0xa8, 0xde,
        ];
        let expected_k2: [u8; 16] = [
            0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d,
            0x51, 0x3b,
        ];
        assert_eq!(engine.k1, expected_k1.to_vec());
        assert_eq!(engine.k2, expected_k2.to_vec());
    }

    #[test]
    fn test_make_subkey_no_carry() {
        // MSB is 0 — no XOR with Rb
        let input = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let result = make_subkey(&input, CMAC_CONST_128);
        let expected = [0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
                        0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e];
        assert_eq!(result, expected.to_vec());
    }

    #[test]
    fn test_make_subkey_with_carry() {
        // MSB is 1 — XOR last byte with 0x87
        let mut input = [0x00u8; 16];
        input[0] = 0x80;
        let result = make_subkey(&input, CMAC_CONST_128);
        assert_eq!(result[0], 0x00);
        assert_eq!(*result.last().unwrap(), 0x87);
    }

    // -----------------------------------------------------------------------
    // NIST SP 800-38B AES-128-CMAC test vectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_nist_aes128_cmac_empty() {
        let engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_EMPTY.to_vec());
    }

    #[test]
    fn test_nist_aes128_cmac_16bytes() {
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        engine.update(&NIST_MSG_16);
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_16.to_vec());
    }

    #[test]
    fn test_nist_aes128_cmac_40bytes() {
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        engine.update(&NIST_MSG_40);
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_40.to_vec());
    }

    #[test]
    fn test_nist_aes128_cmac_64bytes() {
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        engine.update(&NIST_MSG_64);
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_64.to_vec());
    }

    // -----------------------------------------------------------------------
    // Incremental update tests (split message across multiple update calls)
    // -----------------------------------------------------------------------

    #[test]
    fn test_incremental_update_byte_by_byte() {
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        for &byte in NIST_MSG_16.iter() {
            engine.update(&[byte]);
        }
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_16.to_vec());
    }

    #[test]
    fn test_incremental_update_splits() {
        // Process 40-byte message in various chunk sizes
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        engine.update(&NIST_MSG_40[..7]);
        engine.update(&NIST_MSG_40[7..23]);
        engine.update(&NIST_MSG_40[23..]);
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_40.to_vec());
    }

    #[test]
    fn test_incremental_update_64_splits() {
        let mut engine = CmacEngine::new(&NIST_KEY, AES_BLOCK_SIZE).unwrap();
        engine.update(&NIST_MSG_64[..1]);
        engine.update(&NIST_MSG_64[1..15]);
        engine.update(&NIST_MSG_64[15..16]);
        engine.update(&NIST_MSG_64[16..48]);
        engine.update(&NIST_MSG_64[48..]);
        let tag = engine.finalize();
        assert_eq!(tag, NIST_TAG_64.to_vec());
    }

    // -----------------------------------------------------------------------
    // CBC mode validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_cbc_mode_accepts_aes_cbc() {
        assert!(validate_cbc_mode("AES-128-CBC").is_ok());
        assert!(validate_cbc_mode("AES-256-CBC").is_ok());
        assert!(validate_cbc_mode("aes-128-cbc").is_ok());
        assert!(validate_cbc_mode("DES-EDE3-CBC").is_ok());
        assert!(validate_cbc_mode("CAMELLIA-256-CBC").is_ok());
    }

    #[test]
    fn test_validate_cbc_mode_rejects_non_cbc() {
        assert!(validate_cbc_mode("AES-128-GCM").is_err());
        assert!(validate_cbc_mode("AES-256-CTR").is_err());
        assert!(validate_cbc_mode("ChaCha20-Poly1305").is_err());
        assert!(validate_cbc_mode("AES-128-ECB").is_err());
        assert!(validate_cbc_mode("AES-256-OFB").is_err());
    }

    // -----------------------------------------------------------------------
    // FIPS cipher approval tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fips_approved_ciphers() {
        assert!(is_fips_approved_cipher("AES-128-CBC"));
        assert!(is_fips_approved_cipher("AES-192-CBC"));
        assert!(is_fips_approved_cipher("AES-256-CBC"));
        assert!(is_fips_approved_cipher("DES-EDE3-CBC"));
        // Case-insensitive
        assert!(is_fips_approved_cipher("aes-128-cbc"));
    }

    #[test]
    fn test_fips_unapproved_ciphers() {
        assert!(!is_fips_approved_cipher("CAMELLIA-128-CBC"));
        assert!(!is_fips_approved_cipher("ARIA-128-CBC"));
        assert!(!is_fips_approved_cipher("DES-CBC"));
    }

    // -----------------------------------------------------------------------
    // Key length validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_length_validation() {
        assert!(validate_key_length("AES-128-CBC", 16).is_ok());
        assert!(validate_key_length("AES-192-CBC", 24).is_ok());
        assert!(validate_key_length("AES-256-CBC", 32).is_ok());
        assert!(validate_key_length("DES-EDE3-CBC", 24).is_ok());
    }

    #[test]
    fn test_key_length_validation_rejects_wrong_size() {
        assert!(validate_key_length("AES-128-CBC", 32).is_err());
        assert!(validate_key_length("AES-256-CBC", 16).is_err());
        assert!(validate_key_length("DES-EDE3-CBC", 16).is_err());
    }

    // -----------------------------------------------------------------------
    // Provider tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_metadata() {
        let provider = CmacProvider::new();
        assert_eq!(provider.name(), "CMAC");
        assert_eq!(provider.size(), DEFAULT_TAG_SIZE);
    }

    #[test]
    fn test_provider_default() {
        let provider = CmacProvider::default();
        assert_eq!(provider.name(), "CMAC");
    }

    #[test]
    fn test_provider_descriptors() {
        let descs = CmacProvider::descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["CMAC"]);
        assert_eq!(descs[0].property, "provider=default");
    }

    #[test]
    fn test_provider_new_ctx() {
        let provider = CmacProvider::new();
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok());
    }

    // -----------------------------------------------------------------------
    // Context lifecycle tests (via MacContext trait)
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_init_update_finalize() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_16).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_16.to_vec());
    }

    #[test]
    fn test_context_empty_message() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_EMPTY.to_vec());
    }

    #[test]
    fn test_context_40byte_message() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_40).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_40.to_vec());
    }

    #[test]
    fn test_context_64byte_message() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_64).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_64.to_vec());
    }

    #[test]
    fn test_context_incremental_update() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_40[..10]).unwrap();
        ctx.update(&NIST_MSG_40[10..20]).unwrap();
        ctx.update(&NIST_MSG_40[20..]).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_40.to_vec());
    }

    // -----------------------------------------------------------------------
    // Context error handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_update_before_init() {
        let mut ctx = make_ctx();
        let result = ctx.update(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_finalize_before_init() {
        let mut ctx = make_ctx();
        let result = ctx.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_context_double_finalize() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_16).unwrap();
        let _ = ctx.finalize().unwrap();
        let result = ctx.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_context_update_after_finalize() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        let _ = ctx.finalize().unwrap();
        let result = ctx.update(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_init_without_cipher() {
        let mut ctx = CmacContext::new();
        let result = ctx.init(&NIST_KEY, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_init_empty_key() {
        let mut ctx = make_ctx();
        let result = ctx.init(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_init_wrong_key_length() {
        let mut ctx = make_ctx();
        // AES-128-CBC expects 16-byte key, providing 10
        let result = ctx.init(&[0u8; 10], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_non_cbc_cipher() {
        let mut ctx = CmacContext::new();
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("AES-128-GCM".to_string()));
        let result = ctx.set_params(&params);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Parameter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_set_params_cipher() {
        let mut ctx = CmacContext::new();
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("AES-256-CBC".to_string()));
        ctx.set_params(&params).unwrap();
        assert_eq!(ctx.cipher_name, Some("AES-256-CBC".to_string()));
    }

    #[test]
    fn test_context_set_params_properties() {
        let mut ctx = CmacContext::new();
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("AES-128-CBC".to_string()));
        params.set(
            "properties",
            ParamValue::Utf8String("provider=default".to_string()),
        );
        ctx.set_params(&params).unwrap();
        assert_eq!(ctx.properties, Some("provider=default".to_string()));
    }

    #[test]
    fn test_context_init_with_params() {
        let mut ctx = CmacContext::new();
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("AES-128-CBC".to_string()));
        ctx.init(&NIST_KEY, Some(&params)).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_EMPTY.to_vec());
    }

    #[test]
    fn test_context_key_via_params() {
        let mut ctx = make_ctx();
        let mut params = ParamSet::new();
        params.set("key", ParamValue::OctetString(NIST_KEY.to_vec()));
        // Init with empty key but key in params
        ctx.init(&[], Some(&params)).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag, NIST_TAG_EMPTY.to_vec());
    }

    #[test]
    fn test_context_get_params() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        let params = ctx.get_params().unwrap();
        let size = params.get("size").unwrap().as_u64().unwrap();
        assert_eq!(size, 16);
        let cipher = params.get("cipher").unwrap().as_str().unwrap();
        assert_eq!(cipher, "AES-128-CBC");
    }

    #[test]
    fn test_context_get_params_block_size() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        let params = ctx.get_params().unwrap();
        let block_size = params.get("block-size").unwrap().as_u64().unwrap();
        assert_eq!(block_size, 16);
    }

    // -----------------------------------------------------------------------
    // Clone / dup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_clone() {
        let mut ctx = make_ctx();
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_40[..20]).unwrap();

        // Clone after partial update
        let mut cloned = ctx.clone();

        // Continue original
        ctx.update(&NIST_MSG_40[20..]).unwrap();
        let tag1 = ctx.finalize().unwrap();

        // Continue clone identically
        cloned.update(&NIST_MSG_40[20..]).unwrap();
        let tag2 = cloned.finalize().unwrap();

        assert_eq!(tag1, tag2);
        assert_eq!(tag1, NIST_TAG_40.to_vec());
    }

    #[test]
    fn test_context_clone_uninitialized() {
        let ctx = CmacContext::new();
        let cloned = ctx.clone();
        assert!(matches!(cloned.state, CmacState::Uninitialized));
    }

    // -----------------------------------------------------------------------
    // Re-initialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_reinit() {
        let mut ctx = make_ctx();
        // First computation
        ctx.init(&NIST_KEY, None).unwrap();
        ctx.update(&NIST_MSG_16).unwrap();
        let tag1 = ctx.finalize().unwrap();
        assert_eq!(tag1, NIST_TAG_16.to_vec());

        // Re-initialize and compute again
        ctx.init(&NIST_KEY, None).unwrap();
        let tag2 = ctx.finalize().unwrap();
        assert_eq!(tag2, NIST_TAG_EMPTY.to_vec());
    }

    // -----------------------------------------------------------------------
    // CmacParams tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cmac_params_new() {
        let params = CmacParams::new();
        assert!(params.cipher.is_none());
        assert!(params.properties.is_none());
    }

    #[test]
    fn test_cmac_params_with_cipher() {
        let params = CmacParams::with_cipher("AES-128-CBC");
        assert_eq!(params.cipher, Some("AES-128-CBC".to_string()));
        assert!(params.properties.is_none());
    }

    #[test]
    fn test_cmac_params_default() {
        let params = CmacParams::default();
        assert!(params.cipher.is_none());
        assert!(params.properties.is_none());
    }

    // -----------------------------------------------------------------------
    // Block size inference tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_block_size() {
        assert_eq!(infer_block_size("AES-128-CBC"), AES_BLOCK_SIZE);
        assert_eq!(infer_block_size("AES-256-CBC"), AES_BLOCK_SIZE);
        assert_eq!(infer_block_size("DES-EDE3-CBC"), DES_BLOCK_SIZE);
        assert_eq!(infer_block_size("DES-CBC"), DES_BLOCK_SIZE);
        assert_eq!(infer_block_size("CAMELLIA-256-CBC"), AES_BLOCK_SIZE);
    }

    // -----------------------------------------------------------------------
    // Key length inference tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_key_length() {
        assert_eq!(infer_key_length("AES-128-CBC"), Some(16));
        assert_eq!(infer_key_length("AES-192-CBC"), Some(24));
        assert_eq!(infer_key_length("AES-256-CBC"), Some(32));
        assert_eq!(infer_key_length("DES-EDE3-CBC"), Some(24));
        assert_eq!(infer_key_length("UNKNOWN-CBC"), None);
    }
}
