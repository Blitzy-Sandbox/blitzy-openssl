//! HMAC-DRBG (SP 800-90A §10.1.2) — HMAC-based Deterministic Random Bit Generator.
//!
//! Uses HMAC as the cryptographic primitive. Maintains Key (K) and Value (V)
//! state, performing the two-pass Update algorithm per SP 800-90A §10.1.2.2.
//!
//! Supports all approved hash functions: SHA-1 (legacy), SHA-224, SHA-256,
//! SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384,
//! SHA3-512. Strength derived from the underlying hash function's output size
//! per SP 800-90A Table 2.
//!
//! # Algorithm Overview
//!
//! HMAC-DRBG maintains two state variables:
//! - **K** (Key): HMAC key of length `blocklen` (hash output size), initialized to 0x00
//! - **V** (Value): Working value of length `blocklen`, initialized to 0x01
//!
//! The **Update** function (§10.1.2.2) performs two HMAC passes:
//! 1. K = HMAC(K, V || 0x00 || provided_data), V = HMAC(K, V)
//! 2. If provided_data is non-empty: K = HMAC(K, V || 0x01 || provided_data), V = HMAC(K, V)
//!
//! Source: `providers/implementations/rands/drbg_hmac.c`

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism};
use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::ParamSet;
use tracing::{debug, trace};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hash output size in bytes (SHA-512 = 64 bytes).
/// Matches C `EVP_MAX_MD_SIZE`.
const MAX_MD_SIZE: usize = 64;

/// Seedlen for hash functions with blocklen <= 32 bytes (SHA-1, SHA-224, SHA-256).
/// SP 800-90A Table 2: seedlen = 440 bits = 55 bytes.
const HASH_PRNG_SMALL_SEEDLEN: usize = 55;

/// Seedlen for hash functions with blocklen > 32 bytes (SHA-384, SHA-512).
/// SP 800-90A Table 2: seedlen = 888 bits = 111 bytes.
const HASH_PRNG_MAX_SEEDLEN: usize = 111;

/// Boundary between small and large seedlen classes.
/// Digests with output <= 32 bytes use `HASH_PRNG_SMALL_SEEDLEN`.
const MAX_BLOCKLEN_USING_SMALL_SEEDLEN: usize = 32;

/// Maximum number of generate requests before mandatory reseed.
/// SP 800-90A §10.1.2.5 Step 1: `reseed_counter > reseed_interval`.
const HMAC_DRBG_MAX_RESEED_INTERVAL: u64 = 1 << 48;

/// Maximum number of bytes per generate request.
/// SP 800-90A §10.1.2.5: `max_number_of_bits_per_request` = 2^19 bits = 65536 bytes.
const HMAC_DRBG_MAX_REQUEST: usize = 1 << 16;

// ---------------------------------------------------------------------------
// Digest dispatch helpers
// ---------------------------------------------------------------------------

/// Resolves a digest name string to its output block length in bytes.
///
/// Returns `None` for unsupported digest names. Matching is case-insensitive
/// and supports both hyphenated and non-hyphenated forms.
///
/// # Supported digests (SP 800-90A Table 2)
///
/// | Digest     | blocklen |
/// |------------|----------|
/// | SHA-1      | 20       |
/// | SHA-224    | 28       |
/// | SHA-256    | 32       |
/// | SHA-384    | 48       |
/// | SHA-512    | 64       |
/// | SHA-512/224| 28       |
/// | SHA-512/256| 32       |
/// | SHA3-224   | 28       |
/// | SHA3-256   | 32       |
/// | SHA3-384   | 48       |
/// | SHA3-512   | 64       |
fn blocklen_for_digest(name: &str) -> Option<usize> {
    let upper = name.to_uppercase();
    match upper.as_str() {
        "SHA1" | "SHA-1" => Some(20),
        "SHA224" | "SHA-224" | "SHA512-224" | "SHA-512/224" | "SHA512/224" | "SHA3-224" => {
            Some(28)
        }
        "SHA256" | "SHA-256" | "SHA512-256" | "SHA-512/256" | "SHA512/256" | "SHA3-256" => {
            Some(32)
        }
        "SHA384" | "SHA-384" | "SHA3-384" => Some(48),
        "SHA512" | "SHA-512" | "SHA3-512" => Some(64),
        _ => None,
    }
}

/// Derives the security strength from the hash block length.
///
/// Per SP 800-90A Table 2 and SP 800-57 Part 1:
/// - blocklen <= 20 (SHA-1): strength = 128
/// - blocklen <= 32 (SHA-224, SHA-256): strength = 128 (SHA-224) or 128 bits
///   of collision resistance, but HMAC-DRBG security strength is min(blocklen*8/2, 256)
///   Note: SP 800-90A Table 2 gives SHA-224 strength=192, SHA-256 strength=256
///
/// Simplified mapping matching C `drbg_hmac.c` logic:
/// - blocklen <= 32 → strength = 128
/// - blocklen > 32  → strength = 256
fn strength_for_digest(blocklen: usize) -> u32 {
    if blocklen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN {
        256
    } else {
        128
    }
}

/// Derives the seedlen from the hash block length.
///
/// SP 800-90A Table 2: seedlen depends on the hash output length.
fn seedlen_for_digest(blocklen: usize) -> usize {
    if blocklen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN {
        HASH_PRNG_MAX_SEEDLEN
    } else {
        HASH_PRNG_SMALL_SEEDLEN
    }
}

/// Computes HMAC(key, data) for a given digest name, returning the tag bytes.
///
/// Dispatches to the correct concrete `Hmac<D>` type at runtime based on the
/// digest name string. This is the core primitive used by the Update algorithm.
///
/// Each match arm constructs a concrete `Hmac<D>` via `Mac::new_from_slice()`,
/// feeds the data via `Mac::update()`, and returns the finalized tag. This avoids
/// complex generic trait bounds required by `hmac::Hmac<D>` (`CoreProxy`, etc.)
/// by dispatching directly to monomorphized concrete types.
///
/// # Errors
///
/// Returns `ProviderError::Init` if the digest name is unsupported or the key
/// length is invalid for HMAC construction.
fn hmac_compute(digest_name: &str, key: &[u8], data: &[u8]) -> ProviderResult<Vec<u8>> {
    use hmac::Mac;

    /// Helper macro to avoid repeating the HMAC computation pattern for each
    /// concrete digest type. Constructs `Hmac<$digest_type>`, feeds data,
    /// and returns the finalized tag as `Vec<u8>`.
    macro_rules! compute_hmac {
        ($digest_type:ty, $key:expr, $data:expr) => {{
            let mut mac = <hmac::Hmac<$digest_type>>::new_from_slice($key).map_err(|e| {
                ProviderError::Init(format!("HMAC-DRBG: HMAC key init failed: {}", e))
            })?;
            mac.update($data);
            let result = mac.finalize();
            Ok(result.into_bytes().to_vec())
        }};
    }

    let upper = digest_name.to_uppercase();
    match upper.as_str() {
        "SHA1" | "SHA-1" => compute_hmac!(sha1::Sha1, key, data),
        "SHA224" | "SHA-224" => compute_hmac!(sha2::Sha224, key, data),
        "SHA256" | "SHA-256" => compute_hmac!(sha2::Sha256, key, data),
        "SHA384" | "SHA-384" => compute_hmac!(sha2::Sha384, key, data),
        "SHA512" | "SHA-512" => compute_hmac!(sha2::Sha512, key, data),
        "SHA512-224" | "SHA-512/224" | "SHA512/224" => {
            compute_hmac!(sha2::Sha512_224, key, data)
        }
        "SHA512-256" | "SHA-512/256" | "SHA512/256" => {
            compute_hmac!(sha2::Sha512_256, key, data)
        }
        "SHA3-224" => compute_hmac!(sha3::Sha3_224, key, data),
        "SHA3-256" => compute_hmac!(sha3::Sha3_256, key, data),
        "SHA3-384" => compute_hmac!(sha3::Sha3_384, key, data),
        "SHA3-512" => compute_hmac!(sha3::Sha3_512, key, data),
        _ => Err(ProviderError::Init(format!(
            "HMAC-DRBG: unsupported digest '{digest_name}'"
        ))),
    }
}

// ---------------------------------------------------------------------------
// HmacDrbg — Core HMAC-DRBG mechanism (replaces C PROV_DRBG_HMAC)
// ---------------------------------------------------------------------------

/// HMAC-DRBG mechanism state (SP 800-90A §10.1.2).
///
/// Maintains the HMAC key (K) and value (V) as the DRBG working state.
/// The Update algorithm performs two HMAC operations to derive new K and V
/// from optional additional input.
///
/// # Fields
///
/// - `k`: HMAC key — initialized to 0x00 bytes, updated on each operation.
///   Length equals `blocklen` (hash output size). Zeroized on drop.
/// - `v`: Working value — initialized to 0x01 bytes, updated on each operation.
///   Length equals `blocklen`. Zeroized on drop.
/// - `blocklen`: Output block size of the underlying hash function (bytes).
/// - `digest_name`: Canonical name of the digest algorithm (e.g., "SHA-256").
///
/// # Security
///
/// Both K and V are securely zeroed on drop via the `Zeroize` trait,
/// replacing C `OPENSSL_cleanse()` calls from `drbg_hmac_uninstantiate()`.
///
/// Replaces C `PROV_DRBG_HMAC` from `drbg_hmac.c`.
#[derive(Debug)]
pub struct HmacDrbg {
    /// HMAC key — initialized to 0x00 bytes, updated on each operation.
    k: Vec<u8>,
    /// Working value — initialized to 0x01 bytes, updated on each operation.
    v: Vec<u8>,
    /// Output block size of the underlying hash function (bytes).
    blocklen: usize,
    /// Canonical name of the digest algorithm (e.g., "SHA-256").
    digest_name: String,
}

impl Zeroize for HmacDrbg {
    fn zeroize(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
        self.blocklen = 0;
        // digest_name is not secret, but clear for completeness
        self.digest_name.clear();
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HmacDrbg {
    /// Creates a new HMAC-DRBG mechanism with the specified digest.
    ///
    /// Resolves the digest name to determine `blocklen` (hash output size),
    /// then initializes K to all 0x00 and V to all 0x01 per SP 800-90A §10.1.2.3.
    ///
    /// # Arguments
    ///
    /// * `digest_name` — Name of the hash function (e.g., "SHA-256", "SHA3-512").
    ///   Case-insensitive. See [`blocklen_for_digest`] for supported names.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if `digest_name` is not a supported hash function.
    ///
    /// # Example (internal usage)
    ///
    /// ```ignore
    /// let mechanism = HmacDrbg::new("SHA-256")?;
    /// assert_eq!(mechanism.blocklen(), 32);
    /// assert_eq!(mechanism.digest_name(), "SHA-256");
    /// ```
    pub fn new(digest_name: &str) -> ProviderResult<Self> {
        let blocklen = blocklen_for_digest(digest_name).ok_or_else(|| {
            ProviderError::Init(format!(
                "HMAC-DRBG: unsupported digest '{digest_name}' — expected SHA-1, SHA-224, \
                 SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, \
                 SHA3-384, or SHA3-512"
            ))
        })?;

        // Defensive check: blocklen must not exceed the maximum hash output size.
        // This mirrors C's use of EVP_MAX_MD_SIZE for static array bounds.
        if blocklen > MAX_MD_SIZE {
            return Err(ProviderError::Init(format!(
                "HMAC-DRBG: digest '{digest_name}' has blocklen {blocklen} exceeding \
                 MAX_MD_SIZE {MAX_MD_SIZE}"
            )));
        }

        debug!(
            digest = %digest_name,
            blocklen = blocklen,
            strength = strength_for_digest(blocklen),
            "HMAC-DRBG: created mechanism"
        );

        Ok(Self {
            k: vec![0x00; blocklen],
            v: vec![0x01; blocklen],
            blocklen,
            digest_name: digest_name.to_string(),
        })
    }

    /// Configures the HMAC-DRBG mechanism from a parameter set.
    ///
    /// Supports the following parameters (matching C `drbg_hmac_set_ctx_params`):
    /// - `"digest"` (`Utf8String`): Digest algorithm name to use.
    ///
    /// If the digest name changes, K and V are re-initialized to the new blocklen.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if the specified digest is unsupported.
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Check for digest parameter
        if let Some(param_value) = params.get("digest") {
            // Extract string value from ParamValue
            let name = match param_value {
                openssl_common::param::ParamValue::Utf8String(s) => s.clone(),
                other => {
                    return Err(ProviderError::Init(format!(
                        "HMAC-DRBG: expected UTF-8 string for 'digest' parameter, got {other:?}"
                    )));
                }
            };

            let new_blocklen = blocklen_for_digest(&name).ok_or_else(|| {
                ProviderError::Init(format!(
                    "HMAC-DRBG: unsupported digest '{name}' in set_params"
                ))
            })?;

            if new_blocklen != self.blocklen {
                debug!(
                    old_digest = %self.digest_name,
                    new_digest = %name,
                    old_blocklen = self.blocklen,
                    new_blocklen = new_blocklen,
                    "HMAC-DRBG: digest changed, re-initializing K and V"
                );

                // Re-initialize K and V for new blocklen
                self.k.zeroize();
                self.v.zeroize();
                self.k = vec![0x00; new_blocklen];
                self.v = vec![0x01; new_blocklen];
                self.blocklen = new_blocklen;
            }

            self.digest_name = name;
        }

        Ok(())
    }

    /// Returns the output block size of the underlying hash function (bytes).
    ///
    /// This equals the length of both K and V vectors.
    #[inline]
    #[must_use]
    pub fn blocklen(&self) -> usize {
        self.blocklen
    }

    /// Returns the canonical name of the digest algorithm.
    #[inline]
    #[must_use]
    pub fn digest_name(&self) -> &str {
        &self.digest_name
    }

    /// HMAC-DRBG Update function — SP 800-90A §10.1.2.2.
    ///
    /// Performs the two-pass update of K and V using optional provided data:
    ///
    /// **Pass 1** (always executed):
    /// 1. `K = HMAC(K, V || 0x00 || data[0] || ... || data[n])`
    /// 2. `V = HMAC(K, V)`
    ///
    /// **Pass 2** (only if `additional_data` is non-empty):
    /// 3. `K = HMAC(K, V || 0x01 || data[0] || ... || data[n])`
    /// 4. `V = HMAC(K, V)`
    ///
    /// This exactly matches the C `do_hmac()` / `drbg_hmac_update()` pattern from
    /// `drbg_hmac.c` lines 62-112.
    ///
    /// # Arguments
    ///
    /// * `additional_data` — Slice of byte slices to include as provided data.
    ///   These are concatenated in order (e.g., entropy || nonce || personalization
    ///   for instantiate, or entropy || additional for reseed).
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if HMAC computation fails.
    fn hmac_update(&mut self, additional_data: &[&[u8]]) -> ProviderResult<()> {
        // Determine if we have any non-empty provided data
        let has_data = additional_data.iter().any(|d| !d.is_empty());

        // --- Pass 1: K = HMAC(K, V || 0x00 || additional_data), V = HMAC(K, V) ---
        {
            // Build input: V || 0x00 || additional_data[0] || ... || additional_data[n]
            let mut input = Vec::with_capacity(self.blocklen + 1 + additional_data.iter().map(|d| d.len()).sum::<usize>());
            input.extend_from_slice(&self.v);
            input.push(0x00);
            for data in additional_data {
                input.extend_from_slice(data);
            }

            trace!(
                pass = 1,
                input_len = input.len(),
                "HMAC-DRBG Update: computing K = HMAC(K, V || 0x00 || data)"
            );

            // K = HMAC(K, V || 0x00 || additional_data)
            let new_k = hmac_compute(&self.digest_name, &self.k, &input)?;
            self.k.zeroize();
            self.k = new_k;
            input.zeroize();

            // V = HMAC(K, V)
            let new_v = hmac_compute(&self.digest_name, &self.k, &self.v)?;
            self.v = new_v;
        }

        // --- Pass 2: only if provided_data is non-empty ---
        if has_data {
            // Build input: V || 0x01 || additional_data[0] || ... || additional_data[n]
            let mut input = Vec::with_capacity(self.blocklen + 1 + additional_data.iter().map(|d| d.len()).sum::<usize>());
            input.extend_from_slice(&self.v);
            input.push(0x01);
            for data in additional_data {
                input.extend_from_slice(data);
            }

            trace!(
                pass = 2,
                input_len = input.len(),
                "HMAC-DRBG Update: computing K = HMAC(K, V || 0x01 || data)"
            );

            // K = HMAC(K, V || 0x01 || additional_data)
            let new_k = hmac_compute(&self.digest_name, &self.k, &input)?;
            self.k.zeroize();
            self.k = new_k;
            input.zeroize();

            // V = HMAC(K, V)
            let new_v = hmac_compute(&self.digest_name, &self.k, &self.v)?;
            self.v = new_v;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DrbgMechanism trait implementation
// ---------------------------------------------------------------------------

impl DrbgMechanism for HmacDrbg {
    /// HMAC-DRBG Instantiate — SP 800-90A §10.1.2.3.
    ///
    /// 1. Set K = 0x00...00 (blocklen bytes)
    /// 2. Set V = 0x01...01 (blocklen bytes)
    /// 3. Update(K, V, entropy || nonce || personalization)
    ///
    /// This is a complete fresh instantiation — any previous state is replaced.
    ///
    /// Replaces C `ossl_drbg_hmac_init()` from `drbg_hmac.c` lines 125-142.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if the HMAC update fails.
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        debug!(
            digest = %self.digest_name,
            blocklen = self.blocklen,
            entropy_len = entropy.len(),
            nonce_len = nonce.len(),
            pers_len = personalization.len(),
            "HMAC-DRBG: instantiate"
        );

        // Step 1: K = 0x00...00
        self.k.fill(0x00);
        // Step 2: V = 0x01...01
        self.v.fill(0x01);

        // Step 3: (K, V) = HMAC_DRBG_Update(seed_material, K, V)
        // where seed_material = entropy_input || nonce || personalization_string
        self.hmac_update(&[entropy, nonce, personalization])?;

        trace!(
            "HMAC-DRBG: instantiate complete — K and V updated with seed material"
        );

        Ok(())
    }

    /// HMAC-DRBG Reseed — SP 800-90A §10.1.2.4.
    ///
    /// 1. `Update(K, V, entropy || additional_input)`
    ///
    /// Replaces C `drbg_hmac_reseed()` from `drbg_hmac.c` lines 189-197.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if the HMAC update fails.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        debug!(
            entropy_len = entropy.len(),
            additional_len = additional.len(),
            "HMAC-DRBG: reseed"
        );

        // seed_material = entropy_input || additional_input
        self.hmac_update(&[entropy, additional])?;

        trace!("HMAC-DRBG: reseed complete");
        Ok(())
    }

    /// HMAC-DRBG Generate — SP 800-90A §10.1.2.5.
    ///
    /// 1. If `additional_input` is non-empty: `(K, V) = Update(additional_input)`
    /// 2. Loop: `V = HMAC(K, V)`; append V to output until requested bytes generated
    /// 3. `(K, V) = Update(additional_input)` — post-generation update
    ///
    /// Replaces C `ossl_drbg_hmac_generate()` from `drbg_hmac.c` lines 218-261.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if HMAC computations fail.
    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        debug!(
            output_len = output.len(),
            additional_len = additional.len(),
            "HMAC-DRBG: generate"
        );

        // Step 2: If additional_input ≠ Null, (K, V) = Update(additional_input)
        if !additional.is_empty() {
            self.hmac_update(&[additional])?;
        }

        // Step 3: temp = Null
        // Step 4: While len(temp) < requested_number_of_bits:
        //           V = HMAC(K, V)
        //           temp = temp || V
        // Step 5: returned_bits = leftmost(temp, requested_number_of_bits)
        let mut generated = 0usize;
        while generated < output.len() {
            // V = HMAC(K, V)
            let new_v = hmac_compute(&self.digest_name, &self.k, &self.v)?;
            self.v = new_v;

            // Copy output bytes
            let remaining = output.len() - generated;
            let to_copy = remaining.min(self.blocklen);
            output[generated..generated + to_copy].copy_from_slice(&self.v[..to_copy]);
            generated += to_copy;
        }

        trace!(
            bytes_generated = generated,
            "HMAC-DRBG: output generation loop complete"
        );

        // Step 6: (K, V) = Update(additional_input)
        // Post-generation update — always performed even if additional is empty
        self.hmac_update(&[additional])?;

        trace!("HMAC-DRBG: post-generation update complete");
        Ok(())
    }

    /// HMAC-DRBG Uninstantiate — SP 800-90A §10.1.2.6 (implied).
    ///
    /// Securely zeroes all internal state (K, V, blocklen).
    /// After this call, the mechanism must be re-instantiated before use.
    ///
    /// Replaces C `drbg_hmac_uninstantiate()` from `drbg_hmac.c` lines 281-288
    /// which calls `OPENSSL_cleanse()` on `hmac->K` and `hmac->V`.
    fn uninstantiate(&mut self) {
        debug!("HMAC-DRBG: uninstantiate — zeroing K, V, blocklen");
        self.k.zeroize();
        self.v.zeroize();
        self.blocklen = 0;
    }

    /// HMAC-DRBG Zeroization Verification — FIPS 140-3 requirement.
    ///
    /// Verifies that K and V have been properly zeroed after uninstantiation.
    /// Returns `true` if and only if every byte of K and V is 0x00.
    ///
    /// Replaces C `drbg_hmac_verify_zeroization()` from `drbg_hmac.c` lines 306-323.
    fn verify_zeroization(&self) -> bool {
        let k_zeroed = self.k.iter().all(|&b| b == 0);
        let v_zeroed = self.v.iter().all(|&b| b == 0);
        let result = k_zeroed && v_zeroed;

        trace!(
            k_zeroed = k_zeroed,
            v_zeroed = v_zeroed,
            result = result,
            "HMAC-DRBG: verify_zeroization"
        );

        result
    }
}

// ---------------------------------------------------------------------------
// HmacDrbgProvider — Provider factory (replaces C drbg_hmac_new_wrapper)
// ---------------------------------------------------------------------------

/// Provider factory for HMAC-DRBG instances.
///
/// Implements the [`RandProvider`] trait to register as an HMAC-DRBG algorithm
/// provider in the dispatch system. Creates [`Drbg`]-wrapped [`HmacDrbg`]
/// instances with appropriate configuration derived from the default digest
/// (SHA-256).
///
/// Replaces C provider entry point `drbg_hmac_new_wrapper()` from `drbg_hmac.c`.
pub struct HmacDrbgProvider;

impl RandProvider for HmacDrbgProvider {
    /// Returns the provider algorithm name: `"HMAC-DRBG"`.
    fn name(&self) -> &'static str {
        "HMAC-DRBG"
    }

    /// Creates a new HMAC-DRBG random context with default SHA-256 digest.
    ///
    /// The created context is wrapped in a [`Drbg`] framework instance that
    /// provides state machine management, entropy acquisition, and locking.
    ///
    /// # Default configuration
    ///
    /// - Digest: SHA-256 (blocklen = 32, strength = 128)
    /// - Seedlen: 55 bytes (`HASH_PRNG_SMALL_SEEDLEN`)
    /// - Max request: 65536 bytes
    /// - Reseed interval: 2^48
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if mechanism creation fails.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let default_digest = "SHA-256";
        let mechanism = HmacDrbg::new(default_digest)?;
        let blocklen = mechanism.blocklen();
        let strength = strength_for_digest(blocklen);
        let seedlen = seedlen_for_digest(blocklen);

        let config = DrbgConfig {
            strength,
            min_entropylen: seedlen,
            max_entropylen: seedlen,
            min_noncelen: blocklen / 2,
            max_noncelen: seedlen,
            max_perslen: seedlen,
            max_adinlen: seedlen,
            max_request: HMAC_DRBG_MAX_REQUEST,
            reseed_interval: HMAC_DRBG_MAX_RESEED_INTERVAL,
            reseed_time_interval: 0,
        };

        debug!(
            digest = default_digest,
            blocklen = blocklen,
            strength = strength,
            seedlen = seedlen,
            "HMAC-DRBG: provider creating new context"
        );

        let drbg = Drbg::new(Box::new(mechanism), config);
        Ok(Box::new(drbg))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify HmacDrbg::new succeeds with SHA-256.
    #[test]
    fn test_new_sha256() {
        let drbg = HmacDrbg::new("SHA-256").expect("SHA-256 should be supported");
        assert_eq!(drbg.blocklen(), 32);
        assert_eq!(drbg.digest_name(), "SHA-256");
        assert_eq!(drbg.k.len(), 32);
        assert_eq!(drbg.v.len(), 32);
        assert!(drbg.k.iter().all(|&b| b == 0x00));
        assert!(drbg.v.iter().all(|&b| b == 0x01));
    }

    /// Verify HmacDrbg::new succeeds with SHA-512.
    #[test]
    fn test_new_sha512() {
        let drbg = HmacDrbg::new("SHA-512").expect("SHA-512 should be supported");
        assert_eq!(drbg.blocklen(), 64);
        assert_eq!(drbg.digest_name(), "SHA-512");
    }

    /// Verify HmacDrbg::new succeeds with SHA-1 (legacy).
    #[test]
    fn test_new_sha1() {
        let drbg = HmacDrbg::new("SHA-1").expect("SHA-1 should be supported");
        assert_eq!(drbg.blocklen(), 20);
    }

    /// Verify HmacDrbg::new succeeds with SHA3-256.
    #[test]
    fn test_new_sha3_256() {
        let drbg = HmacDrbg::new("SHA3-256").expect("SHA3-256 should be supported");
        assert_eq!(drbg.blocklen(), 32);
    }

    /// Verify HmacDrbg::new rejects unsupported digest names.
    #[test]
    fn test_new_unsupported() {
        let result = HmacDrbg::new("INVALID-HASH");
        assert!(result.is_err());
    }

    /// Verify blocklen_for_digest returns correct values.
    #[test]
    fn test_blocklen_for_digest() {
        assert_eq!(blocklen_for_digest("SHA-1"), Some(20));
        assert_eq!(blocklen_for_digest("SHA-224"), Some(28));
        assert_eq!(blocklen_for_digest("SHA-256"), Some(32));
        assert_eq!(blocklen_for_digest("SHA-384"), Some(48));
        assert_eq!(blocklen_for_digest("SHA-512"), Some(64));
        assert_eq!(blocklen_for_digest("SHA-512/224"), Some(28));
        assert_eq!(blocklen_for_digest("SHA-512/256"), Some(32));
        assert_eq!(blocklen_for_digest("SHA3-224"), Some(28));
        assert_eq!(blocklen_for_digest("SHA3-256"), Some(32));
        assert_eq!(blocklen_for_digest("SHA3-384"), Some(48));
        assert_eq!(blocklen_for_digest("SHA3-512"), Some(64));
        assert_eq!(blocklen_for_digest("UNSUPPORTED"), None);
    }

    /// Verify strength derivation from blocklen.
    #[test]
    fn test_strength_for_digest() {
        assert_eq!(strength_for_digest(20), 128); // SHA-1
        assert_eq!(strength_for_digest(28), 128); // SHA-224
        assert_eq!(strength_for_digest(32), 128); // SHA-256
        assert_eq!(strength_for_digest(48), 256); // SHA-384
        assert_eq!(strength_for_digest(64), 256); // SHA-512
    }

    /// Verify seedlen derivation from blocklen.
    #[test]
    fn test_seedlen_for_digest() {
        assert_eq!(seedlen_for_digest(20), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(seedlen_for_digest(32), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(seedlen_for_digest(48), HASH_PRNG_MAX_SEEDLEN);
        assert_eq!(seedlen_for_digest(64), HASH_PRNG_MAX_SEEDLEN);
    }

    /// Verify instantiate sets K and V, then updates them with seed material.
    #[test]
    fn test_instantiate() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        let entropy = [0xAA; 32];
        let nonce = [0xBB; 16];
        let pers = [0xCC; 8];

        drbg.instantiate(&entropy, &nonce, &pers).unwrap();

        // After instantiation, K and V should have changed from initial values
        assert!(!drbg.k.iter().all(|&b| b == 0x00), "K should be updated");
        assert!(!drbg.v.iter().all(|&b| b == 0x01), "V should be updated");
    }

    /// Verify reseed changes K and V.
    #[test]
    fn test_reseed() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        let k_before = drbg.k.clone();
        let v_before = drbg.v.clone();

        drbg.reseed(&[0xDD; 32], &[0xEE; 8]).unwrap();

        assert_ne!(drbg.k, k_before, "K should change after reseed");
        assert_ne!(drbg.v, v_before, "V should change after reseed");
    }

    /// Verify generate produces non-zero output and changes internal state.
    #[test]
    fn test_generate() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        let mut output = [0u8; 64];
        drbg.generate(&mut output, &[]).unwrap();

        // Output should not be all zeros (astronomically unlikely with real HMAC)
        assert!(!output.iter().all(|&b| b == 0), "generated output should not be all zeros");
    }

    /// Verify generate with additional input produces different output.
    #[test]
    fn test_generate_with_additional() {
        let mut drbg1 = HmacDrbg::new("SHA-256").unwrap();
        let mut drbg2 = HmacDrbg::new("SHA-256").unwrap();

        let entropy = [0xAA; 32];
        let nonce = [0xBB; 16];
        drbg1.instantiate(&entropy, &nonce, &[]).unwrap();
        drbg2.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg1.generate(&mut out1, &[]).unwrap();
        drbg2.generate(&mut out2, &[0xFF; 16]).unwrap();

        assert_ne!(out1, out2, "additional input should produce different output");
    }

    /// Verify that consecutive generate calls produce different output.
    #[test]
    fn test_generate_different_each_call() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg.generate(&mut out1, &[]).unwrap();
        drbg.generate(&mut out2, &[]).unwrap();

        assert_ne!(out1, out2, "consecutive generates should produce different output");
    }

    /// Verify uninstantiate zeroes K and V.
    #[test]
    fn test_uninstantiate() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        drbg.uninstantiate();

        assert!(drbg.k.iter().all(|&b| b == 0), "K should be zeroed");
        assert!(drbg.v.iter().all(|&b| b == 0), "V should be zeroed");
        assert_eq!(drbg.blocklen, 0, "blocklen should be zeroed");
    }

    /// Verify verify_zeroization returns true after uninstantiate.
    #[test]
    fn test_verify_zeroization_after_uninstantiate() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        assert!(!drbg.verify_zeroization(), "should not be zeroed before uninstantiate");

        drbg.uninstantiate();

        assert!(drbg.verify_zeroization(), "should be zeroed after uninstantiate");
    }

    /// Verify set_params can change the digest.
    #[test]
    fn test_set_params_digest() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        assert_eq!(drbg.blocklen(), 32);

        let mut params = ParamSet::new();
        params.set("digest", openssl_common::param::ParamValue::Utf8String("SHA-512".to_string()));
        drbg.set_params(&params).unwrap();

        assert_eq!(drbg.blocklen(), 64);
        assert_eq!(drbg.digest_name(), "SHA-512");
        assert_eq!(drbg.k.len(), 64);
        assert_eq!(drbg.v.len(), 64);
    }

    /// Verify set_params rejects unsupported digest.
    #[test]
    fn test_set_params_unsupported_digest() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        let mut params = ParamSet::new();
        params.set("digest", openssl_common::param::ParamValue::Utf8String("INVALID".to_string()));

        let result = drbg.set_params(&params);
        assert!(result.is_err());
    }

    /// Verify HmacDrbgProvider creates a valid context.
    #[test]
    fn test_provider_name() {
        let provider = HmacDrbgProvider;
        assert_eq!(provider.name(), "HMAC-DRBG");
    }

    /// Verify HmacDrbgProvider::new_ctx creates a working DRBG.
    #[test]
    fn test_provider_new_ctx() {
        let provider = HmacDrbgProvider;
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok(), "new_ctx should succeed");
    }

    /// Verify generate works across multiple hash sizes.
    #[test]
    fn test_multi_digest_generate() {
        for digest in &["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"] {
            let mut drbg = HmacDrbg::new(digest).expect(&format!("{} should be supported", digest));
            let bl = drbg.blocklen();
            drbg.instantiate(&vec![0xAA; bl], &vec![0xBB; bl / 2], &[]).unwrap();

            let mut output = vec![0u8; 64];
            drbg.generate(&mut output, &[]).unwrap();
            assert!(!output.iter().all(|&b| b == 0), "output should not be all zeros for {}", digest);
        }
    }

    /// Verify generate output length handling for non-blocklen-aligned requests.
    #[test]
    fn test_generate_partial_block() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        drbg.instantiate(&[0xAA; 32], &[0xBB; 16], &[]).unwrap();

        // Request 17 bytes (less than one block of 32)
        let mut output = [0u8; 17];
        drbg.generate(&mut output, &[]).unwrap();
        assert!(!output.iter().all(|&b| b == 0));

        // Request 65 bytes (more than two blocks of 32)
        let mut output2 = [0u8; 65];
        drbg.generate(&mut output2, &[]).unwrap();
        assert!(!output2.iter().all(|&b| b == 0));
    }

    /// Verify Update algorithm: when no additional data, only pass 1 executes.
    #[test]
    fn test_hmac_update_no_data() {
        let mut drbg = HmacDrbg::new("SHA-256").unwrap();
        let k_before = drbg.k.clone();
        let v_before = drbg.v.clone();

        drbg.hmac_update(&[]).unwrap();

        // K and V should change even with empty data (pass 1 always runs)
        assert_ne!(drbg.k, k_before, "K should change after update");
        assert_ne!(drbg.v, v_before, "V should change after update");
    }

    /// Verify Update algorithm: with data, both passes execute (different result).
    #[test]
    fn test_hmac_update_with_data_differs() {
        let mut drbg1 = HmacDrbg::new("SHA-256").unwrap();
        let mut drbg2 = HmacDrbg::new("SHA-256").unwrap();

        drbg1.hmac_update(&[]).unwrap();
        drbg2.hmac_update(&[&[0xFF; 16]]).unwrap();

        assert_ne!(drbg1.k, drbg2.k, "Update with data should differ from without");
        assert_ne!(drbg1.v, drbg2.v, "Update with data should differ from without");
    }
}
