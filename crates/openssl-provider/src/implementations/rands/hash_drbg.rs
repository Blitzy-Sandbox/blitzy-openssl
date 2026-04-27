//! Hash-DRBG (SP 800-90A §10.1.1) — Hash-based Deterministic Random Bit Generator.
//!
//! Uses a hash function as the cryptographic primitive. Maintains V (value)
//! and C (constant) state vectors with modular big-endian addition over seedlen.
//!
//! ## Seed Length Selection (SP 800-90A Table 2)
//!
//! - Hash output ≤ 256 bits → seedlen = 440 bits (55 bytes)
//! - Hash output > 256 bits → seedlen = 888 bits (111 bytes)
//!
//! Supports: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
//! SHA3-224, SHA3-256, SHA3-384, SHA3-512.
//!
//! Source: `providers/implementations/rands/drbg_hash.c`

use crate::traits::{RandContext, RandProvider};
use digest::{DynDigest, Digest};
use openssl_common::error::{ProviderError, ProviderResult};
use tracing::{debug, trace};
use zeroize::Zeroize;

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism};

// ---------------------------------------------------------------------------
// Constants — SP 800-90A Table 2
// ---------------------------------------------------------------------------

/// Maximum seedlen: 888 bits (SP 800-90A Table 2, row for SHA-384/512).
const HASH_PRNG_MAX_SEEDLEN: usize = 888 / 8; // 111 bytes

/// Small seedlen: 440 bits (SP 800-90A Table 2, row for SHA-1/224/256).
const HASH_PRNG_SMALL_SEEDLEN: usize = 440 / 8; // 55 bytes

/// Block size threshold: hashes with output ≤ 256 bits use small seedlen.
const MAX_BLOCKLEN_USING_SMALL_SEEDLEN: usize = 256 / 8; // 32 bytes

/// Maximum number of bytes per `generate()` call (1 << 16 = 65 536).
const MAX_REQUEST_SIZE: usize = 1 << 16;

// ---------------------------------------------------------------------------
// Digest factory — runtime-polymorphic hash selection
// ---------------------------------------------------------------------------

/// Creates a boxed [`DynDigest`] from a digest name string.
///
/// Supports all hash functions listed in SP 800-90A Table 2 for `Hash_DRBG`.
fn create_digest(name: &str) -> ProviderResult<Box<dyn DynDigest>> {
    match name {
        "SHA-1" | "SHA1" => Ok(Box::new(sha1::Sha1::new())),
        "SHA-224" | "SHA2-224" => Ok(Box::new(sha2::Sha224::new())),
        "SHA-256" | "SHA2-256" => Ok(Box::new(sha2::Sha256::new())),
        "SHA-384" | "SHA2-384" => Ok(Box::new(sha2::Sha384::new())),
        "SHA-512" | "SHA2-512" => Ok(Box::new(sha2::Sha512::new())),
        "SHA-512/224" | "SHA2-512/224" => Ok(Box::new(sha2::Sha512_224::new())),
        "SHA-512/256" | "SHA2-512/256" => Ok(Box::new(sha2::Sha512_256::new())),
        "SHA3-224" => Ok(Box::new(sha3::Sha3_224::new())),
        "SHA3-256" => Ok(Box::new(sha3::Sha3_256::new())),
        "SHA3-384" => Ok(Box::new(sha3::Sha3_384::new())),
        "SHA3-512" => Ok(Box::new(sha3::Sha3_512::new())),
        _ => Err(ProviderError::Init(format!(
            "Unsupported digest for Hash-DRBG: '{name}'"
        ))),
    }
}

/// Returns the hash output length (`blocklen`) for a given digest name.
fn blocklen_for_digest(name: &str) -> ProviderResult<usize> {
    match name {
        "SHA-1" | "SHA1" => Ok(20),
        "SHA-224" | "SHA2-224" | "SHA-512/224" | "SHA2-512/224" | "SHA3-224" => Ok(28),
        "SHA-256" | "SHA2-256" | "SHA-512/256" | "SHA2-512/256" | "SHA3-256" => Ok(32),
        "SHA-384" | "SHA2-384" | "SHA3-384" => Ok(48),
        "SHA-512" | "SHA2-512" | "SHA3-512" => Ok(64),
        _ => Err(ProviderError::Init(format!(
            "Unsupported digest for Hash-DRBG: '{name}'"
        ))),
    }
}

/// Returns the security strength in bits for a given digest name.
///
/// Based on SP 800-90A Table 2 "Maximum security strength" column.
fn strength_for_digest(name: &str) -> ProviderResult<u32> {
    match name {
        "SHA-1" | "SHA1" => Ok(128),
        "SHA-224" | "SHA2-224" | "SHA-512/224" | "SHA2-512/224" | "SHA3-224" => Ok(192),
        "SHA-256" | "SHA2-256" | "SHA-512/256" | "SHA2-512/256" | "SHA3-256"
        | "SHA-384" | "SHA2-384" | "SHA3-384"
        | "SHA-512" | "SHA2-512" | "SHA3-512" => Ok(256),
        _ => Err(ProviderError::Init(format!(
            "Unsupported digest for Hash-DRBG: '{name}'"
        ))),
    }
}

// ---------------------------------------------------------------------------
// HashDrbg — SP 800-90A §10.1.1 Hash_DRBG mechanism state
// ---------------------------------------------------------------------------

/// Hash-DRBG mechanism state (SP 800-90A §10.1.1).
///
/// Maintains the V (value) and C (constant) state vectors, each of
/// length `seedlen`. Operations use modular big-endian addition.
///
/// Replaces C `PROV_DRBG_HASH` from `drbg_hash.c`.
///
/// # Memory Safety
///
/// Implements `Zeroize` and [`Drop`] to ensure all key material
/// (V, C, vtmp) is securely wiped from memory on drop and uninstantiate.
/// Replaces C `OPENSSL_cleanse()` calls in `drbg_hash_uninstantiate()`.
#[derive(Debug)]
pub struct HashDrbg {
    /// Hash output block size in bytes.
    blocklen: usize,
    /// Seed length in bytes (55 or 111 depending on hash).
    seedlen: usize,
    /// State value vector V (SP 800-90A working state).
    v: Vec<u8>,
    /// Constant value C (SP 800-90A working state).
    c: Vec<u8>,
    /// Temporary scratch buffer for `hash_gen` data copy.
    vtmp: Vec<u8>,
    /// Digest algorithm name for creating hasher instances.
    digest_name: String,
    /// Internal reseed counter for SP 800-90A §10.1.1.4 V state update.
    reseed_counter: u64,
}

impl Zeroize for HashDrbg {
    fn zeroize(&mut self) {
        self.v.zeroize();
        self.c.zeroize();
        self.vtmp.zeroize();
        self.digest_name.zeroize();
        self.blocklen = 0;
        self.seedlen = 0;
        self.reseed_counter = 0;
    }
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// HashDrbg — Construction and accessors
// ---------------------------------------------------------------------------

impl HashDrbg {
    /// Creates a new Hash-DRBG mechanism configured for the given digest.
    ///
    /// Determines `blocklen` (hash output size) and `seedlen` (440 or 888 bits)
    /// per SP 800-90A Table 2.
    ///
    /// # Arguments
    ///
    /// * `digest_name` — Name of the hash algorithm (e.g., `"SHA-256"`, `"SHA-512"`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the digest name is not supported.
    pub fn new(digest_name: &str) -> ProviderResult<Self> {
        let blocklen = blocklen_for_digest(digest_name)?;
        // SP 800-90A Table 2: seedlen depends on hash output size
        let seedlen = if blocklen <= MAX_BLOCKLEN_USING_SMALL_SEEDLEN {
            HASH_PRNG_SMALL_SEEDLEN
        } else {
            HASH_PRNG_MAX_SEEDLEN
        };

        trace!(
            digest = digest_name,
            blocklen,
            seedlen,
            "Hash-DRBG: created mechanism"
        );

        Ok(Self {
            blocklen,
            seedlen,
            v: vec![0u8; seedlen],
            c: vec![0u8; seedlen],
            vtmp: vec![0u8; seedlen],
            digest_name: digest_name.to_owned(),
            reseed_counter: 0,
        })
    }

    /// Returns the hash output block size in bytes.
    #[inline]
    pub fn blocklen(&self) -> usize {
        self.blocklen
    }

    /// Returns the seed length in bytes (55 or 111).
    #[inline]
    pub fn seedlen(&self) -> usize {
        self.seedlen
    }

    /// Returns the configured digest algorithm name.
    #[inline]
    pub fn digest_name(&self) -> &str {
        &self.digest_name
    }

    // -----------------------------------------------------------------------
    // Hash Derivation Function — SP 800-90A §10.3.1
    // -----------------------------------------------------------------------

    /// Hash Derivation Function (`Hash_df`) per SP 800-90A §10.3.1.
    ///
    /// Derives `out.len()` bytes of output from the concatenation of an
    /// optional leading byte (`inbyte`) and one or more input byte slices.
    ///
    /// ```text
    /// counter = 1
    /// For i = 1 to ceil(no_of_bits_to_return / outlen):
    ///   Hash(counter || no_of_bits_to_return || [inbyte] || input_1 || ... || input_n)
    ///   counter += 1
    /// Return leftmost no_of_bits_to_return bits
    /// ```
    ///
    /// Replaces C `hash_df()` from `drbg_hash.c`.
    fn hash_df(
        &self,
        out: &mut [u8],
        inbyte: Option<u8>,
        inputs: &[&[u8]],
    ) -> ProviderResult<()> {
        let out_len = out.len();
        let no_of_bits_to_return = u32::try_from(out_len.checked_mul(8).ok_or_else(|| {
            ProviderError::Init("Hash-DRBG hash_df: output length overflow".into())
        })?)
        .map_err(|_| ProviderError::Init("Hash-DRBG hash_df: output bits exceed u32".into()))?;

        let mut counter: u8 = 1;
        let mut offset = 0;

        while offset < out_len {
            let mut hasher = create_digest(&self.digest_name)?;

            // Hash(counter || no_of_bits_to_return || ...)
            hasher.update(&[counter]);
            hasher.update(&no_of_bits_to_return.to_be_bytes());

            // Optional leading byte (INBYTE_IGNORE = skip)
            if let Some(ib) = inbyte {
                hasher.update(&[ib]);
            }

            // Concatenated input strings
            for input in inputs {
                hasher.update(input);
            }

            let hash_result = hasher.finalize_reset();
            let remaining = out_len - offset;
            let to_copy = remaining.min(self.blocklen);
            out[offset..offset + to_copy].copy_from_slice(&hash_result[..to_copy]);

            offset += to_copy;
            counter = counter.wrapping_add(1);

            trace!(
                iteration = counter.wrapping_sub(1),
                bytes_written = to_copy,
                total_offset = offset,
                "Hash-DRBG hash_df: iteration"
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Modular big-endian addition — replaces C add_bytes()
    // -----------------------------------------------------------------------

    /// Modular big-endian addition: `dst = (dst + src) mod 2^(dst.len()*8)`.
    ///
    /// `src` is right-aligned within `dst` (aligned at the least-significant byte).
    /// Carry propagates from LSB towards MSB. Matches C `add_bytes()`.
    ///
    /// # Truncation Safety (Rule R6)
    ///
    /// The `as u8` casts extract the low byte of a `u16` intermediate sum.
    /// Since the sum of two `u8` values plus a carry bit is at most 511,
    /// the low byte is always a valid `u8`. Truncation is intentional.
    #[allow(clippy::cast_possible_truncation)]
    fn add_bytes(dst: &mut [u8], src: &[u8]) {
        let dst_len = dst.len();
        let src_len = src.len();
        if src_len == 0 || dst_len == 0 {
            return;
        }
        // src must not exceed dst length
        let effective_src_len = src_len.min(dst_len);
        let offset = dst_len - effective_src_len;

        let mut carry: u16 = 0;

        // Add aligned bytes from least-significant end
        for i in (0..effective_src_len).rev() {
            let sum = u16::from(dst[offset + i]) + u16::from(src[i]) + carry;
            // TRUNCATION: sum ≤ 511, low byte always fits in u8
            dst[offset + i] = sum as u8;
            carry = sum >> 8;
        }

        // Propagate carry to more-significant bytes of dst
        for i in (0..offset).rev() {
            if carry == 0 {
                break;
            }
            let sum = u16::from(dst[i]) + carry;
            // TRUNCATION: sum ≤ 256, low byte always fits in u8
            dst[i] = sum as u8;
            carry = sum >> 8;
        }
    }

    // -----------------------------------------------------------------------
    // add_hash_to_v — replaces C add_hash_to_v()
    // -----------------------------------------------------------------------

    /// Computes `V = V + Hash(inbyte || V || additional_input)` using
    /// modular big-endian addition over `blocklen` bytes of hash output.
    ///
    /// Replaces C `add_hash_to_v()` from `drbg_hash.c`.
    fn add_hash_to_v(&mut self, inbyte: u8, additional: &[u8]) -> ProviderResult<()> {
        let mut hasher = create_digest(&self.digest_name)?;
        hasher.update(&[inbyte]);
        hasher.update(&self.v[..self.seedlen]);
        if !additional.is_empty() {
            hasher.update(additional);
        }
        let hash_result = hasher.finalize_reset();

        // Add hash output to V (modular big-endian addition over seedlen)
        let hash_bytes = &hash_result[..self.blocklen];
        Self::add_bytes(&mut self.v[..self.seedlen], hash_bytes);

        trace!("Hash-DRBG: add_hash_to_v complete");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Hash Generation — SP 800-90A §10.1.1.4
    // -----------------------------------------------------------------------

    /// Hashgen: generate pseudorandom output (SP 800-90A §10.1.1.4).
    ///
    /// ```text
    /// data = V
    /// For i = 1 to ceil(requested_number_of_bits / outlen):
    ///   w = w || Hash(data)
    ///   data = (data + 1) mod 2^seedlen
    /// Return leftmost requested_number_of_bits bits of w
    /// ```
    ///
    /// Uses `vtmp` as the working data copy to avoid modifying V.
    /// Replaces C `hash_gen()` from `drbg_hash.c`.
    fn hash_gen(&mut self, output: &mut [u8]) -> ProviderResult<()> {
        let out_len = output.len();

        // Copy V to vtmp as working data
        self.vtmp[..self.seedlen].copy_from_slice(&self.v[..self.seedlen]);

        let mut offset = 0;
        let one = [1u8];

        while offset < out_len {
            let mut hasher = create_digest(&self.digest_name)?;
            hasher.update(&self.vtmp[..self.seedlen]);
            let hash_result = hasher.finalize_reset();

            let remaining = out_len - offset;
            let to_copy = remaining.min(self.blocklen);
            output[offset..offset + to_copy].copy_from_slice(&hash_result[..to_copy]);
            offset += to_copy;

            if offset < out_len {
                // data = (data + 1) mod 2^seedlen
                Self::add_bytes(&mut self.vtmp[..self.seedlen], &one);
            }

            trace!(
                blocks_done = (offset + self.blocklen - 1) / self.blocklen,
                bytes_written = offset,
                "Hash-DRBG hash_gen: block"
            );
        }

        // Clear scratch buffer (use slice-level zeroize to preserve Vec length;
        // Vec::zeroize() truncates to length 0 which would break subsequent calls)
        self.vtmp[..self.seedlen].zeroize();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DrbgMechanism trait implementation
// ---------------------------------------------------------------------------

impl DrbgMechanism for HashDrbg {
    /// Instantiate Hash-DRBG (SP 800-90A §10.1.1.2).
    ///
    /// ```text
    /// seed_material = entropy_input || nonce || personalization_string
    /// V = Hash_df(seed_material, seedlen)
    /// C = Hash_df(0x00 || V, seedlen)
    /// reseed_counter = 1
    /// ```
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        debug!(
            digest = %self.digest_name,
            entropy_len = entropy.len(),
            nonce_len = nonce.len(),
            pers_len = personalization.len(),
            "Hash-DRBG: instantiate"
        );

        // seed_material = entropy || nonce || personalization
        let mut seed_material =
            Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // V = Hash_df(seed_material, seedlen)
        let mut v_buf = vec![0u8; self.seedlen];
        self.hash_df(&mut v_buf, None, &[&seed_material])?;
        self.v[..self.seedlen].copy_from_slice(&v_buf[..self.seedlen]);

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_buf = vec![0u8; self.seedlen];
        self.hash_df(&mut c_buf, Some(0x00), &[&self.v[..self.seedlen]])?;
        self.c[..self.seedlen].copy_from_slice(&c_buf[..self.seedlen]);

        // Clean up temporaries
        seed_material.zeroize();
        v_buf.zeroize();
        c_buf.zeroize();

        self.reseed_counter = 1;

        debug!("Hash-DRBG: instantiate complete");
        Ok(())
    }

    /// Reseed Hash-DRBG (SP 800-90A §10.1.1.3).
    ///
    /// ```text
    /// seed_material = 0x01 || V || entropy_input || additional_input
    /// V = Hash_df(seed_material, seedlen)
    /// C = Hash_df(0x00 || V, seedlen)
    /// reseed_counter = 1
    /// ```
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        debug!(
            entropy_len = entropy.len(),
            additional_len = additional.len(),
            "Hash-DRBG: reseed"
        );

        // V = Hash_df(0x01 || V || entropy || additional, seedlen)
        let v_snapshot = self.v[..self.seedlen].to_vec();
        let mut v_buf = vec![0u8; self.seedlen];
        self.hash_df(
            &mut v_buf,
            Some(0x01),
            &[&v_snapshot, entropy, additional],
        )?;
        self.v[..self.seedlen].copy_from_slice(&v_buf[..self.seedlen]);

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_buf = vec![0u8; self.seedlen];
        self.hash_df(&mut c_buf, Some(0x00), &[&self.v[..self.seedlen]])?;
        self.c[..self.seedlen].copy_from_slice(&c_buf[..self.seedlen]);

        // Clean up temporaries
        v_buf.zeroize();
        c_buf.zeroize();

        self.reseed_counter = 1;

        debug!("Hash-DRBG: reseed complete");
        Ok(())
    }

    /// Generate pseudorandom output (SP 800-90A §10.1.1.4).
    ///
    /// ```text
    /// If additional_input != "":
    ///   w = Hash(0x02 || V || additional_input)
    ///   V = (V + w) mod 2^seedlen
    /// returned_bits = Hashgen(requested_number_of_bits, V)
    /// H = Hash(0x03 || V)
    /// V = (V + H + C + reseed_counter) mod 2^seedlen
    /// reseed_counter = reseed_counter + 1
    /// ```
    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        trace!(
            requested_bytes = output.len(),
            additional_len = additional.len(),
            reseed_counter = self.reseed_counter,
            "Hash-DRBG: generate"
        );

        // Step 2: If additional_input != empty, mix it in
        if !additional.is_empty() {
            self.add_hash_to_v(0x02, additional)?;
        }

        // Step 3: returned_bits = Hashgen(requested_number_of_bits, V)
        self.hash_gen(output)?;

        // Step 4: H = Hash(0x03 || V)
        let mut hasher = create_digest(&self.digest_name)?;
        hasher.update(&[0x03]);
        hasher.update(&self.v[..self.seedlen]);
        let h = hasher.finalize_reset();

        // Step 5: V = (V + H + C + reseed_counter) mod 2^seedlen
        Self::add_bytes(&mut self.v[..self.seedlen], &h[..self.blocklen]);
        let c_snapshot = self.c[..self.seedlen].to_vec();
        Self::add_bytes(&mut self.v[..self.seedlen], &c_snapshot);

        // Add reseed_counter as 4-byte big-endian (matching C drbg_hash_generate)
        let counter_u32 = u32::try_from(self.reseed_counter.min(u64::from(u32::MAX)))
            .unwrap_or(u32::MAX);
        let counter_bytes = counter_u32.to_be_bytes();
        Self::add_bytes(&mut self.v[..self.seedlen], &counter_bytes);

        // Step 6: reseed_counter = reseed_counter + 1
        self.reseed_counter = self.reseed_counter.saturating_add(1);

        trace!(
            new_reseed_counter = self.reseed_counter,
            "Hash-DRBG: generate complete"
        );
        Ok(())
    }

    /// Uninstantiate: securely clear all working state.
    ///
    /// Replaces C `drbg_hash_uninstantiate()` which calls
    /// `OPENSSL_cleanse()` on V, C, and vtmp.
    fn uninstantiate(&mut self) {
        debug!("Hash-DRBG: uninstantiate — zeroing state");
        // Use slice-level zeroize to preserve Vec lengths (Vec::zeroize
        // truncates to length 0, which would break re-instantiation).
        self.v[..].zeroize();
        self.c[..].zeroize();
        self.vtmp[..].zeroize();
        self.blocklen = 0;
        self.reseed_counter = 0;
    }

    /// Verify that all working state has been zeroed.
    ///
    /// Returns `true` if V, C, and vtmp are all zero bytes.
    /// Used for FIPS self-test verification.
    fn verify_zeroization(&self) -> bool {
        let v_zero = self.v.iter().all(|&b| b == 0);
        let c_zero = self.c.iter().all(|&b| b == 0);
        let vtmp_zero = self.vtmp.iter().all(|&b| b == 0);
        v_zero && c_zero && vtmp_zero
    }
}

// ---------------------------------------------------------------------------
// HashDrbgProvider — RandProvider factory
// ---------------------------------------------------------------------------

/// Provider factory for Hash-DRBG instances.
///
/// Implements `RandProvider` to register Hash-DRBG as a RAND algorithm
/// in the provider dispatch system. Creates [`Drbg`]-wrapped [`HashDrbg`]
/// instances that implement [`RandContext`].
///
/// Replaces C `drbg_hash_new_wrapper()` from `drbg_hash.c`.
pub struct HashDrbgProvider;

impl RandProvider for HashDrbgProvider {
    /// Returns the algorithm name for Hash-DRBG.
    fn name(&self) -> &'static str {
        "HASH-DRBG"
    }

    /// Creates a new Hash-DRBG context with SHA-256 as the default digest.
    ///
    /// The returned [`RandContext`] wraps a [`Drbg`] managing a [`HashDrbg`]
    /// mechanism with appropriate SP 800-90A parameters.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let default_digest = "SHA-256";
        let mechanism = HashDrbg::new(default_digest)?;
        let seedlen = mechanism.seedlen();
        let strength = strength_for_digest(default_digest)?;

        let config = DrbgConfig {
            strength,
            min_entropylen: seedlen,
            max_entropylen: seedlen.saturating_mul(2),
            min_noncelen: seedlen / 2,
            max_noncelen: seedlen,
            max_perslen: MAX_REQUEST_SIZE,
            max_adinlen: MAX_REQUEST_SIZE,
            max_request: MAX_REQUEST_SIZE,
            ..DrbgConfig::default()
        };

        let drbg = Drbg::new(Box::new(mechanism), config);
        debug!("Hash-DRBG provider: created new context (SHA-256, seedlen={seedlen})");
        Ok(Box::new(drbg))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify seedlen thresholds match SP 800-90A Table 2.
    #[test]
    fn test_seedlen_thresholds() {
        // Small seedlen (output ≤ 256 bits = 32 bytes)
        let sha1 = HashDrbg::new("SHA-1").unwrap();
        assert_eq!(sha1.seedlen(), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(sha1.blocklen(), 20);

        let sha224 = HashDrbg::new("SHA-224").unwrap();
        assert_eq!(sha224.seedlen(), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(sha224.blocklen(), 28);

        let sha256 = HashDrbg::new("SHA-256").unwrap();
        assert_eq!(sha256.seedlen(), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(sha256.blocklen(), 32);

        // Max seedlen (output > 256 bits = 32 bytes)
        let sha384 = HashDrbg::new("SHA-384").unwrap();
        assert_eq!(sha384.seedlen(), HASH_PRNG_MAX_SEEDLEN);
        assert_eq!(sha384.blocklen(), 48);

        let sha512 = HashDrbg::new("SHA-512").unwrap();
        assert_eq!(sha512.seedlen(), HASH_PRNG_MAX_SEEDLEN);
        assert_eq!(sha512.blocklen(), 64);

        // SHA-512/224 and SHA-512/256 use small seedlen
        let sha512_224 = HashDrbg::new("SHA-512/224").unwrap();
        assert_eq!(sha512_224.seedlen(), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(sha512_224.blocklen(), 28);

        let sha512_256 = HashDrbg::new("SHA-512/256").unwrap();
        assert_eq!(sha512_256.seedlen(), HASH_PRNG_SMALL_SEEDLEN);
        assert_eq!(sha512_256.blocklen(), 32);
    }

    /// Verify SHA-3 family digest names are accepted.
    #[test]
    fn test_sha3_digests() {
        let sha3_224 = HashDrbg::new("SHA3-224").unwrap();
        assert_eq!(sha3_224.blocklen(), 28);
        assert_eq!(sha3_224.seedlen(), HASH_PRNG_SMALL_SEEDLEN);

        let sha3_256 = HashDrbg::new("SHA3-256").unwrap();
        assert_eq!(sha3_256.blocklen(), 32);
        assert_eq!(sha3_256.seedlen(), HASH_PRNG_SMALL_SEEDLEN);

        let sha3_384 = HashDrbg::new("SHA3-384").unwrap();
        assert_eq!(sha3_384.blocklen(), 48);
        assert_eq!(sha3_384.seedlen(), HASH_PRNG_MAX_SEEDLEN);

        let sha3_512 = HashDrbg::new("SHA3-512").unwrap();
        assert_eq!(sha3_512.blocklen(), 64);
        assert_eq!(sha3_512.seedlen(), HASH_PRNG_MAX_SEEDLEN);
    }

    /// Verify unsupported digest name returns an error.
    #[test]
    fn test_unsupported_digest() {
        let result = HashDrbg::new("MD5");
        assert!(result.is_err());
    }

    /// Verify that add_bytes performs correct modular big-endian addition.
    #[test]
    fn test_add_bytes_basic() {
        let mut dst = [0x00, 0x00, 0xFF];
        HashDrbg::add_bytes(&mut dst, &[0x01]);
        assert_eq!(dst, [0x00, 0x01, 0x00]); // 0xFF + 0x01 = 0x100, carry

        let mut dst2 = [0xFF, 0xFF, 0xFF];
        HashDrbg::add_bytes(&mut dst2, &[0x01]);
        assert_eq!(dst2, [0x00, 0x00, 0x00]); // overflow wraps
    }

    /// Verify add_bytes with different src/dst lengths.
    #[test]
    fn test_add_bytes_asymmetric() {
        let mut dst = [0x00, 0x00, 0x10, 0x20];
        HashDrbg::add_bytes(&mut dst, &[0x05, 0x06]);
        // src [0x05, 0x06] is right-aligned: dst[2] += 0x05, dst[3] += 0x06
        assert_eq!(dst, [0x00, 0x00, 0x15, 0x26]);
    }

    /// Verify add_bytes with carry propagation across multiple bytes.
    #[test]
    fn test_add_bytes_carry_propagation() {
        let mut dst = [0x01, 0xFF, 0xFF, 0xFF];
        HashDrbg::add_bytes(&mut dst, &[0x00, 0x00, 0x02]);
        // 0x01FFFFFF + 0x000002 = 0x02000001
        assert_eq!(dst, [0x02, 0x00, 0x00, 0x01]);
    }

    /// Verify DrbgMechanism lifecycle: instantiate → generate → uninstantiate.
    #[test]
    fn test_mechanism_lifecycle() {
        let mut drbg = HashDrbg::new("SHA-256").unwrap();
        let entropy = [0xABu8; 55]; // seedlen = 55 for SHA-256
        let nonce = [0xCDu8; 28];
        let pers = b"test personalization";

        // Instantiate
        drbg.instantiate(&entropy, &nonce, pers).unwrap();
        assert!(!drbg.verify_zeroization(), "V/C should not be zero after instantiate");

        // Generate
        let mut output = [0u8; 64];
        drbg.generate(&mut output, &[]).unwrap();
        assert!(output.iter().any(|&b| b != 0), "output should not be all zeros");

        // Uninstantiate
        drbg.uninstantiate();
        assert!(drbg.verify_zeroization(), "V/C/vtmp should be zero after uninstantiate");
    }

    /// Verify that reseed changes internal state.
    #[test]
    fn test_reseed_changes_state() {
        let mut drbg = HashDrbg::new("SHA-256").unwrap();
        let entropy = [0xABu8; 55];
        let nonce = [0xCDu8; 28];

        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        // Snapshot V before reseed
        let v_before = drbg.v.clone();

        let new_entropy = [0xEFu8; 55];
        drbg.reseed(&new_entropy, &[]).unwrap();

        assert_ne!(drbg.v, v_before, "V should change after reseed");
        assert_eq!(drbg.reseed_counter, 1, "reseed_counter should reset to 1");
    }

    /// Verify that generate with additional_input produces different output.
    #[test]
    fn test_generate_with_additional() {
        let mut drbg = HashDrbg::new("SHA-256").unwrap();
        let entropy = [0xABu8; 55];
        let nonce = [0xCDu8; 28];

        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out1 = [0u8; 32];
        let mut drbg2 = HashDrbg::new("SHA-256").unwrap();
        drbg2.instantiate(&entropy, &nonce, &[]).unwrap();

        // Generate without additional
        drbg.generate(&mut out1, &[]).unwrap();

        // Generate with additional from identical state
        let mut out2 = [0u8; 32];
        drbg2.generate(&mut out2, b"extra data").unwrap();

        // Outputs should differ when additional_input differs
        assert_ne!(out1, out2, "additional input should affect output");
    }

    /// Verify the HashDrbgProvider factory creates a valid context.
    #[test]
    fn test_provider_factory() {
        let provider = HashDrbgProvider;
        assert_eq!(provider.name(), "HASH-DRBG");

        let ctx = provider.new_ctx();
        assert!(ctx.is_ok(), "new_ctx should succeed");
    }

    /// Verify that digest name accessor returns the configured name.
    #[test]
    fn test_digest_name_accessor() {
        let drbg = HashDrbg::new("SHA-512").unwrap();
        assert_eq!(drbg.digest_name(), "SHA-512");

        let drbg2 = HashDrbg::new("SHA3-256").unwrap();
        assert_eq!(drbg2.digest_name(), "SHA3-256");
    }

    /// Verify hash_df produces deterministic output.
    #[test]
    fn test_hash_df_deterministic() {
        let drbg = HashDrbg::new("SHA-256").unwrap();
        let input = b"deterministic input";

        let mut out1 = vec![0u8; 55];
        drbg.hash_df(&mut out1, None, &[input.as_slice()]).unwrap();

        let mut out2 = vec![0u8; 55];
        drbg.hash_df(&mut out2, None, &[input.as_slice()]).unwrap();

        assert_eq!(out1, out2, "hash_df should be deterministic");
        assert!(out1.iter().any(|&b| b != 0), "hash_df output should not be all zeros");
    }

    /// Verify hash_df with inbyte differs from without.
    #[test]
    fn test_hash_df_inbyte_affects_output() {
        let drbg = HashDrbg::new("SHA-256").unwrap();
        let input = b"test input";

        let mut out_no_inbyte = vec![0u8; 55];
        drbg.hash_df(&mut out_no_inbyte, None, &[input.as_slice()])
            .unwrap();

        let mut out_with_inbyte = vec![0u8; 55];
        drbg.hash_df(&mut out_with_inbyte, Some(0x00), &[input.as_slice()])
            .unwrap();

        assert_ne!(
            out_no_inbyte, out_with_inbyte,
            "inbyte should affect hash_df output"
        );
    }

    /// Verify security strength mapping for digests.
    #[test]
    fn test_strength_for_digest() {
        assert_eq!(strength_for_digest("SHA-1").unwrap(), 128);
        assert_eq!(strength_for_digest("SHA-224").unwrap(), 192);
        assert_eq!(strength_for_digest("SHA-256").unwrap(), 256);
        assert_eq!(strength_for_digest("SHA-384").unwrap(), 256);
        assert_eq!(strength_for_digest("SHA-512").unwrap(), 256);
        assert_eq!(strength_for_digest("SHA3-256").unwrap(), 256);
        assert!(strength_for_digest("INVALID").is_err());
    }
}
