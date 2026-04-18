//! PKCS#12 KDF — Key Derivation per RFC 7292 Appendix B.
//!
//! Derives keys, IVs, and MAC keys from a password and salt using iterative
//! hashing. Uses a diversifier byte (ID) to select the output type:
//! - ID=1: encryption/decryption key
//! - ID=2: IV
//! - ID=3: MAC key
//!
//! Translation of `providers/implementations/kdfs/pkcs12kdf.c`.
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for optional parameters
//! - **R6:** Checked arithmetic
//! - **R8:** Zero `unsafe` blocks
//! - **R9:** Warning-free

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::ProviderResult;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_PASSWORD` — password (encoded as `BMPString`).
const PARAM_PASSWORD: &str = "pass";
/// `OSSL_KDF_PARAM_SALT` — salt value.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_ITER` — iteration count.
const PARAM_ITER: &str = "iter";
/// `OSSL_KDF_PARAM_PKCS12_ID` — diversifier ID (1=key, 2=IV, 3=MAC key).
const PARAM_ID: &str = "id";

/// Default iteration count.
const DEFAULT_ITERATIONS: u64 = 2048;
/// SHA-256 block size in bytes (u = v = 64 for SHA-256).
const HASH_BLOCK: usize = 64;
/// SHA-256 output length.
const HASH_LEN: usize = 32;

// =============================================================================
// Context
// =============================================================================

/// PKCS#12 KDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Pkcs12Context {
    /// Password (raw bytes, not BMP-encoded — caller handles encoding).
    password: Vec<u8>,
    /// Salt.
    #[zeroize(skip)]
    salt: Vec<u8>,
    /// Iteration count.
    #[zeroize(skip)]
    iterations: u64,
    /// Diversifier ID (1, 2, or 3).
    #[zeroize(skip)]
    id: u8,
}

impl Pkcs12Context {
    fn new() -> Self {
        Self {
            password: Vec::new(),
            salt: Vec::new(),
            iterations: DEFAULT_ITERATIONS,
            id: 1,
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_PASSWORD) {
            self.password = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PKCS12KDF: password must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SALT) {
            self.salt = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PKCS12KDF: salt must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_ITER) {
            self.iterations = v
                .as_u64()
                .ok_or_else(|| ProviderError::Init("PKCS12KDF: iter must be uint".into()))?;
        }
        if let Some(v) = params.get(PARAM_ID) {
            let id_val = v
                .as_u64()
                .ok_or_else(|| ProviderError::Init("PKCS12KDF: id must be uint".into()))?;
            self.id = u8::try_from(id_val)
                .map_err(|_| ProviderError::Init("PKCS12KDF: id must be 1, 2, or 3".into()))?;
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            return Err(ProviderError::Init(
                "PKCS12KDF: password must be set".into(),
            ));
        }
        if self.iterations == 0 {
            return Err(ProviderError::Init(
                "PKCS12KDF: iterations must be > 0".into(),
            ));
        }
        if !(1..=3).contains(&self.id) {
            return Err(ProviderError::Init(
                "PKCS12KDF: id must be 1 (key), 2 (IV), or 3 (MAC key)".into(),
            ));
        }
        Ok(())
    }

    /// PKCS#12 key derivation per RFC 7292 Appendix B.
    ///
    /// ```text
    /// D = ID repeated v bytes
    /// S = salt padded to multiple of v bytes
    /// P = password padded to multiple of v bytes
    /// I = S || P
    /// A_j = H^c(D || I)     (iterate hash c times)
    /// Key = A_1 || A_2 || ...
    /// ```
    fn derive_internal(&self, output: &mut [u8]) -> usize {
        let out_len = output.len();
        let block_v = HASH_BLOCK; // block size

        // Step 1: D = id repeated block_v bytes
        let diversifier = vec![self.id; block_v];

        // Step 2: S = salt padded to ceiling(len/block_v)*block_v, or empty
        let salt_padded = if self.salt.is_empty() {
            Vec::new()
        } else {
            pad_to_block(&self.salt, block_v)
        };

        // Step 3: P = password padded to ceiling(len/block_v)*block_v, or empty
        let pass_padded = if self.password.is_empty() {
            Vec::new()
        } else {
            pad_to_block(&self.password, block_v)
        };

        // Step 4: I = S || P
        let mut i_block = Vec::with_capacity(salt_padded.len() + pass_padded.len());
        i_block.extend_from_slice(&salt_padded);
        i_block.extend_from_slice(&pass_padded);

        // Step 5: Compute output blocks
        let num_blocks = (out_len + HASH_LEN - 1) / HASH_LEN;
        let mut pos = 0;

        for _ in 0..num_blocks {
            // hash_acc = H^c(D || I) — iterated hash
            let mut hash_acc = {
                let mut hasher = Sha256::new();
                hasher.update(&diversifier);
                hasher.update(&i_block);
                hasher.finalize().to_vec()
            };

            for _ in 1..self.iterations {
                hash_acc = Sha256::digest(&hash_acc).to_vec();
            }

            let copy_len = core::cmp::min(HASH_LEN, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&hash_acc[..copy_len]);
            pos += copy_len;

            // Step 6: If more blocks needed, update I
            if pos < out_len {
                let b_pad = pad_to_block(&hash_acc, block_v);
                update_i_block(&mut i_block, &b_pad, block_v);
            }
        }
        out_len
    }
}

/// Pad `data` to a multiple of `block_size` by repeating it.
fn pad_to_block(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let padded_len = ((data.len() + block_size - 1) / block_size) * block_size;
    let mut result = Vec::with_capacity(padded_len);
    while result.len() < padded_len {
        let remaining = padded_len - result.len();
        let copy_len = core::cmp::min(remaining, data.len());
        result.extend_from_slice(&data[..copy_len]);
    }
    result
}

/// Update I block per RFC 7292 Appendix B step 6.
///
/// For each v-byte chunk of I: `I_j = (I_j + B + 1) mod 2^v`
fn update_i_block(i_block: &mut [u8], b: &[u8], v: usize) {
    let num_chunks = i_block.len() / v;
    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * v;
        let mut carry: u16 = 1;
        for k in (0..v).rev() {
            let sum = u16::from(i_block[start + k])
                + u16::from(b[k])
                + carry;
            #[allow(clippy::cast_possible_truncation)]
            // TRUNCATION: intentional low-byte extraction from u16 addition per RFC 7292.
            {
                i_block[start + k] = sum as u8;
            }
            carry = sum >> 8;
        }
    }
}

impl KdfContext for Pkcs12Context {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        Ok(self.derive_internal(key))
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.password.zeroize();
        self.password.clear();
        self.salt.clear();
        self.iterations = DEFAULT_ITERATIONS;
        self.id = 1;
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_u64(PARAM_ITER, self.iterations)
            .push_u64(PARAM_ID, u64::from(self.id))
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// PKCS#12 KDF provider (RFC 7292 Appendix B).
pub struct Pkcs12KdfProvider;

impl KdfProvider for Pkcs12KdfProvider {
    fn name(&self) -> &'static str {
        "PKCS12KDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(Pkcs12Context::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for PKCS#12 KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["PKCS12KDF"],
        "provider=default",
        "PKCS#12 key derivation function (RFC 7292 Appendix B)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(password: &[u8], salt: &[u8], iter: u64, id: u64) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(password.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps.set(PARAM_ITER, ParamValue::UInt64(iter));
        ps.set(PARAM_ID, ParamValue::UInt64(id));
        ps
    }

    #[test]
    fn test_pkcs12_key_derivation() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt", 2048, 1);
        let mut output = vec![0u8; 24];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 24);
        assert_ne!(output, vec![0u8; 24]);
    }

    #[test]
    fn test_pkcs12_iv_derivation() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt", 2048, 2);
        let mut output = vec![0u8; 8];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 8);
        assert_ne!(output, vec![0u8; 8]);
    }

    #[test]
    fn test_pkcs12_mac_key_derivation() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt", 2048, 3);
        let mut output = vec![0u8; 20];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 20);
        assert_ne!(output, vec![0u8; 20]);
    }

    #[test]
    fn test_pkcs12_different_ids_differ() {
        let provider = Pkcs12KdfProvider;
        let mut results = Vec::new();
        for id in 1..=3 {
            let mut ctx = provider.new_ctx().unwrap();
            let ps = make_params(b"password", b"saltsalt", 1024, id);
            let mut output = vec![0u8; 16];
            ctx.derive(&mut output, &ps).unwrap();
            results.push(output);
        }
        assert_ne!(results[0], results[1]);
        assert_ne!(results[1], results[2]);
    }

    #[test]
    fn test_pkcs12_invalid_id() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"salt", 1, 4);
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_pkcs12_zero_iterations() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"salt", 0, 1);
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_pkcs12_reset() {
        let provider = Pkcs12KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"salt", 1, 1);
        let mut output = vec![0u8; 16];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
