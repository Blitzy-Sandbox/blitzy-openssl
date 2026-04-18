//! Password-Based Key Derivation Function 2 (PKCS#5 v2.1, SP 800-132).
//!
//! Source: `providers/implementations/kdfs/pbkdf2.c`
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for salt
//! - **R6:** Iteration count validated, checked arithmetic
//! - **R8:** Zero `unsafe` blocks
//! - **R9:** Warning-free

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

const PARAM_DIGEST: &str = "digest";
const PARAM_PASSWORD: &str = "pass";
const PARAM_SALT: &str = "salt";
const PARAM_ITER: &str = "iter";
const PARAM_PKCS5: &str = "pkcs5";

/// Minimum iteration count for FIPS compliance (the FIPS provider layer
/// enforces a higher floor; this non-FIPS minimum matches C OpenSSL).
const MIN_ITERATIONS: u32 = 1;
/// Default iteration count — secure default for non-FIPS usage.
const DEFAULT_ITERATIONS: u32 = 2048;

/// Supported hash algorithms for PBKDF2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

impl HashAlgorithm {
    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn from_name(name: &str) -> ProviderResult<Self> {
        match name.to_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" | "SHA2-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" | "SHA2-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" | "SHA2-512" => Ok(Self::Sha512),
            _ => Err(ProviderError::Init(
                format!("PBKDF2: unsupported digest '{name}'"),
            )),
        }
    }

    /// Compute HMAC with the selected hash algorithm.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init("HMAC key initialization failed".into())` if key initialisation fails
    /// (should not occur — HMAC accepts arbitrary key lengths).
    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use digest::Mac;
        let bytes = match self {
            Self::Sha1 => {
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(bytes)
    }
}

/// PBKDF2 context holding all derivation parameters.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Pbkdf2Context {
    password: Vec<u8>,
    salt: Vec<u8>,
    #[zeroize(skip)]
    iterations: u32,
    #[zeroize(skip)]
    hash: HashAlgorithm,
    /// PKCS#5 v1 mode flag — when true, relaxes validation.
    #[zeroize(skip)]
    pkcs5_mode: bool,
}

impl Pbkdf2Context {
    fn new() -> Self {
        Self {
            password: Vec::new(),
            salt: Vec::new(),
            iterations: DEFAULT_ITERATIONS,
            hash: HashAlgorithm::default(),
            pkcs5_mode: false,
        }
    }

    /// PBKDF2 core: `DK = T_1 || T_2 || ... || T_dklen/hlen`
    /// `T_i = F(Password, Salt, c, i)`
    /// `F(Password, Salt, c, i) = U_1 ^ U_2 ^ ... ^ U_c`
    /// where `U_1 = PRF(Password, Salt || INT(i))`
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = self.hash.output_len();
        let dk_len = output.len();

        if dk_len == 0 {
            return Err(ProviderError::Init(
                "PBKDF2: output length must be > 0".into(),
            ));
        }

        // PKCS#5 v2.1 §5.2: dkLen must be <= (2^32 - 1) * hLen
        let max_len = h_len.checked_mul(u32::MAX as usize).ok_or_else(|| {
            ProviderError::Init("PBKDF2: overflow computing max output length".into())
        })?;
        if dk_len > max_len {
            return Err(ProviderError::Init(
                format!("PBKDF2: requested length {dk_len} exceeds maximum {max_len}"),
            ));
        }

        let num_blocks = (dk_len + h_len - 1) / h_len;
        let mut pos = 0;

        for block_num in 1..=num_blocks {
            // U_1 = PRF(Password, Salt || INT_32_BE(i))
            let mut salt_with_block = Vec::with_capacity(self.salt.len() + 4);
            salt_with_block.extend_from_slice(&self.salt);
            let block_num_u32 = u32::try_from(block_num).map_err(|_| {
                ProviderError::Init("PBKDF2: block number overflow".into())
            })?;
            salt_with_block.extend_from_slice(&block_num_u32.to_be_bytes());

            let mut u_prev = self.hash.hmac(&self.password, &salt_with_block)?;
            let mut result = u_prev.clone();

            // U_2 through U_c
            for _ in 1..self.iterations {
                let u_curr = self.hash.hmac(&self.password, &u_prev)?;
                for (r, u) in result.iter_mut().zip(u_curr.iter()) {
                    *r ^= u;
                }
                u_prev = u_curr;
            }

            let remaining = dk_len - pos;
            let copy_len = core::cmp::min(remaining, h_len);
            output[pos..pos + copy_len].copy_from_slice(&result[..copy_len]);
            pos += copy_len;

            // Zeroize temporaries
            u_prev.zeroize();
            result.zeroize();
        }

        Ok(dk_len)
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(PARAM_DIGEST) {
            let name = val.as_str().ok_or_else(|| {
                ProviderError::Init("PBKDF2: digest must be a string".into())
            })?;
            self.hash = HashAlgorithm::from_name(name)?;
        }
        if let Some(val) = params.get(PARAM_PASSWORD) {
            self.password = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("PBKDF2: password must be bytes".into())
            })?.to_vec();
        }
        if let Some(val) = params.get(PARAM_SALT) {
            let s = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("PBKDF2: salt must be bytes".into())
            })?;
            if s.len() > super::MAX_INPUT_LEN {
                return Err(ProviderError::Init("PBKDF2: salt too large".into()));
            }
            self.salt = s.to_vec();
        }
        if let Some(val) = params.get(PARAM_ITER) {
            let i = val.as_u64().ok_or_else(|| {
                ProviderError::Init("PBKDF2: iter must be a uint64".into())
            })?;
            let iterations = u32::try_from(i).map_err(|_| {
                ProviderError::Init("PBKDF2: iter exceeds u32::MAX".into())
            })?;
            if iterations < MIN_ITERATIONS {
                return Err(ProviderError::Init(
                    format!("PBKDF2: iterations must be >= {MIN_ITERATIONS}"),
                ));
            }
            self.iterations = iterations;
        }
        if let Some(val) = params.get(PARAM_PKCS5) {
            let v = val.as_u64().unwrap_or(0);
            self.pkcs5_mode = v != 0;
        }
        Ok(())
    }
}

impl KdfContext for Pbkdf2Context {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        if self.password.is_empty() && !self.pkcs5_mode {
            return Err(ProviderError::Init(
                "PBKDF2: password must be set before derivation".into(),
            ));
        }
        if self.salt.is_empty() && !self.pkcs5_mode {
            tracing::warn!("PBKDF2: empty salt — this weakens the derived key");
        }
        if self.iterations < 1000 {
            tracing::warn!(
                iterations = self.iterations,
                "PBKDF2: iteration count below NIST SP 800-132 recommended minimum of 1000; \
                 the FIPS provider enforces a higher floor"
            );
        }
        self.derive_internal(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.password.zeroize();
        self.password.clear();
        self.salt.zeroize();
        self.salt.clear();
        self.iterations = DEFAULT_ITERATIONS;
        self.pkcs5_mode = false;
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, format!("{:?}", self.hash))
            .push_u64(PARAM_ITER, u64::from(self.iterations))
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// PBKDF2 provider factory.
pub struct Pbkdf2Provider;

impl KdfProvider for Pbkdf2Provider {
    fn name(&self) -> &'static str {
        "PBKDF2"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        tracing::debug!("Pbkdf2Provider::new_ctx");
        Ok(Box::new(Pbkdf2Context::new()))
    }
}

/// Returns algorithm descriptors for PBKDF2.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["PBKDF2"],
        "provider=default",
        "Password-Based Key Derivation Function 2 (PKCS#5 v2.1)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    /// RFC 6070 Test Vector 1: "password" / "salt" / 1 iteration / 20 bytes.
    #[test]
    fn test_pbkdf2_rfc6070_vector1() {
        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-1".to_string()));
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(b"password".to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        ps.set(PARAM_ITER, ParamValue::UInt64(1));

        let provider = Pbkdf2Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 20];
        ctx.derive(&mut output, &ps).unwrap();

        let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
        assert_eq!(output, expected);
    }

    /// RFC 6070 Test Vector 2: 2 iterations.
    #[test]
    fn test_pbkdf2_rfc6070_vector2() {
        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-1".to_string()));
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(b"password".to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        ps.set(PARAM_ITER, ParamValue::UInt64(2));

        let provider = Pbkdf2Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 20];
        ctx.derive(&mut output, &ps).unwrap();

        let expected = hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap();
        assert_eq!(output, expected);
    }

    /// Test missing password returns error.
    #[test]
    fn test_pbkdf2_missing_password() {
        let provider = Pbkdf2Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
