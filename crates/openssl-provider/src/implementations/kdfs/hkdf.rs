//! HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
//!
//! This module provides an idiomatic Rust translation of
//! `providers/implementations/kdfs/hkdf.c`. It implements:
//!
//! - **HKDF** — full extract-then-expand and one-shot modes
//! - **TLS13-KDF** — the TLS 1.3 variant per RFC 8446 §7.1
//!
//! # Algorithm Overview
//!
//! HKDF operates in two stages:
//! 1. **Extract**: `PRK = HMAC-Hash(salt, IKM)` — produces a pseudorandom key
//! 2. **Expand**: derives output keying material from PRK and info
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for salt and info (no sentinel values)
//! - **R6:** Output length validated via checked arithmetic
//! - **R8:** Zero `unsafe` blocks
//! - **R9:** Warning-free with comprehensive documentation
//!
//! Source: `providers/implementations/kdfs/hkdf.c`

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_DIGEST` — hash algorithm name.
const PARAM_DIGEST: &str = "digest";
/// `OSSL_KDF_PARAM_KEY` — input keying material.
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_SALT` — optional salt.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_INFO` — context/application-specific info.
const PARAM_INFO: &str = "info";
/// `OSSL_KDF_PARAM_MODE` — operation mode (extract-and-expand, extract, expand).
const PARAM_MODE: &str = "mode";

// =============================================================================
// HKDF Mode Enum
// =============================================================================

/// HKDF operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HkdfMode {
    /// Full extract-then-expand (default).
    ExtractAndExpand,
    /// Extract-only: output is the PRK.
    ExtractOnly,
    /// Expand-only: IKM is treated as the PRK.
    ExpandOnly,
}

impl Default for HkdfMode {
    fn default() -> Self {
        Self::ExtractAndExpand
    }
}

// =============================================================================
// Hash Algorithm Selection
// =============================================================================

/// Supported hash algorithms for HKDF.
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
    /// Returns the output length in bytes for this hash algorithm.
    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Parse hash algorithm from name string.
    fn from_name(name: &str) -> ProviderResult<Self> {
        match name.to_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" | "SHA2-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" | "SHA2-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" | "SHA2-512" => Ok(Self::Sha512),
            _ => Err(ProviderError::Init(
                format!("HKDF: unsupported digest '{name}'"),
            )),
        }
    }

    /// Compute HMAC using the selected hash algorithm.
        /// # Errors
    ///
    /// Returns `ProviderError` if HMAC key initialisation fails (should not
    /// happen — HMAC accepts arbitrary-length keys, but we propagate the
    /// error defensively).
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

    /// Compute raw hash digest. Used by TLS 1.3 Transcript-Hash and future
    /// HKDF-based protocols that need a plain digest alongside HMAC.
    #[allow(dead_code)] // Library API: used by TLS 1.3 Transcript-Hash callers
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use digest::Digest;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

// =============================================================================
// HKDF Context
// =============================================================================

/// HKDF context holding all derivation parameters.
///
/// Replaces `KDF_HKDF` struct from `hkdf.c`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct HkdfContext {
    /// Input keying material.
    key: Vec<u8>,
    /// Salt (if empty, a hash-length block of zeros is used per RFC 5869).
    salt: Vec<u8>,
    /// Info string segments concatenated.
    info: Vec<u8>,
    /// Selected hash algorithm name.
    #[zeroize(skip)]
    hash: HashAlgorithm,
    /// Operation mode (extract-and-expand, extract-only, expand-only).
    #[zeroize(skip)]
    mode: HkdfMode,
}

impl HkdfContext {
    /// Creates a new context with default parameters.
    fn new() -> Self {
        Self {
            key: Vec::new(),
            salt: Vec::new(),
            info: Vec::new(),
            hash: HashAlgorithm::default(),
            mode: HkdfMode::default(),
        }
    }

    /// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    ///
    /// If salt is empty, uses a hash-length block of zeros per RFC 5869 §2.2.
    fn extract(&self) -> ProviderResult<Vec<u8>> {
        let salt = if self.salt.is_empty() {
            vec![0u8; self.hash.output_len()]
        } else {
            self.salt.clone()
        };
        self.hash.hmac(&salt, &self.key)
    }

    /// HKDF-Expand: OKM = T(1) || T(2) || ... || T(N), truncated
    ///
    /// T(0) = empty string
    /// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    fn expand(&self, prk: &[u8], length: usize) -> ProviderResult<Vec<u8>> {
        let hash_len = self.hash.output_len();
        // RFC 5869 §2.3: L must be <= 255 * HashLen
        let max_len = hash_len.checked_mul(255).ok_or_else(|| {
            ProviderError::Init("HKDF: overflow computing max output length".into())
        })?;
        if length > max_len {
            return Err(ProviderError::Init(format!(
                "HKDF: requested length {length} exceeds maximum {max_len}"
            )));
        }
        if length == 0 {
            return Err(ProviderError::Init(
                "HKDF: output length must be > 0".into(),
            ));
        }

        let n = (length + hash_len - 1) / hash_len;
        let mut okm = Vec::with_capacity(length);
        let mut t_prev: Vec<u8> = Vec::new();

        for i in 1..=n {
            let mut input = Vec::with_capacity(t_prev.len() + self.info.len() + 1);
            input.extend_from_slice(&t_prev);
            input.extend_from_slice(&self.info);
            // Counter byte: i as u8 (safe since n <= 255)
            #[allow(clippy::cast_possible_truncation)]
            // TRUNCATION: i is bounded by n <= 255, so fits in u8
            input.push(i as u8);

            t_prev = self.hash.hmac(prk, &input)?;
            okm.extend_from_slice(&t_prev);
        }

        okm.truncate(length);
        Ok(okm)
    }

    /// Apply parameters from a [`ParamSet`].
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(PARAM_DIGEST) {
            let name = val.as_str().ok_or_else(|| {
                ProviderError::Init("HKDF: digest must be a string".into())
            })?;
            self.hash = HashAlgorithm::from_name(name)?;
            tracing::debug!(digest = name, "HkdfContext: digest set");
        }
        if let Some(val) = params.get(PARAM_KEY) {
            let k = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("HKDF: key must be bytes".into())
            })?;
            if k.is_empty() {
                return Err(ProviderError::Init("HKDF: key must not be empty".into()));
            }
            self.key = k.to_vec();
        }
        if let Some(val) = params.get(PARAM_SALT) {
            self.salt = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("HKDF: salt must be bytes".into())
            })?.to_vec();
        }
        if let Some(val) = params.get(PARAM_INFO) {
            let info_data = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("HKDF: info must be bytes".into())
            })?;
            if info_data.len() > super::MAX_INPUT_LEN {
                return Err(ProviderError::Init("HKDF: info too large".into()));
            }
            self.info = info_data.to_vec();
        }
        if let Some(val) = params.get(PARAM_MODE) {
            let mode_str = val.as_str().ok_or_else(|| {
                ProviderError::Init("HKDF: mode must be a string".into())
            })?;
            self.mode = match mode_str.to_uppercase().as_str() {
                "EXTRACT_AND_EXPAND" => HkdfMode::ExtractAndExpand,
                "EXTRACT_ONLY" => HkdfMode::ExtractOnly,
                "EXPAND_ONLY" => HkdfMode::ExpandOnly,
                _ => {
                    return Err(ProviderError::Init(
                        format!("HKDF: unknown mode '{mode_str}'"),
                    ));
                }
            };
        }
        Ok(())
    }
}

impl KdfContext for HkdfContext {
    /// Derives key material using HKDF.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        if self.key.is_empty() {
            return Err(ProviderError::Init(
                "HKDF: key (IKM) must be set before derivation".into(),
            ));
        }

        let result = match self.mode {
            HkdfMode::ExtractAndExpand => {
                let prk = self.extract()?;
                self.expand(&prk, key.len())?
            }
            HkdfMode::ExtractOnly => self.extract()?,
            HkdfMode::ExpandOnly => {
                // In expand-only mode, key IS the PRK
                let prk = self.key.clone();
                self.expand(&prk, key.len())?
            }
        };

        let copy_len = core::cmp::min(key.len(), result.len());
        key[..copy_len].copy_from_slice(&result[..copy_len]);
        tracing::debug!(
            bytes = copy_len,
            mode = ?self.mode,
            hash = ?self.hash,
            "HkdfContext::derive complete"
        );
        Ok(copy_len)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.key.zeroize();
        self.key.clear();
        self.salt.zeroize();
        self.salt.clear();
        self.info.zeroize();
        self.info.clear();
        self.mode = HkdfMode::default();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, format!("{:?}", self.hash))
            .push_utf8(PARAM_MODE, format!("{:?}", self.mode))
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// TLS 1.3 KDF Context
// =============================================================================

/// TLS 1.3 Key Derivation context per RFC 8446 §7.1.
///
/// Uses HKDF-Extract and HKDF-Expand-Label as building blocks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Tls13KdfContext {
    /// Input keying material (shared secret).
    key: Vec<u8>,
    /// Salt (previous secret or zero).
    salt: Vec<u8>,
    /// Label for HKDF-Expand-Label.
    #[zeroize(skip)]
    label: String,
    /// Context hash for HKDF-Expand-Label.
    context: Vec<u8>,
    /// Hash algorithm.
    #[zeroize(skip)]
    hash: HashAlgorithm,
    /// Prefix for label construction ("tls13 " by default).
    #[zeroize(skip)]
    prefix: String,
    /// Mode: extract-and-expand or expand-only.
    #[zeroize(skip)]
    mode: HkdfMode,
}

impl Tls13KdfContext {
    fn new() -> Self {
        Self {
            key: Vec::new(),
            salt: Vec::new(),
            label: String::new(),
            context: Vec::new(),
            hash: HashAlgorithm::default(),
            prefix: "tls13 ".to_string(),
            mode: HkdfMode::ExtractAndExpand,
        }
    }

    /// HKDF-Expand-Label per RFC 8446 §7.1:
    /// ```text
    /// HKDF-Expand-Label(Secret, Label, Context, Length) =
    ///     HKDF-Expand(Secret, HkdfLabel, Length)
    /// where HkdfLabel = struct {
    ///     uint16 length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// };
    /// ```
    fn expand_label(
        &self,
        prk: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> ProviderResult<Vec<u8>> {
        let full_label = format!("{}{}", self.prefix, label);
        let label_bytes = full_label.as_bytes();

        if label_bytes.len() > 255 || context.len() > 255 {
            return Err(ProviderError::Init(
                "TLS13-KDF: label or context too long".into(),
            ));
        }

        // Construct HkdfLabel
        let mut hkdf_label = Vec::with_capacity(2 + 1 + label_bytes.len() + 1 + context.len());
        // uint16 length (big-endian)
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: length bounded by 255*HashLen which fits u16
        {
            let len_u16 = u16::try_from(length).map_err(|_| {
                ProviderError::Init("TLS13-KDF: output length exceeds u16".into())
            })?;
            hkdf_label.extend_from_slice(&len_u16.to_be_bytes());
        }
        // opaque label<7..255>
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: label_bytes.len() checked <= 255 above
        hkdf_label.push(label_bytes.len() as u8);
        hkdf_label.extend_from_slice(label_bytes);
        // opaque context<0..255>
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: context.len() checked <= 255 above
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        // Use HKDF-Expand
        let hash_len = self.hash.output_len();
        let max_len = hash_len.checked_mul(255).ok_or_else(|| {
            ProviderError::Init("TLS13-KDF: overflow computing max output length".into())
        })?;
        if length > max_len || length == 0 {
            return Err(ProviderError::Init(
                "TLS13-KDF: invalid output length".into(),
            ));
        }

        let n = (length + hash_len - 1) / hash_len;
        let mut okm = Vec::with_capacity(length);
        let mut t_prev: Vec<u8> = Vec::new();

        for i in 1..=n {
            let mut input = Vec::with_capacity(t_prev.len() + hkdf_label.len() + 1);
            input.extend_from_slice(&t_prev);
            input.extend_from_slice(&hkdf_label);
            #[allow(clippy::cast_possible_truncation)]
            // TRUNCATION: i bounded by n <= 255
            input.push(i as u8);
            t_prev = self.hash.hmac(prk, &input)?;
            okm.extend_from_slice(&t_prev);
        }
        okm.truncate(length);
        Ok(okm)
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(PARAM_DIGEST) {
            let name = val.as_str().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: digest must be a string".into())
            })?;
            self.hash = HashAlgorithm::from_name(name)?;
        }
        if let Some(val) = params.get(PARAM_KEY) {
            self.key = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: key must be bytes".into())
            })?.to_vec();
        }
        if let Some(val) = params.get(PARAM_SALT) {
            self.salt = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: salt must be bytes".into())
            })?.to_vec();
        }
        if let Some(val) = params.get("label") {
            self.label = val.as_str().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: label must be a string".into())
            })?.to_string();
        }
        if let Some(val) = params.get("data") {
            self.context = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: data must be bytes".into())
            })?.to_vec();
        }
        if let Some(val) = params.get("prefix") {
            self.prefix = val.as_str().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: prefix must be a string".into())
            })?.to_string();
        }
        if let Some(val) = params.get(PARAM_MODE) {
            let mode_str = val.as_str().ok_or_else(|| {
                ProviderError::Init("TLS13-KDF: mode must be a string".into())
            })?;
            self.mode = match mode_str.to_uppercase().as_str() {
                "EXTRACT_AND_EXPAND" => HkdfMode::ExtractAndExpand,
                "EXTRACT_ONLY" => HkdfMode::ExtractOnly,
                "EXPAND_ONLY" => HkdfMode::ExpandOnly,
                _ => {
                    return Err(ProviderError::Init(
                        format!("TLS13-KDF: unknown mode '{mode_str}'"),
                    ));
                }
            };
        }
        Ok(())
    }
}

impl KdfContext for Tls13KdfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        if self.key.is_empty() {
            return Err(ProviderError::Init(
                "TLS13-KDF: key must be set before derivation".into(),
            ));
        }

        let result = match self.mode {
            HkdfMode::ExtractAndExpand => {
                let salt = if self.salt.is_empty() {
                    vec![0u8; self.hash.output_len()]
                } else {
                    self.salt.clone()
                };
                let prk = self.hash.hmac(&salt, &self.key)?;
                self.expand_label(&prk, &self.label.clone(), &self.context.clone(), key.len())?
            }
            HkdfMode::ExtractOnly => {
                let salt = if self.salt.is_empty() {
                    vec![0u8; self.hash.output_len()]
                } else {
                    self.salt.clone()
                };
                self.hash.hmac(&salt, &self.key)?
            }
            HkdfMode::ExpandOnly => {
                let prk = self.key.clone();
                self.expand_label(&prk, &self.label.clone(), &self.context.clone(), key.len())?
            }
        };

        let copy_len = core::cmp::min(key.len(), result.len());
        key[..copy_len].copy_from_slice(&result[..copy_len]);
        Ok(copy_len)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.key.zeroize();
        self.key.clear();
        self.salt.zeroize();
        self.salt.clear();
        self.context.zeroize();
        self.context.clear();
        self.label.clear();
        self.mode = HkdfMode::default();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, format!("{:?}", self.hash))
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// HKDF Provider
// =============================================================================

/// HKDF provider factory.
pub struct HkdfProvider;

impl KdfProvider for HkdfProvider {
    fn name(&self) -> &'static str {
        "HKDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        tracing::debug!("HkdfProvider::new_ctx: creating HKDF context");
        Ok(Box::new(HkdfContext::new()))
    }
}

/// TLS 1.3 KDF provider factory.
pub struct Tls13KdfProvider;

impl KdfProvider for Tls13KdfProvider {
    fn name(&self) -> &'static str {
        "TLS13-KDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        tracing::debug!("Tls13KdfProvider::new_ctx: creating TLS13-KDF context");
        Ok(Box::new(Tls13KdfContext::new()))
    }
}

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns algorithm descriptors for HKDF and TLS13-KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HKDF"],
            "provider=default",
            "HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)",
        ),
        algorithm(
            &["TLS13-KDF"],
            "provider=default",
            "TLS 1.3 Key Derivation Function (RFC 8446)",
        ),
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    /// RFC 5869 Test Case 1: SHA-256, basic test case.
    #[test]
    fn test_hkdf_rfc5869_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(ikm.clone()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.clone()));
        ps.set(PARAM_INFO, ParamValue::OctetString(info.clone()));

        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut output = vec![0u8; 42];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 42);

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ).unwrap();
        assert_eq!(output, expected);
    }

    /// Test extract-only mode.
    #[test]
    fn test_hkdf_extract_only() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(ikm.clone()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.clone()));
        ps.set(PARAM_MODE, ParamValue::Utf8String("EXTRACT_ONLY".to_string()));

        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        // PRK should be deterministic
        assert_ne!(output, vec![0u8; 32]);
    }

    /// Test missing key returns error.
    #[test]
    fn test_hkdf_missing_key() {
        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        let result = ctx.derive(&mut output, &ParamSet::default());
        assert!(result.is_err());
    }

    /// Test reset clears state.
    #[test]
    fn test_hkdf_reset() {
        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(b"test_key".to_vec()));
        ctx.set_params(&ps).unwrap();
        ctx.reset().unwrap();

        let mut output = vec![0u8; 32];
        // After reset, key is cleared, should fail
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
