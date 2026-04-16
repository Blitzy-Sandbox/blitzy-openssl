//! # Shared Digest Provider Infrastructure
//!
//! Common types, flags, and utilities shared across all digest provider
//! implementations. This module is the **foundation** for every other digest
//! module in this directory — all digest files depend on the types and
//! functions defined here.
//!
//! ## Source Mapping
//!
//! | Rust item | C source |
//! |-----------|----------|
//! | [`DigestFlags`] | `PROV_DIGEST_FLAG_*` macros from `prov/digestcommon.h` |
//! | [`DigestParams`] | `OSSL_PARAM` bags in `ossl_digest_default_get_params()` |
//! | [`default_get_params()`] | `ossl_digest_default_get_params()` (digestcommon.c:18-44) |
//! | [`default_gettable_params()`] | `ossl_digest_default_gettable_params()` (digestcommon.c:46-51) |
//! | [`is_fips_approved_digest()`] | `ossl_digest_get_approved_nid()` (digest_to_nid.c) |
//! | [`digest_name_to_nid()`] | `ossl_digest_md_to_nid()` (digest_to_nid.c) |
//! | [`DigestContextOps`] | Common context lifecycle helpers from `provider_util.c` |
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use bitflags::bitflags;
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamBuilder, ParamSet};

use crate::traits::DigestContext;

// =============================================================================
// DigestFlags — Bitflags for Digest Algorithm Properties
// =============================================================================

bitflags! {
    /// Bitflags describing behavioural properties of a digest algorithm.
    ///
    /// These flags replace the C preprocessor constants defined in
    /// `providers/implementations/digests/digestcommon.h`:
    ///
    /// - `PROV_DIGEST_FLAG_ALGID_ABSENT` → [`DigestFlags::ALGID_ABSENT`]
    /// - `PROV_DIGEST_FLAG_XOF`          → [`DigestFlags::XOF`]
    /// - Custom provider-specific flag   → [`DigestFlags::CUSTOM`]
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// use openssl_provider::implementations::digests::common::DigestFlags;
    ///
    /// let sha3_flags = DigestFlags::ALGID_ABSENT;
    /// let shake_flags = DigestFlags::XOF | DigestFlags::ALGID_ABSENT;
    /// let no_flags = DigestFlags::empty();
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DigestFlags: u32 {
        /// The `AlgorithmIdentifier` is absent in X.509 encoding.
        ///
        /// When set, the digest does not include an `AlgorithmIdentifier` OID
        /// in its X.509 `DigestAlgorithmIdentifier` structure (the parameter
        /// field is omitted entirely, not just set to NULL). This applies to
        /// SHA-3, SHAKE, Keccak, and other algorithms that use the
        /// `id-shake*` OIDs without parameters.
        ///
        /// Equivalent to C `PROV_DIGEST_FLAG_ALGID_ABSENT` (0x0001).
        const ALGID_ABSENT = 0x0001;

        /// Extendable Output Function (XOF).
        ///
        /// When set, the digest supports variable-length output via the
        /// squeeze operation. Applies to SHAKE128, SHAKE256, cSHAKE, and
        /// KECCAK-KMAC variants. XOF digests may produce output of any
        /// requested length, not just their default digest size.
        ///
        /// Equivalent to C `PROV_DIGEST_FLAG_XOF` (0x0002).
        const XOF = 0x0002;

        /// Custom digest behaviour flag.
        ///
        /// When set, the digest requires non-standard initialization or
        /// parameterisation. Applies to algorithms like BLAKE2 with a key,
        /// cSHAKE with a customisation string, or other provider-specific
        /// variants that extend the basic init/update/finalize lifecycle.
        ///
        /// This is a provider-specific extension flag (0x0004).
        const CUSTOM = 0x0004;
    }
}

// =============================================================================
// DigestParams — Typed Parameter Struct
// =============================================================================

/// Typed parameter struct for digest algorithm configuration.
///
/// Replaces the dynamic `OSSL_PARAM` bags used in C digest providers
/// with compile-time–checked fields. Each provider populates these
/// parameters during registration and context creation.
///
/// # C Parameter Key Mapping
///
/// | Rust field      | C `OSSL_PARAM` key               | `ParamSet` key  |
/// |-----------------|-----------------------------------|-----------------|
/// | `block_size`    | `OSSL_DIGEST_PARAM_BLOCK_SIZE`   | `"blocksize"`   |
/// | `digest_size`   | `OSSL_DIGEST_PARAM_SIZE`         | `"size"`        |
/// | `xof`           | `OSSL_DIGEST_PARAM_XOF`          | `"xof"`         |
/// | `algid_absent`  | `OSSL_DIGEST_PARAM_ALGID_ABSENT` | `"algid-absent"`|
///
/// # Example
///
/// ```rust,ignore
/// use openssl_provider::implementations::digests::common::{DigestFlags, DigestParams};
///
/// // SHA-256: 64-byte block, 32-byte output, no special flags
/// let sha256 = DigestParams::from_flags(64, 32, DigestFlags::empty());
/// assert_eq!(sha256.block_size, 64);
/// assert_eq!(sha256.digest_size, 32);
/// assert!(!sha256.xof);
/// assert!(!sha256.algid_absent);
///
/// // SHAKE-256: 136-byte block, 32-byte default output, XOF + ALGID_ABSENT
/// let shake256 = DigestParams::from_flags(
///     136, 32, DigestFlags::XOF | DigestFlags::ALGID_ABSENT,
/// );
/// assert!(shake256.xof);
/// assert!(shake256.algid_absent);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestParams {
    /// Block size in bytes (e.g., 64 for SHA-256, 128 for SHA-512, 0 for NULL).
    pub block_size: usize,

    /// Output digest size in bytes (e.g., 32 for SHA-256, 0 for NULL).
    /// For XOF digests this is the *default* output length; the actual
    /// output can be any requested size.
    pub digest_size: usize,

    /// Whether this digest is an Extendable Output Function (XOF).
    /// When `true`, the digest supports variable-length squeeze output.
    pub xof: bool,

    /// Whether the `AlgorithmIdentifier` is absent in X.509 encoding.
    /// When `true`, the digest omits the algorithm OID parameter field.
    pub algid_absent: bool,
}

impl DigestParams {
    /// Creates a new `DigestParams` by extracting boolean flags from [`DigestFlags`].
    ///
    /// This is the primary constructor used by digest providers during
    /// registration. It corresponds to the pattern in C where
    /// `ossl_digest_default_get_params()` reads `PROV_DIGEST_FLAG_XOF` and
    /// `PROV_DIGEST_FLAG_ALGID_ABSENT` from the flags field.
    ///
    /// # Arguments
    ///
    /// * `block_size`  — Internal block size in bytes
    /// * `digest_size` — Output digest size in bytes (default for XOF)
    /// * `flags`       — [`DigestFlags`] controlling XOF and `ALGID_ABSENT` properties
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
    /// assert_eq!(params.block_size, 64);
    /// assert!(!params.xof);
    /// ```
    pub fn from_flags(block_size: usize, digest_size: usize, flags: DigestFlags) -> Self {
        Self {
            block_size,
            digest_size,
            xof: flags.contains(DigestFlags::XOF),
            algid_absent: flags.contains(DigestFlags::ALGID_ABSENT),
        }
    }

    /// Converts these parameters into a [`ParamSet`] for provider dispatch.
    ///
    /// The resulting `ParamSet` uses the standard OpenSSL parameter key names:
    ///
    /// - `"blocksize"`    → block size as `UInt64`
    /// - `"size"`         → digest size as `UInt64`
    /// - `"xof"`          → XOF flag as `UInt64` (0 or 1)
    /// - `"algid-absent"` → `ALGID_ABSENT` flag as `UInt64` (0 or 1)
    ///
    /// This replaces the C pattern of populating an `OSSL_PARAM[]` array
    /// in `ossl_digest_default_get_params()`.
    pub fn to_param_set(&self) -> ParamSet {
        ParamBuilder::new()
            .push_u64("blocksize", self.block_size as u64)
            .push_u64("size", self.digest_size as u64)
            .push_u64("xof", u64::from(self.xof))
            .push_u64("algid-absent", u64::from(self.algid_absent))
            .build()
    }
}

// =============================================================================
// DigestContextOps — Common Context Operations Trait
// =============================================================================

/// Extension trait providing common context lifecycle operations shared
/// across all digest implementations.
///
/// This trait requires [`DigestContext`] as a supertrait, ensuring that
/// any type implementing `DigestContextOps` also provides the full
/// streaming digest lifecycle (`init`, `update`, `finalize`, `duplicate`,
/// `get_params`, `set_params`).
///
/// # Implementors
///
/// All concrete digest context types (e.g., `Sha256Context`, `Sha3Context`,
/// `NullDigestContext`) implement this trait to expose their static
/// parameters and flags.
///
/// # C Mapping
///
/// Provides a unified way for the provider framework to query digest
/// metadata from a context instance, replacing the pattern in
/// `providers/common/provider_util.c` where `PROV_DIGEST` structs carried
/// cached algorithm properties alongside the context pointer.
pub trait DigestContextOps: DigestContext {
    /// Returns the [`DigestParams`] for this context.
    ///
    /// This includes block size, digest size, XOF flag, and `ALGID_ABSENT`
    /// flag. Implementations typically return a clone of their stored
    /// parameters or construct them from compile-time constants.
    fn params(&self) -> DigestParams;

    /// Returns the [`DigestFlags`] for this context.
    ///
    /// Flags indicate behavioural properties of the underlying digest
    /// algorithm (XOF, `ALGID_ABSENT`, CUSTOM).
    fn flags(&self) -> DigestFlags;
}

// =============================================================================
// Utility Functions — Parameter Helpers
// =============================================================================

/// Returns the default digest parameters as a [`ParamSet`].
///
/// This is the primary entry point for providers responding to
/// `get_params()` queries. It constructs a `ParamSet` containing the four
/// standard digest parameters: block size, digest size, XOF flag, and
/// `ALGID_ABSENT` flag.
///
/// # C Mapping
///
/// Translates `ossl_digest_default_get_params()` from
/// `providers/implementations/digests/digestcommon.c` (lines 18–44).
///
/// # Arguments
///
/// * `block_size`  — Block size in bytes
/// * `digest_size` — Output digest size in bytes
/// * `flags`       — [`DigestFlags`] for this algorithm
///
/// # Returns
///
/// `Ok(ParamSet)` containing the four standard parameters, or
/// `Err(ProviderError)` if construction fails.
///
/// # Example
///
/// ```rust,ignore
/// let params = default_get_params(64, 32, DigestFlags::empty())?;
/// assert_eq!(params.get("blocksize").and_then(|v| v.as_u64()), Some(64));
/// assert_eq!(params.get("size").and_then(|v| v.as_u64()), Some(32));
/// ```
pub fn default_get_params(
    block_size: usize,
    digest_size: usize,
    flags: DigestFlags,
) -> ProviderResult<ParamSet> {
    let params = DigestParams::from_flags(block_size, digest_size, flags);
    Ok(params.to_param_set())
}

/// Returns the list of parameter keys that a digest provider can supply
/// via `get_params()`.
///
/// This is the gettable-params descriptor: it tells the caller which
/// parameter names are available for querying. The keys correspond to
/// the standard `OSSL_DIGEST_PARAM_*` constants.
///
/// # C Mapping
///
/// Translates `ossl_digest_default_gettable_params()` from
/// `providers/implementations/digests/digestcommon.c` (lines 46–51).
///
/// # Returns
///
/// A `Vec` of static string slices naming the gettable parameters:
/// `["blocksize", "size", "xof", "algid-absent"]`.
pub fn default_gettable_params() -> Vec<&'static str> {
    vec!["blocksize", "size", "xof", "algid-absent"]
}

// =============================================================================
// FIPS Approved Digest Whitelist
// =============================================================================

/// Checks whether the named digest algorithm is FIPS-approved.
///
/// Returns `true` for algorithms approved under FIPS 140-3 for use in
/// FIPS mode. The approved set consists of:
///
/// - **SHA-1**: SHA-1 (for legacy compatibility, signature verification only)
/// - **SHA-2 family**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
/// - **SHA-3 family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
/// - **SHAKE XOFs**: SHAKE-128, SHAKE-256
///
/// Returns `false` for all other algorithms, including:
/// MD5, MD2, MD4, MDC2, RIPEMD-160, Whirlpool, BLAKE2, SM3, NULL,
/// KECCAK-KMAC, cSHAKE, and any unknown names.
///
/// # C Mapping
///
/// Replaces `ossl_digest_get_approved_nid()` from
/// `providers/common/digest_to_nid.c`, which checked the NID against a
/// static whitelist of 11 FIPS-approved hash NIDs (SHA-1 plus the six
/// SHA-2 variants plus the four SHA-3 variants), plus SHAKE-128/256.
///
/// # Arguments
///
/// * `name` — Algorithm name string (case-insensitive matching)
///
/// # Example
///
/// ```rust,ignore
/// assert!(is_fips_approved_digest("SHA-256"));
/// assert!(is_fips_approved_digest("sha3-384"));
/// assert!(!is_fips_approved_digest("MD5"));
/// assert!(!is_fips_approved_digest("BLAKE2B-512"));
/// ```
pub fn is_fips_approved_digest(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        // SHA-1
        "SHA-1" | "SHA1"
        // SHA-2 family (6 variants)
        | "SHA-224" | "SHA224" | "SHA2-224"
        | "SHA-256" | "SHA256" | "SHA2-256"
        | "SHA-384" | "SHA384" | "SHA2-384"
        | "SHA-512" | "SHA512" | "SHA2-512"
        | "SHA-512/224" | "SHA512/224" | "SHA2-512/224"
        | "SHA-512/256" | "SHA512/256" | "SHA2-512/256"
        // SHA-3 family (4 variants)
        | "SHA3-224"
        | "SHA3-256"
        | "SHA3-384"
        | "SHA3-512"
        // SHAKE XOFs
        | "SHAKE-128" | "SHAKE128"
        | "SHAKE-256" | "SHAKE256"
    )
}

// =============================================================================
// Digest Name to NID Mapping
// =============================================================================

/// Maps a digest algorithm name to its legacy numeric identifier (NID).
///
/// Returns `Some(nid)` for known digest names, `None` for unknown or
/// unsupported names. The NID values correspond to the OpenSSL `NID_*`
/// constants used in ASN.1 OID mapping, X.509 encoding, and the legacy
/// `EVP_MD_nid()` API.
///
/// Name matching is case-insensitive. Common aliases are accepted (e.g.,
/// `"SHA256"` and `"SHA-256"` and `"SHA2-256"` all map to `NID_sha256`).
///
/// # C Mapping
///
/// Replaces the `ossl_digest_md_to_nid()` function from
/// `providers/common/digest_to_nid.c`, which performed a lookup by
/// `EVP_MD_get_type()` returning the NID. The C function returned `int`
/// (signed 32-bit), which we preserve as `i32` for FFI compatibility.
///
/// # NID Value Reference
///
/// | Algorithm    | NID  | C Constant       |
/// |-------------|------|------------------|
/// | SHA-1       |   64 | `NID_sha1`       |
/// | SHA-224     |  675 | `NID_sha224`     |
/// | SHA-256     |  672 | `NID_sha256`     |
/// | SHA-384     |  673 | `NID_sha384`     |
/// | SHA-512     |  674 | `NID_sha512`     |
/// | SHA3-224    | 1096 | `NID_sha3_224`   |
/// | SHA3-256    | 1097 | `NID_sha3_256`   |
/// | SHA3-384    | 1098 | `NID_sha3_384`   |
/// | SHA3-512    | 1099 | `NID_sha3_512`   |
/// | SHAKE-128   | 1100 | `NID_shake128`   |
/// | SHAKE-256   | 1101 | `NID_shake256`   |
/// | MD5         |    4 | `NID_md5`        |
/// | MD5-SHA1    |  114 | `NID_md5_sha1`   |
/// | RIPEMD-160  |  117 | `NID_ripemd160`  |
/// | BLAKE2b-512 | 1056 | `NID_blake2b512` |
/// | BLAKE2s-256 | 1057 | `NID_blake2s256` |
/// | SM3         | 1143 | `NID_sm3`        |
/// | NULL        |    0 | `NID_undef`      |
///
/// # Example
///
/// ```rust,ignore
/// assert_eq!(digest_name_to_nid("SHA-256"), Some(672));
/// assert_eq!(digest_name_to_nid("sha3-512"), Some(1099));
/// assert_eq!(digest_name_to_nid("UNKNOWN"), None);
/// ```
pub fn digest_name_to_nid(name: &str) -> Option<i32> {
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
        // SHA-1
        "SHA-1" | "SHA1" => Some(64),

        // SHA-2 family
        "SHA-224" | "SHA224" | "SHA2-224" => Some(675),
        "SHA-256" | "SHA256" | "SHA2-256" => Some(672),
        "SHA-384" | "SHA384" | "SHA2-384" => Some(673),
        "SHA-512" | "SHA512" | "SHA2-512" => Some(674),
        "SHA-512/224" | "SHA512/224" | "SHA2-512/224" => Some(1094),
        "SHA-512/256" | "SHA512/256" | "SHA2-512/256" => Some(1095),

        // SHA-3 family
        "SHA3-224" => Some(1096),
        "SHA3-256" => Some(1097),
        "SHA3-384" => Some(1098),
        "SHA3-512" => Some(1099),

        // SHAKE XOFs
        "SHAKE-128" | "SHAKE128" => Some(1100),
        "SHAKE-256" | "SHAKE256" => Some(1101),

        // MD5
        "MD5" => Some(4),

        // MD5-SHA1 composite
        "MD5-SHA1" | "MD5SHA1" => Some(114),

        // RIPEMD-160
        "RIPEMD-160" | "RIPEMD160" => Some(117),

        // BLAKE2
        "BLAKE2B-512" | "BLAKE2B512" => Some(1056),
        "BLAKE2S-256" | "BLAKE2S256" => Some(1057),

        // SM3 (Chinese national standard)
        "SM3" => Some(1143),

        // Legacy algorithms
        "MD2" => Some(3),
        "MD4" => Some(257),
        "MDC2" => Some(95),
        "WHIRLPOOL" => Some(804),

        // NULL digest (NID_undef)
        "NULL" => Some(0),

        // Unknown
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    // -----------------------------------------------------------------------
    // DigestFlags tests
    // -----------------------------------------------------------------------

    /// Verify that ALGID_ABSENT flag has the correct numeric value.
    #[test]
    fn test_digest_flags_algid_absent_value() {
        assert_eq!(DigestFlags::ALGID_ABSENT.bits(), 0x0001);
    }

    /// Verify that XOF flag has the correct numeric value.
    #[test]
    fn test_digest_flags_xof_value() {
        assert_eq!(DigestFlags::XOF.bits(), 0x0002);
    }

    /// Verify that CUSTOM flag has the correct numeric value.
    #[test]
    fn test_digest_flags_custom_value() {
        assert_eq!(DigestFlags::CUSTOM.bits(), 0x0004);
    }

    /// Verify individual flag containment.
    #[test]
    fn test_digest_flags_contains_single() {
        let flags = DigestFlags::ALGID_ABSENT;
        assert!(flags.contains(DigestFlags::ALGID_ABSENT));
        assert!(!flags.contains(DigestFlags::XOF));
        assert!(!flags.contains(DigestFlags::CUSTOM));
    }

    /// Verify combined flag containment.
    #[test]
    fn test_digest_flags_combined() {
        let flags = DigestFlags::XOF | DigestFlags::ALGID_ABSENT;
        assert!(flags.contains(DigestFlags::XOF));
        assert!(flags.contains(DigestFlags::ALGID_ABSENT));
        assert!(!flags.contains(DigestFlags::CUSTOM));
    }

    /// Verify empty flags contain nothing.
    #[test]
    fn test_digest_flags_empty() {
        let flags = DigestFlags::empty();
        assert!(!flags.contains(DigestFlags::ALGID_ABSENT));
        assert!(!flags.contains(DigestFlags::XOF));
        assert!(!flags.contains(DigestFlags::CUSTOM));
    }

    // -----------------------------------------------------------------------
    // DigestParams tests
    // -----------------------------------------------------------------------

    /// Verify from_flags with no flags set (typical SHA-2 scenario).
    #[test]
    fn test_digest_params_from_flags_no_flags() {
        let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
        assert_eq!(params.block_size, 64);
        assert_eq!(params.digest_size, 32);
        assert!(!params.xof);
        assert!(!params.algid_absent);
    }

    /// Verify from_flags with XOF + ALGID_ABSENT (SHAKE scenario).
    #[test]
    fn test_digest_params_from_flags_xof_algid() {
        let params =
            DigestParams::from_flags(168, 32, DigestFlags::XOF | DigestFlags::ALGID_ABSENT);
        assert_eq!(params.block_size, 168);
        assert_eq!(params.digest_size, 32);
        assert!(params.xof);
        assert!(params.algid_absent);
    }

    /// Verify from_flags with ALGID_ABSENT only (SHA-3 scenario).
    #[test]
    fn test_digest_params_from_flags_algid_only() {
        let params = DigestParams::from_flags(144, 28, DigestFlags::ALGID_ABSENT);
        assert_eq!(params.block_size, 144);
        assert_eq!(params.digest_size, 28);
        assert!(!params.xof);
        assert!(params.algid_absent);
    }

    /// Verify from_flags with zero sizes (NULL digest scenario).
    #[test]
    fn test_digest_params_from_flags_zero_sizes() {
        let params = DigestParams::from_flags(0, 0, DigestFlags::empty());
        assert_eq!(params.block_size, 0);
        assert_eq!(params.digest_size, 0);
    }

    /// Verify to_param_set uses correct key names matching C OSSL_DIGEST_PARAM_*.
    #[test]
    fn test_digest_params_to_param_set_keys() {
        let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
        let pset = params.to_param_set();

        // Verify all four standard keys are present
        assert!(pset.get("blocksize").is_some(), "missing 'blocksize' key");
        assert!(pset.get("size").is_some(), "missing 'size' key");
        assert!(pset.get("xof").is_some(), "missing 'xof' key");
        assert!(
            pset.get("algid-absent").is_some(),
            "missing 'algid-absent' key"
        );
    }

    /// Verify to_param_set value correctness for SHA-256–like parameters.
    #[test]
    fn test_digest_params_to_param_set_values() {
        let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
        let pset = params.to_param_set();

        assert_eq!(
            pset.get("blocksize").and_then(ParamValue::as_u64),
            Some(64),
            "blocksize should be 64"
        );
        assert_eq!(
            pset.get("size").and_then(ParamValue::as_u64),
            Some(32),
            "size should be 32"
        );
        assert_eq!(
            pset.get("xof").and_then(ParamValue::as_u64),
            Some(0),
            "xof should be 0 (false)"
        );
        assert_eq!(
            pset.get("algid-absent").and_then(ParamValue::as_u64),
            Some(0),
            "algid-absent should be 0 (false)"
        );
    }

    /// Verify to_param_set boolean encoding for XOF + ALGID_ABSENT.
    #[test]
    fn test_digest_params_to_param_set_flags_set() {
        let params =
            DigestParams::from_flags(168, 32, DigestFlags::XOF | DigestFlags::ALGID_ABSENT);
        let pset = params.to_param_set();

        assert_eq!(
            pset.get("xof").and_then(ParamValue::as_u64),
            Some(1),
            "xof should be 1 (true)"
        );
        assert_eq!(
            pset.get("algid-absent").and_then(ParamValue::as_u64),
            Some(1),
            "algid-absent should be 1 (true)"
        );
    }

    /// Verify DigestParams Clone.
    #[test]
    fn test_digest_params_clone() {
        let original = DigestParams::from_flags(64, 32, DigestFlags::ALGID_ABSENT);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // -----------------------------------------------------------------------
    // default_get_params tests
    // -----------------------------------------------------------------------

    /// Verify default_get_params returns a valid ParamSet.
    #[test]
    fn test_default_get_params_returns_ok() {
        let result = default_get_params(64, 32, DigestFlags::empty());
        assert!(result.is_ok(), "default_get_params should return Ok");
    }

    /// Verify default_get_params output matches C ossl_digest_default_get_params.
    #[test]
    fn test_default_get_params_values() {
        let pset = default_get_params(64, 32, DigestFlags::empty()).expect("should succeed");

        assert_eq!(pset.get("blocksize").and_then(ParamValue::as_u64), Some(64));
        assert_eq!(pset.get("size").and_then(ParamValue::as_u64), Some(32));
        assert_eq!(pset.get("xof").and_then(ParamValue::as_u64), Some(0));
        assert_eq!(
            pset.get("algid-absent").and_then(ParamValue::as_u64),
            Some(0)
        );
    }

    /// Verify default_get_params with XOF flags.
    #[test]
    fn test_default_get_params_xof() {
        let pset = default_get_params(168, 32, DigestFlags::XOF | DigestFlags::ALGID_ABSENT)
            .expect("should succeed");

        assert_eq!(pset.get("xof").and_then(ParamValue::as_u64), Some(1));
        assert_eq!(
            pset.get("algid-absent").and_then(ParamValue::as_u64),
            Some(1)
        );
    }

    // -----------------------------------------------------------------------
    // default_gettable_params tests
    // -----------------------------------------------------------------------

    /// Verify default_gettable_params returns all four standard keys.
    #[test]
    fn test_default_gettable_params_count() {
        let keys = default_gettable_params();
        assert_eq!(
            keys.len(),
            4,
            "should return exactly 4 gettable parameter keys"
        );
    }

    /// Verify default_gettable_params key names match C OSSL_DIGEST_PARAM_*.
    #[test]
    fn test_default_gettable_params_names() {
        let keys = default_gettable_params();
        assert!(keys.contains(&"blocksize"), "missing 'blocksize'");
        assert!(keys.contains(&"size"), "missing 'size'");
        assert!(keys.contains(&"xof"), "missing 'xof'");
        assert!(keys.contains(&"algid-absent"), "missing 'algid-absent'");
    }

    // -----------------------------------------------------------------------
    // is_fips_approved_digest tests
    // -----------------------------------------------------------------------

    /// Verify SHA-1 is FIPS approved.
    #[test]
    fn test_fips_approved_sha1() {
        assert!(is_fips_approved_digest("SHA-1"));
        assert!(is_fips_approved_digest("SHA1"));
    }

    /// Verify all SHA-2 variants are FIPS approved.
    #[test]
    fn test_fips_approved_sha2_family() {
        assert!(is_fips_approved_digest("SHA-224"));
        assert!(is_fips_approved_digest("SHA-256"));
        assert!(is_fips_approved_digest("SHA-384"));
        assert!(is_fips_approved_digest("SHA-512"));
        assert!(is_fips_approved_digest("SHA-512/224"));
        assert!(is_fips_approved_digest("SHA-512/256"));
    }

    /// Verify SHA-2 aliases are FIPS approved.
    #[test]
    fn test_fips_approved_sha2_aliases() {
        assert!(is_fips_approved_digest("SHA256"));
        assert!(is_fips_approved_digest("SHA2-256"));
        assert!(is_fips_approved_digest("SHA512"));
        assert!(is_fips_approved_digest("SHA2-512"));
    }

    /// Verify all SHA-3 variants are FIPS approved.
    #[test]
    fn test_fips_approved_sha3_family() {
        assert!(is_fips_approved_digest("SHA3-224"));
        assert!(is_fips_approved_digest("SHA3-256"));
        assert!(is_fips_approved_digest("SHA3-384"));
        assert!(is_fips_approved_digest("SHA3-512"));
    }

    /// Verify SHAKE XOFs are FIPS approved.
    #[test]
    fn test_fips_approved_shake() {
        assert!(is_fips_approved_digest("SHAKE-128"));
        assert!(is_fips_approved_digest("SHAKE128"));
        assert!(is_fips_approved_digest("SHAKE-256"));
        assert!(is_fips_approved_digest("SHAKE256"));
    }

    /// Verify case-insensitive matching for FIPS check.
    #[test]
    fn test_fips_approved_case_insensitive() {
        assert!(is_fips_approved_digest("sha-256"));
        assert!(is_fips_approved_digest("Sha3-384"));
        assert!(is_fips_approved_digest("shake-128"));
    }

    /// Verify non-FIPS algorithms are rejected.
    #[test]
    fn test_fips_not_approved_legacy() {
        assert!(!is_fips_approved_digest("MD5"));
        assert!(!is_fips_approved_digest("MD2"));
        assert!(!is_fips_approved_digest("MD4"));
        assert!(!is_fips_approved_digest("MDC2"));
        assert!(!is_fips_approved_digest("RIPEMD-160"));
        assert!(!is_fips_approved_digest("WHIRLPOOL"));
    }

    /// Verify BLAKE2 is not FIPS approved.
    #[test]
    fn test_fips_not_approved_blake2() {
        assert!(!is_fips_approved_digest("BLAKE2B-512"));
        assert!(!is_fips_approved_digest("BLAKE2S-256"));
    }

    /// Verify SM3 is not FIPS approved (Chinese national standard).
    #[test]
    fn test_fips_not_approved_sm3() {
        assert!(!is_fips_approved_digest("SM3"));
    }

    /// Verify NULL digest is not FIPS approved.
    #[test]
    fn test_fips_not_approved_null() {
        assert!(!is_fips_approved_digest("NULL"));
    }

    /// Verify KECCAK-KMAC is not FIPS approved as a standalone digest.
    #[test]
    fn test_fips_not_approved_keccak_kmac() {
        assert!(!is_fips_approved_digest("KECCAK-KMAC-128"));
        assert!(!is_fips_approved_digest("KECCAK-KMAC-256"));
    }

    /// Verify unknown names are not FIPS approved.
    #[test]
    fn test_fips_not_approved_unknown() {
        assert!(!is_fips_approved_digest("NONEXISTENT"));
        assert!(!is_fips_approved_digest(""));
    }

    // -----------------------------------------------------------------------
    // digest_name_to_nid tests
    // -----------------------------------------------------------------------

    /// Verify SHA-1 NID mapping.
    #[test]
    fn test_nid_sha1() {
        assert_eq!(digest_name_to_nid("SHA-1"), Some(64));
        assert_eq!(digest_name_to_nid("SHA1"), Some(64));
    }

    /// Verify SHA-2 NID mappings.
    #[test]
    fn test_nid_sha2_family() {
        assert_eq!(digest_name_to_nid("SHA-224"), Some(675));
        assert_eq!(digest_name_to_nid("SHA-256"), Some(672));
        assert_eq!(digest_name_to_nid("SHA-384"), Some(673));
        assert_eq!(digest_name_to_nid("SHA-512"), Some(674));
        assert_eq!(digest_name_to_nid("SHA-512/224"), Some(1094));
        assert_eq!(digest_name_to_nid("SHA-512/256"), Some(1095));
    }

    /// Verify SHA-2 alias NID mappings.
    #[test]
    fn test_nid_sha2_aliases() {
        assert_eq!(digest_name_to_nid("SHA256"), Some(672));
        assert_eq!(digest_name_to_nid("SHA2-256"), Some(672));
        assert_eq!(digest_name_to_nid("SHA512"), Some(674));
        assert_eq!(digest_name_to_nid("SHA2-512"), Some(674));
    }

    /// Verify SHA-3 NID mappings.
    #[test]
    fn test_nid_sha3_family() {
        assert_eq!(digest_name_to_nid("SHA3-224"), Some(1096));
        assert_eq!(digest_name_to_nid("SHA3-256"), Some(1097));
        assert_eq!(digest_name_to_nid("SHA3-384"), Some(1098));
        assert_eq!(digest_name_to_nid("SHA3-512"), Some(1099));
    }

    /// Verify SHAKE NID mappings.
    #[test]
    fn test_nid_shake() {
        assert_eq!(digest_name_to_nid("SHAKE-128"), Some(1100));
        assert_eq!(digest_name_to_nid("SHAKE128"), Some(1100));
        assert_eq!(digest_name_to_nid("SHAKE-256"), Some(1101));
        assert_eq!(digest_name_to_nid("SHAKE256"), Some(1101));
    }

    /// Verify MD5 and MD5-SHA1 NID mappings.
    #[test]
    fn test_nid_md5() {
        assert_eq!(digest_name_to_nid("MD5"), Some(4));
        assert_eq!(digest_name_to_nid("MD5-SHA1"), Some(114));
        assert_eq!(digest_name_to_nid("MD5SHA1"), Some(114));
    }

    /// Verify RIPEMD-160 NID mapping.
    #[test]
    fn test_nid_ripemd160() {
        assert_eq!(digest_name_to_nid("RIPEMD-160"), Some(117));
        assert_eq!(digest_name_to_nid("RIPEMD160"), Some(117));
    }

    /// Verify BLAKE2 NID mappings.
    #[test]
    fn test_nid_blake2() {
        assert_eq!(digest_name_to_nid("BLAKE2B-512"), Some(1056));
        assert_eq!(digest_name_to_nid("BLAKE2B512"), Some(1056));
        assert_eq!(digest_name_to_nid("BLAKE2S-256"), Some(1057));
        assert_eq!(digest_name_to_nid("BLAKE2S256"), Some(1057));
    }

    /// Verify SM3 NID mapping.
    #[test]
    fn test_nid_sm3() {
        assert_eq!(digest_name_to_nid("SM3"), Some(1143));
    }

    /// Verify legacy algorithm NID mappings.
    #[test]
    fn test_nid_legacy() {
        assert_eq!(digest_name_to_nid("MD2"), Some(3));
        assert_eq!(digest_name_to_nid("MD4"), Some(257));
        assert_eq!(digest_name_to_nid("MDC2"), Some(95));
        assert_eq!(digest_name_to_nid("WHIRLPOOL"), Some(804));
    }

    /// Verify NULL digest NID mapping.
    #[test]
    fn test_nid_null() {
        assert_eq!(digest_name_to_nid("NULL"), Some(0));
    }

    /// Verify case-insensitive NID lookup.
    #[test]
    fn test_nid_case_insensitive() {
        assert_eq!(digest_name_to_nid("sha-256"), Some(672));
        assert_eq!(digest_name_to_nid("Sha3-512"), Some(1099));
        assert_eq!(digest_name_to_nid("md5"), Some(4));
    }

    /// Verify unknown names return None.
    #[test]
    fn test_nid_unknown() {
        assert_eq!(digest_name_to_nid("NONEXISTENT"), None);
        assert_eq!(digest_name_to_nid(""), None);
    }
}
