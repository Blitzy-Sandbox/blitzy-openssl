//! # Shared Digest Infrastructure
//!
//! Common types, flags, and utilities shared across all digest provider
//! implementations. Translates `providers/implementations/digests/digestcommon.c`.
//!
//! ## Key Types
//!
//! - [`DigestFlags`] — Bitflags for algorithm properties (XOF, ALGID_ABSENT, etc.)
//! - [`DigestParams`] — Typed parameter struct for digest configuration
//! - [`DigestContextOps`] — Trait for common context operations
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use bitflags::bitflags;
use openssl_common::error::ProviderResult;
use openssl_common::param::ParamSet;

// =============================================================================
// DigestFlags — Bitflags for Digest Algorithm Properties
// =============================================================================

bitflags! {
    /// Bitflags describing properties of a digest algorithm.
    ///
    /// These flags map to the C preprocessor constants in `digestcommon.c`:
    /// - `PROV_DIGEST_FLAG_ALGID_ABSENT` → [`DigestFlags::ALGID_ABSENT`]
    /// - `PROV_DIGEST_FLAG_XOF` → [`DigestFlags::XOF`]
    /// - `PROV_DIGEST_FLAG_CUSTOM` → [`DigestFlags::CUSTOM`]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DigestFlags: u32 {
        /// The algorithm ID is absent in the AlgorithmIdentifier encoding.
        /// When set, the AlgorithmIdentifier uses a NULL OID.
        /// Equivalent to `PROV_DIGEST_FLAG_ALGID_ABSENT` in C.
        const ALGID_ABSENT = 0x0001;

        /// Extendable Output Function (XOF) — the digest can produce
        /// variable-length output (e.g., SHAKE128, SHAKE256, cSHAKE).
        /// Equivalent to `PROV_DIGEST_FLAG_XOF` in C.
        const XOF = 0x0002;

        /// Custom digest algorithm requiring non-standard initialization
        /// or parameterization (e.g., BLAKE2 with key, cSHAKE with
        /// customization string).
        /// Equivalent to a provider-specific custom flag.
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
/// # C Mapping
///
/// | Rust Field       | C OSSL_PARAM Key           |
/// |------------------|----------------------------|
/// | `block_size`     | `OSSL_DIGEST_PARAM_BLOCK_SIZE` |
/// | `digest_size`    | `OSSL_DIGEST_PARAM_SIZE`   |
/// | `xof`            | `OSSL_DIGEST_PARAM_XOF`    |
/// | `algid_absent`   | `OSSL_DIGEST_PARAM_ALGID_ABSENT` |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestParams {
    /// Block size in bytes (e.g., 64 for SHA-256, 128 for SHA-512).
    pub block_size: usize,

    /// Output digest size in bytes (e.g., 32 for SHA-256, 0 for NULL).
    pub digest_size: usize,

    /// Whether this digest is an extendable output function (XOF).
    pub xof: bool,

    /// Whether the algorithm ID is absent in `AlgorithmIdentifier` encoding.
    pub algid_absent: bool,
}

impl DigestParams {
    /// Creates a new `DigestParams` from the given sizes and [`DigestFlags`].
    ///
    /// # Arguments
    ///
    /// * `block_size` — Block size in bytes
    /// * `digest_size` — Output digest size in bytes
    /// * `flags` — Bitflags controlling XOF and `ALGID_ABSENT` properties
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
    /// This is used when the provider framework needs to pass digest
    /// parameters through the generic `OSSL_PARAM`-equivalent interface.
    pub fn to_param_set(&self) -> ParamSet {
        use openssl_common::param::ParamValue;
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(self.block_size as u64));
        params.set("digest_size", ParamValue::UInt64(self.digest_size as u64));
        params.set("xof", ParamValue::UInt64(u64::from(self.xof)));
        params.set("algid_absent", ParamValue::UInt64(u64::from(self.algid_absent)));
        params
    }
}

// =============================================================================
// DigestContextOps — Common Context Operations Trait
// =============================================================================

/// Trait for common digest context operations.
///
/// Provides access to digest parameters and flags from a context instance.
/// Implemented by all digest context types alongside [`DigestContext`].
pub trait DigestContextOps {
    /// Returns the digest parameters for this context.
    fn params(&self) -> &DigestParams;

    /// Returns the digest flags for this context.
    fn flags(&self) -> DigestFlags;
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Returns the default digest parameters for a named algorithm.
///
/// Used by provider implementations to respond to `get_params` queries
/// without duplicating parameter construction logic.
///
/// # Arguments
///
/// * `name` — Algorithm name (e.g., "SHA-256", "MD5")
/// * `block_size` — Block size in bytes
/// * `digest_size` — Output size in bytes
/// * `flags` — Algorithm flags
pub fn default_get_params(
    _name: &str,
    block_size: usize,
    digest_size: usize,
    flags: DigestFlags,
) -> ProviderResult<ParamSet> {
    let params = DigestParams::from_flags(block_size, digest_size, flags);
    Ok(params.to_param_set())
}

/// Returns the list of parameter keys that a digest provider can supply
/// via `get_params`.
///
/// This is the gettable-params analogue: it tells the caller which
/// parameter names are available for querying.
pub fn default_gettable_params() -> Vec<&'static str> {
    vec![
        "block_size",
        "digest_size",
        "xof",
        "algid_absent",
    ]
}

/// Checks whether the named digest algorithm is FIPS-approved.
///
/// Returns `true` for algorithms approved under FIPS 140-3 (SHA-1,
/// SHA-2 family, SHA-3 family, SHAKE). Returns `false` for legacy
/// algorithms (MD5, MD2, MD4, MDC2, RIPEMD-160, Whirlpool, BLAKE2).
///
/// # C Mapping
///
/// Replaces the per-algorithm `PROV_DIGEST_FLAG_FIPS` check in the
/// FIPS provider's algorithm table.
pub fn is_fips_approved_digest(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "SHA-1" | "SHA1"
            | "SHA-224" | "SHA224" | "SHA2-224"
            | "SHA-256" | "SHA256" | "SHA2-256"
            | "SHA-384" | "SHA384" | "SHA2-384"
            | "SHA-512" | "SHA512" | "SHA2-512"
            | "SHA-512/224" | "SHA512/224" | "SHA2-512/224"
            | "SHA-512/256" | "SHA512/256" | "SHA2-512/256"
            | "SHA3-224"
            | "SHA3-256"
            | "SHA3-384"
            | "SHA3-512"
            | "SHAKE-128" | "SHAKE128"
            | "SHAKE-256" | "SHAKE256"
    )
}

/// Maps a digest algorithm name to its numeric identifier (NID equivalent).
///
/// Returns `None` for unknown or unsupported names. The NID values
/// correspond to the OpenSSL NID constants used in ASN.1 and OID mapping.
///
/// # C Mapping
///
/// Replaces `OBJ_sn2nid()` / `OBJ_ln2nid()` lookups for digest names.
pub fn digest_name_to_nid(name: &str) -> Option<u32> {
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
        // SHAKE
        "SHAKE-128" | "SHAKE128" => Some(1100),
        "SHAKE-256" | "SHAKE256" => Some(1101),
        // MD5
        "MD5" => Some(4),
        // MD5-SHA1 (composite)
        "MD5-SHA1" | "MD5SHA1" => Some(114),
        // RIPEMD-160
        "RIPEMD-160" | "RIPEMD160" => Some(117),
        // BLAKE2
        "BLAKE2B-512" | "BLAKE2B512" => Some(1056),
        "BLAKE2S-256" | "BLAKE2S256" => Some(1057),
        // SM3
        "SM3" => Some(1143),
        // Legacy
        "MD2" => Some(3),
        "MD4" => Some(257),
        "MDC2" => Some(95),
        "WHIRLPOOL" => Some(804),
        // NULL
        "NULL" => Some(0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_flags_algid_absent() {
        let flags = DigestFlags::ALGID_ABSENT;
        assert!(flags.contains(DigestFlags::ALGID_ABSENT));
        assert!(!flags.contains(DigestFlags::XOF));
    }

    #[test]
    fn test_digest_flags_xof() {
        let flags = DigestFlags::XOF | DigestFlags::ALGID_ABSENT;
        assert!(flags.contains(DigestFlags::XOF));
        assert!(flags.contains(DigestFlags::ALGID_ABSENT));
    }

    #[test]
    fn test_digest_params_from_flags() {
        let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
        assert_eq!(params.block_size, 64);
        assert_eq!(params.digest_size, 32);
        assert!(!params.xof);
        assert!(!params.algid_absent);
    }

    #[test]
    fn test_digest_params_xof_from_flags() {
        let params = DigestParams::from_flags(
            168,
            32,
            DigestFlags::XOF | DigestFlags::ALGID_ABSENT,
        );
        assert!(params.xof);
        assert!(params.algid_absent);
    }

    #[test]
    fn test_digest_params_to_param_set() {
        let params = DigestParams::from_flags(64, 32, DigestFlags::empty());
        let pset = params.to_param_set();
        assert!(pset.get("block_size").is_some());
    }

    #[test]
    fn test_is_fips_approved_sha256() {
        assert!(is_fips_approved_digest("SHA-256"));
        assert!(is_fips_approved_digest("sha-256"));
    }

    #[test]
    fn test_is_fips_not_approved_md5() {
        assert!(!is_fips_approved_digest("MD5"));
    }

    #[test]
    fn test_digest_name_to_nid_sha256() {
        assert_eq!(digest_name_to_nid("SHA-256"), Some(672));
    }

    #[test]
    fn test_digest_name_to_nid_unknown() {
        assert_eq!(digest_name_to_nid("NONEXISTENT"), None);
    }
}
