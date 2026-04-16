//! Post-quantum key codecs for ML-KEM, ML-DSA, LMS, and SLH-DSA.
//!
//! Table-driven codecs supporting multiple PKCS#8 payload layouts
//! including OQS interoperability formats.
//!
//! These codec types are defined for use by encoder/decoder implementations
//! in sibling modules (der_decoder, key_encoder, text_encoder). They will be
//! fully referenced once the corresponding encoder/decoder modules are wired.

// Allow dead_code: codec types and static tables are designed for use by sibling
// encoder/decoder modules. They will be referenced once the corresponding
// submodule implementations are fully wired.
#![allow(dead_code)]

/// ML-KEM (FIPS 203) key codec configuration.
///
/// Defines OIDs, key sizes, and serialization strategy for
/// ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets.
#[derive(Debug, Clone)]
pub struct MlKemCodec {
    /// Algorithm name (e.g., "ML-KEM-768").
    pub name: &'static str,
    /// Key encapsulation key size in bytes.
    pub encapsulation_key_size: usize,
    /// Decapsulation key size in bytes.
    pub decapsulation_key_size: usize,
}

/// ML-DSA (FIPS 204) key codec configuration.
///
/// Defines OIDs, key sizes, and serialization strategy for
/// ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
#[derive(Debug, Clone)]
pub struct MlDsaCodec {
    /// Algorithm name (e.g., "ML-DSA-65").
    pub name: &'static str,
    /// Public key size in bytes.
    pub public_key_size: usize,
    /// Private key size in bytes.
    pub private_key_size: usize,
}

/// SLH-DSA (FIPS 205) key codec configuration.
///
/// Defines OIDs, key sizes, and serialization strategy for the
/// 12 SLH-DSA parameter sets (SHA2/SHAKE × 128/192/256 × f/s).
#[derive(Debug, Clone)]
pub struct SlhDsaCodec {
    /// Algorithm name (e.g., "SLH-DSA-SHA2-128f").
    pub name: &'static str,
    /// Public key size in bytes.
    pub public_key_size: usize,
    /// Private key size in bytes.
    pub private_key_size: usize,
}

/// LMS (SP 800-208) key codec configuration.
///
/// Defines OIDs and serialization strategy for LMS/HSS
/// hash-based signature public key verification.
#[derive(Debug, Clone)]
pub struct LmsCodec {
    /// Algorithm name.
    pub name: &'static str,
    /// Maximum public key size in bytes.
    pub max_public_key_size: usize,
}

/// Standard ML-KEM codec entries for all three parameter sets.
pub static ML_KEM_CODECS: &[MlKemCodec] = &[
    MlKemCodec {
        name: "ML-KEM-512",
        encapsulation_key_size: 800,
        decapsulation_key_size: 1632,
    },
    MlKemCodec {
        name: "ML-KEM-768",
        encapsulation_key_size: 1184,
        decapsulation_key_size: 2400,
    },
    MlKemCodec {
        name: "ML-KEM-1024",
        encapsulation_key_size: 1568,
        decapsulation_key_size: 3168,
    },
];

/// Standard ML-DSA codec entries for all three parameter sets.
pub static ML_DSA_CODECS: &[MlDsaCodec] = &[
    MlDsaCodec {
        name: "ML-DSA-44",
        public_key_size: 1312,
        private_key_size: 2560,
    },
    MlDsaCodec {
        name: "ML-DSA-65",
        public_key_size: 1952,
        private_key_size: 4032,
    },
    MlDsaCodec {
        name: "ML-DSA-87",
        public_key_size: 2592,
        private_key_size: 4896,
    },
];

/// Standard SLH-DSA codec entry (representative).
pub static SLH_DSA_CODECS: &[SlhDsaCodec] = &[SlhDsaCodec {
    name: "SLH-DSA-SHA2-128f",
    public_key_size: 32,
    private_key_size: 64,
}];

/// Standard LMS codec entry.
pub static LMS_CODECS: &[LmsCodec] = &[LmsCodec {
    name: "LMS",
    max_public_key_size: 60,
}];
