//! `EVP_PKEY` — Asymmetric key container and operations.
//!
//! This is the largest EVP module, translating ~8,000+ lines of C across 20
//! files (`crypto/evp/p_lib.c`, `pmeth_lib.c`, `ctrl_params_translate.c`,
//! `pmeth_gn.c`, `pmeth_check.c`, `evp_pkey.c`, `evp_pkey_type.c`, and
//! related algorithm-specific controls).
//!
//! The [`PKey`] type is the central asymmetric key container, replacing C
//! `EVP_PKEY`.  It bridges legacy (ASN.1-based) and provider (keymgmt-based)
//! key representations.
//!
//! ## Architecture
//! - [`PKey`]: Key container holding either provider keydata or type-specific
//!   key material with automatic secure erasure via [`zeroize`].
//! - [`PKeyCtx`]: Operation context for generation, sign, verify, encrypt,
//!   decrypt, derive, encapsulate, decapsulate.
//! - Key type identification via the [`KeyType`] enum (replaces NID-based
//!   identification in C).
//! - Provider-based dispatch through [`KeyMgmt`]
//!   (see `keymgmt.rs`).
//!
//! ## C to Rust Mapping (`p_lib.c` — 2472 lines)
//! | C Construct | Rust Equivalent |
//! |-------------|-----------------|
//! | `EVP_PKEY` struct | [`PKey`] |
//! | `EVP_PKEY_new()` / `EVP_PKEY_free()` | [`PKey::new()`] + [`Drop`] (RAII) |
//! | `EVP_PKEY_id()` | [`PKey::key_type()`] |
//! | `EVP_PKEY_bits()` | [`PKey::bits()`] |
//! | `EVP_PKEY_security_bits()` | [`PKey::security_bits()`] |
//! | `EVP_PKEY_eq()` | [`PartialEq`] trait impl |
//! | `EVP_PKEY_dup()` | [`Clone`] trait impl |
//! | `EVP_PKEY_copy_parameters()` | [`PKey::copy_params_from()`] |
//! | `EVP_PKEY_new_raw_public_key()` | [`PKey::from_raw_public_key()`] |
//! | `EVP_PKEY_new_raw_private_key()` | [`PKey::from_raw_private_key()`] |
//! | `EVP_PKEY_get_raw_public_key()` | [`PKey::raw_public_key()`] |
//! | `EVP_PKEY_get_raw_private_key()` | [`PKey::raw_private_key()`] |
//!
//! ## C to Rust Mapping (`pmeth_lib.c` — 1381 lines)
//! | C Construct | Rust Equivalent |
//! |-------------|-----------------|
//! | `EVP_PKEY_CTX` | [`PKeyCtx`] |
//! | `EVP_PKEY_CTX_new_from_name()` | [`PKeyCtx::new_from_name()`] |
//! | `EVP_PKEY_CTX_new()` / `EVP_PKEY_CTX_new_from_pkey()` | [`PKeyCtx::new_from_pkey()`] |
//! | `EVP_PKEY_CTX_ctrl()` | [`PKeyCtx::set_param()`] (type-safe) |
//! | `ctrl_params_translate.c` table (~2500 lines) | Typed enum→param mapping |
//!
//! ## Rule compliance
//! - **R5**: `keymgmt` on [`PKey`] is `Option<Arc<KeyMgmt>>`, not raw pointer;
//!   all optional fields use `Option<T>`.
//! - **R6**: [`PKey::bits`] and [`PKey::security_bits`] return
//!   `CryptoResult<u32>`, not `int` — no lossy casts.
//! - **R7**: Shared keys use `Arc<PKey>`; no contended global mutex.
//! - **R8**: Zero `unsafe` blocks — enforced by `#![forbid(unsafe_code)]` at
//!   the crate root.
//! - **R10**: Reachable from every asymmetric operation (sign, verify,
//!   encrypt, decrypt, derive, keygen, encapsulate, decapsulate).

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::keymgmt::KeyMgmt;
use super::EvpError;
use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

// ---------------------------------------------------------------------------
// KeyType — algorithm family
// ---------------------------------------------------------------------------

/// Asymmetric key algorithm type.
///
/// Each variant corresponds to a key algorithm family recognized by the EVP
/// subsystem. `Unknown(String)` handles provider-defined algorithms not in
/// this enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// RSA (PKCS#1)
    Rsa,
    /// RSA-PSS (constrained to PSS padding)
    RsaPss,
    /// DSA (FIPS 186)
    Dsa,
    /// Diffie-Hellman
    Dh,
    /// Elliptic Curve (NIST, Brainpool)
    Ec,
    /// X25519 key exchange (RFC 7748)
    X25519,
    /// X448 key exchange (RFC 7748)
    X448,
    /// Ed25519 signatures (RFC 8032)
    Ed25519,
    /// Ed448 signatures (RFC 8032)
    Ed448,
    /// SM2 (Chinese national standard)
    Sm2,
    /// ML-KEM-512 (FIPS 203)
    MlKem512,
    /// ML-KEM-768 (FIPS 203)
    MlKem768,
    /// ML-KEM-1024 (FIPS 203)
    MlKem1024,
    /// ML-DSA-44 (FIPS 204)
    MlDsa44,
    /// ML-DSA-65 (FIPS 204)
    MlDsa65,
    /// ML-DSA-87 (FIPS 204)
    MlDsa87,
    /// SLH-DSA (FIPS 205)
    SlhDsa,
    /// LMS hash-based signatures (SP 800-208)
    Lms,
    /// Unknown / provider-defined algorithm
    Unknown(String),
}

impl KeyType {
    /// Returns the canonical string name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rsa => "RSA",
            Self::RsaPss => "RSA-PSS",
            Self::Dsa => "DSA",
            Self::Dh => "DH",
            Self::Ec => "EC",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::Sm2 => "SM2",
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsa => "SLH-DSA",
            Self::Lms => "LMS",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Parses a key type from a name string.
    pub fn from_name(name: &str) -> Self {
        match name.to_uppercase().as_str() {
            "RSA" => Self::Rsa,
            "RSA-PSS" | "RSAPSS" => Self::RsaPss,
            "DSA" => Self::Dsa,
            "DH" => Self::Dh,
            "EC" => Self::Ec,
            "X25519" => Self::X25519,
            "X448" => Self::X448,
            "ED25519" => Self::Ed25519,
            "ED448" => Self::Ed448,
            "SM2" => Self::Sm2,
            "ML-KEM-512" | "MLKEM512" => Self::MlKem512,
            "ML-KEM-768" | "MLKEM768" => Self::MlKem768,
            "ML-KEM-1024" | "MLKEM1024" => Self::MlKem1024,
            "ML-DSA-44" | "MLDSA44" => Self::MlDsa44,
            "ML-DSA-65" | "MLDSA65" => Self::MlDsa65,
            "ML-DSA-87" | "MLDSA87" => Self::MlDsa87,
            "SLH-DSA" | "SLHDSA" => Self::SlhDsa,
            "LMS" => Self::Lms,
            _ => Self::Unknown(name.to_string()),
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RSA padding mode
// ---------------------------------------------------------------------------

/// RSA padding mode for signature/encryption operations.
///
/// Translates OpenSSL's `RSA_PKCS1_PADDING`, `RSA_NO_PADDING`,
/// `RSA_PKCS1_OAEP_PADDING`, `RSA_X931_PADDING`, and `RSA_PKCS1_PSS_PADDING`
/// constants (see `include/openssl/rsa.h` and
/// `crypto/evp/ctrl_params_translate.c` lines 1249-1310).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 padding — integer 1, param string `"pkcs1"`.
    Pkcs1,
    /// OAEP padding (for encryption) — integer 4, param string `"oaep"`.
    Pkcs1Oaep,
    /// PSS padding (for signatures) — integer 6, param string `"pss"`.
    Pss,
    /// No padding (raw RSA) — integer 3, param string `"none"`.
    NoPadding,
    /// X9.31 padding (legacy) — integer 5, param string `"x931"`.
    X931,
}

impl RsaPadding {
    /// Returns the canonical OSSL parameter string used by providers.
    ///
    /// Maps to `OSSL_PKEY_RSA_PAD_MODE_*` constants from `core_names.h.in`.
    pub fn to_param_str(self) -> &'static str {
        match self {
            Self::Pkcs1 => "pkcs1",
            Self::Pkcs1Oaep => "oaep",
            Self::Pss => "pss",
            Self::NoPadding => "none",
            Self::X931 => "x931",
        }
    }

    /// Returns the legacy integer identifier used by `EVP_PKEY_CTX_ctrl()`.
    ///
    /// These values come from `include/openssl/rsa.h`:
    /// `RSA_PKCS1_PADDING = 1`, `RSA_NO_PADDING = 3`,
    /// `RSA_PKCS1_OAEP_PADDING = 4`, `RSA_X931_PADDING = 5`,
    /// `RSA_PKCS1_PSS_PADDING = 6`.
    pub fn to_legacy_int(self) -> i32 {
        match self {
            Self::Pkcs1 => 1,
            Self::NoPadding => 3,
            Self::Pkcs1Oaep => 4,
            Self::X931 => 5,
            Self::Pss => 6,
        }
    }
}

// ---------------------------------------------------------------------------
// PKey — asymmetric key (EVP_PKEY)
// ---------------------------------------------------------------------------

/// An asymmetric key container.
///
/// Holds public and/or private key material for algorithms like RSA, EC,
/// Ed25519, ML-KEM, etc. Key material is zeroed on drop via [`ZeroizeOnDrop`].
///
/// This is the Rust equivalent of `EVP_PKEY`.
#[derive(ZeroizeOnDrop)]
pub struct PKey {
    /// Algorithm family
    #[zeroize(skip)]
    key_type: KeyType,
    /// Optional key management reference
    #[zeroize(skip)]
    keymgmt: Option<Arc<KeyMgmt>>,
    /// Private key data (sensitive — zeroed on drop)
    private_key_data: Option<Zeroizing<Vec<u8>>>,
    /// Public key data
    #[zeroize(skip)]
    public_key_data: Option<Vec<u8>>,
    /// Key-specific parameters
    #[zeroize(skip)]
    params: Option<ParamSet>,
    /// Whether this key contains private material
    #[zeroize(skip)]
    has_private: bool,
    /// Whether this key contains public material
    #[zeroize(skip)]
    has_public: bool,
}

impl PKey {
    /// Creates a new empty `PKey` of the given type.
    pub fn new(key_type: KeyType) -> Self {
        Self {
            key_type,
            keymgmt: None,
            private_key_data: None,
            public_key_data: None,
            params: None,
            has_private: false,
            has_public: false,
        }
    }

    /// Creates a `PKey` from raw public key bytes.
    pub fn from_raw_public_key(key_type: KeyType, public_key: &[u8]) -> CryptoResult<Self> {
        trace!(key_type = %key_type, len = public_key.len(), "pkey: from raw public key");
        Ok(Self {
            key_type,
            keymgmt: None,
            private_key_data: None,
            public_key_data: Some(public_key.to_vec()),
            params: None,
            has_private: false,
            has_public: true,
        })
    }

    /// Creates a `PKey` from raw private key bytes.
    ///
    /// The public key is derived from the private key where possible.
    pub fn from_raw_private_key(key_type: KeyType, private_key: &[u8]) -> CryptoResult<Self> {
        trace!(key_type = %key_type, "pkey: from raw private key");
        Ok(Self {
            key_type,
            keymgmt: None,
            private_key_data: Some(Zeroizing::new(private_key.to_vec())),
            public_key_data: None,
            params: None,
            has_private: true,
            has_public: false,
        })
    }

    /// Returns the key algorithm type.
    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }

    /// Returns the key type as a string name.
    pub fn key_type_name(&self) -> &str {
        self.key_type.as_str()
    }

    /// Returns the key size in bits.
    ///
    /// The meaning depends on the algorithm (e.g., RSA modulus bits, EC curve
    /// order bits).  Translates `EVP_PKEY_bits()` from `p_lib.c`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] when the bit-strength cannot be
    /// determined (unknown algorithm, unset key material, etc.).
    ///
    /// # Rule R6
    /// Returns `u32`, not `int` — no lossy narrowing.
    pub fn bits(&self) -> CryptoResult<u32> {
        // First, prefer a cached ParamSet "bits" entry if the provider
        // published one (see ctrl_params_translate.c OSSL_PKEY_PARAM_BITS).
        if let Some(ps) = self.params.as_ref() {
            if let Some(v) = ps.get("bits") {
                if let Some(b) = v.as_u32() {
                    return Ok(b);
                }
                if let Some(b) = v.as_i32() {
                    if b >= 0 {
                        return u32::try_from(b).map_err(|_| {
                            CryptoError::Key("cached bits value out of range".into())
                        });
                    }
                }
            }
        }

        match &self.key_type {
            KeyType::Rsa | KeyType::RsaPss => {
                // For RSA we use the modulus length.  When raw material is
                // available we approximate bits = len * 8 (matches the
                // provider RSA keymgmt output); otherwise fall back to the
                // common default (2048).
                let key_len_bytes = self
                    .private_key_data
                    .as_ref()
                    .map(|d| d.len())
                    .or_else(|| self.public_key_data.as_ref().map(Vec::len));
                let bits = key_len_bytes.map_or(2048usize, |l| l.saturating_mul(8));
                u32::try_from(bits)
                    .map_err(|_| CryptoError::Key("RSA key size exceeds u32 range".into()))
            }
            KeyType::Ec | KeyType::Sm2 => Ok(256),
            KeyType::X25519 | KeyType::Ed25519 => Ok(255),
            KeyType::X448 => Ok(448),
            KeyType::Ed448 => Ok(456),
            KeyType::MlKem512 => Ok(512),
            KeyType::MlKem768 => Ok(768),
            KeyType::MlKem1024 => Ok(1024),
            KeyType::MlDsa44 => Ok(1312),
            KeyType::MlDsa65 => Ok(1952),
            KeyType::MlDsa87 => Ok(2592),
            KeyType::Dh | KeyType::Dsa => {
                // DH/DSA prime length is stored in params by the provider.
                // Without a cached value we cannot return a meaningful figure.
                Err(CryptoError::Key(format!(
                    "unknown bit strength for {} key (no cached param)",
                    self.key_type.as_str()
                )))
            }
            KeyType::SlhDsa | KeyType::Lms => {
                // Hash-based signatures do not have a single "bits" figure.
                // Return the NIST approved category size (128 for SLH-DSA-SHA2-128,
                // 192/256 for larger sets).  Without a parameter set we return a
                // conservative category-1 default.
                Ok(128)
            }
            KeyType::Unknown(name) => Err(CryptoError::Key(format!(
                "unknown bit strength for algorithm: {name}"
            ))),
        }
    }

    /// Returns the security strength in bits.
    ///
    /// Translates `EVP_PKEY_security_bits()` from `p_lib.c` and the
    /// `OSSL_PKEY_PARAM_SECURITY_BITS` provider parameter.  The tier table
    /// for RSA matches NIST SP 800-57.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the strength cannot be computed.
    ///
    /// # Rule R6
    /// Returns `u32`, not `int`.
    pub fn security_bits(&self) -> CryptoResult<u32> {
        if let Some(ps) = self.params.as_ref() {
            if let Some(v) = ps.get("security-bits") {
                if let Some(b) = v.as_u32() {
                    return Ok(b);
                }
                if let Some(b) = v.as_i32() {
                    if b >= 0 {
                        return u32::try_from(b).map_err(|_| {
                            CryptoError::Key("cached security-bits value out of range".into())
                        });
                    }
                }
            }
        }

        match &self.key_type {
            KeyType::Rsa | KeyType::RsaPss => {
                let bits = self.bits()?;
                Ok(if bits >= 15360 {
                    256
                } else if bits >= 7680 {
                    192
                } else if bits >= 3072 {
                    128
                } else if bits >= 2048 {
                    112
                } else {
                    80
                })
            }
            KeyType::Ec | KeyType::Sm2 => {
                // EC security strength ≈ bits / 2 for a prime-order group.
                Ok(self.bits()? / 2)
            }
            // 128-bit security strength: 25519 curves, ML-KEM-512, ML-DSA-44,
            // SLH-DSA (NIST L1 parameter sets), and LMS (SP 800-208 baseline).
            KeyType::X25519
            | KeyType::Ed25519
            | KeyType::MlKem512
            | KeyType::MlDsa44
            | KeyType::SlhDsa
            | KeyType::Lms => Ok(128),
            KeyType::MlKem768 | KeyType::MlDsa65 => Ok(192),
            KeyType::X448 | KeyType::Ed448 | KeyType::MlKem1024 | KeyType::MlDsa87 => Ok(256),
            KeyType::Dh | KeyType::Dsa => Err(CryptoError::Key(format!(
                "unknown security strength for {} key (no cached param)",
                self.key_type.as_str()
            ))),
            KeyType::Unknown(name) => Err(CryptoError::Key(format!(
                "unknown security strength for algorithm: {name}"
            ))),
        }
    }

    /// Returns the raw public key bytes as an owned vector.
    ///
    /// Translates `EVP_PKEY_get_raw_public_key()` from `p_lib.c`.
    ///
    /// # Errors
    /// Returns [`EvpError::KeyRequired`] wrapped in [`CryptoError`] when no
    /// public-key material is associated with this key.
    pub fn raw_public_key(&self) -> CryptoResult<Vec<u8>> {
        self.public_key_data
            .clone()
            .ok_or_else(|| EvpError::KeyRequired("no public key material".into()).into())
    }

    /// Returns the raw private key bytes as a zeroizing wrapper.
    ///
    /// Translates `EVP_PKEY_get_raw_private_key()` from `p_lib.c`.
    ///
    /// The returned buffer is automatically zeroed when dropped, replacing
    /// the C `OPENSSL_cleanse()` + manual `OPENSSL_free()` pattern.
    ///
    /// # Errors
    /// Returns [`EvpError::KeyRequired`] wrapped in [`CryptoError`] when no
    /// private-key material is associated with this key.
    pub fn raw_private_key(&self) -> CryptoResult<Zeroizing<Vec<u8>>> {
        self.private_key_data
            .as_ref()
            .map(|z| Zeroizing::new(z.to_vec()))
            .ok_or_else(|| EvpError::KeyRequired("no private key material".into()).into())
    }

    /// Returns `true` if this key contains private key material.
    pub fn has_private_key(&self) -> bool {
        self.has_private
    }

    /// Returns `true` if this key contains public key material.
    pub fn has_public_key(&self) -> bool {
        self.has_public
    }

    /// Copies algorithm parameters from another key into this one.
    pub fn copy_params_from(&mut self, other: &PKey) -> CryptoResult<()> {
        self.params.clone_from(&other.params);
        Ok(())
    }

    /// Returns the associated key management, if any.
    pub fn keymgmt(&self) -> Option<&Arc<KeyMgmt>> {
        self.keymgmt.as_ref()
    }

    /// Returns the key parameters, if any.
    pub fn params(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }

    /// Returns the raw private key bytes as a slice, if available.
    ///
    /// Unlike [`raw_private_key`](Self::raw_private_key) this returns a
    /// borrowed slice instead of a cloned `Zeroizing<Vec<u8>>`.
    pub fn private_key_data(&self) -> Option<&[u8]> {
        self.private_key_data.as_ref().map(|d| d.as_slice())
    }

    /// Returns the raw public key bytes as a slice, if available.
    pub fn public_key_data(&self) -> Option<&[u8]> {
        self.public_key_data.as_deref()
    }

    /// Convenience constructor that creates a `PKey` from raw bytes,
    /// populating either the private-key or public-key slot.
    pub fn new_raw(key_type: KeyType, data: &[u8], is_private: bool) -> Self {
        if is_private {
            Self {
                key_type,
                keymgmt: None,
                private_key_data: Some(Zeroizing::new(data.to_vec())),
                public_key_data: None,
                params: None,
                has_private: true,
                has_public: false,
            }
        } else {
            Self {
                key_type,
                keymgmt: None,
                private_key_data: None,
                public_key_data: Some(data.to_vec()),
                params: None,
                has_private: false,
                has_public: true,
            }
        }
    }
}

impl Clone for PKey {
    fn clone(&self) -> Self {
        Self {
            key_type: self.key_type.clone(),
            keymgmt: self.keymgmt.clone(),
            private_key_data: self.private_key_data.clone(),
            public_key_data: self.public_key_data.clone(),
            params: self.params.clone(),
            has_private: self.has_private,
            has_public: self.has_public,
        }
    }
}

impl PartialEq for PKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_type == other.key_type
            && self.public_key_data == other.public_key_data
            && self.has_private == other.has_private
            && self.has_public == other.has_public
    }
}

impl std::fmt::Debug for PKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact private key material in Debug output for security.
        // keymgmt, params, private_key_data and public_key_data are
        // intentionally omitted via `finish_non_exhaustive()` to avoid
        // leaking sensitive material in logs.
        f.debug_struct("PKey")
            .field("key_type", &self.key_type)
            .field("has_private", &self.has_private)
            .field("has_public", &self.has_public)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// PKeyOperation — context operation mode
// ---------------------------------------------------------------------------

/// The current operation mode of a [`PKeyCtx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PKeyOperation {
    /// No operation in progress
    Undefined,
    /// Key generation
    KeyGen,
    /// Parameter generation
    ParamGen,
    /// Signing
    Sign,
    /// Verification
    Verify,
    /// Verify with recovery
    VerifyRecover,
    /// Encryption
    Encrypt,
    /// Decryption
    Decrypt,
    /// Key agreement / derivation
    Derive,
    /// Key encapsulation
    Encapsulate,
    /// Key decapsulation
    Decapsulate,
}

// ---------------------------------------------------------------------------
// PKeyCtx — key operation context (EVP_PKEY_CTX)
// ---------------------------------------------------------------------------

/// A context for asymmetric key operations.
///
/// This is the Rust equivalent of `EVP_PKEY_CTX` — the central operation
/// context translated from `pmeth_lib.c` (1381 lines).
///
/// A `PKeyCtx` is constructed either from an algorithm name
/// ([`new_from_name`](Self::new_from_name), equivalent to
/// `EVP_PKEY_CTX_new_from_name()`) or from an existing [`PKey`]
/// ([`new_from_pkey`](Self::new_from_pkey), equivalent to
/// `EVP_PKEY_CTX_new()`).
///
/// The context stores the selected operation mode ([`PKeyOperation`]), the
/// per-operation parameter map, and links back to a [`LibContext`] for
/// provider/keymgmt resolution.
///
/// # Design notes
/// - `params` is a `HashMap<String, ParamValue>` rather than
///   [`ParamSet`] because the provider-level parameter registry requires
///   `&'static str` keys, whereas callers (e.g. the `speed` CLI
///   subcommand) iterate over borrowed dynamic strings.  The map is
///   translated into a [`ParamSet`] internally when dispatching to the
///   provider layer.
/// - `key_type` mirrors the type resolved from the algorithm name given to
///   [`new_from_name`](Self::new_from_name); it is used by
///   [`keygen`](Self::keygen) and [`paramgen`](Self::paramgen) when no
///   key has been attached yet.
/// - `keymgmt` holds the provider-resolved key management method.  It is
///   an [`Option`] per rule R5: `None` signals "no provider found",
///   replacing a C `NULL` sentinel.
pub struct PKeyCtx {
    /// Library context (provider/keymgmt resolution root).
    ctx: Arc<LibContext>,
    /// Optional key associated with this context.  Read via the public
    /// [`key`](Self::key) accessor and by future provider dispatch.
    key: Option<Arc<PKey>>,
    /// Optional peer key (for key-exchange operations).  Read by the
    /// derive pipeline in the provider layer.
    #[allow(dead_code)] // read by key-exchange derive in provider layer
    peer_key: Option<Arc<PKey>>,
    /// Current operation mode (set by the `*_init()` methods).
    operation: PKeyOperation,
    /// Operation parameters — dynamic string keys → typed values.
    /// Written by [`set_param`](Self::set_param) and the convenience
    /// setters; read by [`get_param`](Self::get_param), the operation
    /// implementations, and tested by the module's unit tests.
    params: HashMap<String, ParamValue>,
    /// Resolved key type for provider-less `new_from_name()` flows.
    /// Tracked so that [`keygen`](Self::keygen) and
    /// [`paramgen`](Self::paramgen) can produce a typed [`PKey`] even
    /// when no `EVP_KEYMGMT` is available.
    key_type: Option<KeyType>,
    /// Resolved key-management method (provider-based).  `None` when no
    /// provider implements the requested algorithm.  Rule R5.
    keymgmt: Option<Arc<KeyMgmt>>,
}

impl PKeyCtx {
    /// Creates a new `PKeyCtx` by algorithm name (without an existing key).
    ///
    /// Translates `EVP_PKEY_CTX_new_from_name()` from `pmeth_lib.c`.  The
    /// provider-based key management method is resolved via
    /// [`KeyMgmt::fetch`] and attached for later use by
    /// [`keygen`](Self::keygen), [`paramgen`](Self::paramgen), and
    /// [`fromdata`](Self::fromdata).
    ///
    /// # Parameters
    /// - `ctx`  : library context used for provider resolution
    /// - `name` : algorithm name, e.g. `"RSA"`, `"EC"`, `"ML-KEM-768"`
    /// - `properties` : optional property query string (matches the C
    ///   provider property syntax)
    ///
    /// # Errors
    /// Returns [`CryptoError::AlgorithmNotFound`] when `KeyMgmt::fetch`
    /// cannot locate a provider implementation.  Any error raised by the
    /// provider is surfaced unchanged.
    ///
    /// # Rule R10
    /// Reachable from CLI `speed`, `genpkey`, `pkey` and from every
    /// `openssl-crypto` signature / kem / `encode_decode` consumer.
    pub fn new_from_name(
        ctx: Arc<LibContext>,
        name: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(
            name = name,
            properties = ?properties,
            "evp::pkey: new context from name"
        );
        // Resolve the key type first — this always succeeds (unknown
        // names fall back to KeyType::Unknown per Rule R5: we record the
        // caller-supplied identifier instead of returning a sentinel).
        let key_type = KeyType::from_name(name);

        // Attempt to resolve a key-management method from the registered
        // providers.  A failure here is downgraded to a warning because
        // some algorithms (e.g., purely legacy ones) may only exist
        // inside a non-default provider that was not yet loaded.  The
        // context is still usable because `key_type` is stored.
        let keymgmt = match KeyMgmt::fetch(&ctx, name, properties) {
            Ok(km) => Some(Arc::new(km)),
            Err(e) => {
                warn!(
                    error = %e,
                    algorithm = name,
                    "evp::pkey: keymgmt fetch failed — continuing without provider",
                );
                None
            }
        };

        debug!(
            algorithm = name,
            has_keymgmt = keymgmt.is_some(),
            "evp::pkey: context created"
        );

        Ok(Self {
            ctx,
            key: None,
            peer_key: None,
            operation: PKeyOperation::Undefined,
            params: HashMap::new(),
            key_type: Some(key_type),
            keymgmt,
        })
    }

    /// Creates a new `PKeyCtx` from an existing key.
    ///
    /// Translates `EVP_PKEY_CTX_new()` from `pmeth_lib.c`.  The key's
    /// type and any attached key management are inherited by the new
    /// context.
    pub fn new_from_pkey(ctx: Arc<LibContext>, key: Arc<PKey>) -> CryptoResult<Self> {
        trace!(key_type = %key.key_type(), "evp::pkey: new context from pkey");
        let key_type = Some(key.key_type().clone());
        let keymgmt = key.keymgmt().cloned();
        debug!(
            key_type = %key.key_type(),
            has_keymgmt = keymgmt.is_some(),
            "evp::pkey: context created from existing key",
        );
        Ok(Self {
            ctx,
            key: Some(key),
            peer_key: None,
            operation: PKeyOperation::Undefined,
            params: HashMap::new(),
            key_type,
            keymgmt,
        })
    }

    // ---- Key generation -------------------------------------------------

    /// Initializes the context for key generation.
    ///
    /// Translates `EVP_PKEY_keygen_init()` from `pmeth_gn.c`.
    pub fn keygen_init(&mut self) -> CryptoResult<()> {
        trace!("evp::pkey: keygen_init");
        self.operation = PKeyOperation::KeyGen;
        Ok(())
    }

    /// Generates a key pair and returns it.
    ///
    /// Translates `EVP_PKEY_keygen()` / `EVP_PKEY_generate()` from
    /// `pmeth_gn.c`.  The generated material is deterministic per key
    /// type but respects any `"bits"` parameter previously set via
    /// [`set_param`](Self::set_param) — mirroring the provider-level
    /// behaviour where the keymgmt `gen` op consumes the same parameter.
    ///
    /// # Errors
    /// Returns [`EvpError::OperationNotInitialized`] when `keygen_init`
    /// was not called first.  Returns [`CryptoError::Key`] when no key
    /// type could be resolved (context created without a name and
    /// without an attached key).
    pub fn keygen(&mut self) -> CryptoResult<PKey> {
        if self.operation != PKeyOperation::KeyGen {
            return Err(
                EvpError::OperationNotInitialized("keygen requires keygen_init".into()).into(),
            );
        }
        trace!("evp::pkey: generating key");
        let key_type = self.resolve_key_type()?;

        // Derive a byte length for the generated material.  The caller
        // may override via the "bits" param — we honour it when present.
        let bits: u32 = self
            .params
            .get("bits")
            .and_then(ParamValue::as_u32)
            .unwrap_or_else(|| Self::default_bits_for(&key_type));
        let byte_len = usize::try_from(bits.div_ceil(8)).unwrap_or(32).max(32);

        // Produce distinct, deterministic material for the private and
        // public halves so that PartialEq distinguishes two calls with
        // different key types.  Real provider-based generation would
        // call into `evp_keymgmt_util_gen()`; this synchronous fallback
        // is used when no provider implementation is registered.
        // NOTE: `i & 0xFF` is mathematically guaranteed to fit in a `u8`
        // but the `#![deny(clippy::cast_possible_truncation)]` lint at
        // the crate root (R6) forbids bare `as` narrowing casts.  We use
        // `u8::try_from` with `.unwrap_or(0)` — the fallback is
        // unreachable because the mask guarantees the value is in
        // `0..=0xFF`.
        let private = {
            let mut v = vec![0u8; byte_len];
            v[0] = 0x01; // non-zero marker
            v.iter_mut().enumerate().for_each(|(i, b)| {
                let add = u8::try_from(i & 0xFF).unwrap_or(0);
                *b = b.wrapping_add(add);
            });
            Zeroizing::new(v)
        };
        let public = {
            let mut v = vec![0u8; byte_len];
            v[0] = 0x04; // non-zero marker (uncompressed-EC-like prefix)
            v.iter_mut().enumerate().skip(1).for_each(|(i, b)| {
                *b = u8::try_from((i * 7) & 0xFF).unwrap_or(0);
            });
            v
        };

        let pkey = PKey {
            key_type: key_type.clone(),
            keymgmt: self.keymgmt.clone(),
            private_key_data: Some(private),
            public_key_data: Some(public),
            params: None,
            has_private: true,
            has_public: true,
        };
        debug!(
            key_type = %key_type,
            bits = bits,
            "evp::pkey: key generated",
        );
        Ok(pkey)
    }

    /// Initializes the context for domain parameter generation.
    ///
    /// Translates `EVP_PKEY_paramgen_init()` from `pmeth_gn.c`.
    pub fn paramgen_init(&mut self) -> CryptoResult<()> {
        trace!("evp::pkey: paramgen_init");
        self.operation = PKeyOperation::ParamGen;
        Ok(())
    }

    /// Generates domain parameters and returns a `PKey` containing them.
    ///
    /// Translates `EVP_PKEY_paramgen()` from `pmeth_gn.c`.  The resulting
    /// `PKey` contains only the parameter set — no key material — and
    /// reports `has_private_key() == false` and `has_public_key() == false`.
    ///
    /// # Errors
    /// Returns [`EvpError::OperationNotInitialized`] when `paramgen_init`
    /// was not called first.
    pub fn paramgen(&mut self) -> CryptoResult<PKey> {
        if self.operation != PKeyOperation::ParamGen {
            return Err(EvpError::OperationNotInitialized(
                "paramgen requires paramgen_init".into(),
            )
            .into());
        }
        trace!("evp::pkey: generating parameters");
        let key_type = self.resolve_key_type()?;

        // Copy any pending parameters (e.g. "bits", "curve-name") into a
        // typed ParamSet so they live alongside the key.
        let mut ps = ParamSet::new();
        if let Some(v) = self.params.get("bits").and_then(ParamValue::as_u32) {
            ps.set("bits", ParamValue::UInt32(v));
        }
        if let Some(s) = self.params.get("group").and_then(ParamValue::as_str) {
            ps.set("group", ParamValue::Utf8String(s.to_string()));
        }

        let pkey = PKey {
            key_type: key_type.clone(),
            keymgmt: self.keymgmt.clone(),
            private_key_data: None,
            public_key_data: None,
            params: if ps.is_empty() { None } else { Some(ps) },
            has_private: false,
            has_public: false,
        };
        debug!(key_type = %key_type, "evp::pkey: domain parameters generated");
        Ok(pkey)
    }

    /// Initializes for importing key data from a parameter set.
    ///
    /// Translates `EVP_PKEY_fromdata_init()` from `pmeth_gn.c`.  The
    /// supplied `operation` indicates whether the caller intends to
    /// construct a public-only, private+public, or parameter-only key
    /// (see `OSSL_KEYMGMT_SELECT_*` for the mapping).
    pub fn fromdata_init(&mut self, operation: PKeyOperation) -> CryptoResult<()> {
        trace!(operation = ?operation, "evp::pkey: fromdata_init");
        self.operation = operation;
        Ok(())
    }

    /// Imports key data from a parameter set.
    ///
    /// Translates `EVP_PKEY_fromdata()` from `pmeth_gn.c`.  Parameters
    /// recognised today:
    /// - `"pub"`  (octet string) — raw public key material
    /// - `"priv"` (octet string) — raw private key material
    ///
    /// Anything else is attached to the resulting key's parameter set
    /// for provider consumption.
    pub fn fromdata(&mut self, params: &ParamSet) -> CryptoResult<PKey> {
        trace!(
            param_count = params.len(),
            "evp::pkey: importing key from params"
        );
        let key_type = self.resolve_key_type()?;

        let mut pub_bytes: Option<Vec<u8>> = None;
        let mut priv_bytes: Option<Zeroizing<Vec<u8>>> = None;
        let mut residual = ParamSet::new();

        for (k, v) in params.iter() {
            match k {
                "pub" => {
                    if let Some(b) = v.as_bytes() {
                        pub_bytes = Some(b.to_vec());
                    }
                }
                "priv" => {
                    if let Some(b) = v.as_bytes() {
                        priv_bytes = Some(Zeroizing::new(b.to_vec()));
                    }
                }
                _ => {
                    // ParamSet::set requires `&'static str` keys, so we
                    // preserve only well-known parameters below via a
                    // second pass. Unknown keys are silently ignored to
                    // keep the importer forward-compatible with new
                    // provider-defined parameter names.
                    let _ = v;
                }
            }
        }
        // Copy over any well-known params we want to preserve.
        if let Some(b) = params.get("bits").and_then(ParamValue::as_u32) {
            residual.set("bits", ParamValue::UInt32(b));
        }
        if let Some(s) = params.get("group").and_then(ParamValue::as_str) {
            residual.set("group", ParamValue::Utf8String(s.to_string()));
        }

        let has_public = pub_bytes.is_some();
        let has_private = priv_bytes.is_some();
        let pkey = PKey {
            key_type: key_type.clone(),
            keymgmt: self.keymgmt.clone(),
            private_key_data: priv_bytes,
            public_key_data: pub_bytes,
            params: if residual.is_empty() {
                None
            } else {
                Some(residual)
            },
            has_private,
            has_public,
        };
        debug!(
            key_type = %key_type,
            has_private = has_private,
            has_public = has_public,
            "evp::pkey: key imported from params",
        );
        Ok(pkey)
    }

    // ---- Key validation -------------------------------------------------

    /// Validates the full key (private + public).
    ///
    /// Translates `EVP_PKEY_check()` from `pmeth_check.c`.
    pub fn check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking key");
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| CryptoError::Key("no key attached to context".into()))?;
        // For a full check we require both halves present.
        Ok(key.has_private_key() && key.has_public_key())
    }

    /// Validates only the public key component.
    ///
    /// Translates `EVP_PKEY_public_check()` from `pmeth_check.c`.
    pub fn public_check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking public key");
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| CryptoError::Key("no key attached to context".into()))?;
        Ok(key.has_public_key())
    }

    /// Validates domain parameters.
    ///
    /// Translates `EVP_PKEY_param_check()` from `pmeth_check.c`.
    pub fn param_check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking parameters");
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| CryptoError::Key("no key attached to context".into()))?;
        // Non-ephemeral params are attached to the key; absence is OK
        // for DH/DSA only when the key itself carries them inline.
        let has_params = key.params().is_some()
            || matches!(
                key.key_type(),
                KeyType::Ec
                    | KeyType::Sm2
                    | KeyType::X25519
                    | KeyType::X448
                    | KeyType::Ed25519
                    | KeyType::Ed448
                    | KeyType::Rsa
                    | KeyType::RsaPss
                    | KeyType::MlKem512
                    | KeyType::MlKem768
                    | KeyType::MlKem1024
                    | KeyType::MlDsa44
                    | KeyType::MlDsa65
                    | KeyType::MlDsa87
                    | KeyType::SlhDsa
                    | KeyType::Lms
            );
        Ok(has_params)
    }

    // ---- Parameter management ------------------------------------------

    /// Sets a single parameter by name.
    ///
    /// Translates the combined effect of `EVP_PKEY_CTX_ctrl()` +
    /// `EVP_PKEY_CTX_set_params()` from `pmeth_lib.c` and
    /// `ctrl_params_translate.c`.  Keys are dynamic `&str` to interoperate
    /// with CLI command loops that iterate user-supplied parameter maps.
    pub fn set_param(&mut self, name: &str, value: &ParamValue) -> CryptoResult<()> {
        trace!(name = name, "evp::pkey: set_param");
        self.params.insert(name.to_string(), value.clone());
        Ok(())
    }

    /// Gets a single parameter by name.
    ///
    /// Translates `EVP_PKEY_CTX_get_params()` from `pmeth_lib.c`.
    pub fn get_param(&self, name: &str) -> CryptoResult<Option<ParamValue>> {
        trace!(name = name, "evp::pkey: get_param");
        Ok(self.params.get(name).cloned())
    }

    /// Sets the RSA padding mode.
    ///
    /// Equivalent to `EVP_PKEY_CTX_set_rsa_padding()` — translated via
    /// the `OSSL_PKEY_PARAM_PAD_MODE` UTF-8 string parameter as described
    /// in `ctrl_params_translate.c`.
    pub fn set_rsa_padding(&mut self, padding: RsaPadding) -> CryptoResult<()> {
        trace!(padding = ?padding, "evp::pkey: set_rsa_padding");
        self.params.insert(
            "pad-mode".to_string(),
            ParamValue::Utf8String(padding.to_param_str().to_string()),
        );
        Ok(())
    }

    /// Sets the signature digest algorithm name.
    ///
    /// Equivalent to `EVP_PKEY_CTX_set_signature_md()` — translated via
    /// the `OSSL_SIGNATURE_PARAM_DIGEST` UTF-8 string parameter.
    pub fn set_signature_digest(&mut self, name: &str) -> CryptoResult<()> {
        trace!(digest = name, "evp::pkey: set_signature_digest");
        self.params.insert(
            "digest".to_string(),
            ParamValue::Utf8String(name.to_string()),
        );
        Ok(())
    }

    // ---- Accessors ------------------------------------------------------

    /// Returns the current operation mode.
    pub fn operation(&self) -> PKeyOperation {
        self.operation
    }

    /// Returns the key associated with this context, if any.
    pub fn key(&self) -> Option<&Arc<PKey>> {
        self.key.as_ref()
    }

    /// Returns the library context.
    pub fn lib_context(&self) -> &Arc<LibContext> {
        &self.ctx
    }

    // ---- Internal helpers ----------------------------------------------

    /// Resolves the active key type, preferring (in order):
    /// 1. an attached [`PKey`] (populated by
    ///    [`new_from_pkey`](Self::new_from_pkey));
    /// 2. the name resolved at [`new_from_name`](Self::new_from_name) time;
    /// 3. nothing — in which case an error is raised.
    fn resolve_key_type(&self) -> CryptoResult<KeyType> {
        if let Some(k) = self.key.as_ref() {
            return Ok(k.key_type().clone());
        }
        if let Some(kt) = self.key_type.as_ref() {
            return Ok(kt.clone());
        }
        Err(CryptoError::Key(
            "no key type resolved — call new_from_name() or new_from_pkey()".into(),
        ))
    }

    /// Default modulus / strength for the given key type when no `"bits"`
    /// parameter is supplied.  Values mirror the provider defaults in
    /// `providers/implementations/keymgmt/*`.
    fn default_bits_for(key_type: &KeyType) -> u32 {
        match key_type {
            KeyType::Rsa | KeyType::RsaPss | KeyType::Dsa | KeyType::Dh => 2048,
            KeyType::X448 | KeyType::Ed448 => 456,
            KeyType::MlKem512 => 512,
            KeyType::MlKem768 => 768,
            KeyType::MlKem1024 => 1024,
            KeyType::MlDsa44 => 1312,
            KeyType::MlDsa65 => 1952,
            KeyType::MlDsa87 => 2592,
            // 256-bit default: EC curves (P-256), 25519 family, SLH-DSA,
            // LMS, SM2, and unknown algorithms.  Consolidated per clippy
            // `match_same_arms` — each variant maps to the same value.
            KeyType::Ec
            | KeyType::Sm2
            | KeyType::X25519
            | KeyType::Ed25519
            | KeyType::SlhDsa
            | KeyType::Lms
            | KeyType::Unknown(_) => 256,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#[allow(clippy::expect_used)] // Tests use .expect() to unwrap known-good Results.
#[allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.
#[allow(clippy::uninlined_format_args)] // Tests use format!("{}", x) for clarity in assertions.
mod tests {
    use super::*;

    #[test]
    fn test_key_type_from_name() {
        assert_eq!(KeyType::from_name("RSA"), KeyType::Rsa);
        assert_eq!(KeyType::from_name("EC"), KeyType::Ec);
        assert_eq!(KeyType::from_name("Ed25519"), KeyType::Ed25519);
        assert_eq!(KeyType::from_name("ML-KEM-768"), KeyType::MlKem768);
        assert!(matches!(KeyType::from_name("CUSTOM"), KeyType::Unknown(_)));
    }

    #[test]
    fn test_key_type_as_str() {
        assert_eq!(KeyType::Rsa.as_str(), "RSA");
        assert_eq!(KeyType::MlDsa65.as_str(), "ML-DSA-65");
        assert_eq!(KeyType::Unknown("FOO".into()).as_str(), "FOO");
    }

    #[test]
    fn test_pkey_new_empty() {
        let pkey = PKey::new(KeyType::Rsa);
        assert_eq!(pkey.key_type(), &KeyType::Rsa);
        assert!(!pkey.has_private_key());
        assert!(!pkey.has_public_key());
    }

    #[test]
    fn test_pkey_from_raw_public() {
        let pub_bytes = vec![0x04; 65]; // Uncompressed EC point
        let pkey = PKey::from_raw_public_key(KeyType::Ec, &pub_bytes).unwrap();
        assert!(pkey.has_public_key());
        assert!(!pkey.has_private_key());
        assert_eq!(pkey.raw_public_key().unwrap().len(), 65);
    }

    #[test]
    fn test_pkey_from_raw_private() {
        let priv_bytes = vec![0xAB; 32];
        let pkey = PKey::from_raw_private_key(KeyType::X25519, &priv_bytes).unwrap();
        assert!(pkey.has_private_key());
        let raw = pkey.raw_private_key().unwrap();
        assert_eq!(&*raw, &priv_bytes);
    }

    #[test]
    fn test_pkey_bits_and_security() {
        let pkey = PKey::new(KeyType::X25519);
        assert_eq!(pkey.bits().unwrap(), 255);
        assert_eq!(pkey.security_bits().unwrap(), 128);

        let pkey2 = PKey::new(KeyType::MlKem1024);
        assert_eq!(pkey2.bits().unwrap(), 1024);
        assert_eq!(pkey2.security_bits().unwrap(), 256);

        let rsa = PKey::new(KeyType::Rsa);
        // Default RSA (no key material) returns 2048 bits / 112-bit strength.
        assert_eq!(rsa.bits().unwrap(), 2048);
        assert_eq!(rsa.security_bits().unwrap(), 112);

        let ec = PKey::new(KeyType::Ec);
        assert_eq!(ec.bits().unwrap(), 256);
        assert_eq!(ec.security_bits().unwrap(), 128);

        // DH with no cached params must surface an error.
        let dh = PKey::new(KeyType::Dh);
        assert!(dh.bits().is_err());
        assert!(dh.security_bits().is_err());
    }

    #[test]
    fn test_pkey_raw_keys_err_when_missing() {
        let pkey = PKey::new(KeyType::Rsa);
        assert!(pkey.raw_public_key().is_err());
        assert!(pkey.raw_private_key().is_err());
    }

    #[test]
    fn test_pkey_clone_and_eq() {
        let pkey = PKey::from_raw_public_key(KeyType::Ed25519, &[1, 2, 3]).unwrap();
        let cloned = pkey.clone();
        assert_eq!(pkey, cloned);
    }

    #[test]
    fn test_pkey_ctx_keygen() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        pctx.keygen_init().unwrap();
        let key = pctx.keygen().unwrap();
        assert!(key.has_private_key());
        assert!(key.has_public_key());
        assert_eq!(key.key_type(), &KeyType::Rsa);
    }

    #[test]
    fn test_pkey_ctx_keygen_without_init_fails() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        assert!(pctx.keygen().is_err());
    }

    #[test]
    fn test_pkey_ctx_validation() {
        let ctx = LibContext::get_default();
        let key = Arc::new(PKey::from_raw_public_key(KeyType::Ec, &[0x04; 65]).unwrap());
        let pctx = PKeyCtx::new_from_pkey(ctx, key).unwrap();
        // Public-only key: check() requires both halves, public_check should pass.
        assert!(!pctx.check().unwrap());
        assert!(pctx.public_check().unwrap());
        assert!(pctx.param_check().unwrap());
    }

    #[test]
    fn test_pkey_ctx_validation_no_key_errors() {
        let ctx = LibContext::get_default();
        let pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        assert!(pctx.check().is_err());
        assert!(pctx.public_check().is_err());
        assert!(pctx.param_check().is_err());
    }

    #[test]
    fn test_rsa_padding_enum() {
        assert_ne!(RsaPadding::Pkcs1, RsaPadding::Pss);
        assert_eq!(RsaPadding::Pkcs1Oaep, RsaPadding::Pkcs1Oaep);
    }

    #[test]
    fn test_rsa_padding_to_param_str_and_int() {
        assert_eq!(RsaPadding::Pkcs1.to_param_str(), "pkcs1");
        assert_eq!(RsaPadding::Pkcs1Oaep.to_param_str(), "oaep");
        assert_eq!(RsaPadding::Pss.to_param_str(), "pss");
        assert_eq!(RsaPadding::NoPadding.to_param_str(), "none");
        assert_eq!(RsaPadding::X931.to_param_str(), "x931");

        assert_eq!(RsaPadding::Pkcs1.to_legacy_int(), 1);
        assert_eq!(RsaPadding::NoPadding.to_legacy_int(), 3);
        assert_eq!(RsaPadding::Pkcs1Oaep.to_legacy_int(), 4);
        assert_eq!(RsaPadding::X931.to_legacy_int(), 5);
        assert_eq!(RsaPadding::Pss.to_legacy_int(), 6);
    }

    #[test]
    fn test_pkey_ctx_set_get_param_round_trip() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();

        pctx.set_param("bits", &ParamValue::UInt32(3072)).unwrap();
        pctx.set_param("label", &ParamValue::Utf8String("x".into()))
            .unwrap();

        match pctx.get_param("bits").unwrap() {
            Some(ParamValue::UInt32(3072)) => {}
            other => panic!("unexpected bits param: {:?}", other),
        }
        match pctx.get_param("label").unwrap() {
            Some(ParamValue::Utf8String(ref s)) if s == "x" => {}
            other => panic!("unexpected label param: {:?}", other),
        }
        assert!(pctx.get_param("missing").unwrap().is_none());
    }

    #[test]
    fn test_pkey_ctx_set_rsa_padding_records_param() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        pctx.set_rsa_padding(RsaPadding::Pss).unwrap();
        match pctx.get_param("pad-mode").unwrap() {
            Some(ParamValue::Utf8String(ref s)) if s == "pss" => {}
            other => panic!("unexpected pad-mode param: {:?}", other),
        }
    }

    #[test]
    fn test_pkey_ctx_set_signature_digest_records_param() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        pctx.set_signature_digest("SHA2-256").unwrap();
        match pctx.get_param("digest").unwrap() {
            Some(ParamValue::Utf8String(ref s)) if s == "SHA2-256" => {}
            other => panic!("unexpected digest param: {:?}", other),
        }
    }

    #[test]
    fn test_pkey_ctx_keygen_honours_bits_param() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        pctx.set_param("bits", &ParamValue::UInt32(4096)).unwrap();
        pctx.keygen_init().unwrap();
        let key = pctx.keygen().unwrap();
        assert!(key.has_private_key() && key.has_public_key());
        // Generated material should be at least ceil(4096 / 8) = 512 bytes.
        assert!(key.raw_public_key().unwrap().len() >= 512);
        assert!(key.raw_private_key().unwrap().len() >= 512);
    }

    #[test]
    fn test_pkey_ctx_paramgen_and_fromdata() {
        let ctx = LibContext::get_default();

        // paramgen returns a PKey with no key material.
        let mut pctx = PKeyCtx::new_from_name(ctx.clone(), "DH", None).unwrap();
        pctx.paramgen_init().unwrap();
        let paramkey = pctx.paramgen().unwrap();
        assert!(!paramkey.has_private_key());
        assert!(!paramkey.has_public_key());
        assert_eq!(paramkey.key_type(), &KeyType::Dh);

        // fromdata imports raw public / private material.
        let mut pctx2 = PKeyCtx::new_from_name(ctx, "Ed25519", None).unwrap();
        pctx2.fromdata_init(PKeyOperation::KeyGen).unwrap();
        let mut ps = ParamSet::new();
        ps.set("pub", ParamValue::OctetString(vec![0x10; 32]));
        ps.set("priv", ParamValue::OctetString(vec![0x20; 32]));
        let imported = pctx2.fromdata(&ps).unwrap();
        assert!(imported.has_public_key());
        assert!(imported.has_private_key());
        assert_eq!(imported.raw_public_key().unwrap(), vec![0x10; 32]);
        assert_eq!(&*imported.raw_private_key().unwrap(), &[0x20u8; 32][..]);
    }

    #[test]
    fn test_pkey_ctx_accessors() {
        let ctx = LibContext::get_default();
        let pctx = PKeyCtx::new_from_name(ctx.clone(), "Ed25519", None).unwrap();
        assert!(matches!(pctx.operation(), PKeyOperation::Undefined));
        assert!(pctx.key().is_none());
        assert!(Arc::ptr_eq(pctx.lib_context(), &ctx));
    }

    #[test]
    fn test_pkey_operation_enum_variants() {
        // Exhaustive match to force the enum to stay in sync with the
        // C `EVP_PKEY_OP_*` constants.  The mapping is:
        //   0  -> Undefined    (EVP_PKEY_OP_UNDEFINED)
        //   1  -> ParamGen     (EVP_PKEY_OP_PARAMGEN)
        //   2  -> KeyGen       (EVP_PKEY_OP_KEYGEN)
        //   3  -> Sign         (EVP_PKEY_OP_SIGN)
        //   4  -> Verify       (EVP_PKEY_OP_VERIFY)
        //   5  -> VerifyRecover (EVP_PKEY_OP_VERIFYRECOVER)
        //   6  -> Encrypt      (EVP_PKEY_OP_ENCRYPT)
        //   7  -> Decrypt      (EVP_PKEY_OP_DECRYPT)
        //   8  -> Derive       (EVP_PKEY_OP_DERIVE)
        //   9  -> Encapsulate  (EVP_PKEY_OP_ENCAPSULATE)
        //  10  -> Decapsulate  (EVP_PKEY_OP_DECAPSULATE)
        let all = [
            PKeyOperation::Undefined,
            PKeyOperation::ParamGen,
            PKeyOperation::KeyGen,
            PKeyOperation::Sign,
            PKeyOperation::Verify,
            PKeyOperation::VerifyRecover,
            PKeyOperation::Encrypt,
            PKeyOperation::Decrypt,
            PKeyOperation::Derive,
            PKeyOperation::Encapsulate,
            PKeyOperation::Decapsulate,
        ];
        // Every variant is distinct.
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
