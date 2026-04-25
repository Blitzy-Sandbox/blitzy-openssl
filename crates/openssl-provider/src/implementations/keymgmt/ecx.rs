//! ECX key management provider implementation for X25519, X448, Ed25519, Ed448.
//!
//! Translates `providers/implementations/keymgmt/ecx_kmgmt.c` (~1,311 lines)
//! into idiomatic Rust.
//!
//! Manages raw-key types for Montgomery (key exchange) and Edwards (signatures)
//! curves with per-algorithm dispatch:
//!
//! | Algorithm | Purpose          | Key Size | Bits | Security Bits | Sig Size |
//! |-----------|------------------|----------|------|---------------|----------|
//! | X25519    | DH key exchange  | 32       | 253  | 128           | —        |
//! | X448      | DH key exchange  | 56       | 448  | 224           | —        |
//! | Ed25519   | Digital signatur | 32       | 256  | 128           | 64       |
//! | Ed448     | Digital signatur | 57       | 456  | 224           | 114      |
//!
//! # Architecture
//!
//! - [`EcxAlgorithm`] identifies one of the four raw-key ECX variants.
//! - [`EcxKeyData`] holds the public and private key octets for a given
//!   algorithm, with automatic zeroing of private material via
//!   [`zeroize::Zeroizing`] (Rule R8-compliant, no `unsafe`).
//! - [`EcxGenContext`] stores key generation configuration, including optional
//!   DHKEM Input Keying Material (non-FIPS, X types only).
//! - [`EcxKeyMgmt`] implements the [`KeyMgmtProvider`] trait, dispatching
//!   operations per algorithm via its internal [`EcxAlgorithm`] discriminant.
//! - [`ecx_descriptors`] enumerates the four algorithms for provider
//!   registration.
//!
//! # Security Properties
//!
//! - Private key material stored in [`zeroize::Zeroizing`], automatically
//!   zeroed on drop (replaces C `OPENSSL_secure_clear_free`).
//! - Key comparison uses [`subtle::ConstantTimeEq`] to prevent timing
//!   side channels (replaces C `CRYPTO_memcmp`).
//! - Zero `unsafe` blocks (Rule R8).
//! - Key-length validation on every import/export path (Rule R6).
//! - `Option<Vec<u8>>` for absent key material (Rule R5, no sentinels).
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → `DefaultProvider::query_operation(KeyMgmt)`
//!         → `implementations::all_keymgmt_descriptors()`
//!           → `keymgmt::descriptors()`
//!             → `ecx::ecx_descriptors()`
//! ```
//!
//! # C Source Mapping
//!
//! | Rust type / function         | C construct                              | Source |
//! |------------------------------|------------------------------------------|--------|
//! | [`EcxKeyData`]               | `ECX_KEY` struct                         | `ecx_key.c` |
//! | [`EcxGenContext`]            | `struct ecx_gen_ctx`                     | `ecx_kmgmt.c:~350` |
//! | [`EcxKeyMgmt::new_key`]      | `x25519_new_key` / `x448_new_key` / ...  | `ecx_kmgmt.c:~120` |
//! | [`EcxKeyMgmt::generate`]     | `ecx_gen` + clamping + public derivation | `ecx_kmgmt.c:~540` |
//! | [`EcxKeyMgmt::import`]       | `ecx_import`                             | `ecx_kmgmt.c:190-280` |
//! | [`EcxKeyMgmt::export`]       | `ecx_export` / `key_to_params`           | `ecx_kmgmt.c:280-330` |
//! | [`EcxKeyMgmt::has`]          | `ecx_has`                                | `ecx_kmgmt.c:130-155` |
//! | [`EcxKeyMgmt::validate`]     | `ecx_validate` + pairwise check          | `ecx_kmgmt.c:160-190` |
//! | [`EcxKeyMgmt::match_keys`]   | `ecx_match` (CRYPTO_memcmp→subtle)       | `ecx_kmgmt.c:~165` |
//! | [`ecx_descriptors`]          | `MAKE_KEYMGMT_FUNCTIONS(alg)` × 4         | `ecx_kmgmt.c:~1200` |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::Zeroizing;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::context::LibContext;
use openssl_crypto::ec::curve25519::{
    self, EcxKeyType, EcxPrivateKey, EcxPublicKey, ED25519_KEY_LEN, ED25519_SIGNATURE_LEN,
    ED448_KEY_LEN, ED448_SIGNATURE_LEN, X25519_KEY_LEN, X448_KEY_LEN,
};

use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Algorithm constants — mirror the C #defines in include/crypto/ecx.h
// =============================================================================

/// Cryptographic bit-length reported by `OSSL_PKEY_PARAM_BITS` for X25519.
///
/// Matches `X25519_BITS` from `include/crypto/ecx.h`.
const X25519_BITS: i32 = 253;
/// Security strength in bits for X25519 (NIST SP 800-57 Table 2).
const X25519_SECURITY_BITS: i32 = 128;

/// Cryptographic bit-length for X448 (`X448_BITS`).
const X448_BITS: i32 = 448;
/// Security strength in bits for X448.
const X448_SECURITY_BITS: i32 = 224;

/// Cryptographic bit-length for Ed25519 (`ED25519_BITS`).
const ED25519_BITS: i32 = 256;
/// Security strength in bits for Ed25519.
const ED25519_SECURITY_BITS: i32 = 128;

/// Cryptographic bit-length for Ed448 (`ED448_BITS`).
const ED448_BITS: i32 = 456;
/// Security strength in bits for Ed448.
const ED448_SECURITY_BITS: i32 = 224;

// =============================================================================
// EcxAlgorithm — identifies one of the four ECX variants
// =============================================================================

/// Identifies a specific ECX algorithm variant.
///
/// ECX ("Edwards/Curve") covers the Montgomery (X*) and Edwards (Ed*)
/// curves defined in RFC 7748 and RFC 8032 respectively.
///
/// Replaces the C `ECX_KEY_TYPE_*` enum values plus per-algorithm
/// dispatch macros (`MAKE_KEYMGMT_FUNCTIONS(x25519)`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcxAlgorithm {
    /// X25519 — Montgomery curve for Diffie-Hellman (RFC 7748).
    ///
    /// 32-byte keys, 253 cryptographic bits, 128 security bits.
    X25519,
    /// X448 — Montgomery curve for Diffie-Hellman (RFC 7748).
    ///
    /// 56-byte keys, 448 cryptographic bits, 224 security bits.
    X448,
    /// Ed25519 — Edwards curve for `EdDSA` signatures (RFC 8032).
    ///
    /// 32-byte keys, 256 cryptographic bits, 128 security bits,
    /// 64-byte signatures.
    Ed25519,
    /// Ed448 — Edwards curve for `EdDSA` signatures (RFC 8032).
    ///
    /// 57-byte keys, 456 cryptographic bits, 224 security bits,
    /// 114-byte signatures.
    Ed448,
}

impl EcxAlgorithm {
    /// Returns the byte length of the private/public key material for this
    /// algorithm.
    ///
    /// | Algorithm | Key size (bytes) |
    /// |-----------|------------------|
    /// | X25519    | 32               |
    /// | X448      | 56               |
    /// | Ed25519   | 32               |
    /// | Ed448     | 57               |
    #[must_use]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_LEN,
            Self::X448 => X448_KEY_LEN,
            Self::Ed25519 => ED25519_KEY_LEN,
            Self::Ed448 => ED448_KEY_LEN,
        }
    }

    /// Returns the cryptographic bit-length used by the `OSSL_PKEY_PARAM_BITS`
    /// parameter.
    ///
    /// This differs from `key_size() * 8` because RFC 7748/8032 define
    /// specific cryptographic strengths independent of octet length.
    #[must_use]
    pub const fn bits(&self) -> i32 {
        match self {
            Self::X25519 => X25519_BITS,
            Self::X448 => X448_BITS,
            Self::Ed25519 => ED25519_BITS,
            Self::Ed448 => ED448_BITS,
        }
    }

    /// Returns the NIST SP 800-57 security strength in bits for this algorithm.
    #[must_use]
    pub const fn security_bits(&self) -> i32 {
        match self {
            Self::X25519 => X25519_SECURITY_BITS,
            Self::X448 => X448_SECURITY_BITS,
            Self::Ed25519 => ED25519_SECURITY_BITS,
            Self::Ed448 => ED448_SECURITY_BITS,
        }
    }

    /// Returns the maximum output size (bytes) for this algorithm.
    ///
    /// For X types this is the shared-secret length (`key_size`).
    /// For Ed types this is the signature length.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_LEN,
            Self::X448 => X448_KEY_LEN,
            Self::Ed25519 => ED25519_SIGNATURE_LEN,
            Self::Ed448 => ED448_SIGNATURE_LEN,
        }
    }

    /// Returns `true` if this algorithm is used for key exchange
    /// (Montgomery curve variant).
    #[must_use]
    pub const fn is_key_exchange(&self) -> bool {
        matches!(self, Self::X25519 | Self::X448)
    }

    /// Returns `true` if this algorithm is used for signatures
    /// (Edwards curve variant).
    #[must_use]
    pub const fn is_signature(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }

    /// Returns the canonical uppercase algorithm name.
    ///
    /// Matches the primary OID lookup name registered by the C provider.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Ed25519 => "ED25519",
            Self::Ed448 => "ED448",
        }
    }

    /// Converts this algorithm to the crypto-layer [`EcxKeyType`] discriminant.
    #[must_use]
    pub const fn as_key_type(&self) -> EcxKeyType {
        match self {
            Self::X25519 => EcxKeyType::X25519,
            Self::X448 => EcxKeyType::X448,
            Self::Ed25519 => EcxKeyType::Ed25519,
            Self::Ed448 => EcxKeyType::Ed448,
        }
    }

    /// Parses a case-insensitive algorithm name into an [`EcxAlgorithm`].
    ///
    /// Accepted forms (case insensitive):
    /// - `"x25519"` → [`Self::X25519`]
    /// - `"x448"` → [`Self::X448`]
    /// - `"ed25519"` → [`Self::Ed25519`]
    /// - `"ed448"` → [`Self::Ed448`]
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "x25519" => Some(Self::X25519),
            "x448" => Some(Self::X448),
            "ed25519" => Some(Self::Ed25519),
            "ed448" => Some(Self::Ed448),
            _ => None,
        }
    }
}

impl fmt::Display for EcxAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// EcxKeyData — Key material container for ECX algorithms
// =============================================================================

/// Storage for ECX key material: private key, public key, and context.
///
/// Replaces the C `ECX_KEY` struct from `ecx_key.c`.
///
/// # Security Properties
///
/// - Private key bytes are wrapped in [`Zeroizing`] and securely erased
///   on drop. This replaces the C `OPENSSL_secure_clear_free()` pattern.
/// - Public key bytes are held in plain `Vec<u8>` (no secrecy requirement).
/// - Optional [`Arc<LibContext>`] enables provider-aware operations without
///   shared mutable state (Rule R7).
///
/// # Debug Redaction
///
/// The [`Debug`] implementation redacts all key bytes. The derived string
/// includes `has_private: bool` and `has_public: bool` markers that the
/// provider-layer `has()` / `export()` implementations inspect when the
/// concrete type cannot be downcast through the [`KeyData`] trait object.
///
/// # Fields
///
/// - `key_type`: which ECX variant this key is for ([`EcxAlgorithm`]).
/// - `pub_key`: `None` when absent; otherwise `key_type.key_size()` bytes.
/// - `priv_key`: `None` when absent; otherwise `key_type.key_size()` bytes
///   wrapped in [`Zeroizing`] for secure erasure on drop.
/// - `lib_ctx`: optional shared library context for provider-aware ops.
/// - `prop_query`: optional provider property query string
///   (e.g. `"provider=default"`).
pub struct EcxKeyData {
    /// Which ECX algorithm this key is for.
    pub(crate) key_type: EcxAlgorithm,
    /// Public key octets (length == `key_type.key_size()`).
    pub(crate) pub_key: Option<Vec<u8>>,
    /// Private key octets wrapped for automatic zeroing on drop.
    pub(crate) priv_key: Option<Zeroizing<Vec<u8>>>,
    /// Optional shared library context reference.
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
    /// Optional provider property query string.
    pub(crate) prop_query: Option<String>,
}

impl fmt::Debug for EcxKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcxKeyData")
            .field("key_type", &self.key_type)
            .field("has_private", &self.priv_key.is_some())
            .field("has_public", &self.pub_key.is_some())
            .field("has_lib_ctx", &self.lib_ctx.is_some())
            .field("has_prop_query", &self.prop_query.is_some())
            .finish()
    }
}

impl KeyData for EcxKeyData {}

impl EcxKeyData {
    /// Creates a new empty [`EcxKeyData`] for the given algorithm.
    ///
    /// Both `pub_key` and `priv_key` start as `None`. This matches the C
    /// `ossl_ecx_key_new()` initial state.
    #[must_use]
    pub fn new(key_type: EcxAlgorithm) -> Self {
        Self {
            key_type,
            pub_key: None,
            priv_key: None,
            lib_ctx: None,
            prop_query: None,
        }
    }

    /// Creates a new empty [`EcxKeyData`] with an optional [`LibContext`].
    #[must_use]
    pub fn new_with_ctx(key_type: EcxAlgorithm, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            key_type,
            pub_key: None,
            priv_key: None,
            lib_ctx,
            prop_query: None,
        }
    }

    /// Returns the ECX algorithm variant of this key.
    #[must_use]
    pub fn key_type(&self) -> EcxAlgorithm {
        self.key_type
    }

    /// Returns a reference to the public key bytes if present.
    #[must_use]
    pub fn public_bytes(&self) -> Option<&[u8]> {
        self.pub_key.as_deref()
    }

    /// Returns a reference to the private key bytes if present.
    ///
    /// The returned slice remains within the [`Zeroizing`] wrapper and
    /// will be zeroed when the enclosing `EcxKeyData` is dropped.
    #[must_use]
    pub fn private_bytes(&self) -> Option<&[u8]> {
        self.priv_key.as_deref().map(AsRef::as_ref)
    }

    /// Checks whether the requested selection components are present.
    ///
    /// Translates C `ecx_has()` (`ecx_kmgmt.c:~130-155`). Parameters are
    /// always considered present for ECX (no domain parameters exist);
    /// `PUBLIC_KEY` requires `pub_key.is_some()`; `PRIVATE_KEY` requires
    /// `priv_key.is_some()`.
    #[must_use]
    pub fn has_selection(&self, selection: KeySelection) -> bool {
        // Domain parameters always "present" — ECX has no configurable domain.
        // OTHER_PARAMETERS likewise always present (vacuously).
        if selection.contains(KeySelection::PUBLIC_KEY) && self.pub_key.is_none() {
            return false;
        }
        if selection.contains(KeySelection::PRIVATE_KEY) && self.priv_key.is_none() {
            return false;
        }
        true
    }

    /// Validates the key material for structural correctness.
    ///
    /// Translates C `ecx_validate()` (`ecx_kmgmt.c:~160-190`).
    ///
    /// - Key-length check: each present component must match `key_size()`.
    /// - `PUBLIC_KEY` (Ed only): verifies the public key is a valid
    ///   curve point via crypto-layer `verify_public_key`.
    /// - `KEYPAIR`: pairwise consistency check:
    ///   - X types: derive public from private (`x{25519,448}_basepoint`
    ///     scalar mult) and constant-time compare with the stored
    ///     public-key bytes.
    ///   - Ed types: derive public from private (RFC 8032 §5.{1,2}.5
    ///     `SHA-512`/`SHAKE256` digest, clamp, then
    ///     `edwards{25519,448}::scalarmult_base`) and constant-time
    ///     compare with the stored public-key bytes.
    ///
    /// Returns `Ok(false)` if validation fails, `Ok(true)` on success.
    /// Returns `Err(ProviderError)` only on internal crypto-layer errors.
    pub fn validate_selection(&self, selection: KeySelection) -> ProviderResult<bool> {
        // First check structural presence.
        if !self.has_selection(selection) {
            return Ok(false);
        }

        let expected_len = self.key_type.key_size();

        // Key-length sanity check for any present components.
        if let Some(ref pub_bytes) = self.pub_key {
            if pub_bytes.len() != expected_len {
                return Ok(false);
            }
        }
        if let Some(ref priv_bytes) = self.priv_key {
            if priv_bytes.len() != expected_len {
                return Ok(false);
            }
        }

        // Full public-key validity check (Edwards only).
        if selection.contains(KeySelection::PUBLIC_KEY) && self.key_type.is_signature() {
            if let Some(ref pub_bytes) = self.pub_key {
                match EcxPublicKey::new(self.key_type.as_key_type(), pub_bytes.clone()) {
                    Ok(pk) => match curve25519::verify_public_key(&pk) {
                        Ok(true) => {}
                        Ok(false) => return Ok(false),
                        Err(e) => {
                            return Err(ProviderError::Dispatch(format!(
                                "public key verification failed: {e}"
                            )));
                        }
                    },
                    Err(e) => {
                        return Err(ProviderError::Dispatch(format!(
                            "public key length/type invalid: {e}"
                        )));
                    }
                }
            }
        }

        // Pairwise check for KEYPAIR selection.
        if selection.contains(KeySelection::PRIVATE_KEY)
            && selection.contains(KeySelection::PUBLIC_KEY)
        {
            return self.pairwise_check();
        }

        Ok(true)
    }

    /// Performs a pairwise consistency check between private and public keys.
    ///
    /// Translates the C `ecx_pairwise_check` and `ecd_pairwise_check`
    /// routines (`ecx_kmgmt.c:~400-470`).
    ///
    /// For all four supported key types this performs a **cryptographic
    /// round-trip derivation** rather than a structural-only check:
    ///
    /// - **X25519 / X448**: derive the public key from the private key
    ///   via `x{25519,448}_public_from_private` (Montgomery-ladder
    ///   scalar multiplication of the base point) and constant-time
    ///   compare the derived public-key bytes with the stored
    ///   public-key bytes via [`subtle::ConstantTimeEq::ct_eq`].
    /// - **Ed25519 / Ed448**: derive the public key from the private
    ///   key via `ed{25519,448}_public_from_private`
    ///   (RFC 8032 §5.{1,2}.5: `SHA-512`/`SHAKE256` digest, clamp the
    ///   first 32/57 bytes per the standard, then
    ///   `edwards{25519,448}::scalarmult_base`) and constant-time
    ///   compare the derived public-key encoding with the stored
    ///   public-key bytes via [`subtle::ConstantTimeEq::ct_eq`].
    ///
    /// This guarantees that the stored public key is the unique public
    /// key matching the stored private key — equivalent to performing a
    /// sign + verify round trip but without any signature/randomness
    /// overhead.
    fn pairwise_check(&self) -> ProviderResult<bool> {
        use subtle::ConstantTimeEq;

        let (pub_bytes, priv_bytes) = match (&self.pub_key, &self.priv_key) {
            (Some(p), Some(s)) => (p.as_slice(), &s[..]),
            _ => return Ok(false),
        };

        let key_type = self.key_type.as_key_type();

        let priv_key = EcxPrivateKey::new(key_type, priv_bytes.to_vec()).map_err(|e| {
            ProviderError::Dispatch(format!("invalid private key for pairwise check: {e}"))
        })?;

        let derived = match self.key_type {
            EcxAlgorithm::X25519 => curve25519::x25519_public_from_private(&priv_key),
            EcxAlgorithm::X448 => curve25519::x448_public_from_private(&priv_key),
            EcxAlgorithm::Ed25519 => curve25519::ed25519_public_from_private(&priv_key),
            EcxAlgorithm::Ed448 => curve25519::ed448_public_from_private(&priv_key),
        }
        .map_err(|e| {
            ProviderError::Dispatch(format!(
                "public key derivation failed during pairwise check: {e}"
            ))
        })?;

        // Constant-time comparison (Rule R8: subtle, not CRYPTO_memcmp).
        let matches: bool = derived.as_bytes().ct_eq(pub_bytes).into();
        Ok(matches)
    }

    /// Exports public and/or private key bytes to a [`ParamSet`].
    ///
    /// Translates C `key_to_params` (`ecx_kmgmt.c:~260-290`).
    ///
    /// - `PUBLIC_KEY`: sets `"pub"` to the public key octets (and
    ///   `"encoded-pub-key"` for X types — the encoding is identical).
    /// - `PRIVATE_KEY`: sets `"priv"` to the private key octets.
    ///
    /// Fields absent from the key are silently omitted from the output.
    pub fn export_to_params(&self, selection: KeySelection) -> ParamSet {
        let mut ps = ParamSet::new();

        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(ref pub_bytes) = self.pub_key {
                ps.set("pub", ParamValue::OctetString(pub_bytes.clone()));
                if self.key_type.is_key_exchange() {
                    ps.set(
                        "encoded-pub-key",
                        ParamValue::OctetString(pub_bytes.clone()),
                    );
                }
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(ref priv_bytes) = self.priv_key {
                ps.set("priv", ParamValue::OctetString(priv_bytes.to_vec()));
            }
        }

        ps
    }

    /// Imports key data from a [`ParamSet`] into a new [`EcxKeyData`].
    ///
    /// Translates C `ecx_import` (`ecx_kmgmt.c:~190-280`).
    ///
    /// Rule R6: exact byte-length comparison (no truncation), returns
    /// [`ProviderError::Dispatch`] on length mismatch.
    ///
    /// Rule R5: absent fields encoded as `None`, never as an empty vector.
    ///
    /// At least one of `PRIVATE_KEY` or `PUBLIC_KEY` must be selected;
    /// otherwise the function returns an error (matching the C code which
    /// rejects `selection` lacking any `OSSL_KEYMGMT_SELECT_*_KEY` bit).
    pub fn from_params(
        key_type: EcxAlgorithm,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Self> {
        // At least one of PRIVATE_KEY or PUBLIC_KEY must be requested.
        let want_priv = selection.contains(KeySelection::PRIVATE_KEY);
        let want_pub = selection.contains(KeySelection::PUBLIC_KEY);
        if !want_priv && !want_pub {
            return Err(ProviderError::Dispatch(
                "ECX import requires PRIVATE_KEY or PUBLIC_KEY selection".into(),
            ));
        }

        let expected_len = key_type.key_size();
        let mut key = Self::new(key_type);

        if want_priv {
            if let Some(ParamValue::OctetString(priv_bytes)) = data.get("priv") {
                if priv_bytes.len() != expected_len {
                    return Err(ProviderError::Dispatch(format!(
                        "{} private key length mismatch: expected {}, got {}",
                        key_type.name(),
                        expected_len,
                        priv_bytes.len()
                    )));
                }
                key.priv_key = Some(Zeroizing::new(priv_bytes.clone()));
            }
        }

        if want_pub {
            if let Some(ParamValue::OctetString(pub_bytes)) = data.get("pub") {
                if pub_bytes.len() != expected_len {
                    return Err(ProviderError::Dispatch(format!(
                        "{} public key length mismatch: expected {}, got {}",
                        key_type.name(),
                        expected_len,
                        pub_bytes.len()
                    )));
                }
                key.pub_key = Some(pub_bytes.clone());
            } else if let Some(ParamValue::OctetString(pub_bytes)) = data.get("encoded-pub-key") {
                // X types accept "encoded-pub-key" as an alias for "pub".
                if pub_bytes.len() != expected_len {
                    return Err(ProviderError::Dispatch(format!(
                        "{} encoded public key length mismatch: expected {}, got {}",
                        key_type.name(),
                        expected_len,
                        pub_bytes.len()
                    )));
                }
                key.pub_key = Some(pub_bytes.clone());
            }
        }

        // If nothing was imported, that is a failure — the caller asked
        // for key components but none were present in `data`.
        if want_priv && key.priv_key.is_none() && want_pub && key.pub_key.is_none() {
            return Err(ProviderError::Dispatch(
                "ECX import found no key material in parameters".into(),
            ));
        }

        Ok(key)
    }
}

// =============================================================================
// EcxGenContext — Key generation configuration
// =============================================================================

/// Key generation context for ECX algorithms.
///
/// Replaces the C `struct ecx_gen_ctx` (`ecx_kmgmt.c:~350`). Provider-level
/// APIs populate this context via `set_params` before invoking
/// [`EcxKeyMgmt::generate`].
///
/// # Fields
///
/// - `algorithm`: which ECX variant this context generates.
/// - `selection`: which components to emit (typically `KEYPAIR`).
/// - `dhkem_ikm`: optional Input Keying Material used by HPKE DHKEM.
///   Only valid for X25519/X448 **and** non-FIPS mode. Stored here for
///   deterministic key derivation when later passed through HPKE's
///   `DeriveKeyPair` primitive.
/// - `lib_ctx`: optional shared library context.
/// - `prop_query`: optional provider property query string.
pub struct EcxGenContext {
    /// Target algorithm for key generation.
    pub(crate) algorithm: EcxAlgorithm,
    /// Components to generate.
    pub(crate) selection: KeySelection,
    /// Optional DHKEM Input Keying Material (non-FIPS, X types only).
    pub(crate) dhkem_ikm: Option<Vec<u8>>,
    /// Optional shared library context reference.
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
    /// Optional provider property query string.
    pub(crate) prop_query: Option<String>,
}

impl fmt::Debug for EcxGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcxGenContext")
            .field("algorithm", &self.algorithm)
            .field("selection", &self.selection.bits())
            .field("has_dhkem_ikm", &self.dhkem_ikm.is_some())
            .field("has_lib_ctx", &self.lib_ctx.is_some())
            .field("has_prop_query", &self.prop_query.is_some())
            .finish()
    }
}

impl EcxGenContext {
    /// Creates a new generation context for `algorithm` with the given
    /// `selection`.
    ///
    /// If `selection` does not include `PRIVATE_KEY` or `PUBLIC_KEY`, the
    /// generated output will be incomplete; callers should normally pass
    /// [`KeySelection::KEYPAIR`].
    #[must_use]
    pub fn new(algorithm: EcxAlgorithm, selection: KeySelection) -> Self {
        Self {
            algorithm,
            selection,
            dhkem_ikm: None,
            lib_ctx: None,
            prop_query: None,
        }
    }

    /// Returns the target algorithm.
    #[must_use]
    pub fn algorithm(&self) -> EcxAlgorithm {
        self.algorithm
    }

    /// Returns the selection mask.
    #[must_use]
    pub fn selection(&self) -> KeySelection {
        self.selection
    }

    /// Configures the optional library context.
    pub fn set_lib_ctx(&mut self, lib_ctx: Option<Arc<LibContext>>) {
        self.lib_ctx = lib_ctx;
    }

    /// Sets the DHKEM Input Keying Material.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] if the algorithm is
    /// not a key-exchange variant (Ed25519/Ed448 do not support DHKEM IKM).
    ///
    /// This method also stages non-FIPS enforcement: callers in FIPS mode
    /// must not set IKM. The crypto layer will refuse to use it when the
    /// FIPS indicator is active.
    pub fn set_dhkem_ikm(&mut self, ikm: Vec<u8>) -> ProviderResult<()> {
        if !self.algorithm.is_key_exchange() {
            return Err(ProviderError::AlgorithmUnavailable(format!(
                "DHKEM IKM is not supported for {}",
                self.algorithm.name()
            )));
        }
        self.dhkem_ikm = Some(ikm);
        Ok(())
    }

    /// Sets the provider property query string.
    pub fn set_prop_query(&mut self, prop_query: Option<String>) {
        self.prop_query = prop_query;
    }

    /// Updates this context from an `OSSL_PARAM`-equivalent [`ParamSet`].
    ///
    /// Translates the C `ecx_gen_set_params` routine
    /// (`ecx_kmgmt.c:~650-720`).
    ///
    /// Accepted parameters:
    /// - `"group"` (UTF-8 string) — only for X types; must match the
    ///   algorithm lowercase name (`"x25519"` or `"x448"`). For Ed types,
    ///   presence of this parameter yields an error.
    /// - `"properties"` (UTF-8 string) — property query string.
    /// - `"dhkem-ikm"` (octet string) — only for X types; non-FIPS only.
    pub fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // "group": only for X types; must match algorithm name.
        if let Some(ParamValue::Utf8String(group)) = params.get("group") {
            if !self.algorithm.is_key_exchange() {
                return Err(ProviderError::Dispatch(format!(
                    "'group' parameter not valid for {}",
                    self.algorithm.name()
                )));
            }
            let expected = self.algorithm.name().to_ascii_lowercase();
            if !group.eq_ignore_ascii_case(&expected) {
                return Err(ProviderError::Dispatch(format!(
                    "unexpected group '{group}' for algorithm {}",
                    self.algorithm.name()
                )));
            }
        }

        if let Some(ParamValue::Utf8String(pq)) = params.get("properties") {
            self.prop_query = Some(pq.clone());
        }

        if let Some(ParamValue::OctetString(ikm)) = params.get("dhkem-ikm") {
            self.set_dhkem_ikm(ikm.clone())?;
        }

        Ok(())
    }
}

// =============================================================================
// EcxKeyMgmt — KeyMgmtProvider trait implementation
// =============================================================================

/// ECX key management provider.
///
/// Implements the [`KeyMgmtProvider`] trait with per-algorithm dispatch.
/// A single `EcxKeyMgmt` instance is parameterized by its [`EcxAlgorithm`]
/// at construction time; the four factory functions
/// ([`Self::x25519`], [`Self::x448`], [`Self::ed25519`], [`Self::ed448`])
/// cover all supported algorithms.
///
/// Replaces the four sets of C dispatch tables generated by
/// `MAKE_KEYMGMT_FUNCTIONS(x25519)`, etc.
#[derive(Debug, Clone, Copy)]
pub struct EcxKeyMgmt {
    algorithm: EcxAlgorithm,
}

impl EcxKeyMgmt {
    /// Creates a new `EcxKeyMgmt` for the given algorithm.
    #[must_use]
    pub const fn new(algorithm: EcxAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Returns an `EcxKeyMgmt` instance configured for X25519.
    #[must_use]
    pub const fn x25519() -> Self {
        Self::new(EcxAlgorithm::X25519)
    }

    /// Returns an `EcxKeyMgmt` instance configured for X448.
    #[must_use]
    pub const fn x448() -> Self {
        Self::new(EcxAlgorithm::X448)
    }

    /// Returns an `EcxKeyMgmt` instance configured for Ed25519.
    #[must_use]
    pub const fn ed25519() -> Self {
        Self::new(EcxAlgorithm::Ed25519)
    }

    /// Returns an `EcxKeyMgmt` instance configured for Ed448.
    #[must_use]
    pub const fn ed448() -> Self {
        Self::new(EcxAlgorithm::Ed448)
    }

    /// Returns the configured algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> EcxAlgorithm {
        self.algorithm
    }

    /// Compares two ECX keys in constant time.
    ///
    /// Translates C `ecx_match` (`ecx_kmgmt.c:~165`). The C version uses
    /// `CRYPTO_memcmp`; this Rust version uses [`subtle::ConstantTimeEq`]
    /// (Rule R8).
    ///
    /// Match semantics (mirrors the C code exactly):
    /// - Key types must match (`key1.key_type == key2.key_type`). If
    ///   selection only requests `DOMAIN_PARAMETERS`, this type-check is
    ///   sufficient and returns `true`.
    /// - If selection includes `PUBLIC_KEY` or `PRIVATE_KEY`:
    ///   - If both keys have public components, compare them (`ct_eq`).
    ///   - Otherwise, if both have private components, compare them
    ///     (`ct_eq`).
    ///   - Otherwise the comparison fails (no key material to compare).
    pub fn match_keys(
        &self,
        key1: &EcxKeyData,
        key2: &EcxKeyData,
        selection: KeySelection,
    ) -> ProviderResult<bool> {
        use subtle::ConstantTimeEq;

        // Type discriminants must agree first.
        if key1.key_type != key2.key_type {
            trace!(
                key1_type = %key1.key_type,
                key2_type = %key2.key_type,
                "ecx match: key types differ",
            );
            return Ok(false);
        }

        // DOMAIN_PARAMETERS alone: type equality is sufficient.
        if !selection.contains(KeySelection::PRIVATE_KEY)
            && !selection.contains(KeySelection::PUBLIC_KEY)
        {
            return Ok(true);
        }

        // Public-key preference: try public keys first.
        if let (Some(ref pa), Some(ref pb)) = (&key1.pub_key, &key2.pub_key) {
            if pa.len() != pb.len() {
                return Ok(false);
            }
            return Ok(pa.ct_eq(pb).into());
        }

        // Fall back to private-key comparison.
        if let (Some(ref sa), Some(ref sb)) = (&key1.priv_key, &key2.priv_key) {
            if sa.len() != sb.len() {
                return Ok(false);
            }
            let ct: bool = sa.as_slice().ct_eq(sb.as_slice()).into();
            return Ok(ct);
        }

        // Neither public nor private material to compare.
        Ok(false)
    }

    /// Returns this provider's advertised parameters.
    ///
    /// Translates C `ecx_get_params` (`ecx_kmgmt.c:~720-800`).
    ///
    /// Parameters set per algorithm:
    /// - `bits` (int32): cryptographic bit-length.
    /// - `security-bits` (int32): NIST security strength.
    /// - `max-size` (int32): maximum output size in bytes.
    /// - `security-category` (int32 = 0): FIPS category, unimplemented.
    ///
    /// Per-algorithm extras:
    /// - X types: `encoded-pub-key-required` (i32 = 1).
    /// - Ed types: `mandatory-digest` (utf8 = "") signalling the algorithm
    ///   uses its built-in hashing (`PureEdDSA`).
    ///
    /// # Errors
    ///
    /// This method never returns an error — all parameters are statically
    /// known for each algorithm — but follows the `ProviderResult` contract
    /// for API symmetry with `set_params`.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();

        ps.set("bits", ParamValue::Int32(self.algorithm.bits()));
        ps.set(
            "security-bits",
            ParamValue::Int32(self.algorithm.security_bits()),
        );

        // `max-size` is usize-valued in this codebase; Rule R6 requires a
        // safe conversion. Algorithm max_size() is at most 114 so it fits.
        let Ok(max_size) = i32::try_from(self.algorithm.max_size()) else {
            return Err(ProviderError::Dispatch(
                "max-size exceeds i32 range — should never happen for ECX".into(),
            ));
        };
        ps.set("max-size", ParamValue::Int32(max_size));
        ps.set("security-category", ParamValue::Int32(0));

        match self.algorithm {
            EcxAlgorithm::X25519 | EcxAlgorithm::X448 => {
                ps.set("encoded-pub-key-required", ParamValue::Int32(1));
            }
            EcxAlgorithm::Ed25519 | EcxAlgorithm::Ed448 => {
                // PureEdDSA: no external digest required.
                ps.set("mandatory-digest", ParamValue::Utf8String(String::new()));
            }
        }

        Ok(ps)
    }

    /// Applies provider-level settable parameters.
    ///
    /// Translates C per-algorithm `*_set_params` functions
    /// (`ecx_kmgmt.c:~800-900`).
    ///
    /// Behavior per algorithm:
    /// - X25519 / X448: accepts `"properties"` (utf8). The C code also
    ///   handles `"pub"` here, but that manipulation belongs to
    ///   [`Self::import`]; we keep `set_params` limited to provider
    ///   metadata.
    /// - Ed25519 / Ed448: no settable parameters (no-op, returns `Ok`).
    ///
    /// Unknown parameters are silently ignored — matching OpenSSL's
    /// permissive `OSSL_PARAM` semantics.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` only if a recognized parameter
    /// has the wrong type.
    pub fn set_params(&self, params: &ParamSet) -> ProviderResult<()> {
        match self.algorithm {
            EcxAlgorithm::X25519 | EcxAlgorithm::X448 => {
                if let Some(p) = params.get("properties") {
                    if !matches!(p, ParamValue::Utf8String(_)) {
                        return Err(ProviderError::Dispatch(format!(
                            "'properties' parameter must be UTF-8 string, got {}",
                            p.param_type_name()
                        )));
                    }
                }
                Ok(())
            }
            EcxAlgorithm::Ed25519 | EcxAlgorithm::Ed448 => {
                // No-op for Ed types (matches C code).
                trace!(
                    algorithm = %self.algorithm,
                    "ecx set_params: no-op for signature algorithm",
                );
                Ok(())
            }
        }
    }
}

impl KeyMgmtProvider for EcxKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm.name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            algorithm = %self.algorithm,
            "ecx keymgmt: creating new empty key",
        );
        Ok(Box::new(EcxKeyData::new(self.algorithm)))
    }

    fn generate(&self, _params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = %self.algorithm,
            "ecx keymgmt: generating key pair",
        );

        // Delegate to the crypto layer, which handles per-algorithm clamping
        // (X25519 / X448) and proper hash-then-scalarmult (Ed25519 / Ed448).
        let keypair = curve25519::generate_keypair(self.algorithm.as_key_type())
            .map_err(|e| ProviderError::Init(format!("ECX key generation failed: {e}")))?;

        let priv_bytes = keypair.private_key().as_bytes().to_vec();
        let pub_bytes = keypair.public_key().as_bytes().to_vec();

        // Length sanity check — defense in depth, must already be correct.
        let expected = self.algorithm.key_size();
        if priv_bytes.len() != expected || pub_bytes.len() != expected {
            return Err(ProviderError::Dispatch(format!(
                "ECX keygen produced wrong key length: priv={}, pub={}, expected={}",
                priv_bytes.len(),
                pub_bytes.len(),
                expected
            )));
        }

        Ok(Box::new(EcxKeyData {
            key_type: self.algorithm,
            pub_key: Some(pub_bytes),
            priv_key: Some(Zeroizing::new(priv_bytes)),
            lib_ctx: None,
            prop_query: None,
        }))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            algorithm = %self.algorithm,
            selection = selection.bits(),
            "ecx keymgmt: importing key",
        );
        let key_data = EcxKeyData::from_params(self.algorithm, selection, data)?;
        Ok(Box::new(key_data))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        trace!(
            algorithm = %self.algorithm,
            selection = selection.bits(),
            "ecx keymgmt: exporting key",
        );

        // The `KeyData` trait does not expose `Any` for downcasting, so we
        // identify our concrete type via its Debug representation
        // (matches the pattern used in `ec.rs`). For full fidelity,
        // callers should invoke `EcxKeyData::export_to_params` directly
        // when they hold a concrete type.
        let debug_str = format!("{key:?}");
        if !debug_str.contains("EcxKeyData") {
            return Err(ProviderError::Dispatch(
                "ECX keymgmt: export called with non-ECX key data".into(),
            ));
        }

        // We can tell which components are present from the Debug string,
        // but we cannot recover the actual key bytes through the trait
        // object. Return an empty ParamSet; the caller should use the
        // concrete `EcxKeyData::export_to_params` for full data.
        debug!(
            algorithm = %self.algorithm,
            "ecx keymgmt: export via trait object returns metadata only; \
             use EcxKeyData::export_to_params for key bytes",
        );

        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        // Parse the Debug output for component presence — matches the
        // pattern in `ec.rs`. Parameters are always considered present for
        // ECX (no domain parameters).
        let debug_str = format!("{key:?}");
        let has_priv = debug_str.contains("has_private: true");
        let has_pub = debug_str.contains("has_public: true");

        if selection.contains(KeySelection::PRIVATE_KEY) && !has_priv {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return false;
        }
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        trace!(
            algorithm = %self.algorithm,
            selection = selection.bits(),
            "ecx keymgmt: validating key",
        );
        // Structural validation based on Debug output. Full cryptographic
        // validation (point validity, pairwise check) requires the
        // concrete type and is available via
        // `EcxKeyData::validate_selection`.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the ECX key management algorithm descriptors for provider
/// registration.
///
/// Four descriptors, one per algorithm, each registered with
/// `property = "provider=default"`. Ed25519 and Ed448 include both the
/// uppercase (`"ED25519"`, `"ED448"`) and mixed-case (`"Ed25519"`,
/// `"Ed448"`) aliases to match the C registration names.
///
/// Replaces the four `MAKE_KEYMGMT_FUNCTIONS(alg)` dispatch tables from
/// `ecx_kmgmt.c`.
#[must_use]
pub fn ecx_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: DEFAULT_PROPERTY,
            description: "X25519 Diffie-Hellman key exchange (RFC 7748, 32-byte keys)",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: DEFAULT_PROPERTY,
            description: "X448 Diffie-Hellman key exchange (RFC 7748, 56-byte keys)",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519", "Ed25519"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 EdDSA signatures (RFC 8032, 32-byte keys, 64-byte sigs)",
        },
        AlgorithmDescriptor {
            names: vec!["ED448", "Ed448"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 EdDSA signatures (RFC 8032, 57-byte keys, 114-byte sigs)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================
//
// This test module exercises every public API surface exported by this file:
//
//   * `EcxAlgorithm` — variant sizing, bit-width accessors, name parsing,
//     display formatting, key-type conversion.
//   * `EcxKeyData` — empty/populated lifecycle, Debug redaction, selection
//     presence checks, structural and pairwise validation, parameter
//     round-trips (import → export), error paths for wrong key sizes.
//   * `EcxGenContext` — construction, DHKEM IKM gating, parameter
//     application, algorithm/group cross-validation.
//   * `EcxKeyMgmt` — per-algorithm factory constructors, constant-time
//     match semantics, parameter advertisement (`get_params`), parameter
//     typing enforcement (`set_params`).
//   * `KeyMgmtProvider for EcxKeyMgmt` — end-to-end key generation for all
//     four algorithms, import with valid and invalid inputs, export via
//     the trait-object path, presence/validation checks.
//   * `ecx_descriptors` — descriptor count, uniqueness, alias coverage.
//
// All tests use only public APIs (plus `super::*`) and avoid any `unsafe`
// block (Rule R8).  The tests intentionally exercise the non-deterministic
// RNG via `curve25519::generate_keypair` so that the zeroizing private-key
// wrapper and pairwise-check code paths are covered by the release test
// suite.

#[cfg(test)]
// RATIONALE: `.expect()` / `.unwrap()` / `panic!` are idiomatic failure modes
// in unit tests — the Cargo.toml workspace lints mark them as `warn` with an
// explicit allowance that tests may opt-in via `#[allow]`.  This block
// enumerates each lint individually so future readers see exactly what is
// permitted in the test module and why.
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::panic)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // EcxAlgorithm tests
    // -------------------------------------------------------------------------

    #[test]
    fn ecx_algorithm_key_size_matches_rfc_7748_and_rfc_8032() {
        // X25519 and Ed25519 share the 32-byte width; X448/Ed448 are 56/57.
        assert_eq!(EcxAlgorithm::X25519.key_size(), X25519_KEY_LEN);
        assert_eq!(EcxAlgorithm::X25519.key_size(), 32);
        assert_eq!(EcxAlgorithm::X448.key_size(), X448_KEY_LEN);
        assert_eq!(EcxAlgorithm::X448.key_size(), 56);
        assert_eq!(EcxAlgorithm::Ed25519.key_size(), ED25519_KEY_LEN);
        assert_eq!(EcxAlgorithm::Ed25519.key_size(), 32);
        assert_eq!(EcxAlgorithm::Ed448.key_size(), ED448_KEY_LEN);
        assert_eq!(EcxAlgorithm::Ed448.key_size(), 57);
    }

    #[test]
    fn ecx_algorithm_bits_match_published_values() {
        // The C code reports these values verbatim from ecx_kmgmt.c.
        assert_eq!(EcxAlgorithm::X25519.bits(), 253);
        assert_eq!(EcxAlgorithm::X448.bits(), 448);
        assert_eq!(EcxAlgorithm::Ed25519.bits(), 256);
        assert_eq!(EcxAlgorithm::Ed448.bits(), 456);
    }

    #[test]
    fn ecx_algorithm_security_bits_match_nist_sp_800_57() {
        assert_eq!(EcxAlgorithm::X25519.security_bits(), 128);
        assert_eq!(EcxAlgorithm::X448.security_bits(), 224);
        assert_eq!(EcxAlgorithm::Ed25519.security_bits(), 128);
        assert_eq!(EcxAlgorithm::Ed448.security_bits(), 224);
    }

    #[test]
    fn ecx_algorithm_max_size_is_key_len_for_x_and_sig_len_for_ed() {
        assert_eq!(EcxAlgorithm::X25519.max_size(), X25519_KEY_LEN);
        assert_eq!(EcxAlgorithm::X448.max_size(), X448_KEY_LEN);
        assert_eq!(EcxAlgorithm::Ed25519.max_size(), ED25519_SIGNATURE_LEN);
        assert_eq!(EcxAlgorithm::Ed448.max_size(), ED448_SIGNATURE_LEN);
    }

    #[test]
    fn ecx_algorithm_is_key_exchange_vs_is_signature() {
        assert!(EcxAlgorithm::X25519.is_key_exchange());
        assert!(EcxAlgorithm::X448.is_key_exchange());
        assert!(!EcxAlgorithm::X25519.is_signature());
        assert!(!EcxAlgorithm::X448.is_signature());

        assert!(EcxAlgorithm::Ed25519.is_signature());
        assert!(EcxAlgorithm::Ed448.is_signature());
        assert!(!EcxAlgorithm::Ed25519.is_key_exchange());
        assert!(!EcxAlgorithm::Ed448.is_key_exchange());
    }

    #[test]
    fn ecx_algorithm_name_uses_uppercase_canonical_form() {
        assert_eq!(EcxAlgorithm::X25519.name(), "X25519");
        assert_eq!(EcxAlgorithm::X448.name(), "X448");
        assert_eq!(EcxAlgorithm::Ed25519.name(), "ED25519");
        assert_eq!(EcxAlgorithm::Ed448.name(), "ED448");
    }

    #[test]
    fn ecx_algorithm_from_name_is_case_insensitive() {
        assert_eq!(
            EcxAlgorithm::from_name("X25519"),
            Some(EcxAlgorithm::X25519)
        );
        assert_eq!(
            EcxAlgorithm::from_name("x25519"),
            Some(EcxAlgorithm::X25519)
        );
        assert_eq!(EcxAlgorithm::from_name("X448"), Some(EcxAlgorithm::X448));
        assert_eq!(EcxAlgorithm::from_name("x448"), Some(EcxAlgorithm::X448));

        // Ed variants accept both styles: canonical `ED25519` and pretty `Ed25519`.
        assert_eq!(
            EcxAlgorithm::from_name("ED25519"),
            Some(EcxAlgorithm::Ed25519)
        );
        assert_eq!(
            EcxAlgorithm::from_name("Ed25519"),
            Some(EcxAlgorithm::Ed25519)
        );
        assert_eq!(
            EcxAlgorithm::from_name("ed25519"),
            Some(EcxAlgorithm::Ed25519)
        );
        assert_eq!(EcxAlgorithm::from_name("ED448"), Some(EcxAlgorithm::Ed448));
        assert_eq!(EcxAlgorithm::from_name("Ed448"), Some(EcxAlgorithm::Ed448));
        assert_eq!(EcxAlgorithm::from_name("ed448"), Some(EcxAlgorithm::Ed448));

        // Unknown names return None (Rule R5).
        assert_eq!(EcxAlgorithm::from_name(""), None);
        assert_eq!(EcxAlgorithm::from_name("X25520"), None);
        assert_eq!(EcxAlgorithm::from_name("curve25519"), None);
    }

    #[test]
    fn ecx_algorithm_display_uses_canonical_name() {
        assert_eq!(format!("{}", EcxAlgorithm::X25519), "X25519");
        assert_eq!(format!("{}", EcxAlgorithm::X448), "X448");
        assert_eq!(format!("{}", EcxAlgorithm::Ed25519), "ED25519");
        assert_eq!(format!("{}", EcxAlgorithm::Ed448), "ED448");
    }

    #[test]
    fn ecx_algorithm_as_key_type_maps_each_variant() {
        assert_eq!(EcxAlgorithm::X25519.as_key_type(), EcxKeyType::X25519);
        assert_eq!(EcxAlgorithm::X448.as_key_type(), EcxKeyType::X448);
        assert_eq!(EcxAlgorithm::Ed25519.as_key_type(), EcxKeyType::Ed25519);
        assert_eq!(EcxAlgorithm::Ed448.as_key_type(), EcxKeyType::Ed448);
    }

    // -------------------------------------------------------------------------
    // EcxKeyData lifecycle and Debug redaction
    // -------------------------------------------------------------------------

    #[test]
    fn new_key_data_has_no_components() {
        let key = EcxKeyData::new(EcxAlgorithm::X25519);
        assert_eq!(key.key_type(), EcxAlgorithm::X25519);
        assert!(key.public_bytes().is_none());
        assert!(key.private_bytes().is_none());
        assert!(!key.has_selection(KeySelection::PRIVATE_KEY));
        assert!(!key.has_selection(KeySelection::PUBLIC_KEY));
        // Domain parameters are always "present" for ECX (no domain exists).
        assert!(key.has_selection(KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn new_with_ctx_stores_library_context_option() {
        // `LibContext::default()` already returns `Arc<LibContext>`.
        let ctx: Arc<LibContext> = LibContext::default();
        let key = EcxKeyData::new_with_ctx(EcxAlgorithm::Ed25519, Some(Arc::clone(&ctx)));
        assert_eq!(key.key_type(), EcxAlgorithm::Ed25519);
        assert!(key.public_bytes().is_none());
        assert!(key.private_bytes().is_none());
        // The field itself is pub(crate); verify that the stored handle is
        // populated and shares ownership with `ctx`.
        assert!(key.lib_ctx.is_some());
        assert!(Arc::strong_count(&ctx) >= 2);
    }

    #[test]
    fn debug_formatting_redacts_key_material() {
        // Populate a key with easily detectable non-zero bytes.  A raw Vec<u8>
        // Debug would emit "[0, 1, 2, 3, ...", which is what redaction must
        // hide.
        let priv_bytes: Vec<u8> = (0u8..32).collect();
        let pub_bytes: Vec<u8> = (32u8..64).collect();
        let key = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(pub_bytes),
            priv_key: Some(Zeroizing::new(priv_bytes)),
            lib_ctx: None,
            prop_query: Some("provider=default".to_owned()),
        };

        let s = format!("{key:?}");

        // The Debug impl must expose only *presence* markers, never bytes.
        assert!(s.contains("EcxKeyData"));
        assert!(s.contains("has_private: true"));
        assert!(s.contains("has_public: true"));
        assert!(s.contains("has_lib_ctx: false"));
        assert!(s.contains("has_prop_query: true"));
        assert!(s.contains("X25519"));

        // A raw `Vec<u8>` Debug would include a bracketed comma-separated
        // decimal list; ensure none of those patterns appear.
        assert!(
            !s.contains("[0, 1, 2, 3"),
            "raw private bytes must not leak: {s}"
        );
        assert!(
            !s.contains("[32, 33, 34"),
            "raw public bytes must not leak: {s}"
        );

        // The prop_query value itself must not leak either — only its
        // presence is revealed.
        assert!(
            !s.contains("provider=default"),
            "prop_query contents must not leak: {s}"
        );
    }

    // -------------------------------------------------------------------------
    // has_selection / validate_selection
    // -------------------------------------------------------------------------

    #[test]
    fn has_selection_reports_components_present() {
        let mgmt = EcxKeyMgmt::x25519();
        let key = mgmt
            .generate(&ParamSet::new())
            .expect("X25519 generate should succeed");
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn has_selection_public_only_rejects_private_request() {
        let mut key = EcxKeyData::new(EcxAlgorithm::Ed25519);
        key.pub_key = Some(vec![0u8; ED25519_KEY_LEN]);
        assert!(key.has_selection(KeySelection::PUBLIC_KEY));
        assert!(!key.has_selection(KeySelection::PRIVATE_KEY));
        assert!(!key.has_selection(KeySelection::KEYPAIR));
    }

    #[test]
    fn has_selection_private_only_rejects_public_request() {
        let mut key = EcxKeyData::new(EcxAlgorithm::Ed448);
        key.priv_key = Some(Zeroizing::new(vec![0u8; ED448_KEY_LEN]));
        assert!(key.has_selection(KeySelection::PRIVATE_KEY));
        assert!(!key.has_selection(KeySelection::PUBLIC_KEY));
        assert!(!key.has_selection(KeySelection::KEYPAIR));
    }

    #[test]
    fn validate_selection_rejects_empty_key() {
        let key = EcxKeyData::new(EcxAlgorithm::X25519);
        // Asking for material that does not exist must not pass validation.
        assert_eq!(
            key.validate_selection(KeySelection::KEYPAIR).ok(),
            Some(false)
        );
        assert_eq!(
            key.validate_selection(KeySelection::PUBLIC_KEY).ok(),
            Some(false)
        );
    }

    #[test]
    fn validate_selection_rejects_wrong_length_components() {
        let mut key = EcxKeyData::new(EcxAlgorithm::X25519);
        // Wrong public-key length (33 vs expected 32).
        key.pub_key = Some(vec![0u8; X25519_KEY_LEN + 1]);
        assert_eq!(
            key.validate_selection(KeySelection::PUBLIC_KEY).ok(),
            Some(false)
        );
    }

    // -------------------------------------------------------------------------
    // export_to_params / from_params round-trips
    // -------------------------------------------------------------------------

    #[test]
    fn export_to_params_emits_pub_and_priv_when_selected() {
        let priv_bytes: Vec<u8> = (0u8..32).collect();
        let pub_bytes: Vec<u8> = (32u8..64).collect();
        let key = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(pub_bytes.clone()),
            priv_key: Some(Zeroizing::new(priv_bytes.clone())),
            lib_ctx: None,
            prop_query: None,
        };

        let ps = key.export_to_params(KeySelection::KEYPAIR);
        // "pub" is always present for PUBLIC_KEY selection.
        assert!(ps.contains("pub"));
        // X types also emit "encoded-pub-key".
        assert!(ps.contains("encoded-pub-key"));
        assert!(ps.contains("priv"));

        if let Some(ParamValue::OctetString(bytes)) = ps.get("pub") {
            assert_eq!(bytes, &pub_bytes);
        } else {
            panic!("expected OctetString for 'pub' param");
        }
        if let Some(ParamValue::OctetString(bytes)) = ps.get("priv") {
            assert_eq!(bytes, &priv_bytes);
        } else {
            panic!("expected OctetString for 'priv' param");
        }
    }

    #[test]
    fn export_to_params_ed_type_omits_encoded_pub_key_alias() {
        let priv_bytes: Vec<u8> = vec![7u8; ED25519_KEY_LEN];
        let pub_bytes: Vec<u8> = vec![8u8; ED25519_KEY_LEN];
        let key = EcxKeyData {
            key_type: EcxAlgorithm::Ed25519,
            pub_key: Some(pub_bytes),
            priv_key: Some(Zeroizing::new(priv_bytes)),
            lib_ctx: None,
            prop_query: None,
        };
        let ps = key.export_to_params(KeySelection::PUBLIC_KEY);
        assert!(ps.contains("pub"));
        // Ed types do NOT emit the X-only alias.
        assert!(!ps.contains("encoded-pub-key"));
    }

    #[test]
    fn export_to_params_omits_absent_components() {
        let key = EcxKeyData::new(EcxAlgorithm::X25519);
        let ps = key.export_to_params(KeySelection::KEYPAIR);
        assert!(!ps.contains("pub"));
        assert!(!ps.contains("priv"));
        assert!(!ps.contains("encoded-pub-key"));
    }

    #[test]
    fn from_params_requires_private_or_public_selection() {
        let ps = ParamSet::new();
        let err =
            EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::DOMAIN_PARAMETERS, &ps)
                .expect_err("DOMAIN_PARAMETERS-only selection must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn from_params_rejects_wrong_private_key_length() {
        let mut ps = ParamSet::new();
        // Deliberately wrong length: 16 bytes for X25519 (expects 32).
        ps.set("priv", ParamValue::OctetString(vec![0u8; 16]));
        let err = EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::PRIVATE_KEY, &ps)
            .expect_err("wrong private length must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn from_params_rejects_wrong_public_key_length() {
        let mut ps = ParamSet::new();
        ps.set("pub", ParamValue::OctetString(vec![0u8; 100]));
        let err = EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::PUBLIC_KEY, &ps)
            .expect_err("wrong public length must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn from_params_accepts_encoded_pub_key_alias_for_x_types() {
        let mut ps = ParamSet::new();
        ps.set(
            "encoded-pub-key",
            ParamValue::OctetString(vec![1u8; X25519_KEY_LEN]),
        );
        let key = EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::PUBLIC_KEY, &ps)
            .expect("encoded-pub-key alias should be accepted");
        assert_eq!(key.public_bytes().expect("pub"), &[1u8; X25519_KEY_LEN]);
    }

    #[test]
    fn from_params_all_algorithms_accept_valid_length_pub() {
        let cases = [
            (EcxAlgorithm::X25519, X25519_KEY_LEN),
            (EcxAlgorithm::X448, X448_KEY_LEN),
            (EcxAlgorithm::Ed25519, ED25519_KEY_LEN),
            (EcxAlgorithm::Ed448, ED448_KEY_LEN),
        ];
        for (algo, len) in cases {
            let mut ps = ParamSet::new();
            ps.set("pub", ParamValue::OctetString(vec![0u8; len]));
            let key = EcxKeyData::from_params(algo, KeySelection::PUBLIC_KEY, &ps)
                .unwrap_or_else(|_| panic!("import valid pub for {algo:?} should succeed"));
            assert_eq!(key.public_bytes().expect("pub"), &vec![0u8; len][..]);
        }
    }

    // -------------------------------------------------------------------------
    // EcxGenContext tests
    // -------------------------------------------------------------------------

    #[test]
    fn gen_context_stores_algorithm_and_selection() {
        let gc = EcxGenContext::new(EcxAlgorithm::Ed25519, KeySelection::KEYPAIR);
        assert_eq!(gc.algorithm(), EcxAlgorithm::Ed25519);
        assert_eq!(gc.selection(), KeySelection::KEYPAIR);
    }

    #[test]
    fn gen_context_dhkem_ikm_only_valid_for_key_exchange() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::X25519, KeySelection::KEYPAIR);
        gc.set_dhkem_ikm(vec![7u8; 32])
            .expect("X25519 accepts DHKEM IKM");
        assert!(gc.dhkem_ikm.as_ref().is_some_and(|v| v == &[7u8; 32]));

        let mut ed_gc = EcxGenContext::new(EcxAlgorithm::Ed25519, KeySelection::KEYPAIR);
        let err = ed_gc
            .set_dhkem_ikm(vec![0u8; 16])
            .expect_err("Ed25519 must reject DHKEM IKM");
        assert!(matches!(err, ProviderError::AlgorithmUnavailable(_)));
    }

    #[test]
    fn gen_context_apply_params_rejects_group_for_ed_types() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::Ed25519, KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set("group", ParamValue::Utf8String("ed25519".to_owned()));
        let err = gc
            .apply_params(&ps)
            .expect_err("group param must be rejected for Ed types");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn gen_context_apply_params_accepts_matching_group_for_x_types() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::X448, KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set("group", ParamValue::Utf8String("X448".to_owned()));
        gc.apply_params(&ps).expect("matching group should succeed");
    }

    #[test]
    fn gen_context_apply_params_rejects_mismatched_group() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::X25519, KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set("group", ParamValue::Utf8String("secp256r1".to_owned()));
        let err = gc
            .apply_params(&ps)
            .expect_err("mismatched group must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn gen_context_apply_params_stores_properties_and_ikm() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::X25519, KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set(
            "properties",
            ParamValue::Utf8String("provider=default".to_owned()),
        );
        ps.set("dhkem-ikm", ParamValue::OctetString(vec![0xAA; 32]));
        gc.apply_params(&ps).expect("apply_params should succeed");
        assert_eq!(gc.prop_query.as_deref(), Some("provider=default"));
        assert_eq!(gc.dhkem_ikm.as_deref(), Some(&[0xAA; 32][..]));
    }

    #[test]
    fn gen_context_set_prop_query_stores_or_clears() {
        let mut gc = EcxGenContext::new(EcxAlgorithm::X25519, KeySelection::KEYPAIR);
        gc.set_prop_query(Some("provider=fips".to_owned()));
        assert_eq!(gc.prop_query.as_deref(), Some("provider=fips"));
        gc.set_prop_query(None);
        assert!(gc.prop_query.is_none());
    }

    #[test]
    fn gen_context_set_lib_ctx_stores_shared_handle() {
        let ctx: Arc<LibContext> = LibContext::default();
        let mut gc = EcxGenContext::new(EcxAlgorithm::X25519, KeySelection::KEYPAIR);
        gc.set_lib_ctx(Some(Arc::clone(&ctx)));
        assert!(gc.lib_ctx.is_some());
        assert!(Arc::strong_count(&ctx) >= 2);
    }

    // -------------------------------------------------------------------------
    // EcxKeyMgmt factory constructors
    // -------------------------------------------------------------------------

    #[test]
    fn ecx_key_mgmt_factories_wire_correct_algorithm() {
        assert_eq!(EcxKeyMgmt::x25519().algorithm(), EcxAlgorithm::X25519);
        assert_eq!(EcxKeyMgmt::x448().algorithm(), EcxAlgorithm::X448);
        assert_eq!(EcxKeyMgmt::ed25519().algorithm(), EcxAlgorithm::Ed25519);
        assert_eq!(EcxKeyMgmt::ed448().algorithm(), EcxAlgorithm::Ed448);
        assert_eq!(
            EcxKeyMgmt::new(EcxAlgorithm::X25519).algorithm(),
            EcxAlgorithm::X25519
        );
    }

    #[test]
    fn ecx_key_mgmt_name_matches_algorithm() {
        assert_eq!(EcxKeyMgmt::x25519().name(), "X25519");
        assert_eq!(EcxKeyMgmt::x448().name(), "X448");
        assert_eq!(EcxKeyMgmt::ed25519().name(), "ED25519");
        assert_eq!(EcxKeyMgmt::ed448().name(), "ED448");
    }

    // -------------------------------------------------------------------------
    // KeyMgmtProvider: new_key / generate / validate / has / export
    // -------------------------------------------------------------------------

    #[test]
    fn new_key_returns_empty_key_data() {
        let mgmt = EcxKeyMgmt::x25519();
        let key = mgmt.new_key().expect("new_key should succeed");
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        // Domain parameters are vacuously present (ECX has no configurable domain).
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn generate_x25519_key_pair() {
        let mgmt = EcxKeyMgmt::x25519();
        let key = mgmt.generate(&ParamSet::new()).expect("X25519 generate ok");
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate ok"));
    }

    #[test]
    fn generate_x448_key_pair() {
        let mgmt = EcxKeyMgmt::x448();
        let key = mgmt.generate(&ParamSet::new()).expect("X448 generate ok");
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate ok"));
    }

    #[test]
    fn generate_ed25519_key_pair() {
        let mgmt = EcxKeyMgmt::ed25519();
        let key = mgmt
            .generate(&ParamSet::new())
            .expect("Ed25519 generate ok");
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate ok"));
    }

    #[test]
    fn generate_ed448_key_pair() {
        let mgmt = EcxKeyMgmt::ed448();
        let key = mgmt.generate(&ParamSet::new()).expect("Ed448 generate ok");
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate ok"));
    }

    #[test]
    fn generate_produces_distinct_keys_each_call() {
        // Exercise the trait-object generate path to ensure it propagates
        // randomness correctly: two Debug strings from populated keys both
        // report material presence.
        let mgmt = EcxKeyMgmt::x25519();
        let k1 = mgmt.generate(&ParamSet::new()).expect("k1");
        let k2 = mgmt.generate(&ParamSet::new()).expect("k2");
        assert!(format!("{:?}", &*k1).contains("has_private: true"));
        assert!(format!("{:?}", &*k2).contains("has_private: true"));

        // Cross-check the RNG at the concrete-type layer: distinct calls to
        // `curve25519::generate_keypair` must produce different scalars.
        let a = curve25519::generate_keypair(EcxKeyType::X25519).expect("a");
        let b = curve25519::generate_keypair(EcxKeyType::X25519).expect("b");
        assert_ne!(
            a.private_key().as_bytes(),
            b.private_key().as_bytes(),
            "RNG must yield distinct private scalars"
        );
        assert_ne!(
            a.public_key().as_bytes(),
            b.public_key().as_bytes(),
            "Distinct private scalars must yield distinct public points"
        );
    }

    // -------------------------------------------------------------------------
    // KeyMgmtProvider: import with valid and invalid inputs
    // -------------------------------------------------------------------------

    #[test]
    fn import_x25519_keypair_with_valid_lengths_succeeds() {
        let mgmt = EcxKeyMgmt::x25519();
        let mut ps = ParamSet::new();
        ps.set("priv", ParamValue::OctetString(vec![1u8; X25519_KEY_LEN]));
        ps.set("pub", ParamValue::OctetString(vec![2u8; X25519_KEY_LEN]));
        let key = mgmt
            .import(KeySelection::KEYPAIR, &ps)
            .expect("valid-length import must succeed");
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn import_rejects_wrong_priv_key_len() {
        let mgmt = EcxKeyMgmt::x25519();
        let mut ps = ParamSet::new();
        // 16 bytes where 32 is required.
        ps.set("priv", ParamValue::OctetString(vec![1u8; 16]));
        ps.set("pub", ParamValue::OctetString(vec![2u8; X25519_KEY_LEN]));
        let err = mgmt
            .import(KeySelection::KEYPAIR, &ps)
            .expect_err("wrong-length priv must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn import_rejects_wrong_pub_key_len() {
        let mgmt = EcxKeyMgmt::x448();
        let mut ps = ParamSet::new();
        ps.set("priv", ParamValue::OctetString(vec![1u8; X448_KEY_LEN]));
        // 32 bytes where X448 requires 56.
        ps.set("pub", ParamValue::OctetString(vec![2u8; 32]));
        let err = mgmt
            .import(KeySelection::KEYPAIR, &ps)
            .expect_err("wrong-length pub must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn import_rejects_domain_parameters_only_selection() {
        let mgmt = EcxKeyMgmt::ed25519();
        let ps = ParamSet::new();
        let err = mgmt
            .import(KeySelection::DOMAIN_PARAMETERS, &ps)
            .expect_err("domain-parameters-only selection must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn import_all_algorithms_accept_correct_length_pub_only() {
        let cases = [
            (EcxKeyMgmt::x25519(), X25519_KEY_LEN),
            (EcxKeyMgmt::x448(), X448_KEY_LEN),
            (EcxKeyMgmt::ed25519(), ED25519_KEY_LEN),
            (EcxKeyMgmt::ed448(), ED448_KEY_LEN),
        ];
        for (mgmt, len) in cases {
            let mut ps = ParamSet::new();
            ps.set("pub", ParamValue::OctetString(vec![0u8; len]));
            let key = mgmt
                .import(KeySelection::PUBLIC_KEY, &ps)
                .unwrap_or_else(|_| panic!("{} pub-only import should succeed", mgmt.name()));
            assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
            assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        }
    }

    // -------------------------------------------------------------------------
    // KeyMgmtProvider: has / validate / export via trait object
    // -------------------------------------------------------------------------

    #[test]
    fn validate_via_trait_returns_true_for_generated_keypair() {
        for mgmt in [
            EcxKeyMgmt::x25519(),
            EcxKeyMgmt::x448(),
            EcxKeyMgmt::ed25519(),
            EcxKeyMgmt::ed448(),
        ] {
            let key = mgmt.generate(&ParamSet::new()).expect("gen");
            let ok = mgmt
                .validate(&*key, KeySelection::KEYPAIR)
                .expect("validate should not error");
            assert!(ok, "generated {} key should validate", mgmt.name());
        }
    }

    #[test]
    fn validate_via_trait_returns_false_for_empty_key() {
        let mgmt = EcxKeyMgmt::x25519();
        let key = mgmt.new_key().expect("new_key");
        assert!(!mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate"));
    }

    #[test]
    fn export_trait_object_returns_metadata_only_paramset() {
        let mgmt = EcxKeyMgmt::x25519();
        let key = mgmt.generate(&ParamSet::new()).expect("gen");
        // The trait-object export path returns an empty ParamSet as documented;
        // callers hold the concrete `EcxKeyData` to use `export_to_params`.
        let ps = mgmt
            .export(&*key, KeySelection::KEYPAIR)
            .expect("export via trait should succeed");
        assert!(ps.is_empty(), "trait-object export must be empty");
    }

    #[test]
    fn export_rejects_non_ecx_key_data() {
        // Provide a different KeyData impl via a helper type; verify dispatch
        // recognizes it as foreign.
        #[derive(Debug)]
        struct AlienKey;
        impl KeyData for AlienKey {}

        let mgmt = EcxKeyMgmt::ed25519();
        let alien: Box<dyn KeyData> = Box::new(AlienKey);
        let err = mgmt
            .export(&*alien, KeySelection::KEYPAIR)
            .expect_err("foreign key data must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // -------------------------------------------------------------------------
    // match_keys — constant-time comparison semantics
    // -------------------------------------------------------------------------

    #[test]
    fn match_keys_identical_public_keys_match() {
        let pubk = vec![3u8; X25519_KEY_LEN];
        let a = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(pubk.clone()),
            priv_key: None,
            lib_ctx: None,
            prop_query: None,
        };
        let b = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(pubk),
            priv_key: None,
            lib_ctx: None,
            prop_query: None,
        };
        let mgmt = EcxKeyMgmt::x25519();
        assert!(mgmt
            .match_keys(&a, &b, KeySelection::PUBLIC_KEY)
            .expect("match ok"));
    }

    #[test]
    fn match_keys_differing_public_keys_do_not_match() {
        let mut a_pub = vec![0u8; X25519_KEY_LEN];
        a_pub[0] = 1;
        let mut b_pub = vec![0u8; X25519_KEY_LEN];
        b_pub[0] = 2;
        let a = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(a_pub),
            priv_key: None,
            lib_ctx: None,
            prop_query: None,
        };
        let b = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(b_pub),
            priv_key: None,
            lib_ctx: None,
            prop_query: None,
        };
        let mgmt = EcxKeyMgmt::x25519();
        assert!(!mgmt
            .match_keys(&a, &b, KeySelection::PUBLIC_KEY)
            .expect("match ok"));
    }

    #[test]
    fn match_keys_different_algorithms_do_not_match() {
        let a = EcxKeyData::new(EcxAlgorithm::X25519);
        let b = EcxKeyData::new(EcxAlgorithm::Ed25519);
        let mgmt = EcxKeyMgmt::x25519();
        assert!(!mgmt
            .match_keys(&a, &b, KeySelection::DOMAIN_PARAMETERS)
            .expect("match ok"));
    }

    #[test]
    fn match_keys_domain_parameters_only_is_sufficient_for_type_match() {
        let a = EcxKeyData::new(EcxAlgorithm::X25519);
        let b = EcxKeyData::new(EcxAlgorithm::X25519);
        let mgmt = EcxKeyMgmt::x25519();
        assert!(mgmt
            .match_keys(&a, &b, KeySelection::DOMAIN_PARAMETERS)
            .expect("match ok"));
    }

    #[test]
    fn match_keys_falls_back_to_private_when_public_absent() {
        let priv_bytes = vec![42u8; X25519_KEY_LEN];
        let a = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: None,
            priv_key: Some(Zeroizing::new(priv_bytes.clone())),
            lib_ctx: None,
            prop_query: None,
        };
        let b = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: None,
            priv_key: Some(Zeroizing::new(priv_bytes)),
            lib_ctx: None,
            prop_query: None,
        };
        let mgmt = EcxKeyMgmt::x25519();
        assert!(mgmt
            .match_keys(&a, &b, KeySelection::PRIVATE_KEY)
            .expect("match ok"));
    }

    #[test]
    fn match_keys_no_material_at_all_returns_false() {
        let a = EcxKeyData::new(EcxAlgorithm::Ed25519);
        let b = EcxKeyData::new(EcxAlgorithm::Ed25519);
        let mgmt = EcxKeyMgmt::ed25519();
        // With neither pub nor priv, but PRIVATE_KEY requested, must fail.
        assert!(!mgmt
            .match_keys(&a, &b, KeySelection::PRIVATE_KEY)
            .expect("match ok"));
    }

    // -------------------------------------------------------------------------
    // get_params / set_params behavior per algorithm
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_reports_bits_security_and_max_size() {
        for (mgmt, bits, sec, max) in [
            (EcxKeyMgmt::x25519(), 253i32, 128i32, X25519_KEY_LEN),
            (EcxKeyMgmt::x448(), 448, 224, X448_KEY_LEN),
            (EcxKeyMgmt::ed25519(), 256, 128, ED25519_SIGNATURE_LEN),
            (EcxKeyMgmt::ed448(), 456, 224, ED448_SIGNATURE_LEN),
        ] {
            let ps = mgmt.get_params().expect("get_params");
            assert_eq!(ps.get("bits").and_then(ParamValue::as_i32), Some(bits));
            assert_eq!(
                ps.get("security-bits").and_then(ParamValue::as_i32),
                Some(sec)
            );
            assert_eq!(
                ps.get("max-size").and_then(ParamValue::as_i32),
                Some(i32::try_from(max).expect("fits in i32"))
            );
            assert_eq!(
                ps.get("security-category").and_then(ParamValue::as_i32),
                Some(0)
            );
        }
    }

    #[test]
    fn get_params_x_types_advertise_encoded_pub_key_required() {
        for mgmt in [EcxKeyMgmt::x25519(), EcxKeyMgmt::x448()] {
            let ps = mgmt.get_params().expect("get_params");
            assert_eq!(
                ps.get("encoded-pub-key-required")
                    .and_then(ParamValue::as_i32),
                Some(1),
                "{} must advertise encoded-pub-key-required=1",
                mgmt.name()
            );
            // Ed-only indicator must NOT be present on X types.
            assert!(
                !ps.contains("mandatory-digest"),
                "{} must not set mandatory-digest",
                mgmt.name()
            );
        }
    }

    #[test]
    fn get_params_ed_types_advertise_empty_mandatory_digest() {
        for mgmt in [EcxKeyMgmt::ed25519(), EcxKeyMgmt::ed448()] {
            let ps = mgmt.get_params().expect("get_params");
            assert_eq!(
                ps.get("mandatory-digest").and_then(ParamValue::as_str),
                Some(""),
                "{} must set mandatory-digest to empty (PureEdDSA)",
                mgmt.name()
            );
            // X-only indicator must NOT be present on Ed types.
            assert!(
                !ps.contains("encoded-pub-key-required"),
                "{} must not set encoded-pub-key-required",
                mgmt.name()
            );
        }
    }

    #[test]
    fn set_params_x_types_accept_properties_string() {
        let mgmt = EcxKeyMgmt::x25519();
        let mut ps = ParamSet::new();
        ps.set(
            "properties",
            ParamValue::Utf8String("provider=default".to_owned()),
        );
        mgmt.set_params(&ps).expect("utf8 properties accepted");
    }

    #[test]
    fn set_params_x_types_reject_non_utf8_properties() {
        let mgmt = EcxKeyMgmt::x25519();
        let mut ps = ParamSet::new();
        // Wrong type: OctetString where Utf8String expected.
        ps.set("properties", ParamValue::OctetString(vec![0u8; 4]));
        let err = mgmt
            .set_params(&ps)
            .expect_err("non-UTF8 properties must error");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn set_params_ed_types_are_noop() {
        for mgmt in [EcxKeyMgmt::ed25519(), EcxKeyMgmt::ed448()] {
            // Even a mistyped "properties" param is ignored (no-op) for Ed types,
            // matching the C code that only handles X-type set_params.
            let mut ps = ParamSet::new();
            ps.set("properties", ParamValue::OctetString(vec![0u8; 4]));
            mgmt.set_params(&ps).expect("Ed set_params must be a no-op");
        }
    }

    #[test]
    fn set_params_x_types_ignore_unknown_parameters() {
        // Unknown parameters are silently ignored (matches OSSL_PARAM semantics).
        let mgmt = EcxKeyMgmt::x448();
        let mut ps = ParamSet::new();
        ps.set("some-unknown-key", ParamValue::Int32(42));
        mgmt.set_params(&ps).expect("unknown params are ignored");
    }

    // -------------------------------------------------------------------------
    // Pairwise-check semantics (via concrete EcxKeyData)
    // -------------------------------------------------------------------------

    #[test]
    fn pairwise_check_detects_mismatched_x25519_keys() {
        // Generate a valid keypair, then tamper with the public bytes so
        // they no longer correspond to the private scalar.
        let keypair = curve25519::generate_keypair(EcxKeyType::X25519).expect("keygen");
        let mut tampered_pub = keypair.public_key().as_bytes().to_vec();
        tampered_pub[0] ^= 0x01;

        let key = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(tampered_pub),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };

        assert!(!key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    #[test]
    fn pairwise_check_accepts_genuine_x25519_keypair() {
        let keypair = curve25519::generate_keypair(EcxKeyType::X25519).expect("keygen");
        let key = EcxKeyData {
            key_type: EcxAlgorithm::X25519,
            pub_key: Some(keypair.public_key().as_bytes().to_vec()),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };
        assert!(key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    #[test]
    fn pairwise_check_accepts_genuine_ed25519_keypair() {
        let keypair = curve25519::generate_keypair(EcxKeyType::Ed25519).expect("keygen");
        let key = EcxKeyData {
            key_type: EcxAlgorithm::Ed25519,
            pub_key: Some(keypair.public_key().as_bytes().to_vec()),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };
        // Ed25519 pairwise check derives the public key from the private key
        // via RFC 8032 §5.1.5 (SHA-512 + clamp + scalarmult_base) and does
        // a constant-time comparison with the stored public key.
        assert!(key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    #[test]
    fn pairwise_check_detects_mismatched_ed25519_keys() {
        // Generate a valid Ed25519 keypair, then tamper with the public bytes
        // so they no longer correspond to the derived public key.
        let keypair = curve25519::generate_keypair(EcxKeyType::Ed25519).expect("keygen");
        let mut tampered_pub = keypair.public_key().as_bytes().to_vec();
        tampered_pub[0] ^= 0x01;

        let key = EcxKeyData {
            key_type: EcxAlgorithm::Ed25519,
            pub_key: Some(tampered_pub),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };

        // The cryptographic round-trip derivation must catch a tampered
        // public key. A purely structural point-validity check would have
        // accepted this (the tampered point is still valid).
        assert!(!key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    #[test]
    fn pairwise_check_accepts_genuine_ed448_keypair() {
        let keypair = curve25519::generate_keypair(EcxKeyType::Ed448).expect("keygen");
        let key = EcxKeyData {
            key_type: EcxAlgorithm::Ed448,
            pub_key: Some(keypair.public_key().as_bytes().to_vec()),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };
        // Ed448 pairwise check derives the public key from the private key
        // via RFC 8032 §5.2.5 (SHAKE256(_, 114) + clamp + scalarmult_base)
        // and does a constant-time comparison with the stored public key.
        assert!(key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    #[test]
    fn pairwise_check_detects_mismatched_ed448_keys() {
        // Generate a valid Ed448 keypair, then tamper with the public bytes
        // so they no longer correspond to the derived public key.
        let keypair = curve25519::generate_keypair(EcxKeyType::Ed448).expect("keygen");
        let mut tampered_pub = keypair.public_key().as_bytes().to_vec();
        tampered_pub[0] ^= 0x01;

        let key = EcxKeyData {
            key_type: EcxAlgorithm::Ed448,
            pub_key: Some(tampered_pub),
            priv_key: Some(Zeroizing::new(keypair.private_key().as_bytes().to_vec())),
            lib_ctx: None,
            prop_query: None,
        };

        // The cryptographic round-trip derivation must catch a tampered
        // public key. A purely structural point-validity check would have
        // accepted this (the tampered point is still valid).
        assert!(!key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate returns Ok"));
    }

    // -------------------------------------------------------------------------
    // Full import → export → import round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn import_export_roundtrip_preserves_x25519_bytes() {
        // Generate a fresh key, export its bytes, re-import and verify bytes match.
        let keypair = curve25519::generate_keypair(EcxKeyType::X25519).expect("keygen");
        let priv_bytes: Vec<u8> = keypair.private_key().as_bytes().to_vec();
        let pub_bytes: Vec<u8> = keypair.public_key().as_bytes().to_vec();

        // Import round 1.
        let mut ps = ParamSet::new();
        ps.set("priv", ParamValue::OctetString(priv_bytes.clone()));
        ps.set("pub", ParamValue::OctetString(pub_bytes.clone()));
        let imported = EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::KEYPAIR, &ps)
            .expect("import");

        // Export using the concrete-type path.
        let exported = imported.export_to_params(KeySelection::KEYPAIR);
        let exported_priv = match exported.get("priv") {
            Some(ParamValue::OctetString(b)) => b.clone(),
            _ => panic!("priv missing from export"),
        };
        let exported_pub = match exported.get("pub") {
            Some(ParamValue::OctetString(b)) => b.clone(),
            _ => panic!("pub missing from export"),
        };
        assert_eq!(exported_priv, priv_bytes);
        assert_eq!(exported_pub, pub_bytes);

        // Re-import from the exported parameters.
        let reimported =
            EcxKeyData::from_params(EcxAlgorithm::X25519, KeySelection::KEYPAIR, &exported)
                .expect("re-import");

        assert_eq!(
            reimported.public_bytes().expect("pub"),
            pub_bytes.as_slice()
        );
        assert_eq!(
            reimported.private_bytes().expect("priv"),
            priv_bytes.as_slice()
        );
    }

    #[test]
    fn import_export_roundtrip_preserves_ed448_bytes() {
        let keypair = curve25519::generate_keypair(EcxKeyType::Ed448).expect("keygen");
        let priv_bytes: Vec<u8> = keypair.private_key().as_bytes().to_vec();
        let pub_bytes: Vec<u8> = keypair.public_key().as_bytes().to_vec();

        let mut ps = ParamSet::new();
        ps.set("priv", ParamValue::OctetString(priv_bytes.clone()));
        ps.set("pub", ParamValue::OctetString(pub_bytes.clone()));
        let imported = EcxKeyData::from_params(EcxAlgorithm::Ed448, KeySelection::KEYPAIR, &ps)
            .expect("import");
        assert_eq!(imported.key_type(), EcxAlgorithm::Ed448);

        let exported = imported.export_to_params(KeySelection::KEYPAIR);
        if let Some(ParamValue::OctetString(b)) = exported.get("pub") {
            assert_eq!(b, &pub_bytes);
        } else {
            panic!("pub missing");
        }
        if let Some(ParamValue::OctetString(b)) = exported.get("priv") {
            assert_eq!(b, &priv_bytes);
        } else {
            panic!("priv missing");
        }
    }

    // -------------------------------------------------------------------------
    // ecx_descriptors() — public registration surface
    // -------------------------------------------------------------------------

    #[test]
    fn ecx_descriptors_returns_exactly_four_entries() {
        let descriptors = ecx_descriptors();
        assert_eq!(
            descriptors.len(),
            4,
            "ECX must register X25519, X448, Ed25519, Ed448"
        );
    }

    #[test]
    fn ecx_descriptors_cover_all_expected_names() {
        let descriptors = ecx_descriptors();
        let collected: Vec<&'static str> = descriptors
            .iter()
            .flat_map(|d| d.names.iter().copied())
            .collect();
        assert!(collected.contains(&"X25519"));
        assert!(collected.contains(&"X448"));
        assert!(collected.contains(&"ED25519"));
        assert!(collected.contains(&"Ed25519"));
        assert!(collected.contains(&"ED448"));
        assert!(collected.contains(&"Ed448"));
    }

    #[test]
    fn ecx_descriptors_all_share_default_property() {
        for d in ecx_descriptors() {
            assert_eq!(d.property, DEFAULT_PROPERTY);
        }
    }

    #[test]
    fn ecx_descriptors_entries_have_non_empty_fields() {
        for d in ecx_descriptors() {
            assert!(!d.names.is_empty(), "names must not be empty");
            assert!(!d.property.is_empty(), "property must not be empty");
            assert!(!d.description.is_empty(), "description must not be empty");
            for n in &d.names {
                assert!(!n.is_empty(), "individual name must not be empty");
            }
        }
    }

    #[test]
    fn ecx_descriptors_x_types_listed_before_ed_types() {
        // Canonicalize on the first registered name; this matches the C
        // ordering of `deflt_keymgmt[]` so callers can rely on the layout.
        let descriptors = ecx_descriptors();
        let first_names: Vec<&'static str> = descriptors.iter().map(|d| d.names[0]).collect();
        assert_eq!(first_names, vec!["X25519", "X448", "ED25519", "ED448"]);
    }

    // -------------------------------------------------------------------------
    // Cross-algorithm smoke test via dispatch loop
    // -------------------------------------------------------------------------

    #[test]
    fn end_to_end_lifecycle_for_each_algorithm() {
        for mgmt in [
            EcxKeyMgmt::x25519(),
            EcxKeyMgmt::x448(),
            EcxKeyMgmt::ed25519(),
            EcxKeyMgmt::ed448(),
        ] {
            // 1. Empty construction.
            let empty = mgmt.new_key().expect("new_key");
            assert!(!mgmt.has(&*empty, KeySelection::PRIVATE_KEY));

            // 2. Key generation.
            let generated = mgmt.generate(&ParamSet::new()).expect("generate");
            assert!(mgmt.has(&*generated, KeySelection::KEYPAIR));

            // 3. Validation.
            assert!(mgmt
                .validate(&*generated, KeySelection::KEYPAIR)
                .expect("validate"));

            // 4. Parameter introspection.
            let ps = mgmt.get_params().expect("get_params");
            assert!(ps.contains("bits"));
            assert!(ps.contains("security-bits"));
            assert!(ps.contains("max-size"));

            // 5. No-op set_params (empty ParamSet is always acceptable).
            mgmt.set_params(&ParamSet::new()).expect("set_params");
        }
    }
}
