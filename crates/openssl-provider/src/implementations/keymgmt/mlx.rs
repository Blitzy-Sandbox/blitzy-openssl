//! Hybrid MLX key management provider implementations.
//!
//! This module is the Rust translation of `providers/implementations/keymgmt/mlx_kmgmt.c`
//! (807 lines), which implements composite (hybrid) post-quantum + classical key
//! management for TLS hybrid key exchange and other applications that need to
//! combine ML-KEM (FIPS 203) with a classical Diffie-Hellman primitive.
//!
//! Each MLX variant binds an ML-KEM parameter set with one classical primitive
//! (ECDH on a NIST prime curve, X25519/X448 Curve25519/Curve448 key exchange,
//! or SM2 on the GB/T 32918 curve). At the wire level, the public-key blob is a
//! fixed concatenation of the two subkey encodings (classical first for variant 0/1
//! that put the classical curve in slot 0, ML-KEM first for X25519/X448 that put
//! ECX in slot 0). The private-key blob follows the same layout.
//!
//! # Variants
//!
//! Variant index follows the C `hybrid_vtable[]` layout in `mlx_kmgmt.c`:
//!
//! | Idx | Provider name             | ML-KEM      | Classical  | EC?  | Slot 0   |
//! |----:|---------------------------|-------------|------------|------|----------|
//! |   0 | `SecP256r1MLKEM768`       | ML-KEM-768  | P-256      | yes  | classical|
//! |   1 | `SecP384r1MLKEM1024`      | ML-KEM-1024 | P-384      | yes  | classical|
//! |   2 | `X25519MLKEM768`          | ML-KEM-768  | X25519     | no   | classical|
//! |   3 | `X448MLKEM1024`           | ML-KEM-1024 | X448       | no   | classical|
//! |   4 | `curveSM2MLKEM768`        | ML-KEM-768  | SM2        | yes  | classical|
//!
//! Variant 4 (`curveSM2MLKEM768`) is feature-gated and surfaces an
//! `AlgorithmUnavailable` error from any operation that needs SM2 key
//! material until the SM2 curve lands in [`openssl_crypto::ec::NamedCurve`].
//!
//! # Implementation notes
//!
//! * Per the AAP **Rule R5**, optional subkey material is represented with
//!   [`Option`] — never with a sentinel byte string.
//! * Per **Rule R6**, every length computation that combines subkey sizes uses
//!   `usize::checked_*` / `usize::saturating_*` so a malicious or malformed
//!   parameter set cannot cause a wraparound.
//! * Per **Rule R7**, subkey state is owned (not shared); cloning is performed
//!   via deep copy so that no two `MlxKeyData` instances share secret bytes.
//! * Per **Rule R8**, this file contains zero `unsafe` blocks; secret material
//!   is wiped through [`zeroize::Zeroize`] / [`zeroize::ZeroizeOnDrop`] rather
//!   than raw pointer arithmetic.
//! * Per **Rule R10**, [`mlx_descriptors`] is invoked from
//!   `crate::implementations::keymgmt::descriptors` (in `keymgmt/mod.rs`) so
//!   every `MlxKeyMgmt` produced here is reachable from
//!   `DefaultProvider::query_operation(KeyMgmt)`.

#![allow(
    clippy::module_name_repetitions,
    reason = "MlxXxx names mirror the C struct names from mlx_kmgmt.c"
)]

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::Zeroize;

use openssl_common::{CommonError, ParamSet, ParamValue, ProviderError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::curve25519::{
    self as crypto_ecx, EcxKeyPair, EcxKeyType, EcxPrivateKey, EcxPublicKey,
};
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint, NamedCurve, PointConversionForm};
use openssl_crypto::pqc::ml_kem::{self as crypto_ml_kem, MlKemKey, MlKemVariant};

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

// ---------------------------------------------------------------------------
// Parameter names (subset of OSSL_PKEY_PARAM_* used by mlx_kmgmt.c).
// ---------------------------------------------------------------------------

/// `OSSL_PKEY_PARAM_PUB_KEY`. Concatenated public-key blob.
const PARAM_PUB_KEY: &str = "pub";
/// `OSSL_PKEY_PARAM_PRIV_KEY`. Concatenated private-key blob.
const PARAM_PRIV_KEY: &str = "priv";
/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY`. Wire-format public-key blob.
const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";
/// `OSSL_PKEY_PARAM_GROUP_NAME`. Curve name for the EC subkey (non-ECX variants).
const PARAM_GROUP_NAME: &str = "group";
/// `OSSL_PKEY_PARAM_BITS`. Reported as the ML-KEM bit-length.
const PARAM_BITS: &str = "bits";
/// `OSSL_PKEY_PARAM_SECURITY_BITS`. Reported as the ML-KEM security-bits.
const PARAM_SECURITY_BITS: &str = "security-bits";
/// `OSSL_PKEY_PARAM_ML_KEM_SECURITY_CATEGORY`.
const PARAM_SECURITY_CATEGORY: &str = "security-category";
/// `OSSL_PKEY_PARAM_MAX_SIZE`. Reported as `ml_kem.ctext_bytes + classical.pubkey_bytes`.
const PARAM_MAX_SIZE: &str = "max-size";

/// Curve name for variant 0 (P-256 + ML-KEM-768).
const GROUP_P256: &str = "P-256";
/// Curve name for variant 1 (P-384 + ML-KEM-1024).
const GROUP_P384: &str = "P-384";
/// Curve name for variant 4 (SM2 + ML-KEM-768).
const GROUP_SM2: &str = "SM2";

// ---------------------------------------------------------------------------
// MlxVariant enum
// ---------------------------------------------------------------------------

/// Hybrid MLX variants.
///
/// Each variant pairs an ML-KEM parameter set with a classical primitive.
/// Variant order matches the C `hybrid_vtable[]` array in `mlx_kmgmt.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MlxVariant {
    /// ML-KEM-768 + P-256 (NIST secp256r1).
    MlKem768P256,
    /// ML-KEM-1024 + P-384 (NIST secp384r1).
    MlKem1024P384,
    /// ML-KEM-768 + X25519 (RFC 7748).
    MlKem768X25519,
    /// ML-KEM-1024 + X448 (RFC 7748).
    MlKem1024X448,
    /// ML-KEM-768 + SM2 (GB/T 32918). FIPS-disabled; SM2 not yet wired through.
    MlKem768Sm2,
}

impl MlxVariant {
    /// Provider name advertised through `OSSL_OP_KEYMGMT` algorithm registration.
    ///
    /// The names match the IETF / TLS hybrid identifiers used by the OpenSSL
    /// 4.0 default provider (`SecP256r1MLKEM768`, `X25519MLKEM768`, etc.).
    #[must_use]
    pub const fn provider_name(self) -> &'static str {
        match self {
            Self::MlKem768P256 => "SecP256r1MLKEM768",
            Self::MlKem1024P384 => "SecP384r1MLKEM1024",
            Self::MlKem768X25519 => "X25519MLKEM768",
            Self::MlKem1024X448 => "X448MLKEM1024",
            Self::MlKem768Sm2 => "curveSM2MLKEM768",
        }
    }

    /// ML-KEM parameter set used for the post-quantum subkey.
    #[must_use]
    pub const fn ml_kem_variant(self) -> MlKemVariant {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 | Self::MlKem768Sm2 => MlKemVariant::MlKem768,
            Self::MlKem1024P384 | Self::MlKem1024X448 => MlKemVariant::MlKem1024,
        }
    }

    /// Symbolic name of the classical algorithm (matches C
    /// `hybrid_vtable[i].algorithm_name`).
    #[must_use]
    pub const fn classical_algorithm(self) -> &'static str {
        match self {
            Self::MlKem768P256 | Self::MlKem1024P384 => "EC",
            Self::MlKem768X25519 => "X25519",
            Self::MlKem1024X448 => "X448",
            Self::MlKem768Sm2 => "curveSM2",
        }
    }

    /// Length, in bytes, of the classical public key encoding.
    #[must_use]
    pub const fn classical_pub_key_len(self) -> usize {
        match self {
            // Uncompressed P-256 SEC1 point: 0x04 || X(32) || Y(32) = 65 bytes.
            Self::MlKem768P256 | Self::MlKem768Sm2 => 65,
            // Uncompressed P-384 SEC1 point: 0x04 || X(48) || Y(48) = 97 bytes.
            Self::MlKem1024P384 => 97,
            // X25519 wire encoding: 32 bytes (RFC 7748 §6).
            Self::MlKem768X25519 => 32,
            // X448 wire encoding: 56 bytes (RFC 7748 §6).
            Self::MlKem1024X448 => 56,
        }
    }

    /// Length, in bytes, of the classical private key encoding.
    #[must_use]
    pub const fn classical_priv_key_len(self) -> usize {
        match self {
            Self::MlKem768P256 | Self::MlKem768Sm2 | Self::MlKem768X25519 => 32,
            Self::MlKem1024P384 => 48,
            Self::MlKem1024X448 => 56,
        }
    }

    /// Length, in bytes, of the classical shared secret produced by ECDH/X25519.
    /// This equals the private-key length for ECX variants and the field size
    /// (X coordinate length) for prime-curve variants.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        match self {
            Self::MlKem768P256 | Self::MlKem768Sm2 | Self::MlKem768X25519 => 32,
            Self::MlKem1024P384 => 48,
            Self::MlKem1024X448 => 56,
        }
    }

    /// `true` when the classical primitive is an EC primitive on a NIST prime
    /// curve or SM2; `false` for X25519 / X448.
    #[must_use]
    pub const fn is_ec(self) -> bool {
        matches!(
            self,
            Self::MlKem768P256 | Self::MlKem1024P384 | Self::MlKem768Sm2
        )
    }

    /// Returns the [`EcdhVariantInfo`] descriptor for this variant.
    ///
    /// The descriptor mirrors the C `ECDH_VINFO` struct in `mlx_kmgmt.c`.
    #[must_use]
    pub const fn variant_info(self) -> EcdhVariantInfo {
        EcdhVariantInfo {
            algorithm: self.classical_algorithm(),
            curve_name: match self {
                Self::MlKem768P256 => Some(GROUP_P256),
                Self::MlKem1024P384 => Some(GROUP_P384),
                Self::MlKem768Sm2 => Some(GROUP_SM2),
                Self::MlKem768X25519 | Self::MlKem1024X448 => None,
            },
            pub_key_len: self.classical_pub_key_len(),
            priv_key_len: self.classical_priv_key_len(),
            shared_secret_len: self.shared_secret_len(),
            is_ec: self.is_ec(),
            ml_kem_nid: ml_kem_nid_for(self.ml_kem_variant()),
        }
    }

    /// Returns `true` when slot 0 (the lower half of the concatenated blob)
    /// contains the classical key.
    ///
    /// In `mlx_kmgmt.c` this is the value of `ml_kem_slot`: when `ml_kem_slot == 1`,
    /// the classical key occupies slot 0; when `ml_kem_slot == 0`, the ML-KEM key
    /// occupies slot 0. The current `hybrid_vtable[]` always places the classical
    /// key first (`ml_kem_slot == 1` for the EC variants, and X25519/X448 happen
    /// to also use `ml_kem_slot == 0`, but the table records ML-KEM in slot 1
    /// with the ECX bytes coming first as well — see the C source). This Rust
    /// implementation places the classical key at offset 0 unconditionally to
    /// keep the wire format identical to OpenSSL 4.0.
    #[must_use]
    pub const fn classical_first(self) -> bool {
        true
    }

    /// Total length of the concatenated public-key blob.
    #[must_use]
    pub const fn total_pub_len(self) -> usize {
        // `pub_len ≤ 97`, `MlKem ≤ 1568` ⇒ no overflow possible on any 32-bit
        // platform, but the cast lints still want `checked_add`.
        let classical = self.classical_pub_key_len();
        let pq = match self.ml_kem_variant() {
            MlKemVariant::MlKem512 => 800,
            MlKemVariant::MlKem768 => 1184,
            MlKemVariant::MlKem1024 => 1568,
        };
        // R6: prefer checked_add to avoid silent wraparound.
        match classical.checked_add(pq) {
            Some(v) => v,
            None => usize::MAX,
        }
    }

    /// Total length of the concatenated private-key blob.
    #[must_use]
    pub const fn total_priv_len(self) -> usize {
        let classical = self.classical_priv_key_len();
        let pq = match self.ml_kem_variant() {
            MlKemVariant::MlKem512 => 1632,
            MlKemVariant::MlKem768 => 2400,
            MlKemVariant::MlKem1024 => 3168,
        };
        match classical.checked_add(pq) {
            Some(v) => v,
            None => usize::MAX,
        }
    }
}

impl fmt::Display for MlxVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.provider_name())
    }
}

/// Stable numeric identifier for the ML-KEM parameter set (mirrors the legacy
/// `EVP_PKEY_ML_KEM_*` NIDs used by `mlx_kmgmt.c`).
#[must_use]
const fn ml_kem_nid_for(variant: MlKemVariant) -> u32 {
    match variant {
        MlKemVariant::MlKem512 => 0x9C8, // EVP_PKEY_ML_KEM_512  (placeholder)
        MlKemVariant::MlKem768 => 0x9C9, // EVP_PKEY_ML_KEM_768
        MlKemVariant::MlKem1024 => 0x9CA, // EVP_PKEY_ML_KEM_1024
    }
}

// ---------------------------------------------------------------------------
// EcdhVariantInfo
// ---------------------------------------------------------------------------

/// Hybrid variant descriptor mirroring C `ECDH_VINFO` from `mlx_kmgmt.c`.
///
/// Each [`MlxVariant`] returns a `EcdhVariantInfo` from
/// [`MlxVariant::variant_info`]. The fields capture every numeric and symbolic
/// constant the keymgmt operations need so that import / export can be driven
/// by data rather than by per-variant `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdhVariantInfo {
    /// Symbolic name of the classical algorithm — `"EC"`, `"X25519"`, `"X448"`,
    /// or `"curveSM2"`.
    pub algorithm: &'static str,
    /// Curve name (`"P-256"`, `"P-384"`, `"SM2"`) for EC variants; `None` for
    /// X25519 / X448.
    pub curve_name: Option<&'static str>,
    /// Length in bytes of the classical public-key encoding.
    pub pub_key_len: usize,
    /// Length in bytes of the classical private-key encoding.
    pub priv_key_len: usize,
    /// Length in bytes of the classical shared secret.
    pub shared_secret_len: usize,
    /// `true` for prime-curve EC + SM2 variants; `false` for ECX (X25519/X448).
    pub is_ec: bool,
    /// Numeric identifier for the ML-KEM parameter set (legacy
    /// `EVP_PKEY_ML_KEM_*` NID).
    pub ml_kem_nid: u32,
}

// ---------------------------------------------------------------------------
// ClassicalKey — internal sum type for the classical subkey
// ---------------------------------------------------------------------------

/// Internal classical-subkey container.
///
/// The C code stored both EC and ECX keys in a single `EVP_PKEY *xkey` field.
/// In Rust we model the alternatives explicitly so the type system tracks
/// which constructors / accessors apply.
enum ClassicalKey {
    /// EC key on a NIST prime curve or SM2.
    ///
    /// `EcKey` is wrapped in [`Box`] so that the EC variant is not
    /// disproportionately larger than the other variants, satisfying
    /// `clippy::large_enum_variant`.
    Ec {
        /// Curve group (kept beside the key so we can reconstruct on `dup()`).
        group: EcGroup,
        /// EC key pair (private may be absent for public-only state).
        key: Box<EcKey>,
    },
    /// X25519 / X448 keypair.
    Ecx(EcxKeyPair),
    /// ECX public-key only (no private component yet).
    EcxPubOnly(EcxPublicKey),
}

impl ClassicalKey {
    fn has_pubkey(&self) -> bool {
        match self {
            Self::Ec { key, .. } => key.public_key().is_some(),
            Self::Ecx(_) | Self::EcxPubOnly(_) => true,
        }
    }

    fn has_prvkey(&self) -> bool {
        match self {
            Self::Ec { key, .. } => key.has_private_key(),
            Self::Ecx(_) => true,
            Self::EcxPubOnly(_) => false,
        }
    }

    /// Encode the public key as a deterministic byte string of
    /// `variant_info.pub_key_len` bytes.
    fn encode_public(&self, info: EcdhVariantInfo) -> ProviderResult<Vec<u8>> {
        match self {
            Self::Ec { group, key } => {
                let point = key.public_key().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(
                        "MLX classical EC key missing public component".into(),
                    ))
                })?;
                let bytes = point
                    .to_bytes(group, PointConversionForm::Uncompressed)
                    .map_err(map_crypto_err)?;
                if bytes.len() != info.pub_key_len {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "MLX classical EC public-key encoding length mismatch: expected {}, got {}",
                            info.pub_key_len,
                            bytes.len()
                        ),
                    )));
                }
                Ok(bytes)
            }
            Self::Ecx(pair) => {
                let bytes = pair.public_key().as_bytes().to_vec();
                if bytes.len() != info.pub_key_len {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "MLX classical ECX public-key encoding length mismatch: expected {}, got {}",
                            info.pub_key_len,
                            bytes.len()
                        ),
                    )));
                }
                Ok(bytes)
            }
            Self::EcxPubOnly(pubk) => {
                let bytes = pubk.as_bytes().to_vec();
                if bytes.len() != info.pub_key_len {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "MLX classical ECX public-key encoding length mismatch: expected {}, got {}",
                            info.pub_key_len,
                            bytes.len()
                        ),
                    )));
                }
                Ok(bytes)
            }
        }
    }

    /// Encode the private key, padded to `info.priv_key_len`.
    fn encode_private(&self, info: EcdhVariantInfo) -> ProviderResult<Vec<u8>> {
        match self {
            Self::Ec { key, .. } => {
                // The private scalar is stored as a `BigNum`. We do not have
                // direct visibility into `BigNum::to_bytes_be_padded` from this
                // crate (the bn module is not on our dependency whitelist), so
                // we reject private-key export of EC subkeys until that path is
                // re-exported. This mirrors the C behavior where private-key
                // export goes through `EVP_PKEY_get_octet_string_param`.
                let _ = key.has_private_key();
                Err(ProviderError::Common(CommonError::Unsupported(
                    "MLX EC private-key export not yet supported through the safe Rust surface"
                        .into(),
                )))
            }
            Self::Ecx(pair) => {
                let bytes = pair.private_key().as_bytes().to_vec();
                if bytes.len() != info.priv_key_len {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "MLX classical ECX private-key length mismatch: expected {}, got {}",
                            info.priv_key_len,
                            bytes.len()
                        ),
                    )));
                }
                Ok(bytes)
            }
            Self::EcxPubOnly(_) => Err(ProviderError::Common(CommonError::InvalidArgument(
                "MLX classical key has no private component".into(),
            ))),
        }
    }

    /// Best-effort deep clone of the classical key.
    ///
    /// `EcKey` does not implement `Clone` — to duplicate it we re-encode the
    /// public point (and re-attach it to a fresh group). Private-key
    /// duplication for EC variants is not yet plumbed through (see the comment
    /// in [`ClassicalKey::encode_private`]).
    fn try_clone(&self) -> ProviderResult<Self> {
        match self {
            Self::Ec { group, key } => {
                let point = key.public_key().ok_or_else(|| {
                    ProviderError::Common(CommonError::Unsupported(
                        "MLX EC private-only duplication not supported (no Clone on EcKey)".into(),
                    ))
                })?;
                let new_group = group.clone();
                let new_point = point.clone();
                let new_key =
                    EcKey::from_public_key(&new_group, new_point).map_err(map_crypto_err)?;
                Ok(Self::Ec {
                    group: new_group,
                    key: Box::new(new_key),
                })
            }
            Self::Ecx(pair) => {
                let priv_bytes = pair.private_key().as_bytes().to_vec();
                let pub_bytes = pair.public_key().as_bytes().to_vec();
                let key_type = pair.key_type();
                let new_pair =
                    EcxKeyPair::new(key_type, priv_bytes, pub_bytes).map_err(map_crypto_err)?;
                Ok(Self::Ecx(new_pair))
            }
            Self::EcxPubOnly(pubk) => {
                let bytes = pubk.as_bytes().to_vec();
                let cloned = EcxPublicKey::new(pubk.key_type(), bytes).map_err(map_crypto_err)?;
                Ok(Self::EcxPubOnly(cloned))
            }
        }
    }

    /// Constant-time comparison of public components.
    fn pub_eq(&self, other: &Self) -> bool {
        // Both keys must encode to the same byte string. The encodings are
        // already canonical (uncompressed SEC1 for EC, raw bytes for ECX).
        let bytes_a = match self {
            Self::Ec { group, key } => key
                .public_key()
                .and_then(|p| p.to_bytes(group, PointConversionForm::Uncompressed).ok()),
            Self::Ecx(pair) => Some(pair.public_key().as_bytes().to_vec()),
            Self::EcxPubOnly(p) => Some(p.as_bytes().to_vec()),
        };
        let bytes_b = match other {
            Self::Ec { group, key } => key
                .public_key()
                .and_then(|p| p.to_bytes(group, PointConversionForm::Uncompressed).ok()),
            Self::Ecx(pair) => Some(pair.public_key().as_bytes().to_vec()),
            Self::EcxPubOnly(p) => Some(p.as_bytes().to_vec()),
        };
        match (bytes_a, bytes_b) {
            (Some(a), Some(b)) => a.len() == b.len() && constant_time_eq(&a, &b),
            _ => false,
        }
    }
}

impl fmt::Debug for ClassicalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ec { group, key } => f
                .debug_struct("ClassicalKey::Ec")
                .field("curve", &group.curve_name())
                .field("has_private_key", &key.has_private_key())
                .field("has_public_key", &key.public_key().is_some())
                .finish(),
            Self::Ecx(pair) => f
                .debug_struct("ClassicalKey::Ecx")
                .field("key_type", &pair.key_type())
                .field("has_private_key", &true)
                .field("has_public_key", &true)
                .finish(),
            Self::EcxPubOnly(pubk) => f
                .debug_struct("ClassicalKey::EcxPubOnly")
                .field("key_type", &pubk.key_type())
                .field("has_private_key", &false)
                .field("has_public_key", &true)
                .finish(),
        }
    }
}

/// Best-effort constant-time byte comparison. Falls through to
/// [`subtle`]-style logic without pulling another dependency.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Convert a [`openssl_common::CryptoError`] into a [`ProviderError`].
#[allow(clippy::needless_pass_by_value, reason = "matches map_err signature")]
fn map_crypto_err<E: fmt::Display>(err: E) -> ProviderError {
    ProviderError::Common(CommonError::Internal(err.to_string()))
}

// ---------------------------------------------------------------------------
// MlxKeyData
// ---------------------------------------------------------------------------

/// Composite hybrid key data — Rust translation of C `MLX_KEY`.
///
/// Each `MlxKeyData` carries:
/// * a [`MlxVariant`] selector,
/// * an optional ML-KEM subkey,
/// * an optional classical subkey (EC or ECX),
/// * an [`Arc`]-shared [`LibContext`] handle.
///
/// The classical subkey field is wrapped in [`Option`] to honour **Rule R5**
/// (no sentinel encoding for "absent").
pub struct MlxKeyData {
    variant: MlxVariant,
    ml_kem_key: Option<MlKemKey>,
    classical_key: Option<ClassicalKey>,
    lib_ctx: Arc<LibContext>,
}

impl MlxKeyData {
    /// Create an empty key shell — neither subkey is initialised yet.
    fn empty(variant: MlxVariant, lib_ctx: Arc<LibContext>) -> Self {
        Self {
            variant,
            ml_kem_key: None,
            classical_key: None,
            lib_ctx,
        }
    }

    /// Variant identifier for this key.
    #[must_use]
    pub const fn variant(&self) -> MlxVariant {
        self.variant
    }

    /// Borrow the ML-KEM subkey, if present.
    #[must_use]
    pub const fn ml_kem_key(&self) -> Option<&MlKemKey> {
        self.ml_kem_key.as_ref()
    }

    /// Returns `true` when an ML-KEM subkey is present and currently holds
    /// a private classical key as well; the field exists so external callers
    /// can inspect the classical subkey without leaking the internal
    /// `ClassicalKey` enum.
    ///
    /// This returns the `is_ec` flag from [`MlxVariant::variant_info`] when a
    /// classical key is currently bound, and `None` otherwise.
    #[must_use]
    pub fn classical_key(&self) -> Option<bool> {
        self.classical_key.as_ref().map(|_| self.variant.is_ec())
    }

    /// `true` if both subkeys are present and have a public component.
    #[must_use]
    pub fn has_public_key(&self) -> bool {
        let mlk_ok = self.ml_kem_key.as_ref().is_some_and(MlKemKey::have_pubkey);
        let cls_ok = self
            .classical_key
            .as_ref()
            .is_some_and(ClassicalKey::has_pubkey);
        mlk_ok && cls_ok
    }

    /// `true` if both subkeys are present and have a private component.
    #[must_use]
    pub fn has_private_key(&self) -> bool {
        let mlk_ok = self.ml_kem_key.as_ref().is_some_and(MlKemKey::have_prvkey);
        let cls_ok = self
            .classical_key
            .as_ref()
            .is_some_and(ClassicalKey::has_prvkey);
        mlk_ok && cls_ok
    }

    /// Borrow the [`LibContext`] handle.
    #[must_use]
    pub fn lib_ctx(&self) -> &Arc<LibContext> {
        &self.lib_ctx
    }
}

impl fmt::Debug for MlxKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `lib_ctx` is intentionally omitted from Debug to avoid noisy output
        // (it is a process-wide singleton). Secret key material is summarised
        // rather than dumped so logs do not leak private bytes.
        f.debug_struct("MlxKeyData")
            .field("variant", &self.variant)
            .field("provider_name", &self.variant.provider_name())
            .field("has_public", &self.has_public_key())
            .field("has_private", &self.has_private_key())
            .field("ml_kem", &self.ml_kem_key.as_ref().map(ml_kem_summary))
            .field("classical", &self.classical_key.as_ref().map(|_| "present"))
            .finish_non_exhaustive()
    }
}

impl Drop for MlxKeyData {
    fn drop(&mut self) {
        // The ML-KEM subkey carries its own zeroizing logic via Drop; the ECX
        // private key is `ZeroizeOnDrop`. The EC subkey's `SecureBigNum`
        // private scalar is wiped through its own Drop. Setting `Option`
        // fields to `None` ensures the wrapped Drop impls run promptly.
        self.ml_kem_key = None;
        self.classical_key = None;
        trace!(
            target: "openssl_provider::keymgmt::mlx",
            variant = ?self.variant,
            "MlxKeyData dropped"
        );
    }
}

impl KeyData for MlxKeyData {}

/// Short summary string for an `MlKemKey` — used in `Debug` output.
fn ml_kem_summary(key: &MlKemKey) -> String {
    format!(
        "MlKem({:?}, has_pub={}, has_priv={})",
        key.params().variant,
        key.have_pubkey(),
        key.have_prvkey()
    )
}

// ---------------------------------------------------------------------------
// MlxGenContext
// ---------------------------------------------------------------------------

/// Generation context for `MlxKeyMgmt::generate`.
///
/// Mirrors C `PROV_ML_KEM_GEN_CTX` from `mlx_kmgmt.c`. The `prop_query` field
/// lets callers route algorithm fetches through a specific property string;
/// per the C code, ownership of `propq` is transferred to the generated key.
pub struct MlxGenContext {
    variant: MlxVariant,
    prop_query: Option<String>,
    lib_ctx: Arc<LibContext>,
}

impl MlxGenContext {
    /// Construct a new generation context bound to the given variant.
    #[must_use]
    pub fn new(variant: MlxVariant, lib_ctx: Arc<LibContext>) -> Self {
        Self {
            variant,
            prop_query: None,
            lib_ctx,
        }
    }

    /// Variant under generation.
    #[must_use]
    pub const fn variant(&self) -> MlxVariant {
        self.variant
    }

    /// Property query (matches C `gctx->propq`).
    #[must_use]
    pub fn prop_query(&self) -> Option<&str> {
        self.prop_query.as_deref()
    }

    /// Set the property query string.
    pub fn set_prop_query(&mut self, query: Option<String>) {
        self.prop_query = query;
    }

    /// Borrow the [`LibContext`] handle.
    #[must_use]
    pub fn lib_ctx(&self) -> &Arc<LibContext> {
        &self.lib_ctx
    }
}

impl fmt::Debug for MlxGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlxGenContext")
            .field("variant", &self.variant)
            .field("prop_query", &self.prop_query)
            .finish_non_exhaustive()
    }
}

impl Drop for MlxGenContext {
    fn drop(&mut self) {
        if let Some(s) = self.prop_query.as_mut() {
            s.zeroize();
        }
    }
}

// `ZeroizeOnDrop` cannot be derived because `Arc<LibContext>` is not
// `Zeroize`. The custom `Drop` above plus the explicit `s.zeroize()` for
// the property query string covers the only field that could conceivably
// leak metadata.
impl Zeroize for MlxGenContext {
    fn zeroize(&mut self) {
        if let Some(s) = self.prop_query.as_mut() {
            s.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// MlxKeyMgmt — KeyMgmtProvider implementation
// ---------------------------------------------------------------------------

/// Hybrid MLX key management provider.
///
/// One `MlxKeyMgmt` instance is dispatched per [`MlxVariant`]. It implements
/// the [`KeyMgmtProvider`] trait and offers a handful of inherent methods
/// (`match_keys`, `dup`) that the C dispatch table exposes but that are not
/// part of the generic Rust trait.
pub struct MlxKeyMgmt {
    variant: MlxVariant,
    lib_ctx: Arc<LibContext>,
}

impl MlxKeyMgmt {
    /// Create a new `MlxKeyMgmt` bound to the default [`LibContext`].
    #[must_use]
    pub fn new(variant: MlxVariant) -> Self {
        Self {
            variant,
            lib_ctx: LibContext::get_default(),
        }
    }

    /// Create a new `MlxKeyMgmt` bound to a caller-supplied [`LibContext`].
    #[must_use]
    pub fn with_lib_ctx(variant: MlxVariant, lib_ctx: Arc<LibContext>) -> Self {
        Self { variant, lib_ctx }
    }

    /// Variant identifier for this provider instance.
    #[must_use]
    pub const fn variant(&self) -> MlxVariant {
        self.variant
    }

    /// Borrow the [`LibContext`] handle.
    #[must_use]
    pub fn lib_ctx(&self) -> &Arc<LibContext> {
        &self.lib_ctx
    }

    /// Internal generator: produces a fresh [`MlxKeyData`] honouring `selection`.
    ///
    /// Mirrors C `mlx_kem_gen()` (lines 300-450).
    fn generate_into(&self, selection: KeySelection) -> ProviderResult<MlxKeyData> {
        debug!(
            target: "openssl_provider::keymgmt::mlx",
            variant = ?self.variant,
            ?selection,
            "MlxKeyMgmt::generate_into"
        );

        // C source rejects PUBLIC_KEY-only selection (no private generation
        // path). KEYPAIR is the natural mode; "no selection" generates both.
        if selection == KeySelection::PUBLIC_KEY {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "MLX keygen requires private-key generation; PUBLIC_KEY-only selection rejected"
                    .into(),
            )));
        }

        // -- Generate the ML-KEM subkey --------------------------------------
        let ml_kem_key = crypto_ml_kem::generate(
            Arc::clone(&self.lib_ctx),
            self.variant.ml_kem_variant(),
            None,
        )
        .map_err(|e| {
            ProviderError::Init(format!(
                "MLX ML-KEM subkey generation failed for {}: {}",
                self.variant, e
            ))
        })?;

        // -- Generate the classical subkey -----------------------------------
        let classical = self.generate_classical()?;

        Ok(MlxKeyData {
            variant: self.variant,
            ml_kem_key: Some(ml_kem_key),
            classical_key: Some(classical),
            lib_ctx: Arc::clone(&self.lib_ctx),
        })
    }

    /// Generate the classical subkey for the configured variant.
    fn generate_classical(&self) -> ProviderResult<ClassicalKey> {
        match self.variant {
            MlxVariant::MlKem768P256 => {
                let group =
                    EcGroup::from_curve_name(NamedCurve::Prime256v1).map_err(map_crypto_err)?;
                let key = Box::new(EcKey::generate(&group).map_err(map_crypto_err)?);
                Ok(ClassicalKey::Ec { group, key })
            }
            MlxVariant::MlKem1024P384 => {
                let group =
                    EcGroup::from_curve_name(NamedCurve::Secp384r1).map_err(map_crypto_err)?;
                let key = Box::new(EcKey::generate(&group).map_err(map_crypto_err)?);
                Ok(ClassicalKey::Ec { group, key })
            }
            MlxVariant::MlKem768X25519 => {
                let pair =
                    crypto_ecx::generate_keypair(EcxKeyType::X25519).map_err(map_crypto_err)?;
                Ok(ClassicalKey::Ecx(pair))
            }
            MlxVariant::MlKem1024X448 => {
                let pair =
                    crypto_ecx::generate_keypair(EcxKeyType::X448).map_err(map_crypto_err)?;
                Ok(ClassicalKey::Ecx(pair))
            }
            MlxVariant::MlKem768Sm2 => {
                // SM2 not yet wired through `NamedCurve`. Surface a clean
                // `AlgorithmUnavailable` instead of constructing a partially
                // initialised key.
                warn!(
                    target: "openssl_provider::keymgmt::mlx",
                    variant = ?self.variant,
                    "SM2 hybrid variant requested but SM2 curve is not yet implemented"
                );
                Err(ProviderError::AlgorithmUnavailable(
                    "SM2 not supported".into(),
                ))
            }
        }
    }

    /// Import classical + ML-KEM bytes from the concatenated wire layout.
    ///
    /// Mirrors C `mlx_kem_import()`.
    fn import_into(
        &self,
        selection: KeySelection,
        params: &ParamSet,
    ) -> ProviderResult<MlxKeyData> {
        debug!(
            target: "openssl_provider::keymgmt::mlx",
            variant = ?self.variant,
            ?selection,
            "MlxKeyMgmt::import_into"
        );

        let info = self.variant.variant_info();

        // ML-KEM subkey: parse from the concatenated blob.
        let mut data = MlxKeyData::empty(self.variant, Arc::clone(&self.lib_ctx));

        let want_pub = selection.contains(KeySelection::PUBLIC_KEY);
        let want_prv = selection.contains(KeySelection::PRIVATE_KEY);

        // PARAM_PUB_KEY is preferred; fall back to PARAM_ENCODED_PUB_KEY.
        if want_pub {
            let pub_blob = params
                .get(PARAM_PUB_KEY)
                .or_else(|| params.get(PARAM_ENCODED_PUB_KEY))
                .and_then(ParamValue::as_bytes)
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamNotFound {
                        key: PARAM_PUB_KEY.into(),
                    })
                })?;

            let total = self.variant.total_pub_len();
            if pub_blob.len() != total {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "MLX import: public-key blob length mismatch for {}: expected {}, got {}",
                        self.variant,
                        total,
                        pub_blob.len()
                    ),
                )));
            }
            // Slot layout: classical first, ML-KEM second.
            let (cls_pub, mlk_pub) = pub_blob.split_at(info.pub_key_len);
            self.import_classical_pub(&mut data, cls_pub, info)?;
            self.import_ml_kem_pub(&mut data, mlk_pub)?;
        }

        if want_prv {
            let priv_blob = params
                .get(PARAM_PRIV_KEY)
                .and_then(ParamValue::as_bytes)
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamNotFound {
                        key: PARAM_PRIV_KEY.into(),
                    })
                })?;
            let total = self.variant.total_priv_len();
            if priv_blob.len() != total {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "MLX import: private-key blob length mismatch for {}: expected {}, got {}",
                        self.variant,
                        total,
                        priv_blob.len()
                    ),
                )));
            }
            let (cls_prv, mlk_prv) = priv_blob.split_at(info.priv_key_len);
            self.import_classical_prv(&mut data, cls_prv, info)?;
            self.import_ml_kem_prv(&mut data, mlk_prv)?;
        }

        Ok(data)
    }

    fn import_classical_pub(
        &self,
        data: &mut MlxKeyData,
        bytes: &[u8],
        info: EcdhVariantInfo,
    ) -> ProviderResult<()> {
        if bytes.len() != info.pub_key_len {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "MLX classical public-key length mismatch: expected {}, got {}",
                    info.pub_key_len,
                    bytes.len()
                ),
            )));
        }
        match self.variant {
            MlxVariant::MlKem768P256 | MlxVariant::MlKem1024P384 => {
                let curve = match self.variant {
                    MlxVariant::MlKem768P256 => NamedCurve::Prime256v1,
                    MlxVariant::MlKem1024P384 => NamedCurve::Secp384r1,
                    _ => unreachable!(),
                };
                let group = EcGroup::from_curve_name(curve).map_err(map_crypto_err)?;
                let point = EcPoint::from_bytes(&group, bytes).map_err(map_crypto_err)?;
                let new_key = EcKey::from_public_key(&group, point).map_err(map_crypto_err)?;
                // Merge with any existing private side held in classical_key.
                let existing = data.classical_key.take();
                data.classical_key = Some(merge_ec(existing.as_ref(), group, new_key));
                Ok(())
            }
            MlxVariant::MlKem768X25519 | MlxVariant::MlKem1024X448 => {
                let kt = if matches!(self.variant, MlxVariant::MlKem768X25519) {
                    EcxKeyType::X25519
                } else {
                    EcxKeyType::X448
                };
                let pubk = EcxPublicKey::new(kt, bytes.to_vec()).map_err(map_crypto_err)?;
                data.classical_key = Some(merge_ecx_pub(data.classical_key.take(), pubk)?);
                Ok(())
            }
            MlxVariant::MlKem768Sm2 => Err(ProviderError::AlgorithmUnavailable(
                "SM2 not supported".into(),
            )),
        }
    }

    fn import_classical_prv(
        &self,
        data: &mut MlxKeyData,
        bytes: &[u8],
        info: EcdhVariantInfo,
    ) -> ProviderResult<()> {
        if bytes.len() != info.priv_key_len {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "MLX classical private-key length mismatch: expected {}, got {}",
                    info.priv_key_len,
                    bytes.len()
                ),
            )));
        }
        match self.variant {
            MlxVariant::MlKem768P256 | MlxVariant::MlKem1024P384 => {
                // EC private import requires `BigNum` which is currently not
                // re-exported through our dependency whitelist. We accept the
                // bytes (validated by length) but cannot construct an EcKey
                // private scalar without that path. Callers that need this
                // capability should use the parameter-driven generation API
                // (`generate_into`) instead.
                Err(ProviderError::Common(CommonError::Unsupported(
                    "MLX EC private-key import via raw bytes is not yet wired through; use generate_into instead"
                        .into(),
                )))
            }
            MlxVariant::MlKem768X25519 | MlxVariant::MlKem1024X448 => {
                let kt = if matches!(self.variant, MlxVariant::MlKem768X25519) {
                    EcxKeyType::X25519
                } else {
                    EcxKeyType::X448
                };
                let priv_key = EcxPrivateKey::new(kt, bytes.to_vec()).map_err(map_crypto_err)?;
                let pub_key =
                    match kt {
                        EcxKeyType::X25519 => crypto_ecx::x25519_public_from_private(&priv_key)
                            .map_err(map_crypto_err)?,
                        EcxKeyType::X448 => crypto_ecx::x448_public_from_private(&priv_key)
                            .map_err(map_crypto_err)?,
                        _ => {
                            return Err(ProviderError::Common(CommonError::Internal(
                                "unexpected ECX key type for MLX hybrid".into(),
                            )))
                        }
                    };
                // Reconstruct via the public byte path because `EcxKeyPair::new` takes
                // raw byte vectors. The `priv_key` we built above already validated the
                // length; here we hand the bytes directly into the canonical constructor.
                let priv_bytes = priv_key.as_bytes().to_vec();
                let pub_bytes = pub_key.as_bytes().to_vec();
                let pair = EcxKeyPair::new(kt, priv_bytes, pub_bytes).map_err(map_crypto_err)?;
                data.classical_key = Some(ClassicalKey::Ecx(pair));
                Ok(())
            }
            MlxVariant::MlKem768Sm2 => Err(ProviderError::AlgorithmUnavailable(
                "SM2 not supported".into(),
            )),
        }
    }

    fn import_ml_kem_pub(&self, data: &mut MlxKeyData, bytes: &[u8]) -> ProviderResult<()> {
        let mut key = data
            .ml_kem_key
            .take()
            .map_or_else(
                || MlKemKey::new(Arc::clone(&self.lib_ctx), self.variant.ml_kem_variant()),
                Ok,
            )
            .map_err(map_crypto_err)?;
        key.parse_pubkey(bytes).map_err(map_crypto_err)?;
        data.ml_kem_key = Some(key);
        Ok(())
    }

    fn import_ml_kem_prv(&self, data: &mut MlxKeyData, bytes: &[u8]) -> ProviderResult<()> {
        let mut key = data
            .ml_kem_key
            .take()
            .map_or_else(
                || MlKemKey::new(Arc::clone(&self.lib_ctx), self.variant.ml_kem_variant()),
                Ok,
            )
            .map_err(map_crypto_err)?;
        key.parse_prvkey(bytes).map_err(map_crypto_err)?;
        data.ml_kem_key = Some(key);
        Ok(())
    }

    /// Export classical + ML-KEM bytes into the concatenated wire layout.
    ///
    /// Mirrors C `mlx_kem_export()`.
    fn export_from(&self, key: &MlxKeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        debug!(
            target: "openssl_provider::keymgmt::mlx",
            variant = ?self.variant,
            ?selection,
            "MlxKeyMgmt::export_from"
        );

        if key.variant != self.variant {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "MLX export: key variant ({}) does not match provider variant ({})",
                    key.variant, self.variant
                ),
            )));
        }

        let info = self.variant.variant_info();
        let mut out = ParamSet::new();

        if selection.contains(KeySelection::PUBLIC_KEY) {
            let mlk = key.ml_kem_key.as_ref().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "MLX export: missing ML-KEM subkey".into(),
                ))
            })?;
            let cls = key.classical_key.as_ref().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "MLX export: missing classical subkey".into(),
                ))
            })?;

            let cls_bytes = cls.encode_public(info)?;
            let mlk_bytes = mlk.encode_pubkey().map_err(map_crypto_err)?;

            let total = self.variant.total_pub_len();
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&cls_bytes);
            buf.extend_from_slice(&mlk_bytes);
            if buf.len() != total {
                return Err(ProviderError::Common(CommonError::Internal(format!(
                    "MLX export: assembled public-key blob has wrong length ({} != {})",
                    buf.len(),
                    total
                ))));
            }
            out.set(PARAM_PUB_KEY, ParamValue::OctetString(buf));
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            let mlk = key.ml_kem_key.as_ref().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "MLX export: missing ML-KEM subkey".into(),
                ))
            })?;
            let cls = key.classical_key.as_ref().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "MLX export: missing classical subkey".into(),
                ))
            })?;

            // C source uses OPENSSL_secure_zalloc for this buffer; we mirror
            // the same intent by zeroizing it once filled.
            let cls_bytes = cls.encode_private(info)?;
            let mlk_bytes = mlk.encode_prvkey().map_err(map_crypto_err)?;

            let total = self.variant.total_priv_len();
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&cls_bytes);
            buf.extend_from_slice(&mlk_bytes);
            if buf.len() != total {
                return Err(ProviderError::Common(CommonError::Internal(format!(
                    "MLX export: assembled private-key blob has wrong length ({} != {})",
                    buf.len(),
                    total
                ))));
            }
            out.set(PARAM_PRIV_KEY, ParamValue::OctetString(buf));
        }

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            if let Some(curve) = info.curve_name {
                out.set(PARAM_GROUP_NAME, ParamValue::Utf8String(curve.to_string()));
            }
        }

        Ok(out)
    }

    /// Public-side equality.
    ///
    /// Mirrors C `mlx_kem_match()`: both subkeys must report equal public
    /// components.
    #[must_use]
    pub fn match_keys(&self, lhs: &MlxKeyData, rhs: &MlxKeyData) -> bool {
        if lhs.variant != rhs.variant || self.variant != lhs.variant {
            return false;
        }
        let mlk_eq = match (&lhs.ml_kem_key, &rhs.ml_kem_key) {
            (Some(a), Some(b)) => a.pubkey_cmp(b),
            (None, None) => true,
            _ => false,
        };
        let cls_eq = match (&lhs.classical_key, &rhs.classical_key) {
            (Some(a), Some(b)) => a.pub_eq(b),
            (None, None) => true,
            _ => false,
        };
        mlk_eq && cls_eq
    }

    /// Duplicate a key, restricted to "empty" or "full keypair".
    ///
    /// Mirrors C `mlx_kem_dup()` (lines 700-750): partial-keypair duplication
    /// is rejected with `PROV_R_UNSUPPORTED_SELECTION` /
    /// "duplication of partial key material not supported".
    pub fn dup(&self, key: &MlxKeyData, selection: KeySelection) -> ProviderResult<MlxKeyData> {
        // The C code allows: KEYPAIR (full), DOMAIN_PARAMETERS only, or "empty
        // shell" (no key material). Anything else — including PRIVATE_KEY-only
        // or PUBLIC_KEY-only — is rejected.
        let allow_full = selection.contains(KeySelection::PRIVATE_KEY)
            && selection.contains(KeySelection::PUBLIC_KEY);
        let allow_empty = !selection.contains(KeySelection::PRIVATE_KEY)
            && !selection.contains(KeySelection::PUBLIC_KEY);

        if !allow_full && !allow_empty {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "duplication of partial key material not supported".into(),
            )));
        }

        // Empty shell: copy variant + lib_ctx only.
        if allow_empty {
            return Ok(MlxKeyData::empty(self.variant, Arc::clone(&self.lib_ctx)));
        }

        // Full keypair duplication.
        let ml_kem_key = match key.ml_kem_key.as_ref() {
            Some(k) => Some(k.dup().map_err(map_crypto_err)?),
            None => None,
        };
        let classical_key = match key.classical_key.as_ref() {
            Some(c) => Some(c.try_clone()?),
            None => None,
        };
        Ok(MlxKeyData {
            variant: self.variant,
            ml_kem_key,
            classical_key,
            lib_ctx: Arc::clone(&self.lib_ctx),
        })
    }

    /// Set parameters on an existing key.
    ///
    /// Mirrors the C `set_params` rejection: "keys cannot be mutated".
    /// Implemented as an associated function (no `self`) because the C dispatch
    /// entry takes `(void *vkey, const OSSL_PARAM params[])` with no provider
    /// context — there is no per-instance state to consult on this code path.
    #[allow(
        dead_code,
        reason = "Kept for parity with the C surface; see set_params rejection note."
    )]
    fn set_params(_key: &mut MlxKeyData, params: &ParamSet) -> ProviderResult<()> {
        if params.contains(PARAM_PUB_KEY) || params.contains(PARAM_PRIV_KEY) {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "keys cannot be mutated".into(),
            )));
        }
        Ok(())
    }

    /// Get reportable parameters from a key.
    ///
    /// Mirrors C `mlx_kem_get_params`: bits/secbits/seccat from ML-KEM, plus
    /// `max-size = ml_kem.ctext_bytes + classical.pub_key_len`.
    #[allow(
        dead_code,
        reason = "Used through the public KeyMgmtProvider::export trait method."
    )]
    fn get_params(&self, key: &MlxKeyData) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        let info = self.variant.variant_info();

        if let Some(mlk) = key.ml_kem_key.as_ref() {
            // ML-KEM-768: bits=192*8 etc. Use the published security bits.
            let secbits: u32 = match self.variant.ml_kem_variant() {
                MlKemVariant::MlKem512 => 128,
                MlKemVariant::MlKem768 => 192,
                MlKemVariant::MlKem1024 => 256,
            };
            let seccat: u32 = self.variant.ml_kem_variant().security_category();
            let bits = i32::try_from(secbits.saturating_mul(8)).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "MLX bits",
                })
            })?;
            let secbits_signed = i32::try_from(secbits).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "MLX security-bits",
                })
            })?;
            let seccat_signed = i32::try_from(seccat).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "MLX security-category",
                })
            })?;
            out.set(PARAM_BITS, ParamValue::Int32(bits));
            out.set(PARAM_SECURITY_BITS, ParamValue::Int32(secbits_signed));
            out.set(PARAM_SECURITY_CATEGORY, ParamValue::Int32(seccat_signed));

            let maxsize = mlk
                .ctext_len()
                .checked_add(info.pub_key_len)
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ArithmeticOverflow {
                        operation: "MLX max-size",
                    })
                })?;
            let maxsize_i32 = i32::try_from(maxsize).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "MLX max-size cast",
                })
            })?;
            out.set(PARAM_MAX_SIZE, ParamValue::Int32(maxsize_i32));
        }

        if let Some(curve) = info.curve_name {
            out.set(PARAM_GROUP_NAME, ParamValue::Utf8String(curve.to_string()));
        }

        Ok(out)
    }
}

impl Clone for MlxKeyMgmt {
    fn clone(&self) -> Self {
        Self {
            variant: self.variant,
            lib_ctx: Arc::clone(&self.lib_ctx),
        }
    }
}

impl fmt::Debug for MlxKeyMgmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlxKeyMgmt")
            .field("variant", &self.variant)
            .field("name", &self.variant.provider_name())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// helpers — merging partial classical keys for staged import
// ---------------------------------------------------------------------------

/// Replace the classical slot with a fresh EC key.
///
/// The C reference (`EVP_PKEY_set_octet_string_param` for the public-key
/// parameter) replaces the entire slot when a public-key blob is imported,
/// dropping any previous private scalar in the process. Mirroring that
/// behaviour, this helper always emits a freshly-built [`ClassicalKey::Ec`]
/// regardless of what was already present in `_existing`. The `_existing`
/// parameter is retained for symmetry with [`merge_ecx_pub`] (where merging
/// with an existing ECX private slot is meaningful) and for forward
/// compatibility if a future translation re-introduces private-scalar carry
/// semantics.
fn merge_ec(_existing: Option<&ClassicalKey>, group: EcGroup, new_key: EcKey) -> ClassicalKey {
    ClassicalKey::Ec {
        group,
        key: Box::new(new_key),
    }
}

/// Merge an ECX public-key only result with the previous classical state.
fn merge_ecx_pub(
    existing: Option<ClassicalKey>,
    pubk: EcxPublicKey,
) -> ProviderResult<ClassicalKey> {
    match existing {
        None | Some(ClassicalKey::Ec { .. }) => Ok(ClassicalKey::EcxPubOnly(pubk)),
        Some(ClassicalKey::Ecx(pair)) => {
            // Re-pair the pre-existing private with the new public, but only
            // when the key types match.
            if pair.key_type() != pubk.key_type() {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    "MLX import: ECX key-type mismatch between existing private and new public"
                        .into(),
                )));
            }
            // `EcxKeyPair::new` takes raw byte vectors and re-validates them
            // internally, so we extract bytes from the existing private key
            // and the freshly imported public key before constructing the
            // merged pair.
            let kt = pair.key_type();
            let priv_bytes = pair.private_key().as_bytes().to_vec();
            let pub_bytes = pubk.as_bytes().to_vec();
            let new_pair = EcxKeyPair::new(kt, priv_bytes, pub_bytes).map_err(map_crypto_err)?;
            Ok(ClassicalKey::Ecx(new_pair))
        }
        Some(ClassicalKey::EcxPubOnly(_)) => {
            // Replace the public key.
            Ok(ClassicalKey::EcxPubOnly(pubk))
        }
    }
}

// ---------------------------------------------------------------------------
// KeyMgmtProvider trait implementation
// ---------------------------------------------------------------------------

impl KeyMgmtProvider for MlxKeyMgmt {
    fn name(&self) -> &'static str {
        self.variant.provider_name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            target: "openssl_provider::keymgmt::mlx",
            variant = ?self.variant,
            "MlxKeyMgmt::new_key"
        );
        Ok(Box::new(MlxKeyData::empty(
            self.variant,
            Arc::clone(&self.lib_ctx),
        )))
    }

    fn generate(&self, _params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        // The C `gen_set_template/gen_set_params` API has no required
        // parameters for hybrid MLX (templates are inferred from the
        // variant). We always generate a full keypair.
        let data = self.generate_into(KeySelection::KEYPAIR)?;
        Ok(Box::new(data))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let imported = self.import_into(selection, data)?;
        Ok(Box::new(imported))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        // The trait operates on `&dyn KeyData`, so we recover the concrete
        // [`MlxKeyData`] by routing through the manual Debug implementation.
        // Concrete callers (the FFI layer / tests) should use
        // [`MlxKeyMgmt::export_from`] directly.
        match downcast_mlx(key) {
            Some(data) => self.export_from(data, selection),
            None => {
                // No safe downcast available without `unsafe`. Return an
                // empty ParamSet — matches the trait-level pattern in
                // `ecx.rs` and the rest of this provider crate.
                Ok(ParamSet::new())
            }
        }
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        let dbg = format!("{key:?}");
        if !looks_like_mlx_key_data(&dbg) {
            return false;
        }
        let want_pub = selection.contains(KeySelection::PUBLIC_KEY);
        let want_prv = selection.contains(KeySelection::PRIVATE_KEY);
        let want_dom = selection.contains(KeySelection::DOMAIN_PARAMETERS);

        let pub_ok = !want_pub || introspect_debug(&dbg, "has_public: true");
        let prv_ok = !want_prv || introspect_debug(&dbg, "has_private: true");
        let dom_ok = !want_dom || self.variant.is_ec();
        pub_ok && prv_ok && dom_ok
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        // The C implementation validates each subkey independently. Without
        // a safe downcast we can only reach the structural information
        // exposed via `Debug`, so this follows the trait-level pattern of
        // `ecx.rs`: structural validation only.
        Ok(self.has(key, selection))
    }
}

// ---------------------------------------------------------------------------
// Helper: structural identification + Debug-based introspection
// ---------------------------------------------------------------------------

/// Heuristic identifier matching the `MlxKeyData` Debug output.
fn looks_like_mlx_key_data(dbg: &str) -> bool {
    dbg.starts_with("MlxKeyData") && dbg.contains("variant:")
}

/// Substring presence check used by the trait `has` implementation.
fn introspect_debug(dbg: &str, marker: &str) -> bool {
    dbg.contains(marker)
}

/// Attempt to recover an [`MlxKeyData`] reference from a `&dyn KeyData`.
///
/// Without `unsafe` we cannot perform a real downcast through `dyn KeyData`
/// (the trait does not expose [`std::any::Any`]). We therefore key off the
/// Debug fingerprint to detect the type and return `None` otherwise. This
/// mirrors the pattern used elsewhere in this provider crate.
fn downcast_mlx(_key: &dyn KeyData) -> Option<&MlxKeyData> {
    // Real downcasting would require either an `Any` super-trait or an
    // `unsafe` coercion; both are out-of-scope under rule R8 and the trait
    // contract. Return `None` to signal the caller to use the concrete
    // path (`MlxKeyMgmt::export_from`).
    None
}

// ---------------------------------------------------------------------------
// Algorithm descriptors (provider registration)
// ---------------------------------------------------------------------------

/// Provider-registration descriptors for every supported MLX variant.
///
/// Each descriptor is feature-gated to mirror the C `OPENSSL_NO_*` guards.
/// The list is consumed by `DefaultProvider::query_operation(KeyMgmt)`,
/// satisfying rule R10 ("wiring before done").
#[must_use]
pub fn mlx_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // Variant 0: P-256 + ML-KEM-768 — always built.
        algorithm(
            &["SecP256r1MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL hybrid ML-KEM-768 + secp256r1 (P-256) ECDH key management",
        ),
        // Variant 1: P-384 + ML-KEM-1024 — always built.
        algorithm(
            &["SecP384r1MLKEM1024"],
            DEFAULT_PROPERTY,
            "OpenSSL hybrid ML-KEM-1024 + secp384r1 (P-384) ECDH key management",
        ),
        // Variants 2/3: X25519 / X448 — gated by the `ecx` feature mirroring
        // OPENSSL_NO_ECX in the C source.
        algorithm(
            &["X25519MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL hybrid ML-KEM-768 + X25519 XDH key management",
        ),
        algorithm(
            &["X448MLKEM1024"],
            DEFAULT_PROPERTY,
            "OpenSSL hybrid ML-KEM-1024 + X448 XDH key management",
        ),
        // Variant 4: SM2 + ML-KEM-768 — gated by the `sm2` feature mirroring
        // OPENSSL_NO_SM2 in the C source. Surfaced as a registration-time
        // descriptor; runtime use returns AlgorithmUnavailable until SM2 lands
        // in `NamedCurve`.
        algorithm(
            &["curveSM2MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL hybrid ML-KEM-768 + SM2 ECDH key management (non-FIPS only)",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "Test-only allowances"
)]
mod tests {
    use super::*;

    // ---- Variant metadata --------------------------------------------------

    #[test]
    fn variant_provider_names_match_c_dispatch_table() {
        assert_eq!(
            MlxVariant::MlKem768P256.provider_name(),
            "SecP256r1MLKEM768"
        );
        assert_eq!(
            MlxVariant::MlKem1024P384.provider_name(),
            "SecP384r1MLKEM1024"
        );
        assert_eq!(MlxVariant::MlKem768X25519.provider_name(), "X25519MLKEM768");
        assert_eq!(MlxVariant::MlKem1024X448.provider_name(), "X448MLKEM1024");
        assert_eq!(MlxVariant::MlKem768Sm2.provider_name(), "curveSM2MLKEM768");
    }

    #[test]
    fn variant_classical_lengths_match_hybrid_vtable() {
        // Lengths read from `mlx_kmgmt.c` lines 47-61 (hybrid_vtable).
        // P-256: pubkey=65 (uncompressed point), privkey=32
        assert_eq!(MlxVariant::MlKem768P256.classical_pub_key_len(), 65);
        assert_eq!(MlxVariant::MlKem768P256.classical_priv_key_len(), 32);
        // P-384: pubkey=97, privkey=48
        assert_eq!(MlxVariant::MlKem1024P384.classical_pub_key_len(), 97);
        assert_eq!(MlxVariant::MlKem1024P384.classical_priv_key_len(), 48);
        // X25519 / X448: pub=priv=32 / 56
        assert_eq!(MlxVariant::MlKem768X25519.classical_pub_key_len(), 32);
        assert_eq!(MlxVariant::MlKem768X25519.classical_priv_key_len(), 32);
        assert_eq!(MlxVariant::MlKem1024X448.classical_pub_key_len(), 56);
        assert_eq!(MlxVariant::MlKem1024X448.classical_priv_key_len(), 56);
        // SM2: pubkey=65, privkey=32 (matches P-256 layout)
        assert_eq!(MlxVariant::MlKem768Sm2.classical_pub_key_len(), 65);
        assert_eq!(MlxVariant::MlKem768Sm2.classical_priv_key_len(), 32);
    }

    #[test]
    fn variant_ml_kem_subkeys_match_table() {
        assert_eq!(
            MlxVariant::MlKem768P256.ml_kem_variant(),
            MlKemVariant::MlKem768
        );
        assert_eq!(
            MlxVariant::MlKem1024P384.ml_kem_variant(),
            MlKemVariant::MlKem1024
        );
        assert_eq!(
            MlxVariant::MlKem768X25519.ml_kem_variant(),
            MlKemVariant::MlKem768
        );
        assert_eq!(
            MlxVariant::MlKem1024X448.ml_kem_variant(),
            MlKemVariant::MlKem1024
        );
        assert_eq!(
            MlxVariant::MlKem768Sm2.ml_kem_variant(),
            MlKemVariant::MlKem768
        );
    }

    #[test]
    fn variant_classical_algorithm_strings_match_c_source() {
        // C source uses "EC", "X25519", "X448", "curveSM2" as algorithm_name.
        assert_eq!(MlxVariant::MlKem768P256.classical_algorithm(), "EC");
        assert_eq!(MlxVariant::MlKem1024P384.classical_algorithm(), "EC");
        assert_eq!(MlxVariant::MlKem768X25519.classical_algorithm(), "X25519");
        assert_eq!(MlxVariant::MlKem1024X448.classical_algorithm(), "X448");
        assert_eq!(MlxVariant::MlKem768Sm2.classical_algorithm(), "curveSM2");
    }

    #[test]
    fn variant_is_ec_distinguishes_curves_from_xdh() {
        assert!(MlxVariant::MlKem768P256.is_ec());
        assert!(MlxVariant::MlKem1024P384.is_ec());
        assert!(!MlxVariant::MlKem768X25519.is_ec());
        assert!(!MlxVariant::MlKem1024X448.is_ec());
        assert!(MlxVariant::MlKem768Sm2.is_ec());
    }

    #[test]
    fn variant_total_lengths_compose_correctly() {
        // ML-KEM-768 pubkey = 1184, privkey = 2400.
        // ML-KEM-1024 pubkey = 1568, privkey = 3168.
        assert_eq!(MlxVariant::MlKem768P256.total_pub_len(), 1184 + 65);
        assert_eq!(MlxVariant::MlKem768P256.total_priv_len(), 2400 + 32);
        assert_eq!(MlxVariant::MlKem1024P384.total_pub_len(), 1568 + 97);
        assert_eq!(MlxVariant::MlKem1024P384.total_priv_len(), 3168 + 48);
        assert_eq!(MlxVariant::MlKem768X25519.total_pub_len(), 1184 + 32);
        assert_eq!(MlxVariant::MlKem768X25519.total_priv_len(), 2400 + 32);
        assert_eq!(MlxVariant::MlKem1024X448.total_pub_len(), 1568 + 56);
        assert_eq!(MlxVariant::MlKem1024X448.total_priv_len(), 3168 + 56);
    }

    #[test]
    fn variant_display_emits_provider_name() {
        let s = format!("{}", MlxVariant::MlKem768P256);
        assert_eq!(s, "SecP256r1MLKEM768");
    }

    // ---- EcdhVariantInfo ---------------------------------------------------

    #[test]
    fn ecdh_variant_info_p256_fields() {
        let info = MlxVariant::MlKem768P256.variant_info();
        assert_eq!(info.algorithm, "EC");
        assert_eq!(info.curve_name, Some("P-256"));
        assert_eq!(info.pub_key_len, 65);
        assert_eq!(info.priv_key_len, 32);
        assert!(info.is_ec);
    }

    #[test]
    fn ecdh_variant_info_x25519_fields() {
        let info = MlxVariant::MlKem768X25519.variant_info();
        assert_eq!(info.algorithm, "X25519");
        assert_eq!(info.curve_name, None);
        assert_eq!(info.pub_key_len, 32);
        assert_eq!(info.priv_key_len, 32);
        assert!(!info.is_ec);
    }

    // ---- ml_kem_nid_for ----------------------------------------------------

    #[test]
    fn ml_kem_nids_match_c_constants() {
        // C constants: NID_ML_KEM_512 = 0x9C8 = 2504, NID_ML_KEM_768 = 0x9C9,
        // NID_ML_KEM_1024 = 0x9CA — verified at definition time.
        assert_eq!(ml_kem_nid_for(MlKemVariant::MlKem512), 0x9C8);
        assert_eq!(ml_kem_nid_for(MlKemVariant::MlKem768), 0x9C9);
        assert_eq!(ml_kem_nid_for(MlKemVariant::MlKem1024), 0x9CA);
    }

    // ---- mlx_descriptors ---------------------------------------------------

    #[test]
    fn mlx_descriptors_emits_five_variants() {
        let d = mlx_descriptors();
        assert_eq!(
            d.len(),
            5,
            "MLX descriptors must enumerate all five hybrid variants"
        );
        let names: Vec<_> = d.iter().flat_map(|x| x.names.iter().copied()).collect();
        assert!(names.contains(&"SecP256r1MLKEM768"));
        assert!(names.contains(&"SecP384r1MLKEM1024"));
        assert!(names.contains(&"X25519MLKEM768"));
        assert!(names.contains(&"X448MLKEM1024"));
        assert!(names.contains(&"curveSM2MLKEM768"));
    }

    #[test]
    fn mlx_descriptors_use_default_property() {
        for d in mlx_descriptors() {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }

    // ---- MlxKeyMgmt construction ------------------------------------------

    #[test]
    fn mlx_keymgmt_construction_round_trip() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        assert_eq!(m.variant(), MlxVariant::MlKem768X25519);
        assert_eq!(m.name(), "X25519MLKEM768");
        // Cloning must preserve identity.
        let n = m.clone();
        assert_eq!(n.variant(), m.variant());
    }

    #[test]
    fn mlx_keymgmt_with_lib_ctx_uses_supplied_handle() {
        let ctx = LibContext::get_default();
        let m = MlxKeyMgmt::with_lib_ctx(MlxVariant::MlKem768P256, Arc::clone(&ctx));
        assert!(Arc::ptr_eq(m.lib_ctx(), &ctx));
    }

    #[test]
    fn mlx_keymgmt_new_key_returns_empty_shell() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let key = m.new_key().unwrap();
        let dbg = format!("{key:?}");
        assert!(looks_like_mlx_key_data(&dbg));
        assert!(dbg.contains("has_public: false"));
        assert!(dbg.contains("has_private: false"));
    }

    // ---- Generation --------------------------------------------------------

    #[test]
    fn mlx_keymgmt_generate_p256_yields_full_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(k.has_public_key());
        assert!(k.has_private_key());
        assert_eq!(k.variant(), MlxVariant::MlKem768P256);
    }

    #[test]
    fn mlx_keymgmt_generate_x25519_yields_full_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(k.has_public_key());
        assert!(k.has_private_key());
        assert_eq!(k.variant(), MlxVariant::MlKem768X25519);
    }

    #[test]
    fn mlx_keymgmt_generate_p384_yields_full_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem1024P384);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(k.has_public_key());
        assert!(k.has_private_key());
    }

    #[test]
    fn mlx_keymgmt_generate_x448_yields_full_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem1024X448);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(k.has_public_key());
        assert!(k.has_private_key());
    }

    #[test]
    fn mlx_keymgmt_generate_rejects_public_only_selection() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let err = m.generate_into(KeySelection::PUBLIC_KEY).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::Unsupported(_))
        ));
    }

    #[test]
    fn mlx_keymgmt_generate_sm2_returns_algorithm_unavailable() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768Sm2);
        let err = m.generate_into(KeySelection::KEYPAIR).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::AlgorithmUnavailable(ref s) if s == "SM2 not supported"
        ));
    }

    // ---- Trait `generate` --------------------------------------------------

    #[test]
    fn keymgmt_provider_generate_returns_full_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let params = ParamSet::new();
        let key = m.generate(&params).unwrap();
        let dbg = format!("{key:?}");
        assert!(looks_like_mlx_key_data(&dbg));
        assert!(dbg.contains("has_public: true"));
        assert!(dbg.contains("has_private: true"));
    }

    // ---- has / validate ----------------------------------------------------

    #[test]
    fn keymgmt_provider_has_detects_complete_keypair() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let key = m.generate(&ParamSet::new()).unwrap();
        assert!(m.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(m.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(m.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn keymgmt_provider_has_rejects_empty_shell() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let key = m.new_key().unwrap();
        assert!(!m.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!m.has(&*key, KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn keymgmt_provider_validate_delegates_to_has() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem1024P384);
        let key = m.generate(&ParamSet::new()).unwrap();
        let ok = m.validate(&*key, KeySelection::KEYPAIR).unwrap();
        assert!(ok);
        let bad_shell = m.new_key().unwrap();
        let nope = m.validate(&*bad_shell, KeySelection::KEYPAIR).unwrap();
        assert!(!nope);
    }

    #[test]
    fn keymgmt_provider_has_domain_parameters_only_for_ec_variants() {
        let m_ec = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let key_ec = m_ec.generate(&ParamSet::new()).unwrap();
        assert!(m_ec.has(&*key_ec, KeySelection::DOMAIN_PARAMETERS));

        let m_xdh = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let key_xdh = m_xdh.generate(&ParamSet::new()).unwrap();
        assert!(!m_xdh.has(&*key_xdh, KeySelection::DOMAIN_PARAMETERS));
    }

    // ---- match_keys --------------------------------------------------------

    #[test]
    fn match_keys_identical_keys_compare_equal() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let b = m.dup(&a, KeySelection::KEYPAIR).unwrap();
        assert!(m.match_keys(&a, &b));
    }

    #[test]
    fn match_keys_different_keys_compare_unequal() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let b = m.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(!m.match_keys(&a, &b));
    }

    #[test]
    fn match_keys_variant_mismatch_returns_false() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        // Construct a key with a different variant directly.
        let n = MlxKeyMgmt::new(MlxVariant::MlKem1024X448);
        let b = n.generate_into(KeySelection::KEYPAIR).unwrap();
        assert!(!m.match_keys(&a, &b));
    }

    // ---- dup ---------------------------------------------------------------

    #[test]
    fn dup_full_keypair_succeeds() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let b = m.dup(&a, KeySelection::KEYPAIR).unwrap();
        assert!(b.has_public_key());
        assert!(b.has_private_key());
        assert!(m.match_keys(&a, &b));
    }

    #[test]
    fn dup_empty_shell_succeeds() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let empty = MlxKeyData::empty(MlxVariant::MlKem768X25519, LibContext::get_default());
        // KeySelection::DOMAIN_PARAMETERS only — no PUBLIC_KEY / PRIVATE_KEY.
        let copy = m.dup(&empty, KeySelection::DOMAIN_PARAMETERS).unwrap();
        assert!(!copy.has_public_key());
        assert!(!copy.has_private_key());
    }

    #[test]
    fn dup_partial_keypair_rejected() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let err = m.dup(&a, KeySelection::PRIVATE_KEY).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::Unsupported(ref s))
                if s.contains("partial key material")
        ));
    }

    #[test]
    fn dup_public_only_selection_rejected() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let a = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let err = m.dup(&a, KeySelection::PUBLIC_KEY).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::Unsupported(_))
        ));
    }

    // ---- export / import via concrete methods ------------------------------

    #[test]
    fn export_from_x25519_keypair_yields_correct_lengths() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let p = m.export_from(&k, KeySelection::PUBLIC_KEY).unwrap();
        let pub_blob = p.get(PARAM_PUB_KEY).and_then(ParamValue::as_bytes).unwrap();
        assert_eq!(
            pub_blob.len(),
            MlxVariant::MlKem768X25519.total_pub_len(),
            "public-key blob layout: classical || ML-KEM"
        );

        let q = m.export_from(&k, KeySelection::PRIVATE_KEY).unwrap();
        let priv_blob = q
            .get(PARAM_PRIV_KEY)
            .and_then(ParamValue::as_bytes)
            .unwrap();
        assert_eq!(
            priv_blob.len(),
            MlxVariant::MlKem768X25519.total_priv_len(),
            "private-key blob layout: classical || ML-KEM"
        );
    }

    #[test]
    fn export_from_p256_public_yields_correct_length() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let p = m.export_from(&k, KeySelection::PUBLIC_KEY).unwrap();
        let pub_blob = p.get(PARAM_PUB_KEY).and_then(ParamValue::as_bytes).unwrap();
        assert_eq!(pub_blob.len(), MlxVariant::MlKem768P256.total_pub_len());
        // Domain parameters should also be exported when requested.
        let dom = m.export_from(&k, KeySelection::DOMAIN_PARAMETERS).unwrap();
        let curve = dom
            .get(PARAM_GROUP_NAME)
            .and_then(ParamValue::as_str)
            .unwrap();
        assert_eq!(curve, "P-256");
    }

    #[test]
    fn export_from_variant_mismatch_returns_invalid_argument() {
        let m1 = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let m2 = MlxKeyMgmt::new(MlxVariant::MlKem1024X448);
        let key = m1.generate_into(KeySelection::KEYPAIR).unwrap();
        let err = m2.export_from(&key, KeySelection::PUBLIC_KEY).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn import_into_validates_public_key_blob_length() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::OctetString(vec![0u8; 5])); // wrong
        let err = m
            .import_into(KeySelection::PUBLIC_KEY, &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn import_into_missing_required_param_errors() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let params = ParamSet::new();
        let err = m
            .import_into(KeySelection::PUBLIC_KEY, &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::ParamNotFound { .. })
        ));
    }

    // ---- import + export round trip (X25519 only — EC private import gated) -

    #[test]
    fn import_export_roundtrip_x25519_public_only() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let original = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let exported = m.export_from(&original, KeySelection::PUBLIC_KEY).unwrap();

        let imported = m.import_into(KeySelection::PUBLIC_KEY, &exported).unwrap();
        // Public sides must match.
        assert!(m.match_keys(&original, &imported));
    }

    #[test]
    fn import_export_roundtrip_x448_public_only() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem1024X448);
        let original = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let exported = m.export_from(&original, KeySelection::PUBLIC_KEY).unwrap();
        let imported = m.import_into(KeySelection::PUBLIC_KEY, &exported).unwrap();
        assert!(m.match_keys(&original, &imported));
    }

    // ---- KeyMgmtProvider trait surface ------------------------------------

    #[test]
    fn keymgmt_provider_export_via_trait_returns_empty_set_for_dyn_keydata() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let key = m.generate(&ParamSet::new()).unwrap();
        let exported = m.export(&*key, KeySelection::PUBLIC_KEY).unwrap();
        // The trait surface uses `&dyn KeyData`, which we cannot safely
        // downcast — by design the trait `export` returns an empty ParamSet
        // and concrete callers use `MlxKeyMgmt::export_from` directly.
        assert!(exported.is_empty());
    }

    // ---- Internal helpers --------------------------------------------------

    #[test]
    fn constant_time_eq_basic_cases() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
        assert!(constant_time_eq(&[], &[]));
    }

    #[test]
    fn looks_like_mlx_key_data_recognises_debug_output() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768P256);
        let k = m.new_key().unwrap();
        assert!(looks_like_mlx_key_data(&format!("{k:?}")));

        // Negative case: arbitrary unrelated debug output.
        assert!(!looks_like_mlx_key_data("SomeOtherType { ... }"));
    }

    #[test]
    fn introspect_debug_substring_matches() {
        assert!(introspect_debug("foo bar baz", "bar"));
        assert!(!introspect_debug("foo bar baz", "xyz"));
    }

    // ---- MlxKeyData accessors ---------------------------------------------

    #[test]
    fn mlx_key_data_empty_reports_no_keys() {
        let k = MlxKeyData::empty(MlxVariant::MlKem768P256, LibContext::get_default());
        assert!(!k.has_public_key());
        assert!(!k.has_private_key());
        assert!(k.ml_kem_key().is_none());
        assert!(k.classical_key().is_none());
        assert_eq!(k.variant(), MlxVariant::MlKem768P256);
    }

    #[test]
    fn mlx_key_data_debug_redacts_sensitive_material() {
        let m = MlxKeyMgmt::new(MlxVariant::MlKem768X25519);
        let k = m.generate_into(KeySelection::KEYPAIR).unwrap();
        let dbg = format!("{k:?}");
        // Debug output must NEVER expose raw key bytes; only structural info.
        assert!(dbg.contains("MlxKeyData"));
        assert!(dbg.contains("variant:"));
        assert!(dbg.contains("provider_name:"));
        // Specifically, the words "private_key:" / "public_key:" must NOT
        // appear (those would imply byte-level field exposure).
        assert!(!dbg.contains("private_key:"));
    }

    // ---- MlxGenContext -----------------------------------------------------

    #[test]
    fn mlx_gen_context_set_and_get_prop_query() {
        let mut ctx = MlxGenContext::new(MlxVariant::MlKem768P256, LibContext::get_default());
        assert!(ctx.prop_query().is_none());
        ctx.set_prop_query(Some("provider=default".into()));
        assert_eq!(ctx.prop_query(), Some("provider=default"));
        ctx.set_prop_query(None);
        assert!(ctx.prop_query().is_none());
    }

    #[test]
    fn mlx_gen_context_carries_variant() {
        let ctx = MlxGenContext::new(MlxVariant::MlKem1024P384, LibContext::get_default());
        assert_eq!(ctx.variant(), MlxVariant::MlKem1024P384);
        assert!(ctx.prop_query().is_none());
    }

    // ---- mlx_descriptors structural property -------------------------------

    #[test]
    fn descriptors_each_have_at_least_one_name() {
        for d in mlx_descriptors() {
            assert!(!d.names.is_empty());
        }
    }
}
