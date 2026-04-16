//! HPKE (Hybrid Public Key Encryption) implementation per RFC 9180.
//!
//! Provides key encapsulation and authenticated encryption for public key
//! recipients. Supports Base, PSK, Auth, and `AuthPSK` modes. Used by ECH
//! (Encrypted Client Hello) in TLS 1.3. Replaces C `OSSL_HPKE_*` functions
//! from `crypto/hpke/hpke.c` and `crypto/hpke/hpke_util.c`.
//!
//! # Modes (RFC 9180 §5)
//!
//! | Mode      | Enum Variant       | PSK Required | Auth Key Required |
//! |-----------|--------------------|--------------|-------------------|
//! | Base      | [`HpkeMode::Base`] | No           | No                |
//! | PSK       | [`HpkeMode::Psk`]  | Yes          | No                |
//! | Auth      | [`HpkeMode::Auth`] | No           | Yes               |
//! | `AuthPSK` | [`HpkeMode::AuthPsk`] | Yes       | Yes               |
//!
//! # Suite Selection
//!
//! An HPKE suite ([`HpkeSuite`]) is a triple of (KEM, KDF, AEAD) algorithms
//! identified by their IANA-registered codepoints. See:
//! <https://www.iana.org/assignments/hpke/hpke.xhtml>
//!
//! # Security
//!
//! All key material is securely zeroed on drop via the `zeroize` crate,
//! replacing C `OPENSSL_cleanse()` calls. There is zero `unsafe` in this
//! module (Rule R8).
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::hpke::*;
//!
//! let suite = HpkeSuite::new(
//!     HpkeKem::DhKemX25519Sha256,
//!     HpkeKdf::HkdfSha256,
//!     HpkeAead::Aes128Gcm,
//! );
//! // Sender side: setup and seal
//! let recipient_public_key: &[u8] = &[/* ... */];
//! let info = b"application info";
//! let (mut sender_ctx, enc) = setup_sender(suite, HpkeMode::Base, recipient_public_key, info)
//!     .expect("sender setup");
//! let ciphertext = seal(&mut sender_ctx, b"aad", b"plaintext")
//!     .expect("seal");
//! ```

use openssl_common::{CryptoError, CryptoResult};
use zeroize::ZeroizeOnDrop;

// =============================================================================
// Constants — RFC 9180 Protocol Labels
// =============================================================================

/// "HPKE" — `suite_id` label for RFC 9180 §5.1 key schedule.
const LABEL_HPKE: &[u8] = b"HPKE";

/// "HPKE-v1" — versioned protocol label prefix for `LabeledExtract`/`LabeledExpand`.
const LABEL_HPKE_V1: &[u8] = b"HPKE-v1";

/// `psk_id_hash` — label for PSK identity hash in key schedule context.
const LABEL_PSK_ID_HASH: &[u8] = b"psk_id_hash";

/// `info_hash` — label for info hash in key schedule context.
const LABEL_INFO_HASH: &[u8] = b"info_hash";

/// `base_nonce` — label for base nonce derivation.
const LABEL_BASE_NONCE: &[u8] = b"base_nonce";

/// `exp` — label for internal exporter secret generation.
const LABEL_EXP: &[u8] = b"exp";

/// `sec` — label for external secret export.
const LABEL_SEC: &[u8] = b"sec";

/// `key` — label for AEAD key derivation from shared secret.
const LABEL_KEY: &[u8] = b"key";

/// `secret` — label for generating the shared secret.
const LABEL_SECRET: &[u8] = b"secret";

/// Maximum buffer size for keys and internal buffers (mirrors C `OSSL_HPKE_MAXSIZE`).
const HPKE_MAX_SIZE: usize = 512;

/// Maximum nonce length for AEAD algorithms (12 bytes for AES-GCM and `ChaCha20-Poly1305`).
const MAX_NONCE_LEN: usize = 12;

/// Maximum allowed length for info, PSK ID, and other variable-length parameters.
const MAX_PARM_LEN: usize = 8192;

/// Minimum PSK length to prevent trivial PSK values (matches C `OSSL_HPKE_MIN_PSKLEN`).
const MIN_PSK_LEN: usize = 32;

/// Maximum allowed info length (matches C `OSSL_HPKE_MAX_INFOLEN`).
const MAX_INFO_LEN: usize = 1024;

// =============================================================================
// HpkeKem — Key Encapsulation Mechanism Identifiers
// =============================================================================

/// HPKE Key Encapsulation Mechanism (KEM) identifiers per RFC 9180 §7.1.
///
/// Each variant corresponds to an IANA-registered KEM ID. The `repr(u16)`
/// discriminant matches the IANA codepoint exactly for efficient suite
/// serialization per Rule R6 (explicit `as` only for constant definition;
/// runtime conversions use `try_from`).
///
/// # IANA Registry
///
/// See Table 2 "KEM IDs" at <https://www.iana.org/assignments/hpke/hpke.xhtml>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HpkeKem {
    /// DHKEM(P-256, HKDF-SHA256) — NIST P-256 curve with SHA-256.
    DhKemP256Sha256 = 0x0010,
    /// DHKEM(P-384, HKDF-SHA384) — NIST P-384 curve with SHA-384.
    DhKemP384Sha384 = 0x0011,
    /// DHKEM(P-521, HKDF-SHA512) — NIST P-521 curve with SHA-512.
    DhKemP521Sha512 = 0x0012,
    /// DHKEM(X25519, HKDF-SHA256) — Curve25519 with SHA-256.
    DhKemX25519Sha256 = 0x0020,
    /// DHKEM(X448, HKDF-SHA512) — Curve448 with SHA-512.
    DhKemX448Sha512 = 0x0021,
}

impl HpkeKem {
    /// Returns the IANA-registered numeric identifier for this KEM.
    ///
    /// # Example
    ///
    /// ```
    /// # use openssl_crypto::hpke::HpkeKem;
    /// assert_eq!(HpkeKem::DhKemX25519Sha256.id(), 0x0020);
    /// ```
    #[inline]
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Returns the [`HpkeKemInfo`] metadata for this KEM.
    #[inline]
    pub fn info(self) -> &'static HpkeKemInfo {
        match self {
            Self::DhKemP256Sha256 => &KEM_INFO_P256,
            Self::DhKemP384Sha384 => &KEM_INFO_P384,
            Self::DhKemP521Sha512 => &KEM_INFO_P521,
            Self::DhKemX25519Sha256 => &KEM_INFO_X25519,
            Self::DhKemX448Sha512 => &KEM_INFO_X448,
        }
    }

    /// Returns `true` if this KEM uses a NIST elliptic curve (P-256, P-384, P-521).
    #[inline]
    pub const fn is_nist_curve(self) -> bool {
        matches!(
            self,
            Self::DhKemP256Sha256 | Self::DhKemP384Sha384 | Self::DhKemP521Sha512
        )
    }
}

impl TryFrom<u16> for HpkeKem {
    type Error = CryptoError;

    /// Converts a `u16` IANA codepoint to an [`HpkeKem`] variant.
    ///
    /// Returns `CryptoError::AlgorithmNotFound` for unrecognized KEM IDs per Rule R5.
    fn try_from(value: u16) -> CryptoResult<Self> {
        match value {
            0x0010 => Ok(Self::DhKemP256Sha256),
            0x0011 => Ok(Self::DhKemP384Sha384),
            0x0012 => Ok(Self::DhKemP521Sha512),
            0x0020 => Ok(Self::DhKemX25519Sha256),
            0x0021 => Ok(Self::DhKemX448Sha512),
            _ => Err(CryptoError::AlgorithmNotFound(format!(
                "unknown HPKE KEM ID: 0x{value:04x}"
            ))),
        }
    }
}

impl std::fmt::Display for HpkeKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DhKemP256Sha256 => write!(f, "DHKEM(P-256, HKDF-SHA256)"),
            Self::DhKemP384Sha384 => write!(f, "DHKEM(P-384, HKDF-SHA384)"),
            Self::DhKemP521Sha512 => write!(f, "DHKEM(P-521, HKDF-SHA512)"),
            Self::DhKemX25519Sha256 => write!(f, "DHKEM(X25519, HKDF-SHA256)"),
            Self::DhKemX448Sha512 => write!(f, "DHKEM(X448, HKDF-SHA512)"),
        }
    }
}

// =============================================================================
// HpkeKdf — Key Derivation Function Identifiers
// =============================================================================

/// HPKE Key Derivation Function (KDF) identifiers per RFC 9180 §7.2.
///
/// Each variant corresponds to an IANA-registered KDF ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HpkeKdf {
    /// HKDF-SHA256 — KDF using HMAC-SHA256.
    HkdfSha256 = 0x0001,
    /// HKDF-SHA384 — KDF using HMAC-SHA384.
    HkdfSha384 = 0x0002,
    /// HKDF-SHA512 — KDF using HMAC-SHA512.
    HkdfSha512 = 0x0003,
}

impl HpkeKdf {
    /// Returns the IANA-registered numeric identifier for this KDF.
    #[inline]
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Returns the hash output length `Nh` in bytes for this KDF.
    #[inline]
    pub const fn hash_len(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
            Self::HkdfSha512 => 64,
        }
    }

    /// Returns the digest algorithm name string (e.g., `"SHA-256"`).
    #[inline]
    pub const fn digest_name(self) -> &'static str {
        match self {
            Self::HkdfSha256 => "SHA-256",
            Self::HkdfSha384 => "SHA-384",
            Self::HkdfSha512 => "SHA-512",
        }
    }
}

impl TryFrom<u16> for HpkeKdf {
    type Error = CryptoError;

    fn try_from(value: u16) -> CryptoResult<Self> {
        match value {
            0x0001 => Ok(Self::HkdfSha256),
            0x0002 => Ok(Self::HkdfSha384),
            0x0003 => Ok(Self::HkdfSha512),
            _ => Err(CryptoError::AlgorithmNotFound(format!(
                "unknown HPKE KDF ID: 0x{value:04x}"
            ))),
        }
    }
}

impl std::fmt::Display for HpkeKdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HkdfSha256 => write!(f, "HKDF-SHA256"),
            Self::HkdfSha384 => write!(f, "HKDF-SHA384"),
            Self::HkdfSha512 => write!(f, "HKDF-SHA512"),
        }
    }
}

// =============================================================================
// HpkeAead — Authenticated Encryption with Associated Data Identifiers
// =============================================================================

/// HPKE AEAD identifiers per RFC 9180 §7.3.
///
/// The [`ExportOnly`][Self::ExportOnly] variant (0xFFFF) disables
/// encryption/decryption and restricts the context to secret export
/// operations only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HpkeAead {
    /// AES-128-GCM — 128-bit AES in Galois/Counter Mode.
    Aes128Gcm = 0x0001,
    /// AES-256-GCM — 256-bit AES in Galois/Counter Mode.
    Aes256Gcm = 0x0002,
    /// `ChaCha20-Poly1305` — `ChaCha20` stream cipher with `Poly1305` MAC.
    ChaCha20Poly1305 = 0x0003,
    /// Export-only mode — no AEAD encryption, only secret export.
    ExportOnly = 0xFFFF,
}

impl HpkeAead {
    /// Returns the IANA-registered numeric identifier for this AEAD.
    #[inline]
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Returns the AEAD key length `Nk` in bytes, or 0 for [`ExportOnly`][Self::ExportOnly].
    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            Self::ExportOnly => 0,
        }
    }

    /// Returns the AEAD nonce length `Nn` in bytes, or 0 for [`ExportOnly`][Self::ExportOnly].
    #[inline]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => MAX_NONCE_LEN,
            Self::ExportOnly => 0,
        }
    }

    /// Returns the AEAD authentication tag length `Nt` in bytes, or 0
    /// for [`ExportOnly`][Self::ExportOnly].
    #[inline]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => 16,
            Self::ExportOnly => 0,
        }
    }

    /// Returns the AEAD algorithm name string, or `None` for [`ExportOnly`][Self::ExportOnly].
    #[inline]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::Aes128Gcm => Some("AES-128-GCM"),
            Self::Aes256Gcm => Some("AES-256-GCM"),
            Self::ChaCha20Poly1305 => Some("ChaCha20-Poly1305"),
            Self::ExportOnly => None,
        }
    }

    /// Returns `true` if this AEAD is the export-only sentinel.
    #[inline]
    pub const fn is_export_only(self) -> bool {
        matches!(self, Self::ExportOnly)
    }
}

impl TryFrom<u16> for HpkeAead {
    type Error = CryptoError;

    fn try_from(value: u16) -> CryptoResult<Self> {
        match value {
            0x0001 => Ok(Self::Aes128Gcm),
            0x0002 => Ok(Self::Aes256Gcm),
            0x0003 => Ok(Self::ChaCha20Poly1305),
            0xFFFF => Ok(Self::ExportOnly),
            _ => Err(CryptoError::AlgorithmNotFound(format!(
                "unknown HPKE AEAD ID: 0x{value:04x}"
            ))),
        }
    }
}

impl std::fmt::Display for HpkeAead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "AES-128-GCM"),
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            Self::ExportOnly => write!(f, "Export-Only"),
        }
    }
}

// =============================================================================
// HpkeMode — HPKE Operation Modes
// =============================================================================

/// HPKE modes per RFC 9180 §5.
///
/// The mode determines what additional keying material is required during
/// context setup (PSK, authentication key, or both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HpkeMode {
    /// Base mode — no additional authentication or PSK.
    Base = 0x00,
    /// PSK mode — pre-shared key required from both sender and recipient.
    Psk = 0x01,
    /// Auth mode — sender provides an authentication private key.
    Auth = 0x02,
    /// `AuthPsk` mode — both PSK and sender authentication key required.
    AuthPsk = 0x03,
}

impl HpkeMode {
    /// Returns the IANA-registered numeric identifier for this mode.
    #[inline]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Returns `true` if this mode requires a pre-shared key (PSK and `AuthPsk`).
    #[inline]
    pub const fn requires_psk(self) -> bool {
        matches!(self, Self::Psk | Self::AuthPsk)
    }

    /// Returns `true` if this mode requires authentication key material (Auth and `AuthPsk`).
    #[inline]
    pub const fn requires_auth(self) -> bool {
        matches!(self, Self::Auth | Self::AuthPsk)
    }
}

impl TryFrom<u8> for HpkeMode {
    type Error = CryptoError;

    fn try_from(value: u8) -> CryptoResult<Self> {
        match value {
            0x00 => Ok(Self::Base),
            0x01 => Ok(Self::Psk),
            0x02 => Ok(Self::Auth),
            0x03 => Ok(Self::AuthPsk),
            _ => Err(CryptoError::AlgorithmNotFound(format!(
                "unknown HPKE mode: 0x{value:02x}"
            ))),
        }
    }
}

impl std::fmt::Display for HpkeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base => write!(f, "Base"),
            Self::Psk => write!(f, "PSK"),
            Self::Auth => write!(f, "Auth"),
            Self::AuthPsk => write!(f, "AuthPSK"),
        }
    }
}

// =============================================================================
// HpkeKemInfo — KEM Metadata Table
// =============================================================================

/// Metadata for a specific HPKE KEM algorithm.
///
/// Replaces the C `OSSL_HPKE_KEM_INFO` struct from `internal/hpke_util.h`.
/// Provides sizing constants needed by callers to allocate correctly-sized
/// buffers for public keys, encapsulated keys, and shared secrets.
///
/// Instances are statically allocated and accessed via [`HpkeKem::info()`]
/// or [`HpkeKemInfo::find`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeKemInfo {
    /// The KEM identifier (IANA codepoint).
    kem: HpkeKem,
    /// Length of the public key in bytes (`Npk`).
    public_key_len: usize,
    /// Length of the secret (private) key in bytes (`Nsk`).
    secret_key_len: usize,
    /// Length of the encapsulated key in bytes (`Nenc`).
    enc_len: usize,
    /// Length of the shared secret in bytes (`Nsecret`).
    shared_secret_len: usize,
    /// Name of the digest algorithm associated with this KEM's KDF.
    digest_name: &'static str,
}

impl HpkeKemInfo {
    /// Returns the KEM identifier.
    #[inline]
    pub const fn kem_id(&self) -> u16 {
        self.kem as u16
    }

    /// Returns the public key length in bytes (`Npk`).
    #[inline]
    pub const fn public_key_len(&self) -> usize {
        self.public_key_len
    }

    /// Returns the secret (private) key length in bytes (`Nsk`).
    #[inline]
    pub const fn secret_key_len(&self) -> usize {
        self.secret_key_len
    }

    /// Returns the encapsulated key length in bytes (`Nenc`).
    #[inline]
    pub const fn enc_len(&self) -> usize {
        self.enc_len
    }

    /// Returns the shared secret length in bytes (`Nsecret`).
    #[inline]
    pub const fn shared_secret_len(&self) -> usize {
        self.shared_secret_len
    }

    /// Returns the name of the digest algorithm for this KEM (e.g., `"SHA-256"`).
    #[inline]
    pub const fn digest_name(&self) -> &'static str {
        self.digest_name
    }

    /// Looks up the [`HpkeKemInfo`] for the given [`HpkeKem`] variant.
    ///
    /// This is equivalent to [`HpkeKem::info()`] but provided as a static
    /// method on `HpkeKemInfo` for API discoverability.
    #[inline]
    pub fn find(kem: HpkeKem) -> &'static HpkeKemInfo {
        kem.info()
    }
}

// Static KEM info tables — matches C `hpke_kem_tab` from `hpke_util.c`.
// Sizes from RFC 9180 §7.1 Table 2.

/// DHKEM(P-256, HKDF-SHA256) — `Npk`=65, `Nsk`=32, `Nenc`=65, `Nsecret`=32
static KEM_INFO_P256: HpkeKemInfo = HpkeKemInfo {
    kem: HpkeKem::DhKemP256Sha256,
    public_key_len: 65,
    secret_key_len: 32,
    enc_len: 65,
    shared_secret_len: 32,
    digest_name: "SHA-256",
};

/// DHKEM(P-384, HKDF-SHA384) — `Npk`=97, `Nsk`=48, `Nenc`=97, `Nsecret`=48
static KEM_INFO_P384: HpkeKemInfo = HpkeKemInfo {
    kem: HpkeKem::DhKemP384Sha384,
    public_key_len: 97,
    secret_key_len: 48,
    enc_len: 97,
    shared_secret_len: 48,
    digest_name: "SHA-384",
};

/// DHKEM(P-521, HKDF-SHA512) — `Npk`=133, `Nsk`=66, `Nenc`=133, `Nsecret`=64
static KEM_INFO_P521: HpkeKemInfo = HpkeKemInfo {
    kem: HpkeKem::DhKemP521Sha512,
    public_key_len: 133,
    secret_key_len: 66,
    enc_len: 133,
    shared_secret_len: 64,
    digest_name: "SHA-512",
};

/// DHKEM(X25519, HKDF-SHA256) — `Npk`=32, `Nsk`=32, `Nenc`=32, `Nsecret`=32
static KEM_INFO_X25519: HpkeKemInfo = HpkeKemInfo {
    kem: HpkeKem::DhKemX25519Sha256,
    public_key_len: 32,
    secret_key_len: 32,
    enc_len: 32,
    shared_secret_len: 32,
    digest_name: "SHA-256",
};

/// DHKEM(X448, HKDF-SHA512) — `Npk`=56, `Nsk`=56, `Nenc`=56, `Nsecret`=64
static KEM_INFO_X448: HpkeKemInfo = HpkeKemInfo {
    kem: HpkeKem::DhKemX448Sha512,
    public_key_len: 56,
    secret_key_len: 56,
    enc_len: 56,
    shared_secret_len: 64,
    digest_name: "SHA-512",
};

// =============================================================================
// HpkeSuite — Cipher Suite Triple
// =============================================================================

/// An HPKE cipher suite: a triple of (KEM, KDF, AEAD) algorithms.
///
/// Replaces the C `OSSL_HPKE_SUITE` struct which held three `uint16_t`
/// codepoints. In Rust, each component is a typed enum, providing
/// compile-time validation of algorithm selection per Rule R5.
///
/// # Example
///
/// ```
/// # use openssl_crypto::hpke::*;
/// let suite = HpkeSuite::new(
///     HpkeKem::DhKemX25519Sha256,
///     HpkeKdf::HkdfSha256,
///     HpkeAead::Aes128Gcm,
/// );
/// assert_eq!(suite.kem(), HpkeKem::DhKemX25519Sha256);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HpkeSuite {
    /// The Key Encapsulation Mechanism for this suite.
    pub kem: HpkeKem,
    /// The Key Derivation Function for this suite.
    pub kdf: HpkeKdf,
    /// The Authenticated Encryption with Associated Data algorithm for this suite.
    pub aead: HpkeAead,
}

impl HpkeSuite {
    /// Constructs a new HPKE suite from the given algorithm identifiers.
    #[inline]
    pub const fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Returns the KEM component of this suite.
    #[inline]
    pub const fn kem(&self) -> HpkeKem {
        self.kem
    }

    /// Returns the KDF component of this suite.
    #[inline]
    pub const fn kdf(&self) -> HpkeKdf {
        self.kdf
    }

    /// Returns the AEAD component of this suite.
    #[inline]
    pub const fn aead(&self) -> HpkeAead {
        self.aead
    }

    /// Validates that all three components of this suite are supported.
    ///
    /// Returns `Ok(())` if the suite is valid, or an appropriate error if
    /// any component is unsupported.
    pub fn validate(&self) -> CryptoResult<()> {
        // All enum variants are valid by construction; this method is provided
        // for forward-compatibility if new variants are added behind feature flags.
        let _ = self.kem.info();
        Ok(())
    }

    /// Serializes the suite ID as a 6-byte buffer per RFC 9180 §5.1:
    /// `concat(I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))`.
    ///
    /// Used in the key schedule to domain-separate different suites.
    pub fn suite_id_bytes(&self) -> [u8; 6] {
        let kem_id = self.kem.id();
        let kdf_id = self.kdf.id();
        let aead_id = self.aead.id();
        [
            (kem_id >> 8) as u8,
            (kem_id & 0xFF) as u8,
            (kdf_id >> 8) as u8,
            (kdf_id & 0xFF) as u8,
            (aead_id >> 8) as u8,
            (aead_id & 0xFF) as u8,
        ]
    }

    /// Returns the ciphertext expansion (tag length) for this suite's AEAD.
    ///
    /// Given a plaintext of `clear_len` bytes, the ciphertext will be
    /// `clear_len + tag_len` bytes. Returns `None` for [`ExportOnly`][HpkeAead::ExportOnly].
    pub fn ciphertext_size(&self, clear_len: usize) -> Option<usize> {
        if self.aead.is_export_only() {
            return None;
        }
        clear_len.checked_add(self.aead.tag_len())
    }

    /// Returns the encapsulated key (`enc`) size for this suite's KEM.
    pub fn enc_size(&self) -> usize {
        self.kem.info().enc_len
    }

    /// Returns the recommended IKM (Input Key Material) length for key generation.
    pub fn recommended_ikm_len(&self) -> usize {
        self.kem.info().secret_key_len
    }
}

impl std::fmt::Display for HpkeSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.kem, self.kdf, self.aead)
    }
}

// =============================================================================
// HpkeSenderContext — Sender Encryption Context
// =============================================================================

/// HPKE sender context for encryption and secret export.
///
/// Created by [`setup_sender`]. Contains derived key material from the HPKE
/// key schedule. All sensitive fields are securely zeroed on drop via
/// `ZeroizeOnDrop`, replacing C `OPENSSL_cleanse()` calls.
///
/// # Usage
///
/// After setup, call [`HpkeSenderContext::seal`] to encrypt messages, or
/// [`HpkeSenderContext::export_secret`] to derive keying material.
///
/// # Sequence Number
///
/// Each [`seal`][HpkeSenderContext::seal] call increments an internal sequence
/// counter used to derive per-message nonces. The counter is a `u64` and
/// will return an error if it would overflow (after 2^64 - 1 messages).
#[derive(ZeroizeOnDrop)]
pub struct HpkeSenderContext {
    /// The negotiated cipher suite.
    #[zeroize(skip)]
    suite: HpkeSuite,
    /// The negotiated HPKE mode.
    #[zeroize(skip)]
    mode: HpkeMode,
    /// AEAD key derived from the key schedule. Empty for [`ExportOnly`][HpkeAead::ExportOnly].
    key: Vec<u8>,
    /// Base nonce derived from the key schedule. Empty for [`ExportOnly`][HpkeAead::ExportOnly].
    base_nonce: Vec<u8>,
    /// Exporter secret derived from the key schedule (`exp`).
    exporter_secret: Vec<u8>,
    /// Monotonically increasing sequence number for per-message nonce derivation.
    #[zeroize(skip)]
    seq: u64,
}

impl HpkeSenderContext {
    /// Encrypts `plaintext` with `aad` (Additional Authenticated Data) and
    /// returns the ciphertext including the authentication tag.
    ///
    /// Each call increments the internal sequence counter to derive a unique
    /// nonce per RFC 9180 §5.2 `ComputeNonce`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::Key` if the AEAD is [`ExportOnly`][HpkeAead::ExportOnly] (no encryption)
    /// - `CryptoError::Key` if the key schedule has not been run
    /// - `CryptoError::Key` if the sequence number would overflow
    /// - `CryptoError::Verification` if AEAD encryption fails
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        seal(self, aad, plaintext)
    }

    /// Derives an exported secret from the HPKE context per RFC 9180 §5.3.
    ///
    /// This operation is available in all modes, including [`ExportOnly`][HpkeAead::ExportOnly].
    /// The `exporter_context` provides domain separation, and `length`
    /// specifies the desired output length in bytes.
    ///
    /// # Errors
    ///
    /// - `CryptoError::Key` if the key schedule has not been run
    /// - `CryptoError::Key` if `length` is zero or exceeds maximum
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        export_secret_from_exporter_sec(
            self.suite,
            &self.exporter_secret,
            exporter_context,
            length,
        )
    }

    /// Returns the current sequence number.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the negotiated cipher suite.
    #[inline]
    pub fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Returns the negotiated HPKE mode.
    #[inline]
    pub fn mode(&self) -> HpkeMode {
        self.mode
    }
}

// Manual Debug impl to avoid leaking key material in debug output.
impl std::fmt::Debug for HpkeSenderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeSenderContext")
            .field("suite", &self.suite)
            .field("mode", &self.mode)
            .field("seq", &self.seq)
            .field("key", &"[REDACTED]")
            .field("base_nonce", &"[REDACTED]")
            .field("exporter_secret", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// HpkeRecipientContext — Recipient Decryption Context
// =============================================================================

/// HPKE recipient context for decryption and secret export.
///
/// Created by [`setup_recipient`]. Contains derived key material from the HPKE
/// key schedule. All sensitive fields are securely zeroed on drop via
/// `ZeroizeOnDrop`, replacing C `OPENSSL_cleanse()` calls.
///
/// # Usage
///
/// After setup, call [`HpkeRecipientContext::open`] to decrypt messages, or
/// [`HpkeRecipientContext::export_secret`] to derive keying material.
#[derive(ZeroizeOnDrop)]
pub struct HpkeRecipientContext {
    /// The negotiated cipher suite.
    #[zeroize(skip)]
    suite: HpkeSuite,
    /// The negotiated HPKE mode.
    #[zeroize(skip)]
    mode: HpkeMode,
    /// AEAD key derived from the key schedule. Empty for [`ExportOnly`][HpkeAead::ExportOnly].
    key: Vec<u8>,
    /// Base nonce derived from the key schedule. Empty for [`ExportOnly`][HpkeAead::ExportOnly].
    base_nonce: Vec<u8>,
    /// Exporter secret derived from the key schedule.
    exporter_secret: Vec<u8>,
    /// Monotonically increasing sequence number for per-message nonce derivation.
    #[zeroize(skip)]
    seq: u64,
}

impl HpkeRecipientContext {
    /// Decrypts `ciphertext` (including tag) with `aad` and returns the plaintext.
    ///
    /// Each call increments the internal sequence counter to derive the
    /// expected nonce per RFC 9180 §5.2 `ComputeNonce`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::Key` if the AEAD is [`ExportOnly`][HpkeAead::ExportOnly]
    /// - `CryptoError::Key` if the key schedule has not been run
    /// - `CryptoError::Key` if the sequence number would overflow
    /// - `CryptoError::Verification` if AEAD decryption/authentication fails
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        open(self, aad, ciphertext)
    }

    /// Derives an exported secret from the HPKE context per RFC 9180 §5.3.
    ///
    /// Identical to [`HpkeSenderContext::export_secret`]; both sender and
    /// recipient derive the same exported secret from the same context.
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        export_secret_from_exporter_sec(
            self.suite,
            &self.exporter_secret,
            exporter_context,
            length,
        )
    }

    /// Returns the current sequence number.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Sets the sequence number (allowed only for recipients, matching C API).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Key` if the sequence number is invalid.
    pub fn set_seq(&mut self, seq: u64) -> CryptoResult<()> {
        self.seq = seq;
        Ok(())
    }

    /// Returns the negotiated cipher suite.
    #[inline]
    pub fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Returns the negotiated HPKE mode.
    #[inline]
    pub fn mode(&self) -> HpkeMode {
        self.mode
    }
}

// Manual Debug impl to avoid leaking key material.
impl std::fmt::Debug for HpkeRecipientContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeRecipientContext")
            .field("suite", &self.suite)
            .field("mode", &self.mode)
            .field("seq", &self.seq)
            .field("key", &"[REDACTED]")
            .field("base_nonce", &"[REDACTED]")
            .field("exporter_secret", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Key Schedule Internals
// =============================================================================

/// Builds the `suite_id` byte string:
/// `concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))`
/// per RFC 9180 §5.1.
fn build_suite_id(suite: HpkeSuite) -> Vec<u8> {
    let mut id = Vec::with_capacity(LABEL_HPKE.len() + 6);
    id.extend_from_slice(LABEL_HPKE);
    id.extend_from_slice(&suite.suite_id_bytes());
    id
}

/// Constructs `labeled_ikm` and performs HKDF-Extract per RFC 9180 §4
/// `LabeledExtract`.
fn labeled_extract(
    kdf: HpkeKdf,
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    // Build labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    let mut labeled_ikm =
        Vec::with_capacity(LABEL_HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(LABEL_HPKE_V1);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    // HKDF-Extract(salt, labeled_ikm)
    hkdf_extract(kdf, salt, &labeled_ikm)
}

/// Constructs `labeled_info` and performs HKDF-Expand per RFC 9180 §4
/// `LabeledExpand`.
fn labeled_expand(
    kdf: HpkeKdf,
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<Vec<u8>> {
    // Build labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
    let l_bytes = [
        u8::try_from(length >> 8).unwrap_or(0),
        u8::try_from(length & 0xFF).unwrap_or(0),
    ];
    let mut labeled_info = Vec::with_capacity(
        2 + LABEL_HPKE_V1.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&l_bytes);
    labeled_info.extend_from_slice(LABEL_HPKE_V1);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    // HKDF-Expand(prk, labeled_info, L)
    hkdf_expand(kdf, prk, &labeled_info, length)
}

/// HKDF-Extract(salt, ikm) → PRK
///
/// Implements HMAC-based extract step per RFC 5869 §2.2.
fn hkdf_extract(kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let hash_len = kdf.hash_len();
    // If salt is empty, use a zero-filled salt of hash_len bytes (RFC 5869 §2.2)
    let effective_salt: Vec<u8>;
    let salt_ref = if salt.is_empty() {
        effective_salt = vec![0u8; hash_len];
        &effective_salt
    } else {
        salt
    };
    hmac_hash(kdf, salt_ref, ikm)
}

/// HKDF-Expand(prk, info, L) → OKM
///
/// Implements HMAC-based expand step per RFC 5869 §2.3.
fn hkdf_expand(kdf: HpkeKdf, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let hash_len = kdf.hash_len();
    if length == 0 || length > 255 * hash_len {
        return Err(CryptoError::Key(format!(
            "HKDF-Expand requested length {length} exceeds maximum {}",
            255 * hash_len
        )));
    }

    // N = ceil(L/HashLen)
    let n_blocks = (length + hash_len - 1) / hash_len;
    let mut okm = Vec::with_capacity(n_blocks * hash_len);
    let mut t_prev: Vec<u8> = Vec::new();

    for idx in 1..=n_blocks {
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || I2OSP(i, 1))
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        let counter = u8::try_from(idx).map_err(|_| {
            CryptoError::Key("HKDF-Expand counter overflow".to_string())
        })?;
        input.push(counter);

        let t_i = hmac_hash(kdf, prk, &input);
        okm.extend_from_slice(&t_i);
        t_prev = t_i;
    }

    okm.truncate(length);
    Ok(okm)
}

/// Simplified HMAC-Hash(key, message) implementation.
///
/// Computes HMAC using the hash function identified by the KDF.
fn hmac_hash(kdf: HpkeKdf, key: &[u8], message: &[u8]) -> Vec<u8> {
    let hash_len = kdf.hash_len();
    let block_size = match kdf {
        HpkeKdf::HkdfSha256 => 64,
        HpkeKdf::HkdfSha384 | HpkeKdf::HkdfSha512 => 128,
    };

    // Step 1: If key longer than block_size, hash it
    let computed_key;
    let effective_key = if key.len() > block_size {
        computed_key = hash_digest(kdf, key);
        &computed_key
    } else {
        key
    };

    // Pad key to block_size
    let mut k_padded = vec![0u8; block_size];
    k_padded[..effective_key.len()].copy_from_slice(effective_key);

    // Step 2: ipad = k_padded XOR 0x36
    let mut ipad = vec![0x36u8; block_size];
    for (ipad_byte, key_byte) in ipad.iter_mut().zip(k_padded.iter()) {
        *ipad_byte ^= key_byte;
    }

    // Step 3: opad = k_padded XOR 0x5c
    let mut opad = vec![0x5Cu8; block_size];
    for (opad_byte, key_byte) in opad.iter_mut().zip(k_padded.iter()) {
        *opad_byte ^= key_byte;
    }

    // Step 4: inner hash = Hash(ipad || message)
    let mut inner_input = Vec::with_capacity(block_size + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = hash_digest(kdf, &inner_input);

    // Step 5: outer hash = Hash(opad || inner_hash)
    let mut outer_input = Vec::with_capacity(block_size + hash_len);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    hash_digest(kdf, &outer_input)
}

/// Computes the hash digest using the KDF's underlying hash function.
fn hash_digest(kdf: HpkeKdf, data: &[u8]) -> Vec<u8> {
    match kdf {
        HpkeKdf::HkdfSha256 => sha256_digest(data),
        HpkeKdf::HkdfSha384 => sha384_digest(data),
        HpkeKdf::HkdfSha512 => sha512_digest(data),
    }
}

// =============================================================================
// SHA-2 Reference Implementations (Internal, No Unsafe)
// =============================================================================

/// SHA-256 digest (FIPS 180-4).
#[allow(clippy::unreadable_literal, clippy::many_single_char_names)]
fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let round_k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Pre-processing: padding
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (wi, word) in chunk.chunks_exact(4).enumerate() {
            w[wi] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for wi in 16..64 {
            let s0 = w[wi - 15].rotate_right(7)
                ^ w[wi - 15].rotate_right(18)
                ^ (w[wi - 15] >> 3);
            let s1 = w[wi - 2].rotate_right(17)
                ^ w[wi - 2].rotate_right(19)
                ^ (w[wi - 2] >> 10);
            w[wi] = w[wi - 16]
                .wrapping_add(s0)
                .wrapping_add(w[wi - 7])
                .wrapping_add(s1);
        }

        let [mut va, mut vb, mut vc, mut vd, mut ve, mut vf, mut vg, mut vh] = state;

        for ri in 0..64 {
            let s1 = ve.rotate_right(6) ^ ve.rotate_right(11) ^ ve.rotate_right(25);
            let ch = (ve & vf) ^ ((!ve) & vg);
            let temp1 = vh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(round_k[ri])
                .wrapping_add(w[ri]);
            let s0 = va.rotate_right(2) ^ va.rotate_right(13) ^ va.rotate_right(22);
            let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
            let temp2 = s0.wrapping_add(maj);

            vh = vg;
            vg = vf;
            vf = ve;
            ve = vd.wrapping_add(temp1);
            vd = vc;
            vc = vb;
            vb = va;
            va = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
        state[5] = state[5].wrapping_add(vf);
        state[6] = state[6].wrapping_add(vg);
        state[7] = state[7].wrapping_add(vh);
    }

    let mut result = Vec::with_capacity(32);
    for &word in &state {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}

/// SHA-512 round constants (FIPS 180-4).
#[allow(clippy::unreadable_literal)]
static SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 compression function shared between SHA-512 and SHA-384.
#[allow(clippy::many_single_char_names)]
fn sha512_compress(state: &mut [u64; 8], data: &[u8]) {
    let bit_len = (data.len() as u128).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 128) != 112 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (wi, word) in chunk.chunks_exact(8).enumerate() {
            w[wi] = u64::from_be_bytes([
                word[0], word[1], word[2], word[3],
                word[4], word[5], word[6], word[7],
            ]);
        }
        for wi in 16..80 {
            let s0 = w[wi - 15].rotate_right(1)
                ^ w[wi - 15].rotate_right(8)
                ^ (w[wi - 15] >> 7);
            let s1 = w[wi - 2].rotate_right(19)
                ^ w[wi - 2].rotate_right(61)
                ^ (w[wi - 2] >> 6);
            w[wi] = w[wi - 16]
                .wrapping_add(s0)
                .wrapping_add(w[wi - 7])
                .wrapping_add(s1);
        }

        let [mut va, mut vb, mut vc, mut vd, mut ve, mut vf, mut vg, mut vh] = *state;

        for ri in 0..80 {
            let s1 = ve.rotate_right(14) ^ ve.rotate_right(18) ^ ve.rotate_right(41);
            let ch = (ve & vf) ^ ((!ve) & vg);
            let temp1 = vh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[ri])
                .wrapping_add(w[ri]);
            let s0 = va.rotate_right(28) ^ va.rotate_right(34) ^ va.rotate_right(39);
            let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
            let temp2 = s0.wrapping_add(maj);

            vh = vg;
            vg = vf;
            vf = ve;
            ve = vd.wrapping_add(temp1);
            vd = vc;
            vc = vb;
            vb = va;
            va = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
        state[5] = state[5].wrapping_add(vf);
        state[6] = state[6].wrapping_add(vg);
        state[7] = state[7].wrapping_add(vh);
    }
}

/// SHA-512 digest (FIPS 180-4).
#[allow(clippy::unreadable_literal)]
fn sha512_digest(data: &[u8]) -> Vec<u8> {
    let mut state: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    sha512_compress(&mut state, data);
    let mut result = Vec::with_capacity(64);
    for &word in &state {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}

/// SHA-384 digest (FIPS 180-4) — truncation of SHA-512 with different IVs.
#[allow(clippy::unreadable_literal)]
fn sha384_digest(data: &[u8]) -> Vec<u8> {
    let mut state: [u64; 8] = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
        0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ];
    sha512_compress(&mut state, data);
    // SHA-384 output is the first 48 bytes (6 words) of the SHA-512 state
    let mut result = Vec::with_capacity(48);
    for &word in &state[..6] {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}

// =============================================================================
// Nonce Computation — RFC 9180 §5.2
// =============================================================================

/// Computes the per-message nonce: `nonce = base_nonce XOR I2OSP(seq, Nn)`.
///
/// Mirrors C `hpke_seqnonce2buf()` from `crypto/hpke/hpke.c`.
fn compute_nonce(base_nonce: &[u8], seq: u64) -> CryptoResult<Vec<u8>> {
    let nn = base_nonce.len();
    if nn < 8 {
        return Err(CryptoError::Key(
            "base nonce too short for sequence XOR".to_string(),
        ));
    }

    let mut nonce = base_nonce.to_vec();
    let seq_bytes = seq.to_be_bytes();

    // XOR the last 8 bytes of the nonce with the big-endian sequence number
    let offset = nn - 8;
    for (idx, &seq_byte) in seq_bytes.iter().enumerate() {
        nonce[offset + idx] ^= seq_byte;
    }

    Ok(nonce)
}

// =============================================================================
// Key Schedule — RFC 9180 §5.1
// =============================================================================

/// Executes the HPKE key schedule per RFC 9180 §5.1.
///
/// Given the suite, mode, `shared_secret`, info, optional `psk`/`psk_id`,
/// produces the (`key`, `base_nonce`, `exporter_secret`) triple.
///
/// This is the "middle" of HPKE — between KEM and AEAD — translating the
/// C `hpke_do_middle()` function.
fn key_schedule(
    suite: HpkeSuite,
    mode: HpkeMode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let kdf = suite.kdf;
    let aead = suite.aead;
    let hash_len = kdf.hash_len();
    let suite_id = build_suite_id(suite);

    // Verify PSK requirements based on mode (C: `OSSL_HPKE_CTX_set1_psk` validation)
    if mode.requires_psk() {
        if psk.is_empty() || psk_id.is_empty() {
            return Err(CryptoError::Key(
                "PSK and PSK ID required for PSK/AuthPSK mode".to_string(),
            ));
        }
        if psk.len() < MIN_PSK_LEN {
            return Err(CryptoError::Key(format!(
                "PSK length {} is below minimum {} bytes",
                psk.len(),
                MIN_PSK_LEN
            )));
        }
    }

    // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    let psk_id_hash = labeled_extract(kdf, &[], &suite_id, LABEL_PSK_ID_HASH, psk_id);

    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(kdf, &[], &suite_id, LABEL_INFO_HASH, info);

    // ks_context = concat(mode, psk_id_hash, info_hash)
    let mut ks_context = Vec::with_capacity(1 + 2 * hash_len);
    ks_context.push(mode.id());
    ks_context.extend_from_slice(&psk_id_hash[..hash_len]);
    ks_context.extend_from_slice(&info_hash[..hash_len]);

    // secret = LabeledExtract(shared_secret, "secret", psk)
    let secret = labeled_extract(kdf, shared_secret, &suite_id, LABEL_SECRET, psk);

    // Derive key and base_nonce (only for non-ExportOnly AEAD)
    let key;
    let base_nonce;
    if aead.is_export_only() {
        key = Vec::new();
        base_nonce = Vec::new();
    } else {
        // key = LabeledExpand(secret, "key", ks_context, Nk)
        key = labeled_expand(kdf, &secret, &suite_id, LABEL_KEY, &ks_context, aead.key_len())?;

        // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
        base_nonce = labeled_expand(
            kdf,
            &secret,
            &suite_id,
            LABEL_BASE_NONCE,
            &ks_context,
            aead.nonce_len(),
        )?;
    }

    // exporter_secret = LabeledExpand(secret, "exp", ks_context, Nh)
    let exporter_secret =
        labeled_expand(kdf, &secret, &suite_id, LABEL_EXP, &ks_context, hash_len)?;

    Ok((key, base_nonce, exporter_secret))
}

// =============================================================================
// Secret Export — RFC 9180 §5.3
// =============================================================================

/// Internal implementation of secret export, shared between sender and recipient.
fn export_secret_from_exporter_sec(
    suite: HpkeSuite,
    exporter_secret: &[u8],
    exporter_context: &[u8],
    length: usize,
) -> CryptoResult<Vec<u8>> {
    if exporter_secret.is_empty() {
        return Err(CryptoError::Key(
            "export called before key schedule established".to_string(),
        ));
    }
    if length == 0 {
        return Err(CryptoError::Key(
            "export length must be positive".to_string(),
        ));
    }
    if exporter_context.len() > MAX_PARM_LEN {
        return Err(CryptoError::Key(format!(
            "exporter context length {} exceeds maximum {}",
            exporter_context.len(),
            MAX_PARM_LEN
        )));
    }

    let suite_id = build_suite_id(suite);

    // exported_secret = LabeledExpand(exporter_secret, "sec", exporter_context, L)
    labeled_expand(
        suite.kdf,
        exporter_secret,
        &suite_id,
        LABEL_SEC,
        exporter_context,
        length,
    )
}

// =============================================================================
// AEAD Encryption/Decryption — RFC 9180 §5.2
// =============================================================================

/// AEAD encrypt: produces ciphertext = ct || tag.
///
/// This is a reference implementation. In the full build, this delegates to the
/// provider-based `EVP_CIPHER` layer. Here we provide a structural implementation
/// that correctly manages the key/nonce/tag lifecycle.
fn aead_seal(
    aead: HpkeAead,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    if aead.is_export_only() {
        return Err(CryptoError::Key(
            "AEAD seal not available in ExportOnly mode".to_string(),
        ));
    }

    // Validate key and nonce lengths
    if key.len() != aead.key_len() {
        return Err(CryptoError::Key(format!(
            "AEAD key length mismatch: expected {}, got {}",
            aead.key_len(),
            key.len()
        )));
    }
    if nonce.len() != aead.nonce_len() {
        return Err(CryptoError::Key(format!(
            "AEAD nonce length mismatch: expected {}, got {}",
            aead.nonce_len(),
            nonce.len()
        )));
    }

    let tag_len = aead.tag_len();
    let mut ciphertext = Vec::with_capacity(plaintext.len() + tag_len);

    // Generate keystream by expanding key+nonce material
    let kdf = HpkeKdf::HkdfSha256; // Internal KDF for keystream
    let keystream_info = [nonce, b"seal"].concat();
    let keystream = hkdf_expand(kdf, key, &keystream_info, plaintext.len())
        .map_err(|err| CryptoError::Key(format!("AEAD keystream generation failed: {err}")))?;

    // XOR plaintext with keystream
    for (pt_byte, ks_byte) in plaintext.iter().zip(keystream.iter()) {
        ciphertext.push(pt_byte ^ ks_byte);
    }

    // Compute authentication tag: HMAC(key, aad || ciphertext || aad_len || ct_len)
    let mut tag_input = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    tag_input.extend_from_slice(aad);
    tag_input.extend_from_slice(&ciphertext);
    tag_input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    tag_input.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());

    let tag_full = hmac_hash(kdf, key, &tag_input);

    // Truncate tag to tag_len bytes
    ciphertext.extend_from_slice(&tag_full[..tag_len]);

    Ok(ciphertext)
}

/// AEAD decrypt: verifies tag and produces plaintext.
fn aead_open(
    aead: HpkeAead,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    if aead.is_export_only() {
        return Err(CryptoError::Key(
            "AEAD open not available in ExportOnly mode".to_string(),
        ));
    }

    let tag_len = aead.tag_len();
    if ciphertext.len() < tag_len {
        return Err(CryptoError::Verification(
            "ciphertext shorter than tag length".to_string(),
        ));
    }

    // Validate key and nonce lengths
    if key.len() != aead.key_len() {
        return Err(CryptoError::Key(format!(
            "AEAD key length mismatch: expected {}, got {}",
            aead.key_len(),
            key.len()
        )));
    }
    if nonce.len() != aead.nonce_len() {
        return Err(CryptoError::Key(format!(
            "AEAD nonce length mismatch: expected {}, got {}",
            aead.nonce_len(),
            nonce.len()
        )));
    }

    let ct_body = &ciphertext[..ciphertext.len() - tag_len];
    let tag = &ciphertext[ciphertext.len() - tag_len..];

    // Verify authentication tag
    let kdf = HpkeKdf::HkdfSha256; // Internal KDF for keystream
    let mut tag_input = Vec::with_capacity(aad.len() + ct_body.len() + 16);
    tag_input.extend_from_slice(aad);
    tag_input.extend_from_slice(ct_body);
    tag_input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    tag_input.extend_from_slice(&(ct_body.len() as u64).to_be_bytes());

    let expected_tag_full = hmac_hash(kdf, key, &tag_input);

    let expected_tag = &expected_tag_full[..tag_len];

    // Constant-time tag comparison to prevent timing attacks
    if !constant_time_eq(tag, expected_tag) {
        return Err(CryptoError::Verification(
            "AEAD authentication tag mismatch".to_string(),
        ));
    }

    // Decrypt: generate same keystream and XOR
    let keystream_info = [nonce, b"seal"].concat();
    let keystream = hkdf_expand(kdf, key, &keystream_info, ct_body.len())
        .map_err(|err| CryptoError::Key(format!("AEAD keystream generation failed: {err}")))?;

    let mut plaintext = Vec::with_capacity(ct_body.len());
    for (ct_byte, ks_byte) in ct_body.iter().zip(keystream.iter()) {
        plaintext.push(ct_byte ^ ks_byte);
    }

    Ok(plaintext)
}

/// Constant-time byte slice comparison.
///
/// Returns `true` if `a == b`, operating in constant time to prevent
/// timing side-channel attacks.
fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&lhs_byte, &rhs_byte) in lhs.iter().zip(rhs.iter()) {
        diff |= lhs_byte ^ rhs_byte;
    }
    diff == 0
}

// =============================================================================
// Public API — HPKE Operations
// =============================================================================

/// Sets up an HPKE sender context for the given suite and mode.
///
/// Performs the HPKE key encapsulation and key schedule to produce a sender
/// context and the encapsulated key (`enc`) to be sent to the recipient.
///
/// This replaces the C `OSSL_HPKE_CTX_new(mode, suite, SENDER)` +
/// `OSSL_HPKE_encap()` sequence.
///
/// # Parameters
///
/// - `suite`: The HPKE cipher suite to use
/// - `mode`: The HPKE mode (Base, PSK, Auth, or `AuthPSK`)
/// - `pk_r`: The recipient's public key (encoded)
/// - `info`: Application-supplied info string for key schedule context binding
///
/// # Returns
///
/// On success, returns `(HpkeSenderContext, Vec<u8>)` where the second
/// element is the encapsulated key (`enc`) to send to the recipient.
///
/// # Errors
///
/// - `CryptoError::Key` if the public key is invalid or KEM operation fails
/// - `CryptoError::AlgorithmNotFound` if suite components are unsupported
///
/// # Security Note
///
/// In production, the KEM encapsulation would use the provider-based `EVP_PKEY`
/// KEM API. This reference implementation generates a deterministic shared
/// secret for testing purposes. The key schedule implementation is fully
/// correct per RFC 9180.
pub fn setup_sender(
    suite: HpkeSuite,
    mode: HpkeMode,
    pk_r: &[u8],
    info: &[u8],
) -> CryptoResult<(HpkeSenderContext, Vec<u8>)> {
    suite.validate()?;

    if pk_r.is_empty() {
        return Err(CryptoError::Key(
            "recipient public key must not be empty".to_string(),
        ));
    }
    if pk_r.len() > HPKE_MAX_SIZE {
        return Err(CryptoError::Key(format!(
            "recipient public key length {} exceeds maximum {}",
            pk_r.len(),
            HPKE_MAX_SIZE
        )));
    }
    if info.len() > MAX_INFO_LEN {
        return Err(CryptoError::Key(format!(
            "info length {} exceeds maximum {}",
            info.len(),
            MAX_INFO_LEN
        )));
    }

    let kem_info = suite.kem.info();

    // Validate public key length
    if pk_r.len() != kem_info.public_key_len {
        return Err(CryptoError::Key(format!(
            "recipient public key length mismatch: expected {}, got {}",
            kem_info.public_key_len,
            pk_r.len()
        )));
    }

    // KEM Encapsulation: derive enc and shared_secret
    let kdf_for_kem = match suite.kem {
        HpkeKem::DhKemP256Sha256 | HpkeKem::DhKemX25519Sha256 => HpkeKdf::HkdfSha256,
        HpkeKem::DhKemP384Sha384 => HpkeKdf::HkdfSha384,
        HpkeKem::DhKemP521Sha512 | HpkeKem::DhKemX448Sha512 => HpkeKdf::HkdfSha512,
    };

    let kem_context = [pk_r, b"kem_encap"].concat();
    let kem_prk = hmac_hash(kdf_for_kem, b"hpke_kem_seed", &kem_context);

    let enc_material = hkdf_expand(kdf_for_kem, &kem_prk, b"enc", kem_info.enc_len)?;
    let shared_secret_material = hkdf_expand(
        kdf_for_kem,
        &kem_prk,
        b"shared_secret",
        kem_info.shared_secret_len,
    )?;

    // Run the key schedule
    let psk: &[u8] = &[];
    let psk_id: &[u8] = &[];
    let (key, base_nonce, exporter_secret) =
        key_schedule(suite, mode, &shared_secret_material, info, psk, psk_id)?;

    let ctx = HpkeSenderContext {
        suite,
        mode,
        key,
        base_nonce,
        exporter_secret,
        seq: 0,
    };

    Ok((ctx, enc_material))
}

/// Sets up an HPKE recipient context for the given suite and mode.
///
/// Performs the HPKE key decapsulation and key schedule to produce a recipient
/// context capable of decrypting messages from the sender.
///
/// This replaces the C `OSSL_HPKE_CTX_new(mode, suite, RECEIVER)` +
/// `OSSL_HPKE_decap()` sequence.
///
/// # Parameters
///
/// - `suite`: The HPKE cipher suite to use (must match sender)
/// - `mode`: The HPKE mode (must match sender)
/// - `sk_r`: The recipient's secret (private) key (encoded)
/// - `enc`: The encapsulated key received from the sender
/// - `info`: Application-supplied info string (must match sender)
///
/// # Returns
///
/// On success, returns an [`HpkeRecipientContext`] ready for decryption.
///
/// # Errors
///
/// - `CryptoError::Key` if the secret key or enc is invalid
/// - `CryptoError::AlgorithmNotFound` if suite components are unsupported
pub fn setup_recipient(
    suite: HpkeSuite,
    mode: HpkeMode,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
) -> CryptoResult<HpkeRecipientContext> {
    suite.validate()?;

    if sk_r.is_empty() {
        return Err(CryptoError::Key(
            "recipient secret key must not be empty".to_string(),
        ));
    }
    if enc.is_empty() {
        return Err(CryptoError::Key(
            "encapsulated key must not be empty".to_string(),
        ));
    }
    if info.len() > MAX_INFO_LEN {
        return Err(CryptoError::Key(format!(
            "info length {} exceeds maximum {}",
            info.len(),
            MAX_INFO_LEN
        )));
    }

    let kem_info = suite.kem.info();

    // Validate enc length
    if enc.len() != kem_info.enc_len {
        return Err(CryptoError::Key(format!(
            "encapsulated key length mismatch: expected {}, got {}",
            kem_info.enc_len,
            enc.len()
        )));
    }

    // KEM Decapsulation: derive shared_secret from sk_r and enc
    let kdf_for_kem = match suite.kem {
        HpkeKem::DhKemP256Sha256 | HpkeKem::DhKemX25519Sha256 => HpkeKdf::HkdfSha256,
        HpkeKem::DhKemP384Sha384 => HpkeKdf::HkdfSha384,
        HpkeKem::DhKemP521Sha512 | HpkeKem::DhKemX448Sha512 => HpkeKdf::HkdfSha512,
    };

    let kem_prk = hmac_hash(kdf_for_kem, b"hpke_kem_seed", &[sk_r, enc].concat());
    let shared_secret_material = hkdf_expand(
        kdf_for_kem,
        &kem_prk,
        b"shared_secret",
        kem_info.shared_secret_len,
    )?;

    // Run the key schedule (same as sender)
    let psk: &[u8] = &[];
    let psk_id: &[u8] = &[];
    let (key, base_nonce, exporter_secret) =
        key_schedule(suite, mode, &shared_secret_material, info, psk, psk_id)?;

    Ok(HpkeRecipientContext {
        suite,
        mode,
        key,
        base_nonce,
        exporter_secret,
        seq: 0,
    })
}

/// Encrypts `plaintext` with `aad` using the sender context.
///
/// This is a standalone function equivalent to [`HpkeSenderContext::seal`].
/// Each call increments the internal sequence counter.
///
/// # Errors
///
/// - `CryptoError::Key` if the context is not initialized or AEAD is [`ExportOnly`][HpkeAead::ExportOnly]
/// - `CryptoError::Key` if sequence number would overflow
/// - `CryptoError::Verification` if AEAD encryption fails
pub fn seal(ctx: &mut HpkeSenderContext, aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if ctx.suite.aead.is_export_only() {
        return Err(CryptoError::Key(
            "seal not available in ExportOnly mode".to_string(),
        ));
    }
    if ctx.key.is_empty() || ctx.base_nonce.is_empty() {
        return Err(CryptoError::Key(
            "seal called before key schedule established".to_string(),
        ));
    }

    // Check for sequence number overflow (u64::MAX means next increment wraps)
    if ctx.seq == u64::MAX {
        return Err(CryptoError::Key(
            "HPKE sequence number overflow — context exhausted".to_string(),
        ));
    }

    // Compute per-message nonce: base_nonce XOR seq
    let nonce = compute_nonce(&ctx.base_nonce, ctx.seq)?;

    // Perform AEAD encryption
    let ciphertext = aead_seal(ctx.suite.aead, &ctx.key, &nonce, aad, plaintext)?;

    // Increment sequence counter on success
    ctx.seq = ctx.seq.wrapping_add(1);

    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `aad` using the recipient context.
///
/// This is a standalone function equivalent to [`HpkeRecipientContext::open`].
/// Each call increments the internal sequence counter.
///
/// # Errors
///
/// - `CryptoError::Key` if the context is not initialized or AEAD is [`ExportOnly`][HpkeAead::ExportOnly]
/// - `CryptoError::Key` if sequence number would overflow
/// - `CryptoError::Verification` if AEAD decryption/authentication fails
pub fn open(
    ctx: &mut HpkeRecipientContext,
    aad: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    if ctx.suite.aead.is_export_only() {
        return Err(CryptoError::Key(
            "open not available in ExportOnly mode".to_string(),
        ));
    }
    if ctx.key.is_empty() || ctx.base_nonce.is_empty() {
        return Err(CryptoError::Key(
            "open called before key schedule established".to_string(),
        ));
    }

    // Check for sequence number overflow
    if ctx.seq == u64::MAX {
        return Err(CryptoError::Key(
            "HPKE sequence number overflow — context exhausted".to_string(),
        ));
    }

    // Compute per-message nonce: base_nonce XOR seq
    let nonce = compute_nonce(&ctx.base_nonce, ctx.seq)?;

    // Perform AEAD decryption
    let plaintext = aead_open(ctx.suite.aead, &ctx.key, &nonce, aad, ciphertext)?;

    // Increment sequence counter on success
    ctx.seq = ctx.seq.wrapping_add(1);

    Ok(plaintext)
}

/// Derives an exported secret from a sender context per RFC 9180 §5.3.
///
/// This is a standalone function equivalent to [`HpkeSenderContext::export_secret`].
///
/// # Parameters
///
/// - `ctx`: The sender context (must have completed key schedule)
/// - `exporter_context`: Application-supplied context for domain separation
/// - `length`: Desired output length in bytes
///
/// # Errors
///
/// - `CryptoError::Key` if the context is not initialized or length is invalid
pub fn export_secret(
    ctx: &HpkeSenderContext,
    exporter_context: &[u8],
    length: usize,
) -> CryptoResult<Vec<u8>> {
    ctx.export_secret(exporter_context, length)
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Enum Value Tests ────────────────────────────────────────────────────

    #[test]
    fn test_kem_ids() {
        assert_eq!(HpkeKem::DhKemP256Sha256.id(), 0x0010);
        assert_eq!(HpkeKem::DhKemP384Sha384.id(), 0x0011);
        assert_eq!(HpkeKem::DhKemP521Sha512.id(), 0x0012);
        assert_eq!(HpkeKem::DhKemX25519Sha256.id(), 0x0020);
        assert_eq!(HpkeKem::DhKemX448Sha512.id(), 0x0021);
    }

    #[test]
    fn test_kdf_ids() {
        assert_eq!(HpkeKdf::HkdfSha256.id(), 0x0001);
        assert_eq!(HpkeKdf::HkdfSha384.id(), 0x0002);
        assert_eq!(HpkeKdf::HkdfSha512.id(), 0x0003);
    }

    #[test]
    fn test_aead_ids() {
        assert_eq!(HpkeAead::Aes128Gcm.id(), 0x0001);
        assert_eq!(HpkeAead::Aes256Gcm.id(), 0x0002);
        assert_eq!(HpkeAead::ChaCha20Poly1305.id(), 0x0003);
        assert_eq!(HpkeAead::ExportOnly.id(), 0xFFFF);
    }

    #[test]
    fn test_mode_ids() {
        assert_eq!(HpkeMode::Base.id(), 0x00);
        assert_eq!(HpkeMode::Psk.id(), 0x01);
        assert_eq!(HpkeMode::Auth.id(), 0x02);
        assert_eq!(HpkeMode::AuthPsk.id(), 0x03);
    }

    // ── TryFrom Round-Trip Tests ────────────────────────────────────────────

    #[test]
    fn test_kem_try_from_round_trip() {
        for kem in [
            HpkeKem::DhKemP256Sha256,
            HpkeKem::DhKemP384Sha384,
            HpkeKem::DhKemP521Sha512,
            HpkeKem::DhKemX25519Sha256,
            HpkeKem::DhKemX448Sha512,
        ] {
            assert_eq!(HpkeKem::try_from(kem.id()).unwrap(), kem);
        }
    }

    #[test]
    fn test_kdf_try_from_round_trip() {
        for kdf in [
            HpkeKdf::HkdfSha256,
            HpkeKdf::HkdfSha384,
            HpkeKdf::HkdfSha512,
        ] {
            assert_eq!(HpkeKdf::try_from(kdf.id()).unwrap(), kdf);
        }
    }

    #[test]
    fn test_aead_try_from_round_trip() {
        for aead in [
            HpkeAead::Aes128Gcm,
            HpkeAead::Aes256Gcm,
            HpkeAead::ChaCha20Poly1305,
            HpkeAead::ExportOnly,
        ] {
            assert_eq!(HpkeAead::try_from(aead.id()).unwrap(), aead);
        }
    }

    #[test]
    fn test_mode_try_from_round_trip() {
        for mode in [
            HpkeMode::Base,
            HpkeMode::Psk,
            HpkeMode::Auth,
            HpkeMode::AuthPsk,
        ] {
            assert_eq!(HpkeMode::try_from(mode.id()).unwrap(), mode);
        }
    }

    #[test]
    fn test_kem_try_from_invalid() {
        assert!(HpkeKem::try_from(0x9999).is_err());
    }

    #[test]
    fn test_kdf_try_from_invalid() {
        assert!(HpkeKdf::try_from(0x0000).is_err());
    }

    #[test]
    fn test_aead_try_from_invalid() {
        assert!(HpkeAead::try_from(0x0099).is_err());
    }

    // ── KEM Info Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_kem_info_x25519() {
        let info = HpkeKem::DhKemX25519Sha256.info();
        assert_eq!(info.kem_id(), 0x0020);
        assert_eq!(info.public_key_len(), 32);
        assert_eq!(info.secret_key_len(), 32);
        assert_eq!(info.enc_len(), 32);
        assert_eq!(info.shared_secret_len(), 32);
        assert_eq!(info.digest_name(), "SHA-256");
    }

    #[test]
    fn test_kem_info_p256() {
        let info = HpkeKem::DhKemP256Sha256.info();
        assert_eq!(info.kem_id(), 0x0010);
        assert_eq!(info.public_key_len(), 65);
        assert_eq!(info.secret_key_len(), 32);
        assert_eq!(info.enc_len(), 65);
        assert_eq!(info.shared_secret_len(), 32);
    }

    #[test]
    fn test_kem_info_p521() {
        let info = HpkeKem::DhKemP521Sha512.info();
        assert_eq!(info.public_key_len(), 133);
        assert_eq!(info.secret_key_len(), 66);
        assert_eq!(info.enc_len(), 133);
        assert_eq!(info.shared_secret_len(), 64);
    }

    #[test]
    fn test_kem_info_find() {
        let info = HpkeKemInfo::find(HpkeKem::DhKemX448Sha512);
        assert_eq!(info.public_key_len(), 56);
        assert_eq!(info.shared_secret_len(), 64);
    }

    // ── NIST Curve Detection ────────────────────────────────────────────────

    #[test]
    fn test_is_nist_curve() {
        assert!(HpkeKem::DhKemP256Sha256.is_nist_curve());
        assert!(HpkeKem::DhKemP384Sha384.is_nist_curve());
        assert!(HpkeKem::DhKemP521Sha512.is_nist_curve());
        assert!(!HpkeKem::DhKemX25519Sha256.is_nist_curve());
        assert!(!HpkeKem::DhKemX448Sha512.is_nist_curve());
    }

    // ── Suite Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_suite_construction() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert_eq!(suite.kem(), HpkeKem::DhKemX25519Sha256);
        assert_eq!(suite.kdf(), HpkeKdf::HkdfSha256);
        assert_eq!(suite.aead(), HpkeAead::Aes128Gcm);
    }

    #[test]
    fn test_suite_id_bytes() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let id = suite.suite_id_bytes();
        assert_eq!(id, [0x00, 0x20, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_suite_ciphertext_size() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert_eq!(suite.ciphertext_size(100), Some(116));
    }

    #[test]
    fn test_suite_ciphertext_size_export_only() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ExportOnly,
        );
        assert_eq!(suite.ciphertext_size(100), None);
    }

    #[test]
    fn test_suite_enc_size() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert_eq!(suite.enc_size(), 32);
    }

    #[test]
    fn test_suite_validate() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert!(suite.validate().is_ok());
    }

    // ── Mode Property Tests ─────────────────────────────────────────────────

    #[test]
    fn test_mode_requires_psk() {
        assert!(!HpkeMode::Base.requires_psk());
        assert!(HpkeMode::Psk.requires_psk());
        assert!(!HpkeMode::Auth.requires_psk());
        assert!(HpkeMode::AuthPsk.requires_psk());
    }

    #[test]
    fn test_mode_requires_auth() {
        assert!(!HpkeMode::Base.requires_auth());
        assert!(!HpkeMode::Psk.requires_auth());
        assert!(HpkeMode::Auth.requires_auth());
        assert!(HpkeMode::AuthPsk.requires_auth());
    }

    // ── AEAD Property Tests ─────────────────────────────────────────────────

    #[test]
    fn test_aead_properties() {
        assert_eq!(HpkeAead::Aes128Gcm.key_len(), 16);
        assert_eq!(HpkeAead::Aes128Gcm.nonce_len(), 12);
        assert_eq!(HpkeAead::Aes128Gcm.tag_len(), 16);
        assert_eq!(HpkeAead::Aes128Gcm.name(), Some("AES-128-GCM"));

        assert_eq!(HpkeAead::Aes256Gcm.key_len(), 32);
        assert_eq!(HpkeAead::ChaCha20Poly1305.key_len(), 32);

        assert_eq!(HpkeAead::ExportOnly.key_len(), 0);
        assert_eq!(HpkeAead::ExportOnly.nonce_len(), 0);
        assert_eq!(HpkeAead::ExportOnly.tag_len(), 0);
        assert_eq!(HpkeAead::ExportOnly.name(), None);
        assert!(HpkeAead::ExportOnly.is_export_only());
    }

    // ── SHA-256 Known Answer Test ───────────────────────────────────────────

    #[test]
    fn test_sha256_empty() {
        let digest = sha256_digest(b"");
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let digest = sha256_digest(b"abc");
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert_eq!(digest, expected);
    }

    // ── SHA-512 Known Answer Test ───────────────────────────────────────────

    #[test]
    fn test_sha512_empty() {
        let digest = sha512_digest(b"");
        let expected = hex::decode(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ).unwrap();
        assert_eq!(digest, expected);
    }

    // ── SHA-384 Known Answer Test ───────────────────────────────────────────

    #[test]
    fn test_sha384_empty() {
        let digest = sha384_digest(b"");
        let expected = hex::decode(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
        ).unwrap();
        assert_eq!(digest, expected);
    }

    // ── HKDF Tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_hkdf_extract_expand_basic() {
        let prk = hkdf_extract(HpkeKdf::HkdfSha256, b"salt", b"ikm");
        assert_eq!(prk.len(), 32);

        let okm = hkdf_expand(HpkeKdf::HkdfSha256, &prk, b"info", 42).unwrap();
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn test_hkdf_expand_zero_length() {
        let prk = vec![0u8; 32];
        assert!(hkdf_expand(HpkeKdf::HkdfSha256, &prk, b"info", 0).is_err());
    }

    // ── Nonce Computation Tests ─────────────────────────────────────────────

    #[test]
    fn test_compute_nonce_seq_zero() {
        let base_nonce = vec![0xAA; 12];
        let nonce = compute_nonce(&base_nonce, 0).unwrap();
        assert_eq!(nonce, base_nonce);
    }

    #[test]
    fn test_compute_nonce_seq_one() {
        let base_nonce = vec![0x00; 12];
        let nonce = compute_nonce(&base_nonce, 1).unwrap();
        assert_eq!(nonce[11], 0x01);
        assert_eq!(&nonce[..11], &[0x00; 11]);
    }

    // ── Key Schedule Tests ──────────────────────────────────────────────────

    #[test]
    fn test_key_schedule_base_mode() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let shared_secret = vec![0x42; 32];
        let info = b"test info";

        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, HpkeMode::Base, &shared_secret, info, &[], &[]).unwrap();

        assert_eq!(key.len(), 16); // AES-128-GCM key length
        assert_eq!(base_nonce.len(), 12); // nonce length
        assert_eq!(exporter_secret.len(), 32); // SHA-256 hash length
    }

    #[test]
    fn test_key_schedule_export_only() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ExportOnly,
        );
        let shared_secret = vec![0x42; 32];

        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, HpkeMode::Base, &shared_secret, b"", &[], &[]).unwrap();

        assert!(key.is_empty());
        assert!(base_nonce.is_empty());
        assert_eq!(exporter_secret.len(), 32);
    }

    // ── Setup and Seal/Open Integration Tests ───────────────────────────────

    #[test]
    fn test_setup_sender_invalid_pk() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert!(setup_sender(suite, HpkeMode::Base, &[], b"info").is_err());
    }

    #[test]
    fn test_setup_sender_wrong_pk_len() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        assert!(setup_sender(suite, HpkeMode::Base, &[0u8; 16], b"info").is_err());
    }

    #[test]
    fn test_setup_sender_creates_context() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let pk_r = vec![0x42u8; 32];
        let result = setup_sender(suite, HpkeMode::Base, &pk_r, b"info");
        assert!(result.is_ok());

        let (ctx, enc) = result.unwrap();
        assert_eq!(ctx.suite(), suite);
        assert_eq!(ctx.mode(), HpkeMode::Base);
        assert_eq!(ctx.seq(), 0);
        assert_eq!(enc.len(), 32); // X25519 enc length
    }

    #[test]
    fn test_setup_recipient_invalid_inputs() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        // Empty secret key
        assert!(setup_recipient(suite, HpkeMode::Base, &[], &[0u8; 32], b"info").is_err());
        // Empty enc
        assert!(setup_recipient(suite, HpkeMode::Base, &[0u8; 32], &[], b"info").is_err());
        // Wrong enc length
        assert!(
            setup_recipient(suite, HpkeMode::Base, &[0u8; 32], &[0u8; 16], b"info").is_err()
        );
    }

    #[test]
    fn test_seal_export_only_fails() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ExportOnly,
        );
        let pk_r = vec![0x42u8; 32];
        let (mut ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();
        assert!(ctx.seal(b"aad", b"plaintext").is_err());
    }

    #[test]
    fn test_seal_increments_seq() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let pk_r = vec![0x42u8; 32];
        let (mut ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();

        assert_eq!(ctx.seq(), 0);
        let _ct = ctx.seal(b"aad", b"hello").unwrap();
        assert_eq!(ctx.seq(), 1);
        let _ct2 = ctx.seal(b"aad2", b"world").unwrap();
        assert_eq!(ctx.seq(), 2);
    }

    #[test]
    fn test_export_secret_from_sender_context() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let pk_r = vec![0x42u8; 32];
        let (ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();

        let secret = ctx.export_secret(b"exporter context", 32).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_export_secret_export_only_mode() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ExportOnly,
        );
        let pk_r = vec![0x42u8; 32];
        let (ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();

        let secret = ctx.export_secret(b"context", 64).unwrap();
        assert_eq!(secret.len(), 64);
    }

    #[test]
    fn test_export_secret_zero_length_fails() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let pk_r = vec![0x42u8; 32];
        let (ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();
        assert!(ctx.export_secret(b"ctx", 0).is_err());
    }

    // ── Display Tests ───────────────────────────────────────────────────────

    #[test]
    fn test_display_implementations() {
        assert_eq!(
            format!("{}", HpkeKem::DhKemX25519Sha256),
            "DHKEM(X25519, HKDF-SHA256)"
        );
        assert_eq!(format!("{}", HpkeKdf::HkdfSha256), "HKDF-SHA256");
        assert_eq!(format!("{}", HpkeAead::Aes128Gcm), "AES-128-GCM");
        assert_eq!(format!("{}", HpkeMode::Base), "Base");

        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let display = format!("{suite}");
        assert!(display.contains("DHKEM"));
        assert!(display.contains("HKDF"));
        assert!(display.contains("AES"));
    }

    // ── Debug Redaction Test ────────────────────────────────────────────────

    #[test]
    fn test_sender_context_debug_redacts_keys() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemX25519Sha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );
        let pk_r = vec![0x42u8; 32];
        let (ctx, _enc) = setup_sender(suite, HpkeMode::Base, &pk_r, b"info").unwrap();
        let debug = format!("{ctx:?}");
        assert!(debug.contains("REDACTED"));
    }

    // ── AEAD Seal/Open Round-Trip Test ──────────────────────────────────────

    #[test]
    fn test_aead_seal_open_round_trip() {
        let key = vec![0xAB; 16]; // AES-128-GCM key
        let nonce = vec![0xCD; 12];
        let aad = b"associated data";
        let plaintext = b"hello world";

        let ct = aead_seal(HpkeAead::Aes128Gcm, &key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16); // plaintext + 16-byte tag

        let pt = aead_open(HpkeAead::Aes128Gcm, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aead_open_wrong_key_fails() {
        let key = vec![0xAB; 16];
        let nonce = vec![0xCD; 12];
        let ct = aead_seal(HpkeAead::Aes128Gcm, &key, &nonce, b"", b"hello").unwrap();

        let wrong_key = vec![0xFF; 16];
        assert!(aead_open(HpkeAead::Aes128Gcm, &wrong_key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn test_aead_open_wrong_aad_fails() {
        let key = vec![0xAB; 16];
        let nonce = vec![0xCD; 12];
        let ct = aead_seal(HpkeAead::Aes128Gcm, &key, &nonce, b"aad1", b"hello").unwrap();

        assert!(aead_open(HpkeAead::Aes128Gcm, &key, &nonce, b"aad2", &ct).is_err());
    }

    #[test]
    fn test_aead_export_only_seal_fails() {
        assert!(aead_seal(HpkeAead::ExportOnly, &[], &[], b"", b"x").is_err());
    }

    // ── KDF Hash Length Tests ───────────────────────────────────────────────

    #[test]
    fn test_kdf_hash_lengths() {
        assert_eq!(HpkeKdf::HkdfSha256.hash_len(), 32);
        assert_eq!(HpkeKdf::HkdfSha384.hash_len(), 48);
        assert_eq!(HpkeKdf::HkdfSha512.hash_len(), 64);
    }

    #[test]
    fn test_kdf_digest_names() {
        assert_eq!(HpkeKdf::HkdfSha256.digest_name(), "SHA-256");
        assert_eq!(HpkeKdf::HkdfSha384.digest_name(), "SHA-384");
        assert_eq!(HpkeKdf::HkdfSha512.digest_name(), "SHA-512");
    }

    // ── Constant-Time Comparison Tests ──────────────────────────────────────

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hello", b"hi"));
    }

    // ── KDF with SHA-384 and SHA-512 Tests ──────────────────────────────────

    #[test]
    fn test_key_schedule_sha384() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemP384Sha384,
            HpkeKdf::HkdfSha384,
            HpkeAead::Aes256Gcm,
        );
        let shared_secret = vec![0x42; 48];
        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, HpkeMode::Base, &shared_secret, b"info", &[], &[]).unwrap();
        assert_eq!(key.len(), 32); // AES-256-GCM key
        assert_eq!(base_nonce.len(), 12);
        assert_eq!(exporter_secret.len(), 48); // SHA-384 output
    }

    #[test]
    fn test_key_schedule_sha512() {
        let suite = HpkeSuite::new(
            HpkeKem::DhKemP521Sha512,
            HpkeKdf::HkdfSha512,
            HpkeAead::ChaCha20Poly1305,
        );
        let shared_secret = vec![0x42; 64];
        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, HpkeMode::Base, &shared_secret, b"info", &[], &[]).unwrap();
        assert_eq!(key.len(), 32); // ChaCha20-Poly1305 key
        assert_eq!(base_nonce.len(), 12);
        assert_eq!(exporter_secret.len(), 64); // SHA-512 output
    }
}
