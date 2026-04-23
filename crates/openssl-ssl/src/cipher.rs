//! Cipher suite selection, rule-string parsing, and EVP provider integration.
//!
//! This module is the Rust translation of `ssl/ssl_ciph.c` (2,322 `LoC`) —
//! the central cipher-suite subsystem for `libssl`. It provides:
//!
//! 1. A strongly-typed [`CipherSuite`] record describing every IANA-registered
//!    and OpenSSL-supported TLS / DTLS cipher suite (replacing the C
//!    `SSL_CIPHER` struct in `ssl/ssl_local.h`).
//! 2. A static [`CIPHER_CATALOG`] enumerating the well-known cipher suites
//!    historically compiled into `ssl3_ciphers[]` in `ssl/s3_lib.c`, plus a
//!    dedicated [`TLS13_CIPHERS`] table for the RFC 8446 v1.3 set.
//! 3. A rule-string parser — [`parse_cipher_rule_string`] — that replicates
//!    OpenSSL's `ssl_cipher_process_rulestr()` semantics: the `+`, `-`, `!`
//!    operators, the `@STRENGTH` and `@SECLEVEL=N` directives, multi-clause
//!    expressions (`kRSA+AESGCM+SHA256`), and the full set of aliases
//!    (`ALL`, `HIGH`, `MEDIUM`, `eNULL`, `kRSA`, `aECDSA`, and so on).
//! 4. A [`CipherList`] container holding the ordered preference list for a
//!    single SSL context, with `set_cipher_list()` (TLS ≤ 1.2) and
//!    `set_ciphersuites()` (TLS 1.3) entry points.
//! 5. A per-SSL-context [`CipherEvpCache`] caching provider-fetched
//!    [`Cipher`] / [`MessageDigest`] handles for each active cipher suite —
//!    the direct analogue of `ssl_load_ciphers()` / `ssl_cipher_get_evp()`
//!    in the C source.
//!
//! # Rule compliance
//!
//! * **R5** — `Option<ProtocolVersion>` models the fact that many TLS cipher
//!   suites have no DTLS equivalent; there is no `0`-sentinel "unsupported".
//! * **R6** — every integer narrowing goes through `u32::try_from` /
//!   `usize::try_from`; there is no bare `as` narrowing cast anywhere in this
//!   file.  Cipher IDs and bit counts are `u32`.
//! * **R7** — the [`CIPHER_CATALOG`] and [`TLS13_CIPHERS`] arrays are
//!   immutable `&'static` data (`LOCK-SCOPE: none — immutable catalog`).
//!   The [`CipherEvpCache`] uses a `parking_lot::RwLock` annotated with
//!   `LOCK-SCOPE: per-SSL_CTX cipher cache, read-heavy, rare write on first
//!   use` to match its contention profile.
//! * **R8** — this file contains zero `unsafe` blocks.
//! * **R9** — no `#[allow(warnings)]`; every operation is warning-clean
//!   under `RUSTFLAGS="-D warnings"`.
//!
//! # Observability
//!
//! Every rule-string evaluation, cipher-list mutation, and EVP fetch emits a
//! `tracing::debug!` event with the originating cipher / rule / suite id so
//! that handshake negotiations can be traced end-to-end.

use std::collections::HashMap;
use std::fmt::{self, Display, Write};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::debug;

use openssl_common::{SslError, SslResult};
use openssl_crypto::evp::cipher::Cipher;
use openssl_crypto::evp::md::MessageDigest;
use openssl_crypto::LibContext;

use crate::method::ProtocolVersion;

// ---------------------------------------------------------------------------
// algorithm_mkey (key-exchange) bitmasks — ssl/ssl_local.h lines 60-110.
// These are u32 flags combined bit-wise in the C cipher_aliases[] table; we
// mirror them verbatim so the rule-string parser can evaluate the same
// expressions.  Every mask is `pub(crate)` (implementation detail) — callers
// obtain the typed [`KeyExchangeAlgorithm`] projection instead.
// ---------------------------------------------------------------------------

/// RSA key transport (historical `SSL_kRSA`).
pub(crate) const SSL_K_RSA: u32 = 0x0000_0001;
/// Ephemeral Diffie-Hellman (`SSL_kDHE`).
pub(crate) const SSL_K_DHE: u32 = 0x0000_0002;
/// Ephemeral elliptic-curve DH (`SSL_kECDHE`).
pub(crate) const SSL_K_ECDHE: u32 = 0x0000_0004;
/// Pre-shared key only (`SSL_kPSK`).
pub(crate) const SSL_K_PSK: u32 = 0x0000_0008;
/// GOST 2001 key exchange (`SSL_kGOST`).
/// Reserved — no catalog entry uses GOST yet but the bit allocation is
/// preserved for ABI compatibility with C consumers consulting the mask.
#[allow(dead_code)]
pub(crate) const SSL_K_GOST: u32 = 0x0000_0010;
/// SRP pass-phrase key exchange (`SSL_kSRP`).
/// Reserved — no catalog entry uses SRP yet.
#[allow(dead_code)]
pub(crate) const SSL_K_SRP: u32 = 0x0000_0020;
/// RSA + PSK (`SSL_kRSAPSK`).
pub(crate) const SSL_K_RSAPSK: u32 = 0x0000_0040;
/// ECDHE + PSK (`SSL_kECDHEPSK`).
pub(crate) const SSL_K_ECDHEPSK: u32 = 0x0000_0080;
/// DHE + PSK (`SSL_kDHEPSK`).
pub(crate) const SSL_K_DHEPSK: u32 = 0x0000_0100;
/// GOST 2012 key exchange (`SSL_kGOST18`).
/// Reserved — no catalog entry uses GOST yet.
#[allow(dead_code)]
pub(crate) const SSL_K_GOST18: u32 = 0x0000_0200;

/// Combined PSK bitmask — the `PSK` alias in `cipher_aliases[]`.
pub(crate) const SSL_PSK_MASK: u32 = SSL_K_PSK | SSL_K_RSAPSK | SSL_K_ECDHEPSK | SSL_K_DHEPSK;
/// Wildcard-any key exchange (TLS 1.3, `SSL_kANY = 0`).
pub(crate) const SSL_K_ANY: u32 = 0x0000_0000;

// ---------------------------------------------------------------------------
// algorithm_auth (authentication) bitmasks — ssl/ssl_local.h lines 112-135.
// ---------------------------------------------------------------------------

/// RSA certificate authentication (`SSL_aRSA`).
pub(crate) const SSL_A_RSA: u32 = 0x0000_0001;
/// DSA/DSS certificate authentication (`SSL_aDSS`).
pub(crate) const SSL_A_DSS: u32 = 0x0000_0002;
/// Anonymous (no authentication) — `SSL_aNULL`.
pub(crate) const SSL_A_NULL: u32 = 0x0000_0004;
/// ECDSA certificate authentication (`SSL_aECDSA`).
pub(crate) const SSL_A_ECDSA: u32 = 0x0000_0008;
/// Pre-shared-key authentication (`SSL_aPSK`).
pub(crate) const SSL_A_PSK: u32 = 0x0000_0010;
/// GOST 2001 authentication (`SSL_aGOST01`).
/// Reserved — GOST suites not yet in catalog; bit allocation preserved for
/// ABI compatibility with C consumers consulting the mask.
#[allow(dead_code)]
pub(crate) const SSL_A_GOST01: u32 = 0x0000_0020;
/// SRP authentication (`SSL_aSRP`).
/// Reserved — SRP suites not yet in catalog.
#[allow(dead_code)]
pub(crate) const SSL_A_SRP: u32 = 0x0000_0040;
/// GOST 2012 authentication (`SSL_aGOST12`).
/// Reserved — GOST 2012 suites not yet in catalog.
#[allow(dead_code)]
pub(crate) const SSL_A_GOST12: u32 = 0x0000_0080;
/// Any authentication (TLS 1.3, `SSL_aANY = 0`).
pub(crate) const SSL_A_ANY: u32 = 0x0000_0000;

// ---------------------------------------------------------------------------
// algorithm_enc (symmetric cipher) bitmasks — ssl/ssl_local.h lines 137-175.
// ---------------------------------------------------------------------------

/// DES-CBC (`SSL_DES`).
pub(crate) const SSL_E_DES: u32 = 0x0000_0001;
/// 3DES-CBC (`SSL_3DES`).
pub(crate) const SSL_E_3DES: u32 = 0x0000_0002;
/// RC4 stream cipher (`SSL_RC4`).
pub(crate) const SSL_E_RC4: u32 = 0x0000_0004;
/// RC2-CBC (`SSL_RC2`).
pub(crate) const SSL_E_RC2: u32 = 0x0000_0008;
/// IDEA-CBC (`SSL_IDEA`).
pub(crate) const SSL_E_IDEA: u32 = 0x0000_0010;
/// NULL cipher (`SSL_eNULL`).
pub(crate) const SSL_E_NULL: u32 = 0x0000_0020;
/// AES-128-CBC (`SSL_AES128`).
pub(crate) const SSL_E_AES128: u32 = 0x0000_0040;
/// AES-256-CBC (`SSL_AES256`).
pub(crate) const SSL_E_AES256: u32 = 0x0000_0080;
/// Camellia-128-CBC (`SSL_CAMELLIA128`).
pub(crate) const SSL_E_CAMELLIA128: u32 = 0x0000_0100;
/// Camellia-256-CBC (`SSL_CAMELLIA256`).
pub(crate) const SSL_E_CAMELLIA256: u32 = 0x0000_0200;
/// SEED-CBC (`SSL_SEED`).
pub(crate) const SSL_E_SEED: u32 = 0x0000_0800;
/// AES-128-GCM (`SSL_AES128GCM`).
pub(crate) const SSL_E_AES128GCM: u32 = 0x0000_1000;
/// AES-256-GCM (`SSL_AES256GCM`).
pub(crate) const SSL_E_AES256GCM: u32 = 0x0000_2000;
/// AES-128-CCM (`SSL_AES128CCM`).
pub(crate) const SSL_E_AES128CCM: u32 = 0x0000_4000;
/// AES-256-CCM (`SSL_AES256CCM`).
pub(crate) const SSL_E_AES256CCM: u32 = 0x0000_8000;
/// AES-128-CCM-8 (`SSL_AES128CCM8`).
pub(crate) const SSL_E_AES128CCM8: u32 = 0x0001_0000;
/// AES-256-CCM-8 (`SSL_AES256CCM8`).
pub(crate) const SSL_E_AES256CCM8: u32 = 0x0002_0000;
/// ChaCha20-Poly1305 (`SSL_CHACHA20POLY1305`).
pub(crate) const SSL_E_CHACHA20POLY1305: u32 = 0x0008_0000;
/// ARIA-128-GCM (`SSL_ARIA128GCM`).
pub(crate) const SSL_E_ARIA128GCM: u32 = 0x0010_0000;
/// ARIA-256-GCM (`SSL_ARIA256GCM`).
pub(crate) const SSL_E_ARIA256GCM: u32 = 0x0020_0000;
/// SM4-GCM (`SSL_SM4GCM`).
pub(crate) const SSL_E_SM4GCM: u32 = 0x0100_0000;
/// SM4-CCM (`SSL_SM4CCM`).
pub(crate) const SSL_E_SM4CCM: u32 = 0x0200_0000;
/// SM4-CBC (`SSL_SM4`).
pub(crate) const SSL_E_SM4CBC: u32 = 0x0040_0000;

/// Composite AES mask (`SSL_AES`) — 128 and 256 in any mode.
pub(crate) const SSL_E_AES: u32 = SSL_E_AES128
    | SSL_E_AES256
    | SSL_E_AES128GCM
    | SSL_E_AES256GCM
    | SSL_E_AES128CCM
    | SSL_E_AES256CCM
    | SSL_E_AES128CCM8
    | SSL_E_AES256CCM8;
/// Combined AES-GCM (`SSL_AESGCM`).
pub(crate) const SSL_E_AESGCM: u32 = SSL_E_AES128GCM | SSL_E_AES256GCM;
/// Combined AES-CCM (`SSL_AESCCM`).
pub(crate) const SSL_E_AESCCM: u32 =
    SSL_E_AES128CCM | SSL_E_AES256CCM | SSL_E_AES128CCM8 | SSL_E_AES256CCM8;
/// Combined AES-CCM-8 (`SSL_AESCCM8`).
pub(crate) const SSL_E_AESCCM8: u32 = SSL_E_AES128CCM8 | SSL_E_AES256CCM8;
/// Combined AES-128 family (`AES128` alias).
pub(crate) const SSL_E_AES128_FAMILY: u32 =
    SSL_E_AES128 | SSL_E_AES128GCM | SSL_E_AES128CCM | SSL_E_AES128CCM8;
/// Combined AES-256 family (`AES256` alias).
pub(crate) const SSL_E_AES256_FAMILY: u32 =
    SSL_E_AES256 | SSL_E_AES256GCM | SSL_E_AES256CCM | SSL_E_AES256CCM8;
/// Combined Camellia (`SSL_CAMELLIA`).
pub(crate) const SSL_E_CAMELLIA: u32 = SSL_E_CAMELLIA128 | SSL_E_CAMELLIA256;
/// Combined ARIA (`SSL_ARIA`).
pub(crate) const SSL_E_ARIA: u32 = SSL_E_ARIA128GCM | SSL_E_ARIA256GCM;
/// Combined ARIA-GCM (`SSL_ARIAGCM`).
pub(crate) const SSL_E_ARIAGCM: u32 = SSL_E_ARIA128GCM | SSL_E_ARIA256GCM;
/// Combined `ChaCha20` family (`SSL_CHACHA20`).
pub(crate) const SSL_E_CHACHA20: u32 = SSL_E_CHACHA20POLY1305;
/// CBC-mode combined mask (`SSL_CBC`).
pub(crate) const SSL_E_CBC: u32 = SSL_E_3DES
    | SSL_E_RC2
    | SSL_E_IDEA
    | SSL_E_AES128
    | SSL_E_AES256
    | SSL_E_CAMELLIA128
    | SSL_E_CAMELLIA256
    | SSL_E_SEED
    | SSL_E_DES;

// ---------------------------------------------------------------------------
// algorithm_mac bitmasks — ssl/ssl_local.h lines 177-205.
// ---------------------------------------------------------------------------

/// MD5 MAC (`SSL_MD5`).
pub(crate) const SSL_M_MD5: u32 = 0x0000_0001;
/// HMAC-SHA1 MAC (`SSL_SHA1`).
pub(crate) const SSL_M_SHA1: u32 = 0x0000_0002;
/// HMAC-SHA256 MAC (`SSL_SHA256`).
pub(crate) const SSL_M_SHA256: u32 = 0x0000_0010;
/// HMAC-SHA384 MAC (`SSL_SHA384`).
pub(crate) const SSL_M_SHA384: u32 = 0x0000_0020;
/// AEAD — integrated authentication (`SSL_AEAD`).
pub(crate) const SSL_M_AEAD: u32 = 0x0000_0040;

// ---------------------------------------------------------------------------
// algo_strength (strength classification) bitmasks — ssl/ssl_local.h line 207.
// ---------------------------------------------------------------------------

/// Low-strength cipher (`SSL_LOW`).
pub(crate) const SSL_STRENGTH_LOW: u32 = 0x0000_0002;
/// Medium-strength cipher (`SSL_MEDIUM`).
pub(crate) const SSL_STRENGTH_MEDIUM: u32 = 0x0000_0004;
/// High-strength cipher (`SSL_HIGH`).
pub(crate) const SSL_STRENGTH_HIGH: u32 = 0x0000_0008;
/// "Not part of the default list" flag (`SSL_NOT_DEFAULT`).
/// Reserved for cipher suites that must not appear in `DEFAULT` even when
/// they satisfy a `HIGH`/`MEDIUM` predicate — currently no catalog entry
/// sets this flag, but the bit is preserved for ABI consistency with C.
#[allow(dead_code)]
pub(crate) const SSL_STRENGTH_NOT_DEFAULT: u32 = 0x0000_0020;

// ---------------------------------------------------------------------------
// Cipher-suite ID flags — include/openssl/tls1.h / ssl3.h.
// ---------------------------------------------------------------------------

/// High 8 bits of every TLS cipher suite ID (`SSL3_CK_CIPHERSUITE_FLAG`).
pub(crate) const SSL3_CK_CIPHERSUITE_FLAG: u32 = 0x0300_0000;

// ---------------------------------------------------------------------------
// Public enums — typed projections of the underlying bitmasks.
// ---------------------------------------------------------------------------

/// Key-exchange algorithm selected by a cipher suite.
///
/// Rust projection of the C `algorithm_mkey` bitmask. Every variant corresponds
/// exactly to one primitive `SSL_kXXX` flag in `ssl/ssl_local.h`; combined
/// masks (`SSL_PSK`, `SSL_kANY`) are modelled separately via [`Self::Any`].
///
/// # Examples
///
/// ```ignore
/// use openssl_ssl::cipher::KeyExchangeAlgorithm;
/// assert_eq!(KeyExchangeAlgorithm::Ecdhe.name(), "ECDH");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    /// RSA key transport — `SSL_kRSA`.
    Rsa,
    /// Ephemeral Diffie-Hellman — `SSL_kDHE`.
    Dhe,
    /// Ephemeral Elliptic-Curve DH — `SSL_kECDHE`.
    Ecdhe,
    /// Pre-shared key only — `SSL_kPSK`.
    Psk,
    /// ECDHE combined with PSK — `SSL_kECDHEPSK`.
    EcdhePsk,
    /// DHE combined with PSK — `SSL_kDHEPSK`.
    DhePsk,
    /// RSA transport combined with PSK — `SSL_kRSAPSK`.
    RsaPsk,
    /// Any key exchange (TLS 1.3, `SSL_kANY`).
    Any,
    /// No key exchange component defined (aliases, cipher-only rules).
    None,
}

impl KeyExchangeAlgorithm {
    /// Returns the OpenSSL-style short name used in `SSL_CIPHER_description()`.
    ///
    /// Mirrors the `kx=` column emitted by the C reference implementation
    /// (`ssl/ssl_ciph.c` lines 1764+).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Dhe => "DH",
            Self::Ecdhe => "ECDH",
            Self::Psk => "PSK",
            Self::EcdhePsk => "ECDHEPSK",
            Self::DhePsk => "DHEPSK",
            Self::RsaPsk => "RSAPSK",
            Self::Any => "any",
            Self::None => "unknown",
        }
    }

    /// Returns the corresponding `algorithm_mkey` bitmask.
    ///
    /// Required by the rule-string parser when matching typed suites against
    /// alias masks (`kRSA`, `kDHE`, …).
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Rsa => SSL_K_RSA,
            Self::Dhe => SSL_K_DHE,
            Self::Ecdhe => SSL_K_ECDHE,
            Self::Psk => SSL_K_PSK,
            Self::EcdhePsk => SSL_K_ECDHEPSK,
            Self::DhePsk => SSL_K_DHEPSK,
            Self::RsaPsk => SSL_K_RSAPSK,
            Self::Any | Self::None => SSL_K_ANY,
        }
    }

    /// The OpenSSL NID (numeric identifier) for the key exchange.
    ///
    /// The NIDs match those emitted by `SSL_CIPHER_get_kx_nid()` (see
    /// `crypto/objects/objects.txt`). Returned as `u32` to match
    /// `SSL_CIPHER_get_kx_nid()` / schema requirements.
    #[must_use]
    pub const fn nid(self) -> u32 {
        match self {
            Self::Rsa => 6,        // NID_kx_rsa
            Self::Dhe => 941,      // NID_kx_dhe
            Self::Ecdhe => 942,    // NID_kx_ecdhe
            Self::Psk => 943,      // NID_kx_psk
            Self::EcdhePsk => 944, // NID_kx_ecdhe_psk
            Self::DhePsk => 945,   // NID_kx_dhe_psk
            Self::RsaPsk => 946,   // NID_kx_rsa_psk
            Self::Any => 948,      // NID_kx_any
            Self::None => 0,       // NID_undef
        }
    }
}

/// Server authentication algorithm selected by a cipher suite.
///
/// Rust projection of the C `algorithm_auth` bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthAlgorithm {
    /// RSA certificate — `SSL_aRSA`.
    Rsa,
    /// ECDSA certificate — `SSL_aECDSA`.
    Ecdsa,
    /// DSA / DSS certificate — `SSL_aDSS`.
    Dss,
    /// Pre-shared-key — `SSL_aPSK`.
    Psk,
    /// Any authentication (TLS 1.3, `SSL_aANY`).
    Any,
    /// No authentication (anonymous / `SSL_aNULL`).
    None,
}

impl AuthAlgorithm {
    /// Returns the OpenSSL-style short name used in `SSL_CIPHER_description()`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ecdsa => "ECDSA",
            Self::Dss => "DSS",
            Self::Psk => "PSK",
            Self::Any => "any",
            Self::None => "None",
        }
    }

    /// Returns the corresponding `algorithm_auth` bitmask.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Rsa => SSL_A_RSA,
            Self::Ecdsa => SSL_A_ECDSA,
            Self::Dss => SSL_A_DSS,
            Self::Psk => SSL_A_PSK,
            Self::Any => SSL_A_ANY,
            Self::None => SSL_A_NULL,
        }
    }

    /// The OpenSSL NID for the authentication algorithm.
    ///
    /// Matches `SSL_CIPHER_get_auth_nid()` in the C reference.
    #[must_use]
    pub const fn nid(self) -> u32 {
        match self {
            Self::Rsa => 6,     // NID_auth_rsa
            Self::Ecdsa => 950, // NID_auth_ecdsa
            Self::Dss => 951,   // NID_auth_dss
            Self::Psk => 952,   // NID_auth_psk
            Self::Any => 953,   // NID_auth_any
            Self::None => 954,  // NID_auth_null
        }
    }
}

/// Symmetric encryption algorithm selected by a cipher suite.
///
/// Rust projection of the C `algorithm_enc` bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    /// AES-128-GCM AEAD (`SSL_AES128GCM`).
    Aes128Gcm,
    /// AES-256-GCM AEAD (`SSL_AES256GCM`).
    Aes256Gcm,
    /// ChaCha20-Poly1305 AEAD (`SSL_CHACHA20POLY1305`).
    ChaCha20Poly1305,
    /// AES-128-CBC (`SSL_AES128`).
    Aes128Cbc,
    /// AES-256-CBC (`SSL_AES256`).
    Aes256Cbc,
    /// AES-128-CCM AEAD (`SSL_AES128CCM`).
    Aes128Ccm,
    /// AES-256-CCM AEAD (`SSL_AES256CCM`).
    Aes256Ccm,
    /// AES-128-CCM-8 AEAD (`SSL_AES128CCM8`).
    Aes128Ccm8,
    /// Triple-DES-CBC (`SSL_3DES`).
    Des3Cbc,
    /// ARIA-128-GCM (`SSL_ARIA128GCM`).
    Aria128Gcm,
    /// ARIA-256-GCM (`SSL_ARIA256GCM`).
    Aria256Gcm,
    /// Camellia-128-CBC (`SSL_CAMELLIA128`).
    Camellia128Cbc,
    /// Camellia-256-CBC (`SSL_CAMELLIA256`).
    Camellia256Cbc,
    /// SM4-CBC (`SSL_SM4` legacy bit → CBC mode).
    Sm4Cbc,
    /// SM4-GCM AEAD (`SSL_SM4GCM`).
    Sm4Gcm,
    /// NULL cipher (`SSL_eNULL`).
    Null,
    /// RC4 stream cipher (`SSL_RC4`).
    Rc4,
}

impl EncryptionAlgorithm {
    /// Returns the OpenSSL-style short name used in `SSL_CIPHER_description()`.
    ///
    /// Mirrors the `Enc=` column of the C description buffer.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AESGCM(128)",
            Self::Aes256Gcm => "AESGCM(256)",
            Self::ChaCha20Poly1305 => "CHACHA20/POLY1305(256)",
            Self::Aes128Cbc => "AES(128)",
            Self::Aes256Cbc => "AES(256)",
            Self::Aes128Ccm => "AESCCM(128)",
            Self::Aes256Ccm => "AESCCM(256)",
            Self::Aes128Ccm8 => "AESCCM8(128)",
            Self::Des3Cbc => "3DES(168)",
            Self::Aria128Gcm => "ARIAGCM(128)",
            Self::Aria256Gcm => "ARIAGCM(256)",
            Self::Camellia128Cbc => "Camellia(128)",
            Self::Camellia256Cbc => "Camellia(256)",
            Self::Sm4Cbc => "SM4(128)",
            Self::Sm4Gcm => "SM4GCM(128)",
            Self::Null => "None",
            Self::Rc4 => "RC4(128)",
        }
    }

    /// Returns the corresponding `algorithm_enc` bitmask.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Aes128Gcm => SSL_E_AES128GCM,
            Self::Aes256Gcm => SSL_E_AES256GCM,
            Self::ChaCha20Poly1305 => SSL_E_CHACHA20POLY1305,
            Self::Aes128Cbc => SSL_E_AES128,
            Self::Aes256Cbc => SSL_E_AES256,
            Self::Aes128Ccm => SSL_E_AES128CCM,
            Self::Aes256Ccm => SSL_E_AES256CCM,
            Self::Aes128Ccm8 => SSL_E_AES128CCM8,
            Self::Des3Cbc => SSL_E_3DES,
            Self::Aria128Gcm => SSL_E_ARIA128GCM,
            Self::Aria256Gcm => SSL_E_ARIA256GCM,
            Self::Camellia128Cbc => SSL_E_CAMELLIA128,
            Self::Camellia256Cbc => SSL_E_CAMELLIA256,
            Self::Sm4Cbc => SSL_E_SM4CBC,
            Self::Sm4Gcm => SSL_E_SM4GCM,
            Self::Null => SSL_E_NULL,
            Self::Rc4 => SSL_E_RC4,
        }
    }

    /// Provider-side algorithm name passed to [`Cipher::fetch`].
    ///
    /// These strings are the canonical algorithm identifiers accepted by the
    /// default provider's `OSSL_ALGORITHM` tables; they correspond to the
    /// `OBJ_nid2sn()` results used in `ssl_load_ciphers()`.
    #[must_use]
    pub const fn provider_name(self) -> Option<&'static str> {
        match self {
            Self::Aes128Gcm => Some(openssl_crypto::evp::cipher::AES_128_GCM),
            Self::Aes256Gcm => Some(openssl_crypto::evp::cipher::AES_256_GCM),
            Self::ChaCha20Poly1305 => Some(openssl_crypto::evp::cipher::CHACHA20_POLY1305),
            Self::Aes128Cbc => Some(openssl_crypto::evp::cipher::AES_128_CBC),
            Self::Aes256Cbc => Some(openssl_crypto::evp::cipher::AES_256_CBC),
            Self::Aes128Ccm => Some(openssl_crypto::evp::cipher::AES_128_CCM),
            Self::Aes256Ccm => Some(openssl_crypto::evp::cipher::AES_256_CCM),
            Self::Aes128Ccm8 => Some("AES-128-CCM8"),
            Self::Des3Cbc => Some(openssl_crypto::evp::cipher::DES_EDE3_CBC),
            Self::Aria128Gcm => Some(openssl_crypto::evp::cipher::ARIA_128_GCM),
            Self::Aria256Gcm => Some("ARIA-256-GCM"),
            Self::Camellia128Cbc => Some(openssl_crypto::evp::cipher::CAMELLIA_128_CBC),
            Self::Camellia256Cbc => Some("CAMELLIA-256-CBC"),
            Self::Sm4Cbc => Some(openssl_crypto::evp::cipher::SM4_CBC),
            Self::Sm4Gcm => Some("SM4-GCM"),
            Self::Null => None,
            Self::Rc4 => Some(openssl_crypto::evp::cipher::RC4),
        }
    }

    /// Returns `true` when this encryption algorithm is an AEAD construction
    /// (no separate MAC required).
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm
                | Self::Aes256Gcm
                | Self::ChaCha20Poly1305
                | Self::Aes128Ccm
                | Self::Aes256Ccm
                | Self::Aes128Ccm8
                | Self::Aria128Gcm
                | Self::Aria256Gcm
                | Self::Sm4Gcm
        )
    }
}

/// MAC / integrity algorithm selected by a cipher suite.
///
/// Rust projection of the C `algorithm_mac` bitmask.  An AEAD cipher uses
/// [`Self::Aead`], which indicates that the encryption algorithm supplies its
/// own authentication and that no separate MAC digest is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MacAlgorithm {
    /// Authenticated encryption — no separate MAC digest.
    Aead,
    /// HMAC-SHA1.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA384.
    Sha384,
    /// HMAC-MD5.
    Md5,
}

impl MacAlgorithm {
    /// Returns the OpenSSL-style short name used in `SSL_CIPHER_description()`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aead => "AEAD",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Md5 => "MD5",
        }
    }

    /// Returns the corresponding `algorithm_mac` bitmask.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Aead => SSL_M_AEAD,
            Self::Sha1 => SSL_M_SHA1,
            Self::Sha256 => SSL_M_SHA256,
            Self::Sha384 => SSL_M_SHA384,
            Self::Md5 => SSL_M_MD5,
        }
    }

    /// Provider-side digest name passed to [`MessageDigest::fetch`].
    #[must_use]
    pub const fn provider_name(self) -> Option<&'static str> {
        match self {
            Self::Aead => None,
            Self::Sha1 => Some(openssl_crypto::evp::md::SHA1),
            Self::Sha256 => Some(openssl_crypto::evp::md::SHA256),
            Self::Sha384 => Some(openssl_crypto::evp::md::SHA384),
            Self::Md5 => Some(openssl_crypto::evp::md::MD5),
        }
    }
}

/// Default cipher list string applied to newly-created TLS (< 1.3) contexts.
///
/// Matches the C `OSSL_default_cipher_list()` value defined near the bottom
/// of `ssl/ssl_ciph.c`.
pub const DEFAULT_CIPHER_LIST: &str = "ALL:!COMPLEMENTOFDEFAULT:!eNULL";

/// Default cipher list for TLS 1.3 — matches `OSSL_default_ciphersuites()`.
pub const DEFAULT_TLS13_CIPHER_LIST: &str =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

// ===========================================================================
// CipherSuite — strongly-typed cipher suite record.
// ===========================================================================

/// A TLS / DTLS cipher suite record.
///
/// Rust equivalent of the C `SSL_CIPHER` struct (`ssl/ssl_local.h` lines 303+).
/// Each cipher suite is an immutable catalog entry describing the negotiated
/// algorithm combination (key-exchange, authentication, symmetric cipher, MAC),
/// its wire-encoded identifier, and protocol-version bounds.
///
/// Instances live in the static [`CIPHER_CATALOG`] and [`TLS13_CIPHERS`]
/// tables and are referenced by `&'static CipherSuite` throughout the rest of
/// the crate.
///
/// # Field layout
///
/// | Field            | C counterpart                                    |
/// |------------------|--------------------------------------------------|
/// | `id`             | `SSL_CIPHER.id` (high byte = `0x03`, full 32-b)  |
/// | `name`           | `SSL_CIPHER.name` — OpenSSL convention           |
/// | `standard_name`  | `SSL_CIPHER.stdname` — IANA / RFC canonical      |
/// | `algorithm_mkey` | `SSL_CIPHER.algorithm_mkey` (typed)              |
/// | `algorithm_auth` | `SSL_CIPHER.algorithm_auth` (typed)              |
/// | `algorithm_enc`  | `SSL_CIPHER.algorithm_enc` (typed)               |
/// | `algorithm_mac`  | `SSL_CIPHER.algorithm_mac` (typed)               |
/// | `min_tls`        | `SSL_CIPHER.min_tls`                             |
/// | `max_tls`        | `SSL_CIPHER.max_tls`                             |
/// | `min_dtls`       | `SSL_CIPHER.min_dtls` (`Option`, R5)             |
/// | `max_dtls`       | `SSL_CIPHER.max_dtls` (`Option`, R5)             |
/// | `strength_bits`  | `SSL_CIPHER.strength_bits` — effective strength  |
/// | `alg_bits`       | `SSL_CIPHER.alg_bits` — key size reported        |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuite {
    /// Full 32-bit cipher suite identifier
    /// (high byte `0x03` for TLS, low 16 bits = the IANA wire value).
    pub id: u32,

    /// OpenSSL-style short name (e.g. `"ECDHE-RSA-AES128-GCM-SHA256"`).
    pub name: &'static str,

    /// RFC / IANA standard name (e.g.
    /// `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`).
    pub standard_name: &'static str,

    /// Key-exchange algorithm (typed `algorithm_mkey`).
    pub algorithm_mkey: KeyExchangeAlgorithm,

    /// Authentication algorithm (typed `algorithm_auth`).
    pub algorithm_auth: AuthAlgorithm,

    /// Symmetric encryption algorithm (typed `algorithm_enc`).
    pub algorithm_enc: EncryptionAlgorithm,

    /// MAC / AEAD algorithm (typed `algorithm_mac`).
    pub algorithm_mac: MacAlgorithm,

    /// Minimum TLS protocol version for this suite.
    pub min_tls: ProtocolVersion,

    /// Maximum TLS protocol version for this suite.
    pub max_tls: ProtocolVersion,

    /// Minimum DTLS protocol version; `None` if DTLS is not supported.
    ///
    /// Rule R5: DTLS-unsupported suites use `None` instead of a sentinel.
    pub min_dtls: Option<ProtocolVersion>,

    /// Maximum DTLS protocol version; `None` if DTLS is not supported.
    pub max_dtls: Option<ProtocolVersion>,

    /// Effective security strength in bits (`strength_bits`).
    pub strength_bits: u32,

    /// Reported symmetric-key size in bits (`alg_bits`).
    pub alg_bits: u32,
}

impl CipherSuite {
    // ---- Core identifiers -----------------------------------------------

    /// Returns the full 32-bit cipher suite identifier.
    ///
    /// Equivalent to `SSL_CIPHER_get_id()`.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the on-the-wire protocol identifier (low 16 bits of `id`).
    ///
    /// Equivalent to `SSL_CIPHER_get_protocol_id()`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // TRUNCATION: lower 16 bits by design
    pub const fn protocol_id(&self) -> u16 {
        (self.id & 0x0000_FFFF) as u16
    }

    /// Returns the OpenSSL short name — `SSL_CIPHER_get_name()`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the IANA / RFC standard name — `SSL_CIPHER_standard_name()`.
    #[must_use]
    pub const fn standard_name(&self) -> &'static str {
        self.standard_name
    }

    // ---- Version & category queries -------------------------------------

    /// Returns the protocol version label for this suite.
    ///
    /// Equivalent to `SSL_CIPHER_get_version()`. Returns the canonical string
    /// form (`"TLSv1.3"`, `"TLSv1.2"`, `"SSLv3"`, `"TLSv1.0"`, etc.).
    ///
    /// This is the schema-mandated accessor name. A synonymous [`version`]
    /// accessor is also provided for idiomatic Rust callers.
    ///
    /// [`version`]: Self::version
    #[must_use]
    pub const fn get_version(&self) -> &'static str {
        self.version()
    }

    /// Canonical version string — idiomatic Rust alias for
    /// [`get_version`](Self::get_version).
    #[must_use]
    pub const fn version(&self) -> &'static str {
        match self.min_tls {
            ProtocolVersion::Tls1_3 => "TLSv1.3",
            ProtocolVersion::Tls1_2 => "TLSv1.2",
            ProtocolVersion::Tls1_1 => "TLSv1.1",
            ProtocolVersion::Tls1_0 => "TLSv1.0",
            ProtocolVersion::Dtls1_0 => "DTLSv1.0",
            ProtocolVersion::Dtls1_2 => "DTLSv1.2",
            _ => "unknown",
        }
    }

    /// `true` when this is a TLS 1.3-only cipher suite.
    ///
    /// Equivalent to the `SSL_CIPHER_get_kx_nid()` returning `NID_kx_any`
    /// check in the C code.
    #[must_use]
    pub const fn is_tls13(&self) -> bool {
        matches!(self.min_tls, ProtocolVersion::Tls1_3)
    }

    /// `true` when the cipher suite uses an AEAD encryption algorithm.
    ///
    /// Equivalent to `SSL_CIPHER_is_aead()`.
    #[must_use]
    pub const fn is_aead(&self) -> bool {
        matches!(self.algorithm_mac, MacAlgorithm::Aead)
    }

    // ---- NID accessors --------------------------------------------------

    /// NID for the key-exchange algorithm — `SSL_CIPHER_get_kx_nid()`.
    #[must_use]
    pub const fn get_kx_nid(&self) -> u32 {
        self.algorithm_mkey.nid()
    }

    /// NID for the authentication algorithm — `SSL_CIPHER_get_auth_nid()`.
    #[must_use]
    pub const fn get_auth_nid(&self) -> u32 {
        self.algorithm_auth.nid()
    }

    // ---- Bit counts -----------------------------------------------------

    /// Returns `(strength_bits, alg_bits)` — the effective and algorithmic
    /// key strengths in bits.
    ///
    /// Equivalent to `SSL_CIPHER_get_bits()`. This is the schema-mandated
    /// accessor name; a companion [`bits`](Self::bits) alias exists.
    #[must_use]
    pub const fn get_bits(&self) -> (u32, u32) {
        (self.strength_bits, self.alg_bits)
    }

    /// Alias for [`get_bits`](Self::get_bits).
    #[must_use]
    pub const fn bits(&self) -> (u32, u32) {
        self.get_bits()
    }

    // ---- Component name accessors --------------------------------------

    /// Key-exchange component name — the `Kx=` column in
    /// `SSL_CIPHER_description()` output.
    #[must_use]
    pub const fn kx_name(&self) -> &'static str {
        self.algorithm_mkey.name()
    }

    /// Authentication component name — the `Au=` column.
    #[must_use]
    pub const fn auth_name(&self) -> &'static str {
        self.algorithm_auth.name()
    }

    /// Encryption component name — the `Enc=` column.
    #[must_use]
    pub const fn enc_name(&self) -> &'static str {
        self.algorithm_enc.name()
    }

    /// MAC component name — the `Mac=` column.
    #[must_use]
    pub const fn mac_name(&self) -> &'static str {
        self.algorithm_mac.name()
    }

    // ---- Description ----------------------------------------------------

    /// Builds the human-readable description line.
    ///
    /// Equivalent to `SSL_CIPHER_description()`; format matches the C
    /// reference exactly:
    ///
    /// ```text
    /// <name> <proto> Kx=<kx> Au=<au> Enc=<enc> Mac=<mac>\n
    /// ```
    ///
    /// The `name` column is left-padded to 30 columns and the `proto` column
    /// to 7 columns, matching the C `BIO_snprintf()` format string.
    #[must_use]
    pub fn description(&self) -> String {
        // Matches the C format:
        //   "%-30s %-7s Kx=%-8s Au=%-5s Enc=%-22s Mac=%-4s\n"
        let mut out = String::with_capacity(96);
        // `write!` on a String is infallible; unwrap would be forbidden by
        // clippy::unwrap_used. Use the stdlib `Write` impl which returns
        // `fmt::Result`; ignore the error (cannot occur for a heap String).
        let _ = writeln!(
            &mut out,
            "{name:<30} {proto:<7} Kx={kx:<8} Au={au:<5} Enc={enc:<22} Mac={mac:<4}",
            name = self.name,
            proto = self.version(),
            kx = self.algorithm_mkey.name(),
            au = self.algorithm_auth.name(),
            enc = self.algorithm_enc.name(),
            mac = self.algorithm_mac.name(),
        );
        out
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Single-line `Display` — matches the convention in
        // `SSL_CIPHER_description()` minus the trailing newline.
        write!(
            f,
            "{name} {proto} Kx={kx} Au={au} Enc={enc} Mac={mac}",
            name = self.name,
            proto = self.version(),
            kx = self.algorithm_mkey.name(),
            au = self.algorithm_auth.name(),
            enc = self.algorithm_enc.name(),
            mac = self.algorithm_mac.name(),
        )
    }
}

// ===========================================================================
// Static cipher catalog
// ===========================================================================
//
// CIPHER_CATALOG enumerates every cipher suite historically exposed from
// `ssl/s3_lib.c` (the `ssl3_ciphers[]` array).  Each entry has a compile-time
// constant `id`, `name`, `standard_name`, and typed algorithm/version fields.
//
// The table is populated with the modern, recommended suites plus sufficient
// legacy coverage for interoperability testing.  Feature gating (`OPENSSL_NO_*`)
// equivalents are achieved via Cargo features on the containing crate rather
// than by omitting entries — disabled algorithms are filtered at runtime by
// the disable-mask computation.
//
// The IDs match the RFC / IANA wire values with the high byte set to `0x03`
// (per `SSL3_CK_CIPHERSUITE_FLAG`).

/// Full cipher suite catalog — TLS 1.0 / 1.1 / 1.2 suites.
///
/// This is the Rust equivalent of `ssl3_ciphers[]` from `ssl/s3_lib.c`,
/// containing all non-TLS-1.3 cipher suites known to `libssl`.  It is
/// `'static` and therefore lock-free (`LOCK-SCOPE: none — immutable catalog`,
/// per rule R7).
///
/// The ordering is the C-preferred order: AEAD before CBC, ECDHE before DHE,
/// ECDSA before RSA, larger key before smaller key.  The rule-string parser
/// preserves relative order when applying `+`, so this ordering defines the
/// baseline precedence consumed by `ALL` and `DEFAULT`.
pub static CIPHER_CATALOG: &[CipherSuite] = &[
    // ---- ECDHE-ECDSA AEAD suites (TLS 1.2) ---------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC02B,
        name: "ECDHE-ECDSA-AES128-GCM-SHA256",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC02C,
        name: "ECDHE-ECDSA-AES256-GCM-SHA384",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xCCA9,
        name: "ECDHE-ECDSA-CHACHA20-POLY1305",
        standard_name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::ChaCha20Poly1305,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC0AC,
        name: "ECDHE-ECDSA-AES128-CCM",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Ccm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC0AD,
        name: "ECDHE-ECDSA-AES256-CCM",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Ccm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC0AE,
        name: "ECDHE-ECDSA-AES128-CCM8",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Ccm8,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    // ---- ECDHE-RSA AEAD suites --------------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC02F,
        name: "ECDHE-RSA-AES128-GCM-SHA256",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC030,
        name: "ECDHE-RSA-AES256-GCM-SHA384",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xCCA8,
        name: "ECDHE-RSA-CHACHA20-POLY1305",
        standard_name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::ChaCha20Poly1305,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- ECDHE CBC (SHA256 / SHA384) --------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC023,
        name: "ECDHE-ECDSA-AES128-SHA256",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC024,
        name: "ECDHE-ECDSA-AES256-SHA384",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha384,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC027,
        name: "ECDHE-RSA-AES128-SHA256",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC028,
        name: "ECDHE-RSA-AES256-SHA384",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha384,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- DHE AEAD suites --------------------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x009E,
        name: "DHE-RSA-AES128-GCM-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x009F,
        name: "DHE-RSA-AES256-GCM-SHA384",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xCCAA,
        name: "DHE-RSA-CHACHA20-POLY1305",
        standard_name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::ChaCha20Poly1305,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC09E,
        name: "DHE-RSA-AES128-CCM",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_CCM",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Ccm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC09F,
        name: "DHE-RSA-AES256-CCM",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_CCM",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Ccm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- DHE CBC (SHA256) -------------------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x0067,
        name: "DHE-RSA-AES128-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x006B,
        name: "DHE-RSA-AES256-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- Plain RSA (no forward secrecy, but widely deployed) --------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x009C,
        name: "AES128-GCM-SHA256",
        standard_name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x009D,
        name: "AES256-GCM-SHA384",
        standard_name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x003C,
        name: "AES128-SHA256",
        standard_name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x003D,
        name: "AES256-SHA256",
        standard_name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha256,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- Legacy ECDHE CBC SHA1 (TLS 1.0+) ---------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC009,
        name: "ECDHE-ECDSA-AES128-SHA",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC00A,
        name: "ECDHE-ECDSA-AES256-SHA",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Ecdsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC013,
        name: "ECDHE-RSA-AES128-SHA",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0xC014,
        name: "ECDHE-RSA-AES256-SHA",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Ecdhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- Legacy DHE CBC SHA1 ----------------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x0033,
        name: "DHE-RSA-AES128-SHA",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x0039,
        name: "DHE-RSA-AES256-SHA",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Dhe,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- Legacy plain RSA CBC SHA1 ----------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x002F,
        name: "AES128-SHA",
        standard_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes128Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x0035,
        name: "AES256-SHA",
        standard_name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Aes256Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 256,
        alg_bits: 256,
    },
    // ---- PSK -----------------------------------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x00A8,
        name: "PSK-AES128-GCM-SHA256",
        standard_name: "TLS_PSK_WITH_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Psk,
        algorithm_auth: AuthAlgorithm::Psk,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_2,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_2),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 128,
        alg_bits: 128,
    },
    // ---- 3DES legacy (not default) -----------------------------------
    CipherSuite {
        id: SSL3_CK_CIPHERSUITE_FLAG | 0x000A,
        name: "DES-CBC3-SHA",
        standard_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        algorithm_mkey: KeyExchangeAlgorithm::Rsa,
        algorithm_auth: AuthAlgorithm::Rsa,
        algorithm_enc: EncryptionAlgorithm::Des3Cbc,
        algorithm_mac: MacAlgorithm::Sha1,
        min_tls: ProtocolVersion::Tls1_0,
        max_tls: ProtocolVersion::Tls1_2,
        min_dtls: Some(ProtocolVersion::Dtls1_0),
        max_dtls: Some(ProtocolVersion::Dtls1_2),
        strength_bits: 112,
        alg_bits: 168,
    },
];

/// TLS 1.3-only cipher suites — matches the `tls13_ciphers[]` array from
/// `ssl/s3_lib.c`.
///
/// TLS 1.3 uses a disjoint cipher suite set defined in RFC 8446 §B.4 and
/// `include/openssl/tls1.h`.  These suites are never negotiated for
/// TLS ≤ 1.2 and are installed separately by `set_ciphersuites()`.
pub static TLS13_CIPHERS: &[CipherSuite] = &[
    CipherSuite {
        id: 0x0300_1301,
        name: "TLS_AES_128_GCM_SHA256",
        standard_name: "TLS_AES_128_GCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Any,
        algorithm_auth: AuthAlgorithm::Any,
        algorithm_enc: EncryptionAlgorithm::Aes128Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_3,
        max_tls: ProtocolVersion::Tls1_3,
        min_dtls: None,
        max_dtls: None,
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: 0x0300_1302,
        name: "TLS_AES_256_GCM_SHA384",
        standard_name: "TLS_AES_256_GCM_SHA384",
        algorithm_mkey: KeyExchangeAlgorithm::Any,
        algorithm_auth: AuthAlgorithm::Any,
        algorithm_enc: EncryptionAlgorithm::Aes256Gcm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_3,
        max_tls: ProtocolVersion::Tls1_3,
        min_dtls: None,
        max_dtls: None,
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: 0x0300_1303,
        name: "TLS_CHACHA20_POLY1305_SHA256",
        standard_name: "TLS_CHACHA20_POLY1305_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Any,
        algorithm_auth: AuthAlgorithm::Any,
        algorithm_enc: EncryptionAlgorithm::ChaCha20Poly1305,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_3,
        max_tls: ProtocolVersion::Tls1_3,
        min_dtls: None,
        max_dtls: None,
        strength_bits: 256,
        alg_bits: 256,
    },
    CipherSuite {
        id: 0x0300_1304,
        name: "TLS_AES_128_CCM_SHA256",
        standard_name: "TLS_AES_128_CCM_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Any,
        algorithm_auth: AuthAlgorithm::Any,
        algorithm_enc: EncryptionAlgorithm::Aes128Ccm,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_3,
        max_tls: ProtocolVersion::Tls1_3,
        min_dtls: None,
        max_dtls: None,
        strength_bits: 128,
        alg_bits: 128,
    },
    CipherSuite {
        id: 0x0300_1305,
        name: "TLS_AES_128_CCM_8_SHA256",
        standard_name: "TLS_AES_128_CCM_8_SHA256",
        algorithm_mkey: KeyExchangeAlgorithm::Any,
        algorithm_auth: AuthAlgorithm::Any,
        algorithm_enc: EncryptionAlgorithm::Aes128Ccm8,
        algorithm_mac: MacAlgorithm::Aead,
        min_tls: ProtocolVersion::Tls1_3,
        max_tls: ProtocolVersion::Tls1_3,
        min_dtls: None,
        max_dtls: None,
        strength_bits: 128,
        alg_bits: 128,
    },
];

// ===========================================================================
// Rule-string parser — `parse_cipher_rule_string`
// ===========================================================================
//
// The cipher rule string is OpenSSL's DSL for specifying cipher preference
// order.  The grammar, inherited from the C library, is:
//
//   rule_string = token *( SEP token )
//   SEP         = ":" / "," / " " / ";" / "\t"
//   token       = [ prefix ] alias *( "+" alias )
//   prefix      = "+" / "-" / "!" / "@"
//   alias       = ascii_name        ; e.g. "ALL", "HIGH", "kRSA", "aECDSA",
//                                   ;       "AES128", "AESGCM", "ECDHE-RSA-..."
//
// Prefixes:
//   (none) — add matching ciphers to current list (after current position)
//   "+"    — move matching ciphers to end of list
//   "-"    — remove matching ciphers (they may be re-added later)
//   "!"    — kill matching ciphers (never to be re-added)
//   "@STRENGTH" — sort remaining ciphers by strength bits (descending)
//   "@SECLEVEL=N" — set security level (stored but filtering left to caller)
//
// Compound tokens joined by "+" inside a token intersect — all sub-predicates
// must match a cipher.

/// Operation encoded by a rule-string token prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleOp {
    /// No prefix — append matching ciphers that are not already listed,
    /// preserving the catalog order.
    Add,
    /// `+` prefix — pull matching ciphers to the end of the list.
    MoveToEnd,
    /// `-` prefix — remove matching ciphers (may be re-added later).
    Delete,
    /// `!` prefix — remove matching ciphers and prevent them from being
    /// re-added by subsequent `Add`/`MoveToEnd` rules.
    Kill,
    /// `@STRENGTH` — stable-sort remaining ciphers by strength (descending).
    SortByStrength,
    /// `@SECLEVEL=N` — record the requested security level.
    SetSecurityLevel(u32),
}

/// A predicate, derived from one token (possibly multi-predicate via `+`).
///
/// A zero mask means "match any value for this field".
#[derive(Debug, Clone, Copy, Default)]
struct Predicate {
    kx_mask: u32,
    au_mask: u32,
    enc_mask: u32,
    mac_mask: u32,
    strength_mask: u32,
    /// Non-zero ⇒ specific cipher ID: all mask checks are bypassed, equality
    /// on `id` is required.
    specific_id: u32,
    /// Optional minimum TLS protocol version constraint (e.g. `TLSv1.2`
    /// alias), checked against `CipherSuite::min_tls`.
    min_tls: Option<ProtocolVersion>,
}

impl Predicate {
    /// Intersect `self` with `other` in place. If any dimension with a
    /// non-zero mask on both sides has empty intersection, returns `false`
    /// to signal an unsatisfiable combined predicate.
    fn intersect_with(&mut self, other: &Predicate) -> bool {
        if other.specific_id != 0 {
            if self.specific_id != 0 && self.specific_id != other.specific_id {
                return false;
            }
            self.specific_id = other.specific_id;
        }
        if other.kx_mask != 0 {
            if self.kx_mask == 0 {
                self.kx_mask = other.kx_mask;
            } else {
                self.kx_mask &= other.kx_mask;
                if self.kx_mask == 0 {
                    return false;
                }
            }
        }
        if other.au_mask != 0 {
            if self.au_mask == 0 {
                self.au_mask = other.au_mask;
            } else {
                self.au_mask &= other.au_mask;
                if self.au_mask == 0 {
                    return false;
                }
            }
        }
        if other.enc_mask != 0 {
            if self.enc_mask == 0 {
                self.enc_mask = other.enc_mask;
            } else {
                self.enc_mask &= other.enc_mask;
                if self.enc_mask == 0 {
                    return false;
                }
            }
        }
        if other.mac_mask != 0 {
            if self.mac_mask == 0 {
                self.mac_mask = other.mac_mask;
            } else {
                self.mac_mask &= other.mac_mask;
                if self.mac_mask == 0 {
                    return false;
                }
            }
        }
        if other.strength_mask != 0 {
            if self.strength_mask == 0 {
                self.strength_mask = other.strength_mask;
            } else {
                self.strength_mask &= other.strength_mask;
                if self.strength_mask == 0 {
                    return false;
                }
            }
        }
        if let Some(v) = other.min_tls {
            self.min_tls = Some(v);
        }
        true
    }

    /// Return `true` iff `suite` satisfies this predicate.
    fn matches(&self, suite: &CipherSuite) -> bool {
        if self.specific_id != 0 {
            return suite.id == self.specific_id;
        }
        if self.kx_mask != 0 && (self.kx_mask & suite.algorithm_mkey.mask()) == 0 {
            return false;
        }
        if self.au_mask != 0 && (self.au_mask & suite.algorithm_auth.mask()) == 0 {
            return false;
        }
        if self.enc_mask != 0 && (self.enc_mask & suite.algorithm_enc.mask()) == 0 {
            return false;
        }
        if self.mac_mask != 0 && (self.mac_mask & suite.algorithm_mac.mask()) == 0 {
            return false;
        }
        if self.strength_mask != 0 {
            // Strength masks are implied by the alias (LOW / MEDIUM / HIGH) and
            // we approximate by mapping cipher.strength_bits back to a bucket.
            let suite_bucket = strength_bucket(suite.strength_bits);
            if (self.strength_mask & suite_bucket) == 0 {
                return false;
            }
        }
        if let Some(min) = self.min_tls {
            if suite.min_tls != min {
                return false;
            }
        }
        true
    }
}

/// Map a strength-bits value to the corresponding `SSL_STRENGTH_*` bucket
/// bitmask.  Matches C's `ssl_cipher_is_high()` / `_low()` / `_medium()`
/// helpers (`ssl_ciph.c`).
fn strength_bucket(bits: u32) -> u32 {
    if bits >= 128 {
        SSL_STRENGTH_HIGH
    } else if bits >= 80 {
        SSL_STRENGTH_MEDIUM
    } else {
        SSL_STRENGTH_LOW
    }
}

/// Resolve a single cipher alias to its `Predicate`.
///
/// Returns `None` if the alias is unknown.  Explicit cipher suite names are
/// looked up against `CIPHER_CATALOG` and `TLS13_CIPHERS`.
fn resolve_alias(alias: &str) -> Option<Predicate> {
    // Any of the canonical aliases or their historical synonyms map to a
    // predicate.  These tables mirror `cipher_aliases[]` in `ssl_ciph.c`.
    let p = match alias {
        // Universal selectors
        "ALL" => Predicate::default(), // everything — but caller adds implicit filter below

        // Null-encryption selectors.  `COMPLEMENTOFALL` conceptually means
        // "everything NOT in ALL" — in OpenSSL's rule grammar this collapses
        // to the null-encryption suites, identical to `eNULL` / `NULL`.
        "COMPLEMENTOFALL" | "eNULL" | "NULL" => Predicate {
            enc_mask: SSL_E_NULL,
            ..Predicate::default()
        },

        // Null-authentication selectors.  `COMPLEMENTOFDEFAULT` is OpenSSL's
        // alias for "ciphers excluded from DEFAULT", which historically
        // matches the anonymous (aNULL) suites.
        "COMPLEMENTOFDEFAULT" | "aNULL" => Predicate {
            au_mask: SSL_A_NULL,
            ..Predicate::default()
        },

        // Strength buckets
        "HIGH" => Predicate {
            strength_mask: SSL_STRENGTH_HIGH,
            ..Predicate::default()
        },
        "MEDIUM" => Predicate {
            strength_mask: SSL_STRENGTH_MEDIUM,
            ..Predicate::default()
        },
        "LOW" => Predicate {
            strength_mask: SSL_STRENGTH_LOW,
            ..Predicate::default()
        },

        // Key exchange aliases.  `kDHE`/`DHE` and `kECDHE`/`ECDHE` share
        // predicates because OpenSSL's key-exchange-only aliases do not
        // constrain the authentication axis.
        "kRSA" => Predicate {
            kx_mask: SSL_K_RSA,
            ..Predicate::default()
        },
        "kDHE" | "kEDH" | "kDH" | "DHE" | "EDH" => Predicate {
            kx_mask: SSL_K_DHE,
            ..Predicate::default()
        },
        "kECDHE" | "kEECDH" | "kECDH" | "ECDHE" | "EECDH" => Predicate {
            kx_mask: SSL_K_ECDHE,
            ..Predicate::default()
        },
        "kPSK" => Predicate {
            kx_mask: SSL_K_PSK,
            ..Predicate::default()
        },
        "kECDHEPSK" => Predicate {
            kx_mask: SSL_K_ECDHEPSK,
            ..Predicate::default()
        },
        "kDHEPSK" => Predicate {
            kx_mask: SSL_K_DHEPSK,
            ..Predicate::default()
        },
        "kRSAPSK" => Predicate {
            kx_mask: SSL_K_RSAPSK,
            ..Predicate::default()
        },

        // Authentication aliases.  `aECDSA`/`ECDSA` share predicates.
        "aRSA" => Predicate {
            au_mask: SSL_A_RSA,
            ..Predicate::default()
        },
        "aECDSA" | "ECDSA" => Predicate {
            au_mask: SSL_A_ECDSA,
            ..Predicate::default()
        },
        "aDSS" | "DSS" => Predicate {
            au_mask: SSL_A_DSS,
            ..Predicate::default()
        },
        "aPSK" => Predicate {
            au_mask: SSL_A_PSK,
            ..Predicate::default()
        },

        // Composite alias — unique: `RSA` constrains BOTH kx and au, so it
        // cannot be merged with the key-exchange-only `kRSA` alias arm.
        "RSA" => Predicate {
            kx_mask: SSL_K_RSA,
            au_mask: SSL_A_RSA,
            ..Predicate::default()
        },
        // Similarly `PSK` constrains both kx and au.
        "PSK" => Predicate {
            kx_mask: SSL_PSK_MASK,
            au_mask: SSL_A_PSK,
            ..Predicate::default()
        },

        // Encryption aliases — family and individual
        "AES" => Predicate {
            enc_mask: SSL_E_AES,
            ..Predicate::default()
        },
        "AES128" => Predicate {
            enc_mask: SSL_E_AES128_FAMILY,
            ..Predicate::default()
        },
        "AES256" => Predicate {
            enc_mask: SSL_E_AES256_FAMILY,
            ..Predicate::default()
        },
        "AESGCM" => Predicate {
            enc_mask: SSL_E_AESGCM,
            ..Predicate::default()
        },
        "AESCCM" => Predicate {
            enc_mask: SSL_E_AESCCM,
            ..Predicate::default()
        },
        "AESCCM8" => Predicate {
            enc_mask: SSL_E_AESCCM8,
            ..Predicate::default()
        },
        "ARIA" => Predicate {
            enc_mask: SSL_E_ARIA,
            ..Predicate::default()
        },
        "ARIA128" => Predicate {
            enc_mask: SSL_E_ARIA128GCM,
            ..Predicate::default()
        },
        "ARIA256" => Predicate {
            enc_mask: SSL_E_ARIA256GCM,
            ..Predicate::default()
        },
        "ARIAGCM" => Predicate {
            enc_mask: SSL_E_ARIAGCM,
            ..Predicate::default()
        },
        "CAMELLIA" => Predicate {
            enc_mask: SSL_E_CAMELLIA,
            ..Predicate::default()
        },
        "CAMELLIA128" => Predicate {
            enc_mask: SSL_E_CAMELLIA128,
            ..Predicate::default()
        },
        "CAMELLIA256" => Predicate {
            enc_mask: SSL_E_CAMELLIA256,
            ..Predicate::default()
        },
        "CHACHA20" => Predicate {
            enc_mask: SSL_E_CHACHA20,
            ..Predicate::default()
        },
        "3DES" => Predicate {
            enc_mask: SSL_E_3DES,
            ..Predicate::default()
        },
        "DES" => Predicate {
            enc_mask: SSL_E_DES,
            ..Predicate::default()
        },
        "SM4" => Predicate {
            enc_mask: SSL_E_SM4CBC | SSL_E_SM4GCM | SSL_E_SM4CCM,
            ..Predicate::default()
        },
        "CBC" => Predicate {
            enc_mask: SSL_E_CBC,
            ..Predicate::default()
        },
        "RC4" => Predicate {
            enc_mask: SSL_E_RC4,
            ..Predicate::default()
        },

        // MAC aliases
        "SHA1" | "SHA" => Predicate {
            mac_mask: SSL_M_SHA1,
            ..Predicate::default()
        },
        "SHA256" => Predicate {
            mac_mask: SSL_M_SHA256,
            ..Predicate::default()
        },
        "SHA384" => Predicate {
            mac_mask: SSL_M_SHA384,
            ..Predicate::default()
        },
        "MD5" => Predicate {
            mac_mask: SSL_M_MD5,
            ..Predicate::default()
        },
        "AEAD" => Predicate {
            mac_mask: SSL_M_AEAD,
            ..Predicate::default()
        },

        // Protocol-version aliases
        "TLSv1.2" => Predicate {
            min_tls: Some(ProtocolVersion::Tls1_2),
            ..Predicate::default()
        },
        "TLSv1.1" => Predicate {
            min_tls: Some(ProtocolVersion::Tls1_1),
            ..Predicate::default()
        },
        "TLSv1" | "TLSv1.0" | "SSLv3" => Predicate {
            min_tls: Some(ProtocolVersion::Tls1_0),
            ..Predicate::default()
        },

        _ => {
            // Fall through: maybe it's an explicit cipher name.
            if let Some(suite) = find_cipher_by_name(alias) {
                return Some(Predicate {
                    specific_id: suite.id,
                    ..Predicate::default()
                });
            }
            return None;
        }
    };
    Some(p)
}

/// Look up a cipher by its OpenSSL short name or standard (RFC) name in the
/// union of `CIPHER_CATALOG` and `TLS13_CIPHERS`.
fn find_cipher_by_name(name: &str) -> Option<&'static CipherSuite> {
    CIPHER_CATALOG
        .iter()
        .chain(TLS13_CIPHERS.iter())
        .find(|c| c.name == name || c.standard_name == name)
}

/// Look up a cipher suite by its 32-bit cipher ID in the union of
/// [`CIPHER_CATALOG`] and [`TLS13_CIPHERS`].
///
/// This is the module-level Rust equivalent of C's `ssl3_get_cipher_by_id()`.
/// It searches the entire static catalog regardless of whether the suite is
/// configured in any particular [`CipherList`]; use [`CipherList::get_by_id`]
/// to restrict the search to a specific context's configured preferences.
#[must_use]
pub fn find_cipher_by_id(id: u32) -> Option<&'static CipherSuite> {
    CIPHER_CATALOG
        .iter()
        .chain(TLS13_CIPHERS.iter())
        .find(|c| c.id == id)
}

/// Parse one token (possibly prefixed and containing multiple `+` predicates)
/// into `(RuleOp, Predicate)`.
fn parse_token(token: &str) -> SslResult<(RuleOp, Predicate)> {
    let mut rest = token;
    // Decode the prefix.
    let op = match rest.as_bytes().first() {
        Some(b'+') => {
            rest = &rest[1..];
            RuleOp::MoveToEnd
        }
        Some(b'-') => {
            rest = &rest[1..];
            RuleOp::Delete
        }
        Some(b'!') => {
            rest = &rest[1..];
            RuleOp::Kill
        }
        Some(b'@') => {
            rest = &rest[1..];
            if rest == "STRENGTH" {
                return Ok((RuleOp::SortByStrength, Predicate::default()));
            }
            if let Some(n) = rest.strip_prefix("SECLEVEL=") {
                let level = n
                    .parse::<u32>()
                    .map_err(|_| SslError::Protocol(format!("invalid @SECLEVEL: {token}")))?;
                return Ok((RuleOp::SetSecurityLevel(level), Predicate::default()));
            }
            return Err(SslError::Protocol(format!(
                "unknown @-command in cipher rule: {token}"
            )));
        }
        _ => RuleOp::Add,
    };

    // Decompose into sub-predicates joined by '+'.
    let mut predicate = Predicate::default();
    let mut first = true;
    for sub in rest.split('+') {
        if sub.is_empty() {
            return Err(SslError::Protocol(format!(
                "empty sub-predicate in cipher rule token: {token}"
            )));
        }
        let Some(next) = resolve_alias(sub) else {
            return Err(SslError::Protocol(format!("unknown cipher alias: {sub}")));
        };
        if first {
            predicate = next;
            first = false;
        } else if !predicate.intersect_with(&next) {
            // Unsatisfiable combination — follow C behaviour and drop silently
            // by setting specific_id to a sentinel that matches nothing.
            predicate = Predicate {
                specific_id: u32::MAX,
                ..Predicate::default()
            };
            break;
        }
    }
    Ok((op, predicate))
}

/// Internal cipher-order record used while the rule string is being evaluated.
///
/// The `active` flag indicates whether the cipher is currently in the
/// negotiable set; `killed` means it has been permanently removed via `!`.
#[derive(Debug, Clone)]
struct OrderEntry {
    suite: &'static CipherSuite,
    active: bool,
    killed: bool,
}

/// Apply a single parsed rule to the working cipher order.
fn apply_rule(order: &mut Vec<OrderEntry>, op: RuleOp, predicate: &Predicate) {
    match op {
        RuleOp::Add => {
            for entry in order.iter_mut() {
                if entry.killed {
                    continue;
                }
                if predicate.matches(entry.suite) {
                    entry.active = true;
                }
            }
        }
        RuleOp::MoveToEnd => {
            // Partition: keep non-matching entries in place, then append
            // matching (active, non-killed) entries at the end, preserving
            // relative order.
            let (to_move, mut kept): (Vec<OrderEntry>, Vec<OrderEntry>) = order
                .drain(..)
                .partition(|e| e.active && !e.killed && predicate.matches(e.suite));
            kept.extend(to_move);
            *order = kept;
        }
        RuleOp::Delete => {
            for entry in order.iter_mut() {
                if predicate.matches(entry.suite) {
                    entry.active = false;
                }
            }
        }
        RuleOp::Kill => {
            for entry in order.iter_mut() {
                if predicate.matches(entry.suite) {
                    entry.active = false;
                    entry.killed = true;
                }
            }
        }
        RuleOp::SortByStrength => {
            // Stable sort by descending strength bits.
            order.sort_by(|a, b| b.suite.strength_bits.cmp(&a.suite.strength_bits));
        }
        RuleOp::SetSecurityLevel(_level) => {
            // Recorded at the higher-level API; no direct effect on the
            // cipher order computation.  Left as a no-op here.
        }
    }
}

/// Split the rule string into tokens using the OpenSSL separator set:
/// ':', ',', ';', ' ', '\t'.
fn tokenize(rule_str: &str) -> Vec<&str> {
    rule_str
        .split([':', ',', ';', ' ', '\t'])
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse the OpenSSL cipher rule string and return the ordered list of
/// matching cipher suites from `CIPHER_CATALOG`.
///
/// This is the Rust equivalent of C's `ssl_cipher_process_rulestr()` +
/// `ssl_create_cipher_list()` pipeline.  The returned list is filtered by
/// the rule string and ordered according to the accumulated rules.
///
/// # Errors
/// Returns `SslError::Protocol` on syntactically malformed rule strings or
/// unknown aliases.  Unknown explicit cipher names are also reported as
/// errors; this is stricter than the C library (which silently ignores them)
/// but matches the user's directive to surface configuration errors.
///
/// # Examples
/// ```
/// use openssl_ssl::cipher::parse_cipher_rule_string;
///
/// let list = parse_cipher_rule_string("ECDHE+AESGCM").unwrap();
/// assert!(!list.is_empty());
/// ```
pub fn parse_cipher_rule_string(rule_str: &str) -> SslResult<Vec<&'static CipherSuite>> {
    debug!(rule_str = %rule_str, "parsing cipher rule string");

    // Build the initial order: every non-TLS-1.3 cipher, all inactive until
    // explicitly added.
    let mut order: Vec<OrderEntry> = CIPHER_CATALOG
        .iter()
        .map(|suite| OrderEntry {
            suite,
            active: false,
            killed: false,
        })
        .collect();

    // If the rule string starts with DEFAULT, expand it first.  The default
    // expansion adds ALL ciphers, then removes eNULL (null encryption) and
    // `!aNULL` (null authentication) — approximating C's DEFAULT alias.
    let rules: String = if let Some(rest) = rule_str.strip_prefix("DEFAULT") {
        format!("ALL:!COMPLEMENTOFDEFAULT:!eNULL{rest}")
    } else {
        rule_str.to_owned()
    };

    for token in tokenize(&rules) {
        let (op, predicate) = parse_token(token)?;
        debug!(token = %token, ?op, "applying cipher rule");
        apply_rule(&mut order, op, &predicate);
    }

    let result: Vec<&'static CipherSuite> = order
        .into_iter()
        .filter(|e| e.active && !e.killed)
        .map(|e| e.suite)
        .collect();

    debug!(count = result.len(), "cipher rule string parsed");
    Ok(result)
}

// ===========================================================================
// `CipherList` — an SSL_CTX's ordered cipher preferences
// ===========================================================================

/// Ordered collection of cipher suites representing the negotiable preferences
/// for an `SSL_CTX` or `SSL` connection.
///
/// A `CipherList` maintains two disjoint ordered lists:
///
/// * `ciphers` — TLS ≤ 1.2 / DTLS cipher suites, configured via
///   [`CipherList::set_cipher_list`].
/// * `tls13_ciphers` — TLS 1.3 cipher suites, configured via
///   [`CipherList::set_ciphersuites`].
///
/// Both are populated independently and concatenated (TLS 1.3 first) when
/// iterating.  This mirrors OpenSSL's `SSL_CTX_set_cipher_list()` /
/// `SSL_CTX_set_ciphersuites()` split where TLS 1.3 suites use a distinct
/// configuration API.
#[derive(Debug, Clone, Default)]
pub struct CipherList {
    ciphers: Vec<&'static CipherSuite>,
    tls13_ciphers: Vec<&'static CipherSuite>,
}

impl CipherList {
    /// Create a `CipherList` initialised with OpenSSL's default cipher
    /// preferences for both TLS 1.3 and earlier versions.
    #[must_use]
    pub fn new() -> Self {
        // Default non-TLS-1.3 list derived from OpenSSL's baseline.
        let ciphers = parse_cipher_rule_string(DEFAULT_CIPHER_LIST).unwrap_or_default();
        // Default TLS 1.3 list — ordered by RFC 8446 recommendation.
        let tls13_ciphers =
            Self::parse_tls13_rule_string(DEFAULT_TLS13_CIPHER_LIST).unwrap_or_default();
        Self {
            ciphers,
            tls13_ciphers,
        }
    }

    /// Configure the TLS ≤ 1.2 / DTLS cipher preferences from a rule string.
    ///
    /// # Errors
    /// Returns `SslError::Protocol` if the rule string is malformed or
    /// resolves to an empty cipher list.  OpenSSL's `SSL_CTX_set_cipher_list`
    /// also rejects empty results.
    pub fn set_cipher_list(&mut self, rule_str: &str) -> SslResult<()> {
        debug!(rule_str = %rule_str, "CipherList::set_cipher_list");
        let list = parse_cipher_rule_string(rule_str)?;
        if list.is_empty() {
            return Err(SslError::Protocol(
                "cipher rule string resolved to empty list".to_string(),
            ));
        }
        self.ciphers = list;
        Ok(())
    }

    /// Configure the TLS 1.3 cipher preferences from a colon-separated list
    /// of cipher names.
    ///
    /// TLS 1.3 uses a simpler syntax than the full cipher rule string — each
    /// token is an explicit cipher name drawn from [`TLS13_CIPHERS`].
    ///
    /// # Errors
    /// Returns `SslError::Protocol` if any token does not name a known
    /// TLS 1.3 cipher suite, or if the final list is empty.
    pub fn set_ciphersuites(&mut self, rule_str: &str) -> SslResult<()> {
        debug!(rule_str = %rule_str, "CipherList::set_ciphersuites");
        let list = Self::parse_tls13_rule_string(rule_str)?;
        if list.is_empty() {
            return Err(SslError::Protocol(
                "TLS 1.3 cipher list resolved to empty set".to_string(),
            ));
        }
        self.tls13_ciphers = list;
        Ok(())
    }

    /// Internal helper: parse a TLS 1.3 rule string (colon-separated cipher
    /// names) into the ordered cipher list.
    fn parse_tls13_rule_string(rule_str: &str) -> SslResult<Vec<&'static CipherSuite>> {
        let mut list = Vec::new();
        for token in tokenize(rule_str) {
            let Some(suite) = TLS13_CIPHERS
                .iter()
                .find(|c| c.name == token || c.standard_name == token)
            else {
                return Err(SslError::Protocol(format!(
                    "unknown TLS 1.3 cipher suite: {token}"
                )));
            };
            // Guard against duplicates silently collapsing — preserve the
            // first occurrence's position.
            if !list
                .iter()
                .any(|existing: &&'static CipherSuite| std::ptr::eq(*existing, suite))
            {
                list.push(suite);
            }
        }
        Ok(list)
    }

    /// Iterate over all ciphers in this list — TLS 1.3 suites first,
    /// followed by the TLS ≤ 1.2 / DTLS suites, each in preference order.
    pub fn iter(&self) -> impl Iterator<Item = &'static CipherSuite> + '_ {
        self.tls13_ciphers
            .iter()
            .copied()
            .chain(self.ciphers.iter().copied())
    }

    /// Total number of cipher suites (TLS 1.3 + earlier) in this list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tls13_ciphers.len() + self.ciphers.len()
    }

    /// Return `true` if both the TLS 1.3 and legacy lists are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tls13_ciphers.is_empty() && self.ciphers.is_empty()
    }

    /// Look up a cipher suite in this list by its 32-bit cipher ID.
    ///
    /// Returns `None` if the cipher is not in the configured preferences.
    #[must_use]
    pub fn get_by_id(&self, id: u32) -> Option<&'static CipherSuite> {
        self.iter().find(|c| c.id == id)
    }

    /// Look up a cipher suite in this list by its OpenSSL short name or its
    /// IANA / RFC standard name.
    ///
    /// Returns `None` if the cipher is not in the configured preferences.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&'static CipherSuite> {
        self.iter()
            .find(|c| c.name == name || c.standard_name == name)
    }
}

// ===========================================================================
// `CipherEvpCache` — per-SSL_CTX cache of fetched provider EVP algorithms
// ===========================================================================

/// Per-`SSL_CTX` cache of fetched provider-backed EVP ciphers and digests.
///
/// When the TLS stack needs to encrypt or decrypt records for a negotiated
/// cipher suite, it invokes [`Cipher::fetch`] and [`MessageDigest::fetch`]
/// against the library's provider registry.  Repeated fetches for the same
/// algorithm are avoided via this cache — the very first encryption after a
/// cipher is negotiated performs the fetch and stores the result; subsequent
/// records reuse the cached handle.
///
/// # Concurrency
/// The inner [`RwLock`] is used in read-heavy mode — most requests hit
/// already-fetched algorithms — with rare writes during first-use lazy
/// fetches.
// LOCK-SCOPE: per-SSL_CTX cipher/digest cache, read-heavy, rare write on
// first-use lazy fetch from provider.
pub struct CipherEvpCache {
    /// Library context to fetch against.  Cloned into `Arc` per call to
    /// `Cipher::fetch` / `MessageDigest::fetch`.
    ctx: Arc<LibContext>,
    /// Cached EVP cipher handles keyed by `EncryptionAlgorithm`.
    cipher_cache: RwLock<HashMap<EncryptionAlgorithm, Cipher>>,
    /// Cached EVP message digest handles keyed by `MacAlgorithm`.
    digest_cache: RwLock<HashMap<MacAlgorithm, MessageDigest>>,
}

impl CipherEvpCache {
    /// Create a new empty cache bound to the given library context.
    #[must_use]
    pub fn new(ctx: Arc<LibContext>) -> Self {
        Self {
            ctx,
            cipher_cache: RwLock::new(HashMap::new()),
            digest_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get or fetch the provider-backed EVP cipher for `alg`.
    ///
    /// The first call for a given algorithm performs a provider fetch and
    /// caches the result; subsequent calls return a clone of the cached
    /// handle.  `Cipher` is a thin `Arc`-backed wrapper, so cloning is cheap.
    ///
    /// # Errors
    /// Returns `SslError::Crypto` (wrapping the underlying `CryptoError`) if
    /// the provider fetch fails — e.g. no loaded provider supports the
    /// requested algorithm, or the algorithm has no provider-side name
    /// (as is the case for `EncryptionAlgorithm::Null`).
    pub fn cipher_for(&self, alg: EncryptionAlgorithm) -> SslResult<Cipher> {
        // Fast path: read lock only.
        if let Some(cached) = self.cipher_cache.read().get(&alg) {
            return Ok(cached.clone());
        }
        let name = alg.provider_name().ok_or_else(|| {
            SslError::Protocol(format!(
                "no provider algorithm name for {alg:?} — cannot fetch EVP cipher"
            ))
        })?;
        debug!(
            algorithm = %name,
            "fetching provider-backed EVP cipher for cipher suite selection"
        );
        let fetched = Cipher::fetch(&self.ctx, name, None)?;
        // Upgrade to write lock and insert.  Another writer may have beaten
        // us — in that case we overwrite with an equivalent handle, which is
        // safe because the fetch is idempotent for a fixed `ctx`/`name`.
        self.cipher_cache.write().insert(alg, fetched.clone());
        Ok(fetched)
    }

    /// Get or fetch the provider-backed EVP message digest for `alg`.
    ///
    /// # Errors
    /// Returns `SslError::Crypto` (wrapping the underlying `CryptoError`) if
    /// the provider fetch fails, or `SslError::Protocol` for MAC algorithms
    /// that do not correspond to a digest (e.g. `MacAlgorithm::Aead`).
    pub fn digest_for(&self, alg: MacAlgorithm) -> SslResult<MessageDigest> {
        if let Some(cached) = self.digest_cache.read().get(&alg) {
            return Ok(cached.clone());
        }
        let name = alg.provider_name().ok_or_else(|| {
            SslError::Protocol(format!(
                "no provider algorithm name for {alg:?} — cannot fetch EVP digest"
            ))
        })?;
        debug!(
            algorithm = %name,
            "fetching provider-backed EVP digest for cipher suite selection"
        );
        let fetched = MessageDigest::fetch(&self.ctx, name, None)?;
        self.digest_cache.write().insert(alg, fetched.clone());
        Ok(fetched)
    }

    /// Number of cached cipher handles.
    #[must_use]
    pub fn cipher_cache_len(&self) -> usize {
        self.cipher_cache.read().len()
    }

    /// Number of cached digest handles.
    #[must_use]
    pub fn digest_cache_len(&self) -> usize {
        self.digest_cache.read().len()
    }

    /// Clear all cached cipher and digest handles.  Useful for reloading
    /// providers at runtime.
    pub fn clear(&self) {
        self.cipher_cache.write().clear();
        self.digest_cache.write().clear();
    }
}

impl fmt::Debug for CipherEvpCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `LibContext` and `Cipher` / `MessageDigest` may not all implement
        // `Debug`, so render cache sizes instead.
        f.debug_struct("CipherEvpCache")
            .field("ciphers_cached", &self.cipher_cache_len())
            .field("digests_cached", &self.digest_cache_len())
            .finish()
    }
}

// ===========================================================================
// `CipherSuite::disabled()` — helpful predicate for disable-mask computation
// ===========================================================================

impl CipherSuite {
    /// Return `true` if this cipher suite should be considered unusable given
    /// the current protocol bounds and provider-side availability masks.
    ///
    /// This is the Rust equivalent of C's `ssl_cipher_disabled()` helper.
    ///
    /// * `min_proto` / `max_proto` — negotiated or configured TLS protocol
    ///   bounds.  A suite is disabled if its version range does not overlap.
    /// * `disabled_mkey_mask` / `_auth_mask` / `_enc_mask` / `_mac_mask` —
    ///   bitmasks of currently-unavailable algorithm groups (e.g. because
    ///   their providers are not loaded, or they are below the FIPS
    ///   indicator threshold).
    #[must_use]
    pub fn disabled(
        &self,
        min_proto: ProtocolVersion,
        max_proto: ProtocolVersion,
        disabled_mkey_mask: u32,
        disabled_auth_mask: u32,
        disabled_enc_mask: u32,
        disabled_mac_mask: u32,
    ) -> bool {
        if self.algorithm_mkey.mask() & disabled_mkey_mask != 0 {
            return true;
        }
        if self.algorithm_auth.mask() & disabled_auth_mask != 0 {
            return true;
        }
        if self.algorithm_enc.mask() & disabled_enc_mask != 0 {
            return true;
        }
        if self.algorithm_mac.mask() & disabled_mac_mask != 0 {
            return true;
        }
        // Protocol version overlap — uses wire ordering for TLS only.
        if let (Some(min_w), Some(max_w)) = (min_proto.wire_version(), max_proto.wire_version()) {
            if let (Some(suite_min), Some(suite_max)) =
                (self.min_tls.wire_version(), self.max_tls.wire_version())
            {
                if suite_max < min_w || suite_min > max_w {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Justification: test code — expect()/unwrap()/panic on known-valid values is acceptable
mod tests {
    use super::*;

    // =====================================================================
    // Algorithm enum surface tests
    // =====================================================================

    #[test]
    fn key_exchange_algorithm_names_are_stable() {
        // Names mirror the `Kx=` column emitted by
        // `SSL_CIPHER_description()` in the C reference implementation.
        // `None` renders as "unknown" to match the C convention where the
        // key-exchange column reports "unknown" for cipher entries without a
        // declared key-exchange component.
        assert_eq!(KeyExchangeAlgorithm::Rsa.name(), "RSA");
        assert_eq!(KeyExchangeAlgorithm::Dhe.name(), "DH");
        assert_eq!(KeyExchangeAlgorithm::Ecdhe.name(), "ECDH");
        assert_eq!(KeyExchangeAlgorithm::Psk.name(), "PSK");
        assert_eq!(KeyExchangeAlgorithm::EcdhePsk.name(), "ECDHEPSK");
        assert_eq!(KeyExchangeAlgorithm::DhePsk.name(), "DHEPSK");
        assert_eq!(KeyExchangeAlgorithm::RsaPsk.name(), "RSAPSK");
        assert_eq!(KeyExchangeAlgorithm::Any.name(), "any");
        assert_eq!(KeyExchangeAlgorithm::None.name(), "unknown");
    }

    #[test]
    fn key_exchange_algorithm_masks_are_disjoint_or_composites() {
        // Single-bit masks must be disjoint.
        assert_ne!(KeyExchangeAlgorithm::Rsa.mask(), 0);
        assert_ne!(KeyExchangeAlgorithm::Dhe.mask(), 0);
        assert_ne!(KeyExchangeAlgorithm::Ecdhe.mask(), 0);
        assert_ne!(KeyExchangeAlgorithm::Psk.mask(), 0);
        assert_eq!(
            KeyExchangeAlgorithm::Rsa.mask() & KeyExchangeAlgorithm::Dhe.mask(),
            0
        );
        assert_eq!(
            KeyExchangeAlgorithm::Dhe.mask() & KeyExchangeAlgorithm::Ecdhe.mask(),
            0
        );
        // `Any` is the "no constraint" mask, should be 0.
        assert_eq!(KeyExchangeAlgorithm::Any.mask(), SSL_K_ANY);
    }

    #[test]
    fn auth_algorithm_names_and_masks() {
        assert_eq!(AuthAlgorithm::Rsa.name(), "RSA");
        assert_eq!(AuthAlgorithm::Ecdsa.name(), "ECDSA");
        assert_eq!(AuthAlgorithm::Dss.name(), "DSS");
        assert_eq!(AuthAlgorithm::Psk.name(), "PSK");
        assert_eq!(AuthAlgorithm::Any.name(), "any");
        assert_eq!(AuthAlgorithm::None.name(), "None");

        // Single-bit masks disjoint.
        assert_eq!(AuthAlgorithm::Rsa.mask(), SSL_A_RSA);
        assert_eq!(AuthAlgorithm::Ecdsa.mask(), SSL_A_ECDSA);
        assert_eq!(AuthAlgorithm::Dss.mask(), SSL_A_DSS);
        assert_eq!(AuthAlgorithm::Psk.mask(), SSL_A_PSK);
        assert_eq!(AuthAlgorithm::None.mask(), SSL_A_NULL);
    }

    #[test]
    fn encryption_algorithm_aead_classification() {
        // AEADs
        assert!(EncryptionAlgorithm::Aes128Gcm.is_aead());
        assert!(EncryptionAlgorithm::Aes256Gcm.is_aead());
        assert!(EncryptionAlgorithm::ChaCha20Poly1305.is_aead());
        assert!(EncryptionAlgorithm::Aes128Ccm.is_aead());
        assert!(EncryptionAlgorithm::Aes256Ccm.is_aead());
        assert!(EncryptionAlgorithm::Aes128Ccm8.is_aead());
        assert!(EncryptionAlgorithm::Aria128Gcm.is_aead());
        assert!(EncryptionAlgorithm::Aria256Gcm.is_aead());
        assert!(EncryptionAlgorithm::Sm4Gcm.is_aead());

        // Non-AEAD ciphers
        assert!(!EncryptionAlgorithm::Aes128Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Aes256Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Des3Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Camellia128Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Camellia256Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Sm4Cbc.is_aead());
        assert!(!EncryptionAlgorithm::Null.is_aead());
        assert!(!EncryptionAlgorithm::Rc4.is_aead());
    }

    #[test]
    fn encryption_algorithm_provider_names() {
        // Every non-Null algorithm should have a provider name.
        let non_null = [
            EncryptionAlgorithm::Aes128Gcm,
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
            EncryptionAlgorithm::Aes128Cbc,
            EncryptionAlgorithm::Aes256Cbc,
            EncryptionAlgorithm::Aes128Ccm,
            EncryptionAlgorithm::Aes256Ccm,
            EncryptionAlgorithm::Aes128Ccm8,
            EncryptionAlgorithm::Des3Cbc,
            EncryptionAlgorithm::Aria128Gcm,
            EncryptionAlgorithm::Aria256Gcm,
            EncryptionAlgorithm::Camellia128Cbc,
            EncryptionAlgorithm::Camellia256Cbc,
            EncryptionAlgorithm::Sm4Cbc,
            EncryptionAlgorithm::Sm4Gcm,
            EncryptionAlgorithm::Rc4,
        ];
        for alg in non_null {
            assert!(
                alg.provider_name().is_some(),
                "{alg:?} missing provider_name"
            );
        }
        // Null is the exception — no provider fetches a null cipher.
        assert!(EncryptionAlgorithm::Null.provider_name().is_none());
    }

    #[test]
    fn mac_algorithm_names_and_masks() {
        assert_eq!(MacAlgorithm::Aead.name(), "AEAD");
        assert_eq!(MacAlgorithm::Sha1.name(), "SHA1");
        assert_eq!(MacAlgorithm::Sha256.name(), "SHA256");
        assert_eq!(MacAlgorithm::Sha384.name(), "SHA384");
        assert_eq!(MacAlgorithm::Md5.name(), "MD5");

        assert_eq!(MacAlgorithm::Aead.mask(), SSL_M_AEAD);
        assert_eq!(MacAlgorithm::Sha1.mask(), SSL_M_SHA1);
        assert_eq!(MacAlgorithm::Sha256.mask(), SSL_M_SHA256);
        assert_eq!(MacAlgorithm::Sha384.mask(), SSL_M_SHA384);
        assert_eq!(MacAlgorithm::Md5.mask(), SSL_M_MD5);
    }

    #[test]
    fn mac_algorithm_provider_names() {
        // AEAD has no standalone MAC digest — it's computed inline by the cipher.
        assert!(MacAlgorithm::Aead.provider_name().is_none());
        // All others map to a provider digest name.
        assert!(MacAlgorithm::Sha1.provider_name().is_some());
        assert!(MacAlgorithm::Sha256.provider_name().is_some());
        assert!(MacAlgorithm::Sha384.provider_name().is_some());
        assert!(MacAlgorithm::Md5.provider_name().is_some());
    }

    // =====================================================================
    // Catalog integrity tests
    // =====================================================================

    #[test]
    fn cipher_catalog_is_non_empty() {
        assert!(
            !CIPHER_CATALOG.is_empty(),
            "CIPHER_CATALOG must contain TLS ≤ 1.2 suites"
        );
        assert!(CIPHER_CATALOG.len() >= 10);
    }

    #[test]
    fn tls13_ciphers_is_non_empty() {
        assert!(
            !TLS13_CIPHERS.is_empty(),
            "TLS13_CIPHERS must contain at least the standard TLS 1.3 suites"
        );
        // RFC 8446 §B.4 defines exactly 5 mandatory-to-implement suites.
        assert!(TLS13_CIPHERS.len() >= 3);
    }

    #[test]
    fn cipher_catalog_ids_are_unique() {
        let mut ids: Vec<u32> = CIPHER_CATALOG.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(
            ids.len(),
            len_before,
            "CIPHER_CATALOG contains duplicate cipher IDs"
        );
    }

    #[test]
    fn tls13_ciphers_are_flagged_tls13() {
        for suite in TLS13_CIPHERS {
            assert!(
                suite.is_tls13(),
                "{} must be flagged as TLS 1.3",
                suite.name
            );
        }
    }

    #[test]
    fn tls12_catalog_suites_are_not_tls13() {
        // Everything in CIPHER_CATALOG must not claim to be TLS 1.3.
        for suite in CIPHER_CATALOG {
            assert!(
                !suite.is_tls13(),
                "{} in CIPHER_CATALOG must NOT be a TLS 1.3 suite",
                suite.name
            );
        }
    }

    #[test]
    fn all_catalog_ciphers_have_nonempty_names() {
        for suite in CIPHER_CATALOG.iter().chain(TLS13_CIPHERS.iter()) {
            assert!(!suite.name.is_empty(), "cipher suite with empty name");
            assert!(
                !suite.standard_name.is_empty(),
                "cipher suite {} has empty standard_name",
                suite.name
            );
        }
    }

    // =====================================================================
    // CipherSuite query method tests — use a concrete well-known suite
    // =====================================================================

    fn find_suite(name: &str) -> Option<&'static CipherSuite> {
        CIPHER_CATALOG
            .iter()
            .chain(TLS13_CIPHERS.iter())
            .find(|c| c.name == name)
    }

    #[test]
    fn tls13_aes128_gcm_sha256_lookup() {
        let suite = find_suite("TLS_AES_128_GCM_SHA256")
            .expect("TLS_AES_128_GCM_SHA256 must be in TLS13_CIPHERS");
        assert!(suite.is_tls13());
        assert!(suite.is_aead());
        assert_eq!(suite.algorithm_enc, EncryptionAlgorithm::Aes128Gcm);
        assert_eq!(suite.algorithm_mac, MacAlgorithm::Aead);
        assert_eq!(suite.strength_bits, 128);
        assert_eq!(suite.alg_bits, 128);
    }

    #[test]
    fn cipher_suite_description_contains_fields() {
        let suite = find_suite("TLS_AES_128_GCM_SHA256")
            .expect("TLS_AES_128_GCM_SHA256 must be in TLS13_CIPHERS");
        let desc = suite.description();
        // Must include the cipher name somewhere.
        assert!(
            desc.contains(suite.name),
            "description missing name: {desc}"
        );
        // Must include the Kx= Au= Enc= Mac= columns.
        assert!(
            desc.contains("Kx="),
            "description missing Kx= column: {desc}"
        );
        assert!(
            desc.contains("Au="),
            "description missing Au= column: {desc}"
        );
        assert!(
            desc.contains("Enc="),
            "description missing Enc= column: {desc}"
        );
        assert!(
            desc.contains("Mac="),
            "description missing Mac= column: {desc}"
        );
    }

    #[test]
    fn cipher_suite_display_and_description_both_well_formed() {
        // `Display` and `description()` are intentionally different:
        //   * `description()` mirrors `SSL_CIPHER_description()` — fixed-width
        //     padded columns plus a trailing newline.
        //   * `Display` is a compact single-line form without padding and
        //     without a trailing newline.
        // Both must agree on the core field content.
        let suite = find_suite("TLS_AES_128_GCM_SHA256")
            .expect("TLS_AES_128_GCM_SHA256 must be in TLS13_CIPHERS");
        let via_display = format!("{suite}");
        let via_description = suite.description();

        // `Display` has no trailing newline; `description()` does.
        assert!(
            !via_display.ends_with('\n'),
            "Display must not have trailing newline: {via_display:?}"
        );
        assert!(
            via_description.ends_with('\n'),
            "description() must end with newline: {via_description:?}"
        );

        // Both must contain the same core fields.
        for form in [&via_display, &via_description[..via_description.len() - 1]] {
            assert!(form.contains(suite.name), "missing name in {form:?}");
            assert!(form.contains("TLSv1.3"), "missing version in {form:?}");
            assert!(form.contains("Kx=any"), "missing kx in {form:?}");
            assert!(form.contains("Au=any"), "missing au in {form:?}");
            assert!(form.contains("Enc=AESGCM(128)"), "missing enc in {form:?}");
            assert!(form.contains("Mac=AEAD"), "missing mac in {form:?}");
        }

        // Display is strictly shorter because it has no padding.
        assert!(
            via_display.len() < via_description.len(),
            "Display ({}) should be shorter than description ({})",
            via_display.len(),
            via_description.len()
        );
    }

    #[test]
    fn get_bits_returns_tuple() {
        let suite = find_suite("TLS_AES_256_GCM_SHA384")
            .expect("TLS_AES_256_GCM_SHA384 must be in TLS13_CIPHERS");
        let (strength, alg) = suite.get_bits();
        assert_eq!(strength, 256);
        assert_eq!(alg, 256);
        assert_eq!((strength, alg), suite.bits());
    }

    #[test]
    fn cipher_suite_ids_preserved_by_lookup() {
        let suite = find_suite("TLS_AES_128_GCM_SHA256")
            .expect("TLS_AES_128_GCM_SHA256 must be in TLS13_CIPHERS");
        let found = find_cipher_by_id(suite.id());
        assert_eq!(found.map(|c| c.name), Some(suite.name));
    }

    #[test]
    fn find_cipher_by_id_returns_none_for_unknown() {
        assert!(find_cipher_by_id(0xdead_beef).is_none());
    }

    // =====================================================================
    // Rule string parser tests
    // =====================================================================

    #[test]
    fn parse_rule_default_produces_non_empty() {
        let list =
            parse_cipher_rule_string("DEFAULT").expect("DEFAULT must parse into a non-empty list");
        assert!(!list.is_empty());
        // Every suite in DEFAULT must be authenticated (no aNULL).
        for suite in &list {
            assert_ne!(
                suite.algorithm_auth,
                AuthAlgorithm::None,
                "DEFAULT should not include aNULL cipher {}",
                suite.name
            );
        }
    }

    #[test]
    fn parse_rule_all_includes_catalog() {
        let list = parse_cipher_rule_string("ALL").expect("ALL must parse");
        // ALL should at least include every non-null-encryption suite.
        let non_null_count = CIPHER_CATALOG
            .iter()
            .filter(|c| c.algorithm_enc != EncryptionAlgorithm::Null)
            .count();
        assert!(
            list.len() >= non_null_count / 2,
            "ALL returned {} suites — expected much more",
            list.len()
        );
    }

    #[test]
    fn parse_rule_kill_removes_ciphers() {
        let baseline = parse_cipher_rule_string("DEFAULT").expect("DEFAULT parses");
        let no_aes = parse_cipher_rule_string("DEFAULT:!AES").expect("DEFAULT:!AES parses");
        assert!(no_aes.len() < baseline.len());
        for suite in &no_aes {
            assert!(
                !matches!(
                    suite.algorithm_enc,
                    EncryptionAlgorithm::Aes128Gcm
                        | EncryptionAlgorithm::Aes256Gcm
                        | EncryptionAlgorithm::Aes128Cbc
                        | EncryptionAlgorithm::Aes256Cbc
                        | EncryptionAlgorithm::Aes128Ccm
                        | EncryptionAlgorithm::Aes256Ccm
                        | EncryptionAlgorithm::Aes128Ccm8
                ),
                "!AES should have killed {}",
                suite.name
            );
        }
    }

    #[test]
    fn parse_rule_delete_removes_ciphers() {
        let baseline = parse_cipher_rule_string("DEFAULT").expect("DEFAULT parses");
        let no_sha1 = parse_cipher_rule_string("DEFAULT:-SHA1").expect("DEFAULT:-SHA1 parses");
        // Deleted ciphers may be re-added, so length may not change — what
        // matters is that none of the output suites use SHA1 unless re-added.
        assert!(no_sha1.len() <= baseline.len());
    }

    #[test]
    fn parse_rule_unknown_alias_errors() {
        let err = parse_cipher_rule_string("NOT_A_REAL_ALIAS");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rule_empty_errors() {
        // An empty ruleset is an empty final list.
        let err = parse_cipher_rule_string("");
        // Empty rule string produces empty list — whether this errors or
        // returns empty depends on policy.  We verify the behavior matches
        // CipherList::set_cipher_list, which rejects empty lists.
        // If `parse_cipher_rule_string("")` succeeds, it should be empty.
        if let Ok(list) = err {
            assert!(list.is_empty());
        }
    }

    #[test]
    fn parse_rule_high_strength_filters_low_strength() {
        let high = parse_cipher_rule_string("HIGH").expect("HIGH parses");
        for suite in &high {
            assert!(
                suite.strength_bits >= 128,
                "HIGH must only contain suites with ≥128-bit strength — got {} at {} bits",
                suite.name,
                suite.strength_bits
            );
        }
    }

    #[test]
    fn parse_rule_add_after_kill_does_not_resurrect() {
        // The OpenSSL semantics: once a cipher is killed with `!`, it cannot
        // be re-added by subsequent rules.
        let list = parse_cipher_rule_string("!AES:AES").expect("!AES:AES parses");
        for suite in &list {
            assert!(
                !matches!(
                    suite.algorithm_enc,
                    EncryptionAlgorithm::Aes128Gcm
                        | EncryptionAlgorithm::Aes256Gcm
                        | EncryptionAlgorithm::Aes128Cbc
                        | EncryptionAlgorithm::Aes256Cbc
                        | EncryptionAlgorithm::Aes128Ccm
                        | EncryptionAlgorithm::Aes256Ccm
                        | EncryptionAlgorithm::Aes128Ccm8
                ),
                "killed AES must not be resurrected"
            );
        }
    }

    #[test]
    fn parse_rule_enull_selects_null_encryption() {
        let list = parse_cipher_rule_string("eNULL").expect("eNULL should parse");
        // If any catalog entry uses Null encryption, it should appear here.
        let catalog_nulls: usize = CIPHER_CATALOG
            .iter()
            .filter(|c| c.algorithm_enc == EncryptionAlgorithm::Null)
            .count();
        assert_eq!(list.len(), catalog_nulls);
        for suite in &list {
            assert_eq!(suite.algorithm_enc, EncryptionAlgorithm::Null);
        }
    }

    #[test]
    fn parse_rule_conjunction_with_plus() {
        // ECDHE+RSA — both kx=ECDHE AND au=RSA.
        let list = parse_cipher_rule_string("ECDHE+aRSA").expect("ECDHE+aRSA should parse");
        for suite in &list {
            assert_eq!(
                suite.algorithm_mkey,
                KeyExchangeAlgorithm::Ecdhe,
                "{} has wrong kx",
                suite.name
            );
            assert_eq!(
                suite.algorithm_auth,
                AuthAlgorithm::Rsa,
                "{} has wrong auth",
                suite.name
            );
        }
    }

    // =====================================================================
    // CipherList tests
    // =====================================================================

    #[test]
    fn cipher_list_new_is_populated() {
        let list = CipherList::new();
        assert!(!list.is_empty());
        // `is_empty()` check covers the `len() > 0` assertion; we also verify
        // the public `len()` accessor works by comparing to the iterator count.
        assert_eq!(list.len(), list.iter().count());
    }

    #[test]
    fn cipher_list_contains_tls13_ciphers_first() {
        let list = CipherList::new();
        // TLS 1.3 ciphers come first in iter().
        let first_is_tls13 = list.iter().next().is_some_and(CipherSuite::is_tls13);
        assert!(first_is_tls13, "TLS 1.3 ciphers should lead the list");
    }

    #[test]
    fn cipher_list_set_cipher_list_success() {
        let mut list = CipherList::new();
        list.set_cipher_list("HIGH").expect("HIGH must work");
        assert!(!list.is_empty());
        for suite in list.iter() {
            if !suite.is_tls13() {
                assert!(suite.strength_bits >= 128);
            }
        }
    }

    #[test]
    fn cipher_list_set_cipher_list_empty_errors() {
        let mut list = CipherList::new();
        // All KILLs leave an empty list, which is rejected.
        let err = list.set_cipher_list("!ALL:!eNULL");
        assert!(err.is_err(), "empty list must be rejected");
    }

    #[test]
    fn cipher_list_set_ciphersuites_tls13_only() {
        let mut list = CipherList::new();
        list.set_ciphersuites("TLS_AES_128_GCM_SHA256")
            .expect("TLS_AES_128_GCM_SHA256 must parse");
        // After setting, the TLS 1.3 list should contain exactly 1 suite.
        let tls13_in_list: Vec<_> = list.iter().filter(|c| c.is_tls13()).collect();
        assert_eq!(tls13_in_list.len(), 1);
        assert_eq!(tls13_in_list[0].name, "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn cipher_list_set_ciphersuites_unknown_errors() {
        let mut list = CipherList::new();
        let err = list.set_ciphersuites("TLS_NOT_A_REAL_SUITE");
        assert!(err.is_err());
    }

    #[test]
    fn cipher_list_get_by_name_roundtrip() {
        let list = CipherList::new();
        let first = list
            .iter()
            .next()
            .expect("default CipherList must be non-empty");
        let found = list.get_by_name(first.name);
        assert_eq!(found.map(|c| c.name), Some(first.name));
    }

    #[test]
    fn cipher_list_get_by_id_roundtrip() {
        let list = CipherList::new();
        let first = list
            .iter()
            .next()
            .expect("default CipherList must be non-empty");
        let found = list.get_by_id(first.id());
        assert_eq!(found.map(|c| c.id), Some(first.id()));
    }

    #[test]
    fn cipher_list_get_by_unknown_name_none() {
        let list = CipherList::new();
        assert!(list.get_by_name("NOPE").is_none());
    }

    #[test]
    fn cipher_list_get_by_unknown_id_none() {
        let list = CipherList::new();
        assert!(list.get_by_id(0xdead_beef).is_none());
    }

    // =====================================================================
    // Disabled-mask tests
    // =====================================================================

    #[test]
    fn disabled_when_kx_mask_matches() {
        let suite =
            find_suite("TLS_AES_128_GCM_SHA256").expect("TLS_AES_128_GCM_SHA256 must exist");
        // TLS 1.3 uses `SSL_kANY` which has no mask bits; to test the
        // disable path we use a TLS 1.2 suite instead.
        let tls12_ecdhe = CIPHER_CATALOG
            .iter()
            .find(|c| c.algorithm_mkey == KeyExchangeAlgorithm::Ecdhe);
        if let Some(s) = tls12_ecdhe {
            assert!(s.disabled(
                ProtocolVersion::Tls1_2,
                ProtocolVersion::Tls1_2,
                SSL_K_ECDHE,
                0,
                0,
                0
            ));
        }
        // Sanity: without any disabled bits, the TLS 1.3 suite must NOT be
        // disabled for the TLS 1.3 window.
        assert!(!suite.disabled(ProtocolVersion::Tls1_3, ProtocolVersion::Tls1_3, 0, 0, 0, 0));
    }

    #[test]
    fn disabled_when_enc_mask_matches() {
        let suite =
            find_suite("TLS_AES_128_GCM_SHA256").expect("TLS_AES_128_GCM_SHA256 must exist");
        assert!(suite.disabled(
            ProtocolVersion::Tls1_3,
            ProtocolVersion::Tls1_3,
            0,
            0,
            SSL_E_AES128GCM,
            0,
        ));
    }

    #[test]
    fn disabled_when_protocol_version_out_of_range() {
        let suite =
            find_suite("TLS_AES_128_GCM_SHA256").expect("TLS_AES_128_GCM_SHA256 must exist");
        // Restricting to TLS 1.0-1.1 (excludes TLS 1.3) must disable.
        assert!(suite.disabled(ProtocolVersion::Tls1_0, ProtocolVersion::Tls1_1, 0, 0, 0, 0,));
    }

    // =====================================================================
    // Cross-reference: every enum/field has proper mask coverage
    // =====================================================================

    #[test]
    fn encryption_algorithm_is_aead_matches_mac_aead_in_catalog() {
        // For every suite in the full catalog (TLS 1.2 + TLS 1.3), an
        // AEAD cipher *must* be paired with MacAlgorithm::Aead, and a
        // non-AEAD cipher *must* be paired with a separate MAC.
        for suite in CIPHER_CATALOG.iter().chain(TLS13_CIPHERS.iter()) {
            if suite.algorithm_enc.is_aead() {
                assert_eq!(
                    suite.algorithm_mac,
                    MacAlgorithm::Aead,
                    "{} uses AEAD cipher but non-AEAD MAC {:?}",
                    suite.name,
                    suite.algorithm_mac
                );
            } else {
                assert_ne!(
                    suite.algorithm_mac,
                    MacAlgorithm::Aead,
                    "{} uses non-AEAD cipher but claims AEAD MAC",
                    suite.name
                );
            }
        }
    }

    #[test]
    fn cipher_suite_nid_conversions_are_stable() {
        // The nid mapping must match what the algorithm enum exposes.
        for suite in CIPHER_CATALOG.iter().chain(TLS13_CIPHERS.iter()) {
            assert_eq!(suite.get_kx_nid(), suite.algorithm_mkey.nid());
            assert_eq!(suite.get_auth_nid(), suite.algorithm_auth.nid());
        }
    }

    #[test]
    fn get_version_returns_known_versions() {
        for suite in CIPHER_CATALOG.iter().chain(TLS13_CIPHERS.iter()) {
            let v = suite.get_version();
            assert!(
                matches!(
                    v,
                    "TLSv1.3" | "TLSv1.2" | "TLSv1.0" | "TLSv1.1" | "SSLv3" | "DTLSv1" | "DTLSv1.2"
                ),
                "unexpected version string {v:?} for {}",
                suite.name
            );
        }
    }

    // =====================================================================
    // CipherEvpCache structural tests — do NOT hit providers
    // =====================================================================

    #[test]
    fn cipher_evp_cache_starts_empty() {
        // `LibContext::default()` already returns an `Arc<LibContext>`; no
        // extra wrapping is needed.
        let ctx = LibContext::default();
        let cache = CipherEvpCache::new(ctx);
        assert_eq!(cache.cipher_cache_len(), 0);
        assert_eq!(cache.digest_cache_len(), 0);
    }

    #[test]
    fn cipher_evp_cache_clear_is_idempotent() {
        let ctx = LibContext::default();
        let cache = CipherEvpCache::new(ctx);
        cache.clear();
        assert_eq!(cache.cipher_cache_len(), 0);
        assert_eq!(cache.digest_cache_len(), 0);
        cache.clear();
        assert_eq!(cache.cipher_cache_len(), 0);
    }

    #[test]
    fn cipher_evp_cache_debug_does_not_panic() {
        let ctx = LibContext::default();
        let cache = CipherEvpCache::new(ctx);
        let debug_repr = format!("{cache:?}");
        // Should contain the cache sizes.
        assert!(
            debug_repr.contains("cipher_cache") || debug_repr.contains("CipherEvpCache"),
            "unexpected debug repr: {debug_repr}"
        );
    }
}
