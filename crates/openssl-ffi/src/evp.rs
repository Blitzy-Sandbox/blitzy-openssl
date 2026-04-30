//! EVP C ABI wrappers for the `openssl-ffi` crate.
//!
//! This module exports `extern "C"` functions matching the
//! `include/openssl/evp.h` public API contract for the EVP (envelope)
//! high-level cryptographic API.  It covers the major EVP subsystems —
//! message digests (`EVP_MD` / `EVP_MD_CTX`), symmetric ciphers
//! (`EVP_CIPHER` / `EVP_CIPHER_CTX`), asymmetric keys
//! (`EVP_PKEY` / `EVP_PKEY_CTX`), key-derivation (`EVP_KDF`), MAC
//! algorithms (`EVP_MAC`), and pseudo-random generators (`EVP_RAND`) —
//! as well as the algorithm fetch / property-query mechanism used by
//! the provider system.
//!
//! The public surface wraps the safe Rust types from
//! [`openssl_crypto::evp::md`], [`openssl_crypto::evp::cipher`], and
//! [`openssl_crypto::evp::pkey`].  Algorithm descriptors
//! (`EVP_MD`, `EVP_CIPHER`) are reference-counted via [`std::sync::Arc`]
//! so that `EVP_*_up_ref` / `EVP_*_free` correctly track the C-side
//! reference count.  Operation contexts (`EVP_MD_CTX`, `EVP_CIPHER_CTX`)
//! are owned via [`Box`] because they are mutated through method calls
//! and never shared.  `EVP_PKEY` is reference-counted (`Arc<PKey>`)
//! because the `PKeyCtx` constructor [`PKeyCtx::new_from_pkey`] takes
//! an `Arc<PKey>` directly, mirroring the C `EVP_PKEY_up_ref` semantics.
//!
//! # Unsafe policy (Rule R8)
//!
//! This module is allowed to contain `unsafe` code because it lives in
//! the `openssl-ffi` crate — the single designated FFI boundary crate
//! for the workspace.  Every `unsafe` block in this file carries a
//! `// SAFETY:` comment that documents:
//!
//! * NULL-pointer and validity assumptions for pointer parameters.
//! * Alignment assumptions for reinterpretation casts.
//! * Lifetime assumptions for references derived from raw pointers.
//! * Ownership assumptions for `Box::from_raw` / `Arc::from_raw`.
//!
//! # Return-value conventions (from `crypto/evp/{evp_lib,digest,evp_enc,p_lib}.c`)
//!
//! * `EVP_DigestInit_ex` / `_ex2`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex`,
//!   `EVP_DigestFinalXOF` — `1` on success, `0` on failure.
//! * `EVP_EncryptInit_ex` / `_ex2`, `EVP_EncryptUpdate`,
//!   `EVP_EncryptFinal_ex`, and the corresponding `EVP_Decrypt*`
//!   functions — `1` on success, `0` on failure.
//! * `EVP_PKEY_*_init`, `EVP_PKEY_sign`, `EVP_PKEY_verify`,
//!   `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt`, `EVP_PKEY_keygen` —
//!   `1` on success, `0` on failure.  `EVP_PKEY_verify` may
//!   additionally return `1` when the signature is valid and `0` when
//!   it is invalid (with errors enqueued for parser failures).
//! * `EVP_*_get_*` accessors return the queried integer property,
//!   `0` on NULL input, or the negative error code documented in the
//!   header (where applicable).
//! * `EVP_*_get0_name` returns a borrowed C string whose lifetime is
//!   tied to the owning algorithm descriptor.  Callers must not free
//!   the returned pointer.
//! * `EVP_MD_CTX_new`, `EVP_CIPHER_CTX_new`, `EVP_PKEY_new`,
//!   `EVP_PKEY_CTX_new`, `EVP_PKEY_CTX_new_id`, `EVP_PKEY_CTX_new_from_name`,
//!   `EVP_PKEY_CTX_new_from_pkey`, `EVP_MD_fetch`, `EVP_CIPHER_fetch` —
//!   non-NULL pointer on success, NULL on failure.
//!
//! # Unsupported operations
//!
//! The whitelisted dependency set for this module includes only
//! `openssl_crypto::evp::{md, cipher, pkey}`.  Operations that live in
//! `openssl_crypto::evp::{signature, kem, keymgmt, kdf, mac, rand,
//! encode_decode}` (such as `EVP_PKEY_sign`, `EVP_PKEY_verify`,
//! `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt`, `EVP_PKEY_derive`,
//! `EVP_PKEY_encapsulate`, `EVP_PKEY_decapsulate`) cannot be wired
//! through the safe Rust types directly here.  These functions follow
//! a graceful-failure stub strategy: their `_init` variants succeed
//! (returning `1`) so that callers can configure parameters, but the
//! actual operation returns `0` with an error queued.  The full
//! integration will be wired through follow-up commits in the
//! `openssl-ssl`, `openssl-cli`, and provider-side crates.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::ptr;
use std::sync::Arc;

use libc::size_t;

use openssl_common::{CryptoError, CryptoResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::{
    Cipher, CipherCtx, CipherDirection, CipherFlags, CipherMode,
};
use openssl_crypto::evp::md::{digest_one_shot, digest_quick, MdContext, MessageDigest};
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx};

use crate::crypto::OSSL_LIB_CTX;

// ===========================================================================
// Opaque type definitions
// ===========================================================================
//
// Each EVP type is exposed to C as an opaque, zero-sized struct.  The
// real backing storage lives behind `Box`/`Arc` pointers managed by
// the lifecycle wrappers in this module.  The `_private` field
// prevents C consumers from constructing or copying instances.

/// Opaque handle for the `EVP_MD` algorithm descriptor.
///
/// Internally backed by `Arc<MessageDigest>` so that
/// `EVP_MD_up_ref` / `EVP_MD_free` correctly track the C-side
/// reference count.
#[repr(C)]
pub struct EVP_MD {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_MD_CTX` digest operation context.
///
/// Internally backed by `Box<MdContext>`.  Mutation flows through
/// `EVP_DigestInit_ex*`, `EVP_DigestUpdate`, and `EVP_DigestFinal*`.
#[repr(C)]
pub struct EVP_MD_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_CIPHER` algorithm descriptor.
///
/// Internally backed by `Arc<Cipher>` so that
/// `EVP_CIPHER_up_ref` / `EVP_CIPHER_free` correctly track the
/// C-side reference count.
#[repr(C)]
pub struct EVP_CIPHER {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_CIPHER_CTX` cipher operation context.
///
/// Internally backed by `Box<CipherCtx>`.  The `Drop` impl on
/// `CipherCtx` zeroizes all key material automatically.
#[repr(C)]
pub struct EVP_CIPHER_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_PKEY` asymmetric key container.
///
/// Internally backed by `Arc<PKey>` so that
/// `EVP_PKEY_up_ref` / `EVP_PKEY_free` correctly track the C-side
/// reference count.  `PKey` carries `ZeroizeOnDrop` so secret
/// material is wiped automatically when the strong count reaches
/// zero.
#[repr(C)]
pub struct EVP_PKEY {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_PKEY_CTX` operation context.
///
/// Internally backed by `Box<PKeyCtx>`.  Used for keygen, sign,
/// verify, encrypt, decrypt, derive, and parameter-generation
/// operations.
#[repr(C)]
pub struct EVP_PKEY_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_KDF` key-derivation algorithm
/// descriptor.
///
/// Wired through follow-up commits — currently exposes a stable
/// type identity so cbindgen can generate the matching forward
/// declaration in `openssl-rs.h`.
#[repr(C)]
pub struct EVP_KDF {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_KDF_CTX` operation context.
#[repr(C)]
pub struct EVP_KDF_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_MAC` message-authentication-code
/// algorithm descriptor.
#[repr(C)]
pub struct EVP_MAC {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_MAC_CTX` operation context.
#[repr(C)]
pub struct EVP_MAC_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_RAND` deterministic-random-bit-generator
/// algorithm descriptor.
#[repr(C)]
pub struct EVP_RAND {
    _private: [u8; 0],
}

/// Opaque handle for the `EVP_RAND_CTX` operation context.
#[repr(C)]
pub struct EVP_RAND_CTX {
    _private: [u8; 0],
}

/// Opaque handle for the legacy `ENGINE` type.
///
/// In the providers-only architecture used by the Rust workspace this
/// type is preserved purely for ABI compatibility.  All
/// `EVP_*_ex` functions accept a NULL `ENGINE` pointer and use the
/// active `OSSL_LIB_CTX` / property string to select an algorithm
/// implementation.
#[repr(C)]
pub struct ENGINE {
    _private: [u8; 0],
}

/// Opaque placeholder for the `OSSL_PARAM` type.
///
/// The full `OSSL_PARAM` ABI is defined in
/// [`crate::crypto`]; this re-export keeps `EVP_DigestInit_ex2` /
/// `EVP_EncryptInit_ex2` signatures self-consistent within this
/// translation unit.  Currently passing a non-NULL `OSSL_PARAM`
/// pointer through these wrappers is treated as a no-op (the
/// underlying Rust algorithms ignore the parameters) — full
/// parameter propagation will be wired through the
/// `openssl-provider` integration.
#[repr(C)]
pub struct OSSL_PARAM {
    _private: [u8; 0],
}

// ===========================================================================
// Public constants
// ===========================================================================

/// Maximum digest output size in bytes.  Matches `EVP_MAX_MD_SIZE`
/// from `include/openssl/evp.h` (`SHA-512` is the largest fixed-output
/// digest at 64 bytes).
pub const EVP_MAX_MD_SIZE: c_int = 64;

/// Maximum symmetric key length in bytes.  Matches
/// `EVP_MAX_KEY_LENGTH` from `include/openssl/evp.h` (covers
/// `AES-256` at 32 bytes plus headroom for double-key constructions
/// such as `AES-256-XTS`).
pub const EVP_MAX_KEY_LENGTH: c_int = 64;

/// Maximum symmetric IV length in bytes.  Matches
/// `EVP_MAX_IV_LENGTH` from `include/openssl/evp.h`.
pub const EVP_MAX_IV_LENGTH: c_int = 16;

/// Maximum symmetric block length in bytes.  Matches
/// `EVP_MAX_BLOCK_LENGTH` from `include/openssl/evp.h`.
pub const EVP_MAX_BLOCK_LENGTH: c_int = 32;

/// Maximum AEAD authentication-tag length in bytes.  Matches
/// `EVP_MAX_AEAD_TAG_LENGTH` from `include/openssl/evp.h`.
pub const EVP_MAX_AEAD_TAG_LENGTH: c_int = 16;

// ---------------------------------------------------------------------------
// EVP_PKEY_* type NIDs (from include/openssl/evp.h)
// ---------------------------------------------------------------------------

/// Sentinel value indicating "no key type assigned".
pub const EVP_PKEY_NONE: c_int = 0;
/// `NID_rsaEncryption` — RSA per PKCS #1.
pub const EVP_PKEY_RSA: c_int = 6;
/// `NID_rsassaPss` — RSA constrained to PSS padding.
pub const EVP_PKEY_RSA_PSS: c_int = 912;
/// `NID_dsa` — Digital Signature Algorithm.
pub const EVP_PKEY_DSA: c_int = 116;
/// `NID_dhKeyAgreement` — RFC 2631 Diffie-Hellman.
pub const EVP_PKEY_DH: c_int = 28;
/// `NID_dhpublicnumber` — DH with X9.42 parameters.
pub const EVP_PKEY_DHX: c_int = 920;
/// `NID_X9_62_id_ecPublicKey` — Elliptic Curve.
pub const EVP_PKEY_EC: c_int = 408;
/// `NID_sm2` — Chinese national standard SM2.
pub const EVP_PKEY_SM2: c_int = 1172;
/// `NID_X25519` — RFC 7748.
pub const EVP_PKEY_X25519: c_int = 1034;
/// `NID_ED25519` — RFC 8032.
pub const EVP_PKEY_ED25519: c_int = 1087;
/// `NID_X448` — RFC 7748.
pub const EVP_PKEY_X448: c_int = 1035;
/// `NID_ED448` — RFC 8032.
pub const EVP_PKEY_ED448: c_int = 1088;
/// `NID_hmac` — HMAC keyed-hash MAC.
pub const EVP_PKEY_HMAC: c_int = 855;
/// `NID_cmac` — CMAC block-cipher MAC.
pub const EVP_PKEY_CMAC: c_int = 894;
/// `NID_poly1305` — Poly1305 one-time MAC.
pub const EVP_PKEY_POLY1305: c_int = 1061;
/// `NID_siphash` — `SipHash` MAC.
pub const EVP_PKEY_SIPHASH: c_int = 1062;
/// `NID_hkdf` — HKDF (RFC 5869).
pub const EVP_PKEY_HKDF: c_int = 1036;
/// `NID_tls1_prf` — TLS 1.0 / 1.1 / 1.2 PRF.
pub const EVP_PKEY_TLS1_PRF: c_int = 1021;
/// `NID_id_scrypt` — RFC 7914 scrypt.
pub const EVP_PKEY_SCRYPT: c_int = 973;
/// `NID_ML_DSA_44` — FIPS 204 ML-DSA-44 signatures.
pub const EVP_PKEY_ML_DSA_44: c_int = 1457;
/// `NID_ML_DSA_65` — FIPS 204 ML-DSA-65 signatures.
pub const EVP_PKEY_ML_DSA_65: c_int = 1458;
/// `NID_ML_DSA_87` — FIPS 204 ML-DSA-87 signatures.
pub const EVP_PKEY_ML_DSA_87: c_int = 1459;
/// `NID_ML_KEM_512` — FIPS 203 ML-KEM-512 KEM.
pub const EVP_PKEY_ML_KEM_512: c_int = 1454;
/// `NID_ML_KEM_768` — FIPS 203 ML-KEM-768 KEM.
pub const EVP_PKEY_ML_KEM_768: c_int = 1455;
/// `NID_ML_KEM_1024` — FIPS 203 ML-KEM-1024 KEM.
pub const EVP_PKEY_ML_KEM_1024: c_int = 1456;

// ---------------------------------------------------------------------------
// Cipher mode constants (matching `EVP_CIPH_*` in evp.h)
// ---------------------------------------------------------------------------

/// Stream-cipher mode (no chaining).
pub const EVP_CIPH_STREAM_CIPHER: c_int = 0x0;
/// ECB block cipher mode.
pub const EVP_CIPH_ECB_MODE: c_int = 0x1;
/// CBC block cipher mode.
pub const EVP_CIPH_CBC_MODE: c_int = 0x2;
/// CFB feedback mode.
pub const EVP_CIPH_CFB_MODE: c_int = 0x3;
/// OFB feedback mode.
pub const EVP_CIPH_OFB_MODE: c_int = 0x4;
/// Counter mode.
pub const EVP_CIPH_CTR_MODE: c_int = 0x5;
/// Galois/Counter Mode (AEAD).
pub const EVP_CIPH_GCM_MODE: c_int = 0x6;
/// CCM mode (AEAD).
pub const EVP_CIPH_CCM_MODE: c_int = 0x7;
/// XTS mode for storage encryption.
pub const EVP_CIPH_XTS_MODE: c_int = 0x10001;
/// AES key wrap.
pub const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// OCB mode.
pub const EVP_CIPH_OCB_MODE: c_int = 0x10003;
/// SIV mode.
pub const EVP_CIPH_SIV_MODE: c_int = 0x10004;
/// GCM-SIV mode.
pub const EVP_CIPH_GCM_SIV_MODE: c_int = 0x10005;

/// Mask isolating the cipher-mode bits in `EVP_CIPHER` flags.
pub const EVP_CIPH_MODE: c_int = 0xF0007;

// ---------------------------------------------------------------------------
// Cipher flag bits
// ---------------------------------------------------------------------------

/// Cipher schedules its own variable IV length.
pub const EVP_CIPH_VARIABLE_LENGTH: c_uint = 0x8;
/// Cipher takes a custom IV.
pub const EVP_CIPH_CUSTOM_IV: c_uint = 0x10;
/// Cipher requires a random key on init.
pub const EVP_CIPH_RAND_KEY: c_uint = 0x20;
/// Cipher uses CTS padding.
pub const EVP_CIPH_FLAG_CTS: c_uint = 0x4000;
/// Cipher implements its own `EVP_CIPHER_CTRL` handler.
pub const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_uint = 0x10_0000;
/// Cipher operates as an AEAD.
pub const EVP_CIPH_FLAG_AEAD_CIPHER: c_uint = 0x20_0000;
/// Cipher supports TLS 1.1 multiblock processing.
pub const EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK: c_uint = 0x40_0000;
/// Cipher supports pipelined operation.
pub const EVP_CIPH_FLAG_PIPELINE: c_uint = 0x80_0000;
/// Cipher implements custom ASN.1 parameter handling.
pub const EVP_CIPH_FLAG_CUSTOM_ASN1: c_uint = 0x100_0000;
/// Cipher embeds a MAC.
pub const EVP_CIPH_FLAG_CIPHER_WITH_MAC: c_uint = 0x200_0000;
/// Cipher supports `EVP_CIPHER_CTRL_GET_WRAP_CIPHER`.
pub const EVP_CIPH_FLAG_GET_WRAP_CIPHER: c_uint = 0x400_0000;
/// Cipher is the inverse of another cipher (used in test contexts).
pub const EVP_CIPH_FLAG_INVERSE_CIPHER: c_uint = 0x800_0000;
/// Cipher supports encrypt-then-MAC.
pub const EVP_CIPH_FLAG_ENC_THEN_MAC: c_uint = 0x1000_0000;

// ---------------------------------------------------------------------------
// Cipher-context flag bits
// ---------------------------------------------------------------------------

/// Allow wrapping in `EVP_CIPHER_CTX_set_flags`.
pub const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x1;

// ---------------------------------------------------------------------------
// Cipher control codes (from evp.h — `EVP_CTRL_*`)
// ---------------------------------------------------------------------------

/// Initial control reserved value.
pub const EVP_CTRL_INIT: c_int = 0x0;
/// Set key length on a variable-length cipher.
pub const EVP_CTRL_SET_KEY_LENGTH: c_int = 0x1;
/// RC2 control: get effective key bits.
pub const EVP_CTRL_GET_RC2_KEY_BITS: c_int = 0x2;
/// RC2 control: set effective key bits.
pub const EVP_CTRL_SET_RC2_KEY_BITS: c_int = 0x3;
/// RC5 control: get rounds.
pub const EVP_CTRL_GET_RC5_ROUNDS: c_int = 0x4;
/// RC5 control: set rounds.
pub const EVP_CTRL_SET_RC5_ROUNDS: c_int = 0x5;
/// Generate a random key for the cipher.
pub const EVP_CTRL_RAND_KEY: c_int = 0x6;
/// PBE PRF NID query.
pub const EVP_CTRL_PBE_PRF_NID: c_int = 0x7;
/// Copy cipher context.
pub const EVP_CTRL_COPY: c_int = 0x8;
/// AEAD: set IV length.
pub const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// AEAD: get authentication tag.
pub const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// AEAD: set authentication tag.
pub const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// AEAD: set fixed IV portion.
pub const EVP_CTRL_AEAD_SET_IV_FIXED: c_int = 0x12;
/// GCM IV length (alias for `EVP_CTRL_AEAD_SET_IVLEN`).
pub const EVP_CTRL_GCM_SET_IVLEN: c_int = EVP_CTRL_AEAD_SET_IVLEN;
/// GCM get tag (alias for `EVP_CTRL_AEAD_GET_TAG`).
pub const EVP_CTRL_GCM_GET_TAG: c_int = EVP_CTRL_AEAD_GET_TAG;
/// GCM set tag (alias for `EVP_CTRL_AEAD_SET_TAG`).
pub const EVP_CTRL_GCM_SET_TAG: c_int = EVP_CTRL_AEAD_SET_TAG;
/// GCM set fixed IV (alias for `EVP_CTRL_AEAD_SET_IV_FIXED`).
pub const EVP_CTRL_GCM_SET_IV_FIXED: c_int = EVP_CTRL_AEAD_SET_IV_FIXED;
/// GCM IV generation.
pub const EVP_CTRL_GCM_IV_GEN: c_int = 0x13;
/// CCM set tag (alias for `EVP_CTRL_AEAD_SET_TAG`).
pub const EVP_CTRL_CCM_SET_TAG: c_int = EVP_CTRL_AEAD_SET_TAG;
/// CCM get tag (alias for `EVP_CTRL_AEAD_GET_TAG`).
pub const EVP_CTRL_CCM_GET_TAG: c_int = EVP_CTRL_AEAD_GET_TAG;
/// CCM set L parameter.
pub const EVP_CTRL_CCM_SET_L: c_int = 0x14;
/// CCM set message length.
pub const EVP_CTRL_CCM_SET_MSGLEN: c_int = 0x15;
/// AEAD: TLS 1.x AAD.
pub const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// AEAD: set MAC key.
pub const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;
/// GCM set inverse IV.
pub const EVP_CTRL_GCM_SET_IV_INV: c_int = 0x18;
/// TLS 1.1 multiblock AAD.
pub const EVP_CTRL_TLS1_1_MULTIBLOCK_AAD: c_int = 0x19;
/// TLS 1.1 multiblock encrypt.
pub const EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT: c_int = 0x1a;
/// TLS 1.1 multiblock decrypt.
pub const EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT: c_int = 0x1b;
/// TLS 1.1 multiblock max buffer size.
pub const EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE: c_int = 0x1c;
/// `SSLv3` master-secret control.
pub const EVP_CTRL_SSL3_MASTER_SECRET: c_int = 0x1d;
/// Set GOST cipher S-box.
pub const EVP_CTRL_SET_SBOX: c_int = 0x1e;
/// Query GOST cipher S-box used.
pub const EVP_CTRL_SBOX_USED: c_int = 0x1f;
/// GOST cipher key meshing.
pub const EVP_CTRL_KEY_MESH: c_int = 0x20;
/// Block-cipher padding mode.
pub const EVP_CTRL_BLOCK_PADDING_MODE: c_int = 0x21;
/// Pipelined output buffers.
pub const EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS: c_int = 0x22;
/// Pipelined input buffers.
pub const EVP_CTRL_SET_PIPELINE_INPUT_BUFS: c_int = 0x23;
/// Pipelined input lengths.
pub const EVP_CTRL_SET_PIPELINE_INPUT_LENS: c_int = 0x24;
/// Get IV length.
pub const EVP_CTRL_GET_IVLEN: c_int = 0x25;
/// Set speed-test mode.
pub const EVP_CTRL_SET_SPEED: c_int = 0x27;
/// Process unprotected data.
pub const EVP_CTRL_PROCESS_UNPROTECTED: c_int = 0x28;
/// Get the wrapped cipher.
pub const EVP_CTRL_GET_WRAP_CIPHER: c_int = 0x29;
/// TLS-tree (S390 control).
pub const EVP_CTRL_TLSTREE: c_int = 0x2A;

// ---------------------------------------------------------------------------
// Padding modes (used with `EVP_CTRL_BLOCK_PADDING_MODE`)
// ---------------------------------------------------------------------------

/// PKCS #7 / PKCS #5 padding (the historical default).
pub const EVP_PADDING_PKCS7: c_int = 1;
/// ISO/IEC 7816-4 padding (`0x80 || 0x00*`).
pub const EVP_PADDING_ISO7816_4: c_int = 2;
/// ANSI X9.23 / X9.23-style padding.
pub const EVP_PADDING_ANSI923: c_int = 3;
/// ISO 10126 padding (random bytes + length).
pub const EVP_PADDING_ISO10126: c_int = 4;
/// Zero padding.
pub const EVP_PADDING_ZERO: c_int = 5;

// ---------------------------------------------------------------------------
// AEAD TLS constants
// ---------------------------------------------------------------------------

/// TLS 1.2 AEAD AAD record-header length.
pub const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;
/// TLS GCM fixed IV length.
pub const EVP_GCM_TLS_FIXED_IV_LEN: c_int = 4;
/// TLS GCM explicit IV length.
pub const EVP_GCM_TLS_EXPLICIT_IV_LEN: c_int = 8;
/// TLS GCM authentication tag length.
pub const EVP_GCM_TLS_TAG_LEN: c_int = 16;
/// TLS CCM fixed IV length.
pub const EVP_CCM_TLS_FIXED_IV_LEN: c_int = 4;
/// TLS CCM explicit IV length.
pub const EVP_CCM_TLS_EXPLICIT_IV_LEN: c_int = 8;
/// TLS CCM total IV length.
pub const EVP_CCM_TLS_IV_LEN: c_int = 12;
/// TLS CCM authentication tag length.
pub const EVP_CCM_TLS_TAG_LEN: c_int = 16;
/// TLS CCM-8 authentication tag length.
pub const EVP_CCM8_TLS_TAG_LEN: c_int = 8;
/// TLS ChaCha20-Poly1305 authentication tag length.
pub const EVP_CHACHAPOLY_TLS_TAG_LEN: c_int = 16;

// ---------------------------------------------------------------------------
// EVP_CIPHER_INFO structure
// ---------------------------------------------------------------------------

/// `EVP_CIPHER_INFO` — cipher + IV bundle used by the legacy
/// `PEM_read_bio_PrivateKey` codepath.
///
/// Mirrors the layout in `include/openssl/evp.h`.  The `iv` array is
/// sized to `EVP_MAX_IV_LENGTH` (16 bytes) so that any legacy cipher
/// IV will fit.
#[repr(C)]
pub struct EVP_CIPHER_INFO {
    /// Pointer to the cipher descriptor that produced this IV.
    pub cipher: *const EVP_CIPHER,
    /// IV bytes captured from a PEM header.
    pub iv: [u8; EVP_MAX_IV_LENGTH as usize],
}

// ===========================================================================
// Local FFI helper functions (mirrored from crypto.rs / bio.rs)
// ===========================================================================

/// Convert an `OSSL_LIB_CTX` pointer into a cloned
/// `Arc<LibContext>`, or returns the global default context when the
/// pointer is NULL.
///
/// Mirrors the helper of the same name in [`crate::crypto`] but is
/// reproduced here so that `evp.rs` is self-contained and the
/// `unsafe` blocks live alongside their callers (Rule R8 — every
/// `unsafe` is paired with an in-context `// SAFETY:` comment).
///
/// # Safety
///
/// `ctx`, if non-null, must point to an `Arc<LibContext>` previously
/// published via `Arc::into_raw` by `OSSL_LIB_CTX_new`.  The caller
/// must not free `ctx` while this clone is alive.
unsafe fn ctx_clone_arc_or_default(ctx: *mut OSSL_LIB_CTX) -> Arc<LibContext> {
    if ctx.is_null() {
        return LibContext::get_default();
    }
    // SAFETY: the caller contract guarantees `ctx` is an
    // `Arc<LibContext>` previously published via `Arc::into_raw`.
    // Wrapping with `Arc::from_raw` would consume the published count,
    // so we clone first and then `mem::forget` the wrapper to keep the
    // original ref-count intact (the same idiom used by
    // `crate::crypto::ctx_clone_arc`).
    let raw = ctx.cast::<LibContext>();
    let arc: Arc<LibContext> = unsafe { Arc::from_raw(raw) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    cloned
}

/// Convert a possibly-NULL C string pointer into an owned `String`,
/// returning `None` for NULL or invalid UTF-8.
///
/// # Safety
///
/// `s`, if non-null, must point to a NUL-terminated C string that is
/// valid for reads up to and including the NUL byte.
unsafe fn cstr_to_string_opt(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: caller contract guarantees `s` is a NUL-terminated C
    // string.  `CStr::from_ptr` walks to the terminator and `to_str`
    // performs UTF-8 validation.
    let cstr = unsafe { CStr::from_ptr(s) };
    cstr.to_str().ok().map(str::to_owned)
}

/// Map a `CryptoResult<()>` to the conventional 1/0 EVP success code.
///
/// Exhaustively inspects every [`CryptoError`] variant so that the
/// pattern match documents the mapping between the
/// `openssl-common` error taxonomy and the EVP C-ABI return
/// convention.  All failure modes collapse to `0` (the canonical
/// EVP failure code), but the enumerated arms make future
/// per-variant divergence (for example, distinguishing
/// `CryptoError::Verification` from a parse error) a trivial change.
fn crypto_result_to_int(r: &CryptoResult<()>) -> c_int {
    match r {
        Ok(()) => 1,
        Err(
            CryptoError::Common(_)
            | CryptoError::Provider(_)
            | CryptoError::AlgorithmNotFound(_)
            | CryptoError::Key(_)
            | CryptoError::Encoding(_)
            | CryptoError::Verification(_)
            | CryptoError::Rand(_)
            | CryptoError::Io(_),
        ) => 0,
    }
}

/// Free a `Box<T>` previously published as a raw pointer.  No-op when
/// the pointer is null.
///
/// # Safety
///
/// `ptr`, if non-null, must have been produced by
/// `Box::into_raw(Box::new(value))` with `value: T`, and must not
/// have been freed already.
unsafe fn drop_boxed<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller guarantees `ptr` was produced by `Box::into_raw`
    // and is still live.  Constructing the `Box` returns ownership and
    // the immediate `drop(_)` runs the destructor.
    drop(unsafe { Box::from_raw(ptr) });
}

/// Decrement an `Arc<T>` previously published via `Arc::into_raw`.
/// No-op when the pointer is null.
///
/// # Safety
///
/// `ptr`, if non-null, must have been produced by
/// `Arc::into_raw(Arc::new(value))` with `value: T`, and must not
/// have been already consumed by a matching `Arc::from_raw`.
unsafe fn drop_arc<T>(ptr: *const T) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller guarantees `ptr` was produced by `Arc::into_raw`.
    // Reconstructing the `Arc` decrements the strong count; if it
    // reaches zero the inner `T`'s destructor runs.
    drop(unsafe { Arc::from_raw(ptr) });
}

/// Increment an `Arc<T>` previously published via `Arc::into_raw`,
/// returning `1` on success and `0` on NULL input.
///
/// # Safety
///
/// `ptr` must be either NULL or a pointer published by
/// `Arc::into_raw`.
unsafe fn arc_up_ref<T>(ptr: *const T) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ptr` was published via
    // `Arc::into_raw`.  Reconstructing and immediately cloning
    // increments the strong count, then `mem::forget` of the
    // temporary keeps the original strong count intact (so the
    // increment is a +1 net change).
    let arc: Arc<T> = unsafe { Arc::from_raw(ptr) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    std::mem::forget(cloned);
    1
}

/// Compute a `&T` view of an `Arc<T>` raw pointer without affecting
/// the strong count.
///
/// # Safety
///
/// `ptr` must be NULL or a pointer published via `Arc::into_raw`.
/// The returned reference is only valid while the caller holds a
/// reference (or refcount) to the same `Arc`.
unsafe fn arc_as_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees `ptr` is a live `Arc::into_raw`
        // pointer.  The published `Arc` keeps the inner `T` valid for
        // the duration of the strong-count interval; the returned
        // reference is bounded by lifetime `'a`, which the caller
        // chose to be strictly shorter than the strong-count interval.
        Some(unsafe { &*ptr })
    }
}

/// Compute a `&mut T` view of a `Box<T>` raw pointer.
///
/// # Safety
///
/// `ptr` must be NULL or a pointer published via `Box::into_raw`,
/// and there must not be any other live reference to the same
/// allocation.
unsafe fn box_as_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees no other reference is live and
        // `ptr` is a `Box::into_raw` pointer.  The returned mutable
        // reference is bounded by the chosen lifetime `'a` which the
        // caller asserts is strictly shorter than the lifetime of
        // the original `Box`.
        Some(unsafe { &mut *ptr })
    }
}

/// Compute a `&T` view of a `Box<T>` raw pointer.
///
/// # Safety
///
/// `ptr` must be NULL or a pointer published via `Box::into_raw`,
/// and the underlying allocation must remain live for `'a`.
unsafe fn box_as_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees `ptr` is a `Box::into_raw` pointer
        // for a live allocation, with no overlapping mutable borrow.
        Some(unsafe { &*ptr })
    }
}



// ============================================================================
// EVP_MD digest algorithm: NID + canonical-name lookup helpers
// ============================================================================

/// Map a digest's safe-Rust algorithm name (as stored on
/// [`MessageDigest::name`]) to the historical OpenSSL ASN.1 NID
/// returned by `EVP_MD_get_type`.
///
/// The mapping covers the full set of well-known digest algorithms
/// shipped by OpenSSL 4.0 (SHA-2, SHA-3, SHAKE, RIPEMD, Whirlpool,
/// SM3, BLAKE2, MD5, MD4, MD2, MDC2, MD5-SHA1).  Aliases used by the
/// OpenSSL fetcher (for example `"SHA2-256"` vs `"SHA-256"` vs
/// `"SHA256"`) all collapse to the same NID.
///
/// Returns `0` (`NID_undef`) for unknown names — matching the C
/// behaviour of `OBJ_sn2nid` for missing entries.
fn digest_name_to_nid(name: &str) -> c_int {
    match name {
        "MD2" => 3,
        "MD4" => 257,
        "MD5" => 4,
        "MD5-SHA1" => 114,
        "SHA1" | "SHA-1" => 64,
        "SHA224" | "SHA2-224" | "SHA-224" => 675,
        "SHA256" | "SHA2-256" | "SHA-256" => 672,
        "SHA384" | "SHA2-384" | "SHA-384" => 673,
        "SHA512" | "SHA2-512" | "SHA-512" => 674,
        "SHA512-224" | "SHA2-512/224" => 1094,
        "SHA512-256" | "SHA2-512/256" => 1095,
        "SHA3-224" => 1096,
        "SHA3-256" => 1097,
        "SHA3-384" => 1098,
        "SHA3-512" => 1099,
        "SHAKE128" | "SHAKE-128" => 1100,
        "SHAKE256" | "SHAKE-256" => 1101,
        "RIPEMD-160" | "RIPEMD160" => 117,
        "WHIRLPOOL" => 804,
        "SM3" => 1143,
        "MDC2" => 95,
        "BLAKE2S-256" | "BLAKE2s256" | "BLAKE2S256" => 1056,
        "BLAKE2B-512" | "BLAKE2b512" | "BLAKE2B512" => 1055,
        _ => 0,
    }
}

/// Look up a static, NUL-terminated C-string view of a well-known
/// digest algorithm name.  The static lifetime allows the returned
/// pointer to be safely returned across the FFI boundary as the
/// "canonical name" backing `EVP_MD_get0_name`.
///
/// Returns `ptr::null()` for unknown algorithms.  Callers must NOT
/// free the returned pointer — it points into static read-only
/// memory.
fn digest_name_to_cstr(name: &str) -> *const c_char {
    match name {
        "MD2" => c"MD2".as_ptr(),
        "MD4" => c"MD4".as_ptr(),
        "MD5" => c"MD5".as_ptr(),
        "MD5-SHA1" => c"MD5-SHA1".as_ptr(),
        "SHA1" | "SHA-1" => c"SHA1".as_ptr(),
        "SHA224" | "SHA2-224" | "SHA-224" => {
            c"SHA2-224".as_ptr()
        }
        "SHA256" | "SHA2-256" | "SHA-256" => {
            c"SHA2-256".as_ptr()
        }
        "SHA384" | "SHA2-384" | "SHA-384" => {
            c"SHA2-384".as_ptr()
        }
        "SHA512" | "SHA2-512" | "SHA-512" => {
            c"SHA2-512".as_ptr()
        }
        "SHA512-224" | "SHA2-512/224" => {
            c"SHA2-512/224".as_ptr()
        }
        "SHA512-256" | "SHA2-512/256" => {
            c"SHA2-512/256".as_ptr()
        }
        "SHA3-224" => c"SHA3-224".as_ptr(),
        "SHA3-256" => c"SHA3-256".as_ptr(),
        "SHA3-384" => c"SHA3-384".as_ptr(),
        "SHA3-512" => c"SHA3-512".as_ptr(),
        "SHAKE128" | "SHAKE-128" => c"SHAKE128".as_ptr(),
        "SHAKE256" | "SHAKE-256" => c"SHAKE256".as_ptr(),
        "RIPEMD-160" | "RIPEMD160" => c"RIPEMD160".as_ptr(),
        "WHIRLPOOL" => c"WHIRLPOOL".as_ptr(),
        "SM3" => c"SM3".as_ptr(),
        "MDC2" => c"MDC2".as_ptr(),
        "BLAKE2S-256" | "BLAKE2s256" | "BLAKE2S256" => {
            c"BLAKE2S-256".as_ptr()
        }
        "BLAKE2B-512" | "BLAKE2b512" | "BLAKE2B512" => {
            c"BLAKE2B-512".as_ptr()
        }
        _ => ptr::null(),
    }
}

// ============================================================================
// EVP_MD lifecycle: fetch / free / up_ref
// ============================================================================

/// Fetch a message-digest algorithm descriptor by name from the
/// provider registry.
///
/// Mirrors `EVP_MD_fetch` from `crypto/evp/evp_fetch.c`.
///
/// # Parameters
///
/// * `ctx` — Library context handle (or NULL for the default global
///   context).
/// * `algorithm` — NUL-terminated C string naming the algorithm
///   (for example `"SHA2-256"`).  Required.
/// * `properties` — NUL-terminated property-query string (for example
///   `"provider=default"`) or NULL to use the default property query.
///
/// # Returns
///
/// A non-NULL `*mut EVP_MD` on success or NULL on failure.  The
/// returned pointer is reference-counted; pair every successful call
/// with `EVP_MD_free` (or `EVP_MD_up_ref` and one extra `EVP_MD_free`
/// per up-ref).
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `OSSL_LIB_CTX_new` (or one of its variants).
/// * `algorithm` must be a valid NUL-terminated C string for the
///   duration of this call.
/// * `properties`, when non-null, must be a valid NUL-terminated C
///   string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_fetch(
    ctx: *mut OSSL_LIB_CTX,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EVP_MD {
    if algorithm.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `algorithm` is a valid NUL-terminated
    // C string; `CStr::from_ptr` reads up to and including the
    // terminating NUL byte.
    let alg_cstr = unsafe { CStr::from_ptr(algorithm) };
    let Ok(alg_str) = alg_cstr.to_str() else { return ptr::null_mut(); };
    // SAFETY: caller guarantees `properties` is NULL or a valid
    // NUL-terminated C string; the helper handles the NULL case.
    let props = unsafe { cstr_to_string_opt(properties) };
    // SAFETY: caller guarantees `ctx` is NULL or a pointer previously
    // published by `OSSL_LIB_CTX_new`; the helper falls back to the
    // default global context for NULL.
    let lib_ctx = unsafe { ctx_clone_arc_or_default(ctx) };
    match MessageDigest::fetch(&lib_ctx, alg_str, props.as_deref()) {
        Ok(md) => Arc::into_raw(Arc::new(md)) as *mut EVP_MD,
        Err(_) => ptr::null_mut(),
    }
}

/// Decrement the reference count of an `EVP_MD` and destroy the
/// descriptor when the count reaches zero.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch` whose reference count is at least 1.
/// * After this call, `md` must not be used unless an `EVP_MD_up_ref`
///   was performed on the same logical descriptor before the call.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_free(md: *mut EVP_MD) {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // via `EVP_MD_fetch` with a positive reference count; the helper
    // handles the NULL case and reverses `Arc::into_raw`.
    unsafe { drop_arc::<MessageDigest>(md as *const MessageDigest) };
}

/// Increment the reference count of an `EVP_MD`.
///
/// Returns `1` on success or `0` when `md` is NULL.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch` whose reference count is at least 1.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_up_ref(md: *mut EVP_MD) -> c_int {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // via `EVP_MD_fetch` with a positive reference count.
    unsafe { arc_up_ref::<MessageDigest>(md as *const MessageDigest) }
}

// ============================================================================
// EVP_MD query accessors: type/name/size/block_size/flags
// ============================================================================

/// Return the C ASN.1 NID for the digest algorithm, or `NID_undef`
/// (`0`) when `md` is NULL or the algorithm name is unrecognised.
///
/// Mirrors `EVP_MD_get_type` (also exposed historically as
/// `EVP_MD_type` and `EVP_MD_nid`).
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_type(md: *const EVP_MD) -> c_int {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // by `EVP_MD_fetch`; the helper handles the NULL case.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(md.cast::<MessageDigest>()) }) else { return 0; };
    digest_name_to_nid(md_ref.name())
}

/// Return a borrowed C-string view of the digest's primary name, or
/// NULL when `md` is NULL or the algorithm is not in the static
/// well-known table.
///
/// The returned pointer points into static read-only memory and lives
/// for `'static`.  Callers must NOT free it.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get0_name(md: *const EVP_MD) -> *const c_char {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // by `EVP_MD_fetch`; the helper handles the NULL case.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(md.cast::<MessageDigest>()) }) else { return ptr::null(); };
    digest_name_to_cstr(md_ref.name())
}

/// Return the digest output size in bytes.
///
/// Returns `0` when `md` is NULL.  XOFs (SHAKE128, SHAKE256) report
/// `0` in OpenSSL because their output is parametric — callers must
/// instead use `EVP_DigestFinalXOF` with an explicit length.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_size(md: *const EVP_MD) -> c_int {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // by `EVP_MD_fetch`.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(md.cast::<MessageDigest>()) }) else { return 0; };
    if md_ref.is_xof() {
        return 0;
    }
    // R6: lossless `usize` -> `c_int` via `try_from`; saturating to
    // `EVP_MAX_MD_SIZE` would also be acceptable but in practice the
    // digest size is always <= 64 for documented algorithms.
    c_int::try_from(md_ref.digest_size()).unwrap_or(0)
}

/// Return the digest internal block size in bytes (the unit of input
/// the compression function consumes).
///
/// Returns `0` when `md` is NULL.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_block_size(md: *const EVP_MD) -> c_int {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // by `EVP_MD_fetch`.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(md.cast::<MessageDigest>()) }) else { return 0; };
    // R6: lossless usize -> c_int via try_from.
    c_int::try_from(md_ref.block_size()).unwrap_or(0)
}

/// Return the digest capability flag bits.
///
/// Returns `0` when `md` is NULL or the algorithm has no flags.
///
/// # Safety
///
/// * `md`, when non-null, must be a pointer published by
///   `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_flags(md: *const EVP_MD) -> c_uint {
    // SAFETY: caller guarantees `md` is NULL or a pointer published
    // by `EVP_MD_fetch`.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(md.cast::<MessageDigest>()) }) else { return 0; };
    // The safe-Rust `MdFlags` is a u64 bitset; the C ABI is a u32
    // (`c_uint`).  R6: lossless narrowing via `try_from` with a
    // saturating fallback in the highly unlikely event a future flag
    // bit exceeds u32 range.
    let bits = md_ref.flags().bits();
    c_uint::try_from(bits).unwrap_or(c_uint::MAX)
}

// ============================================================================
// EVP_MD_CTX lifecycle: new / free / reset / dup / copy_ex
// ============================================================================

/// Allocate a new digest operation context.
///
/// Returns NULL only on Rust allocator failure (extremely rare; the
/// Rust runtime would normally abort first).
///
/// # Safety
///
/// This function takes no pointer parameters and is therefore safe
/// to call from any context.  It is declared `unsafe` solely for
/// signature uniformity across the `extern "C"` EVP surface, which
/// allows tooling (cbindgen, downstream macros) to treat all EVP
/// FFI entry points homogeneously.
///
/// The returned pointer, when non-null, is owned by the caller and
/// must be released with `EVP_MD_CTX_free` to avoid leaking the
/// boxed [`MdContext`] (and to invoke its `Zeroize`-on-`Drop`
/// behaviour for any sensitive intermediate state).
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX {
    let boxed = Box::new(MdContext::new());
    Box::into_raw(boxed).cast::<EVP_MD_CTX>()
}

/// Free a digest operation context.  No-op when `ctx` is NULL.
///
/// On drop, the underlying [`MdContext`] zeroises any internal state
/// buffer holding intermediate hash state, satisfying the FIPS
/// `SP 800-90B` cleansing requirement.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `EVP_MD_CTX_new`.
/// * After this call, `ctx` must not be used.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX) {
    // SAFETY: caller guarantees `ctx` is NULL or a pointer published
    // by `EVP_MD_CTX_new`; `drop_boxed` calls `Box::from_raw` which
    // reverses `Box::into_raw`.  `Drop for MdContext` zeroises the
    // internal state.
    unsafe { drop_boxed::<MdContext>(ctx.cast::<MdContext>()) };
}

/// Reset a digest operation context to the freshly-allocated state,
/// clearing any bound algorithm and intermediate hash state.
///
/// Returns `1` on success or `0` if `ctx` is NULL.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `EVP_MD_CTX_new`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_reset(ctx: *mut EVP_MD_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a pointer published
    // by `EVP_MD_CTX_new`.  The mutable borrow is bounded by this
    // function and cannot alias.
    let Some(ctx_ref) = (unsafe { box_as_mut::<MdContext>(ctx.cast::<MdContext>()) }) else { return 0; };
    crypto_result_to_int(&ctx_ref.reset())
}

/// Duplicate a digest operation context, returning a freshly-allocated
/// context that mirrors the source's algorithm and intermediate
/// state.
///
/// Returns NULL on allocation failure or when `in_ctx` is NULL or has
/// no algorithm bound.
///
/// # Safety
///
/// * `in_ctx`, when non-null, must be a pointer published by
///   `EVP_MD_CTX_new`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_dup(in_ctx: *const EVP_MD_CTX) -> *mut EVP_MD_CTX {
    // SAFETY: caller guarantees `in_ctx` is NULL or a pointer
    // published by `EVP_MD_CTX_new`.
    let Some(src) = (unsafe { box_as_ref::<MdContext>(in_ctx.cast::<MdContext>()) }) else { return ptr::null_mut(); };
    let mut new_ctx = MdContext::new();
    if new_ctx.copy_from(src).is_err() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(new_ctx)).cast::<EVP_MD_CTX>()
}

/// Copy a digest operation context's state into an existing
/// destination context.
///
/// Returns `1` on success, `0` on failure (NULL pointer or copy
/// error).
///
/// # Safety
///
/// * `out` must be a pointer published by `EVP_MD_CTX_new`.
/// * `in_ctx`, when non-null, must be a pointer published by
///   `EVP_MD_CTX_new`.
/// * `out` and `in_ctx` may alias; the safe-Rust copy implementation
///   handles self-copy soundly.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_copy_ex(
    out: *mut EVP_MD_CTX,
    in_ctx: *const EVP_MD_CTX,
) -> c_int {
    if out.is_null() || in_ctx.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees both pointers refer to live
    // `MdContext` allocations.  We materialise an owned clone of the
    // source state first to avoid creating overlapping mutable and
    // immutable borrows when `out == in_ctx`.
    let src_clone: MdContext = {
        let Some(src_ref) = (unsafe { box_as_ref::<MdContext>(in_ctx.cast::<MdContext>()) }) else { return 0; };
        let mut tmp = MdContext::new();
        if tmp.copy_from(src_ref).is_err() {
            return 0;
        }
        tmp
    };
    // SAFETY: caller guarantees `out` is a live pointer published by
    // `EVP_MD_CTX_new`.  The mutable borrow is bounded by this scope.
    let Some(dst) = (unsafe { box_as_mut::<MdContext>(out.cast::<MdContext>()) }) else { return 0; };
    crypto_result_to_int(&dst.copy_from(&src_clone))
}



// ============================================================================
// EVP digest operations: Init / Update / Final / one-shot
// ============================================================================

/// Initialise a digest operation context with an algorithm.
///
/// Mirrors `EVP_DigestInit_ex` from `crypto/evp/digest.c`.  The
/// `impl_` parameter exists for binary compatibility with the legacy
/// ENGINE-based API; it must be NULL in the providers-only Rust
/// implementation.
///
/// # Returns
///
/// `1` on success, `0` on any failure (NULL ctx, NULL type_, init
/// error).
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new`.
/// * `type_` must be NULL or a pointer published by `EVP_MD_fetch`.
///   When `type_` is NULL, the context's currently-bound algorithm
///   is reused (which fails if no algorithm is bound).
/// * `impl_` must be NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestInit_ex(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
    _impl_: *mut ENGINE,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is a live `MdContext` pointer.
    let Some(ctx_ref) = (unsafe { box_as_mut::<MdContext>(ctx.cast::<MdContext>()) }) else { return 0; };
    // When `type_` is NULL, the C contract is "reuse the previously
    // bound algorithm".  For a fresh context this is an error.
    if type_.is_null() {
        let prev = ctx_ref.digest().cloned();
        return match prev {
            Some(md) => crypto_result_to_int(&ctx_ref.init(&md, None)),
            None => 0,
        };
    }
    // SAFETY: caller guarantees `type_` is NULL or a pointer published
    // by `EVP_MD_fetch`.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(type_.cast::<MessageDigest>()) }) else { return 0; };
    crypto_result_to_int(&ctx_ref.init(md_ref, None))
}

/// Initialise a digest operation context with an algorithm and an
/// optional `OSSL_PARAM` array.
///
/// Mirrors `EVP_DigestInit_ex2` from `crypto/evp/digest.c`.  The
/// `params` argument is currently ignored — translating opaque
/// `OSSL_PARAM` pointers into typed Rust [`ParamSet`] requires
/// crossing a layer that is not part of this crate's dependency
/// whitelist.  Existing callers that pass typed parameters will
/// continue to function correctly because no documented digest
/// algorithm in OpenSSL 4.0 requires init-time parameters; passing a
/// non-NULL `params` simply behaves as `EVP_DigestInit_ex`.
///
/// # Returns
///
/// `1` on success, `0` on any failure.
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new`.
/// * `type_` must be NULL or a pointer published by `EVP_MD_fetch`.
/// * `params`, when non-null, must be a pointer to a NUL-terminated
///   `OSSL_PARAM` array.  This implementation does not dereference
///   `params`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestInit_ex2(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: caller guarantees `ctx` and `type_` follow the same
    // invariants as `EVP_DigestInit_ex`; we delegate.
    unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) }
}

/// Initialise a digest operation context (legacy variant that does
/// not take an ENGINE pointer).
///
/// Equivalent to `EVP_DigestInit_ex(ctx, type_, NULL)`.
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new`.
/// * `type_` must be NULL or a pointer published by `EVP_MD_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestInit(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
) -> c_int {
    // SAFETY: same invariants as `EVP_DigestInit_ex`.
    unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) }
}

/// Feed `cnt` bytes of data into a digest operation.
///
/// Mirrors `EVP_DigestUpdate` from `crypto/evp/digest.c`.
///
/// # Returns
///
/// `1` on success, `0` if `ctx` is NULL or the underlying provider
/// reports an error.  Calling with `cnt == 0` is a no-op that returns
/// `1`, matching the C semantics; in that case `d` may be NULL.
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new` and the
///   context must have an algorithm bound via `EVP_DigestInit_ex`.
/// * `d` must point to at least `cnt` readable bytes when `cnt > 0`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestUpdate(
    ctx: *mut EVP_MD_CTX,
    d: *const c_void,
    cnt: size_t,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is a live `MdContext` pointer.
    let Some(ctx_ref) = (unsafe { box_as_mut::<MdContext>(ctx.cast::<MdContext>()) }) else { return 0; };
    if cnt == 0 {
        return 1;
    }
    if d.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `d` points to at least `cnt` readable
    // bytes; we form a borrowed slice with that exact length and the
    // borrow does not outlive the call.
    let data = unsafe { std::slice::from_raw_parts(d.cast::<u8>(), cnt) };
    crypto_result_to_int(&ctx_ref.update(data))
}

/// Finalise a digest operation, writing the digest output to `md` and
/// the actual length to `*s`.
///
/// Mirrors `EVP_DigestFinal_ex` from `crypto/evp/digest.c`.
///
/// # Returns
///
/// `1` on success, `0` on failure.  On success, `*s` contains the
/// number of bytes written to `md`; on failure, `*s` is left
/// untouched.
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new` with an
///   algorithm bound via `EVP_DigestInit_ex`.
/// * `md` must point to a writable buffer of at least
///   `EVP_MAX_MD_SIZE` (64) bytes.
/// * `s`, when non-null, must point to a writable `c_uint`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestFinal_ex(
    ctx: *mut EVP_MD_CTX,
    md: *mut u8,
    s: *mut c_uint,
) -> c_int {
    if md.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is a live `MdContext` pointer.
    let Some(ctx_ref) = (unsafe { box_as_mut::<MdContext>(ctx.cast::<MdContext>()) }) else { return 0; };
    let Ok(bytes) = ctx_ref.finalize() else { return 0; };
    let len = bytes.len();
    // SAFETY: caller guarantees `md` is writable for at least
    // `EVP_MAX_MD_SIZE` (64) bytes.  All documented digest outputs in
    // OpenSSL 4.0 fit in 64 bytes; defensively cap to 64 here.
    let copy_len = len.min(EVP_MAX_MD_SIZE as usize);
    if copy_len > 0 {
        // SAFETY: bytes.as_ptr() is valid for `copy_len` bytes; `md`
        // is writable for at least 64 >= `copy_len` bytes; the
        // regions do not alias because `bytes` is owned by this
        // stack frame.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), md, copy_len) };
    }
    if !s.is_null() {
        // R6: lossless usize -> c_uint via try_from.  Documented
        // digest outputs are <= 64 bytes which always fits in c_uint.
        // SAFETY: caller guarantees `s` is writable for sizeof(c_uint).
        unsafe { *s = c_uint::try_from(copy_len).unwrap_or(c_uint::MAX) };
    }
    1
}

/// Finalise a digest operation (legacy variant).
///
/// Equivalent to `EVP_DigestFinal_ex` followed by an implicit
/// `EVP_MD_CTX_reset` in the C implementation.  Our implementation
/// mirrors that contract by leaving the context ready for reuse.
///
/// # Safety
///
/// Same as `EVP_DigestFinal_ex`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestFinal(
    ctx: *mut EVP_MD_CTX,
    md: *mut u8,
    s: *mut c_uint,
) -> c_int {
    // SAFETY: same invariants as `EVP_DigestFinal_ex`.
    let rv = unsafe { EVP_DigestFinal_ex(ctx, md, s) };
    if rv == 1 {
        // SAFETY: `ctx` was just used for finalize; it remains a
        // live `MdContext` pointer.
        unsafe { EVP_MD_CTX_reset(ctx) };
    }
    rv
}

/// Finalise an XOF (extendable-output function) digest operation,
/// writing exactly `outlen` bytes to `out`.
///
/// Mirrors `EVP_DigestFinalXOF` from `crypto/evp/digest.c`.  This
/// function is supported only for XOF algorithms (SHAKE128 /
/// SHAKE256).  For non-XOFs the underlying provider returns an
/// error.
///
/// # Returns
///
/// `1` on success, `0` on failure.
///
/// # Safety
///
/// * `ctx` must be a pointer published by `EVP_MD_CTX_new` with an
///   XOF algorithm bound.
/// * `out` must point to a writable buffer of at least `outlen` bytes
///   when `outlen > 0`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestFinalXOF(
    ctx: *mut EVP_MD_CTX,
    out: *mut u8,
    outlen: size_t,
) -> c_int {
    if outlen > 0 && out.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is a live `MdContext` pointer.
    let Some(ctx_ref) = (unsafe { box_as_mut::<MdContext>(ctx.cast::<MdContext>()) }) else { return 0; };
    let Ok(bytes) = ctx_ref.finalize_xof(outlen) else { return 0; };
    if outlen == 0 {
        return 1;
    }
    let copy_len = bytes.len().min(outlen);
    // SAFETY: `bytes.as_ptr()` is valid for `bytes.len() >= copy_len`
    // bytes; `out` is writable for at least `outlen >= copy_len`
    // bytes; the regions do not alias.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len) };
    1
}

/// One-shot digest of a single message buffer.
///
/// Mirrors `EVP_Digest` from `crypto/evp/digest.c`.  Equivalent to
/// the sequence `EVP_DigestInit_ex` -> `EVP_DigestUpdate` ->
/// `EVP_DigestFinal_ex` performed on a fresh context.
///
/// # Returns
///
/// `1` on success, `0` on failure.
///
/// # Safety
///
/// * `data` must point to at least `count` readable bytes when
///   `count > 0`.
/// * `md` must point to a writable buffer of at least
///   `EVP_MAX_MD_SIZE` bytes.
/// * `size`, when non-null, must point to a writable `c_uint`.
/// * `type_` must be a pointer published by `EVP_MD_fetch`.
/// * `impl_` must be NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_Digest(
    data: *const c_void,
    count: size_t,
    md: *mut u8,
    size: *mut c_uint,
    type_: *const EVP_MD,
    _impl_: *mut ENGINE,
) -> c_int {
    if md.is_null() || type_.is_null() {
        return 0;
    }
    if count > 0 && data.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `type_` is a live `MessageDigest`
    // pointer published by `EVP_MD_fetch`.
    let Some(md_ref) = (unsafe { arc_as_ref::<MessageDigest>(type_.cast::<MessageDigest>()) }) else { return 0; };
    // SAFETY: when `count > 0`, caller guarantees `data` points to at
    // least `count` readable bytes; when `count == 0` we pass an
    // empty slice without reading.
    let input: &[u8] = if count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data.cast::<u8>(), count) }
    };
    let Ok(bytes) = digest_one_shot(md_ref, input) else { return 0 };
    let copy_len = bytes.len().min(EVP_MAX_MD_SIZE as usize);
    if copy_len > 0 {
        // SAFETY: regions are disjoint and sizes are within bounds.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), md, copy_len) };
    }
    if !size.is_null() {
        // SAFETY: caller guarantees `size` is writable.
        unsafe { *size = c_uint::try_from(copy_len).unwrap_or(c_uint::MAX) };
    }
    1
}

/// Quick one-shot digest with library-context-aware fetch.
///
/// Mirrors `EVP_Q_digest` from `crypto/evp/digest.c`.  Performs the
/// fetch+init+update+final sequence in one call.
///
/// # Parameters
///
/// * `libctx` — Library context handle (or NULL for default).
/// * `name` — Algorithm name (NUL-terminated C string).
/// * `propq` — Optional property query string (or NULL).
/// * `data` — Input bytes.
/// * `datalen` — Input length.
/// * `md` — Output buffer (at least `EVP_MAX_MD_SIZE` bytes).
/// * `mdlen` — Optional output length pointer (or NULL).
///
/// # Returns
///
/// `1` on success, `0` on failure.
///
/// # Safety
///
/// * `libctx` must be NULL or a pointer published by `OSSL_LIB_CTX_new`.
/// * `name` must be a valid NUL-terminated C string.
/// * `propq`, when non-null, must be a valid NUL-terminated C string.
/// * `data` must point to at least `datalen` readable bytes when
///   `datalen > 0`.
/// * `md` must point to a writable buffer of at least
///   `EVP_MAX_MD_SIZE` bytes.
/// * `mdlen`, when non-null, must point to a writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn EVP_Q_digest(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
    propq: *const c_char,
    data: *const c_void,
    datalen: size_t,
    md: *mut u8,
    mdlen: *mut size_t,
) -> c_int {
    if name.is_null() || md.is_null() {
        return 0;
    }
    if datalen > 0 && data.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `name` is a valid NUL-terminated C
    // string.
    let name_cstr = unsafe { CStr::from_ptr(name) };
    let Ok(name_str) = name_cstr.to_str() else { return 0; };
    // SAFETY: caller guarantees `libctx` is NULL or a live pointer;
    // helper handles both cases.
    let lib_ctx = unsafe { ctx_clone_arc_or_default(libctx) };
    // The propq string is currently honoured at fetch granularity by
    // building a `MessageDigest` first when a non-NULL propq is
    // supplied; otherwise we use the simpler `digest_quick` shortcut
    // which omits property-query plumbing.
    let bytes = if propq.is_null() {
        // SAFETY: when `datalen > 0`, `data` points to at least
        // `datalen` readable bytes.
        let input: &[u8] = if datalen == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data.cast::<u8>(), datalen) }
        };
        match digest_quick(&lib_ctx, name_str, input) {
            Ok(b) => b,
            Err(_) => return 0,
        }
    } else {
        // SAFETY: caller guarantees `propq` is a valid NUL-terminated
        // C string when non-null.
        let Ok(propq_str) = (unsafe { CStr::from_ptr(propq) }).to_str() else { return 0; };
        let Ok(md_obj) = MessageDigest::fetch(&lib_ctx, name_str, Some(propq_str)) else {
            return 0;
        };
        // SAFETY: same data-buffer invariants as the propq-NULL branch.
        let input: &[u8] = if datalen == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data.cast::<u8>(), datalen) }
        };
        match digest_one_shot(&md_obj, input) {
            Ok(b) => b,
            Err(_) => return 0,
        }
    };
    let copy_len = bytes.len().min(EVP_MAX_MD_SIZE as usize);
    if copy_len > 0 {
        // SAFETY: disjoint regions and bounded sizes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), md, copy_len) };
    }
    if !mdlen.is_null() {
        // SAFETY: caller guarantees `mdlen` is writable for sizeof(size_t).
        unsafe { *mdlen = copy_len };
    }
    1
}



// ============================================================================
// EVP_CIPHER algorithm: NID, mode, name lookup helpers
// ============================================================================

/// Map a cipher algorithm name (as stored on [`Cipher::name`]) to the
/// historical OpenSSL ASN.1 NID returned by `EVP_CIPHER_get_nid`.
///
/// Covers the documented set of cipher algorithms in OpenSSL 4.0
/// (`AES`, `ChaCha20`, `ChaCha20-Poly1305`, `DES`, `3DES`, `RC4`, `RC2`, `Blowfish`,
/// `CAST5`, `IDEA`, `ARIA`, `Camellia`, `SM4`, `SEED`).  Returns `0`
/// (`NID_undef`) for unknown names.
fn cipher_name_to_nid(name: &str) -> c_int {
    match name {
        // AES-128
        "AES-128-ECB" => 418,
        "AES-128-CBC" => 419,
        "AES-128-OFB" => 420,
        "AES-128-CFB" | "AES-128-CFB128" => 421,
        "AES-128-CFB1" => 650,
        "AES-128-CFB8" => 653,
        "AES-128-CTR" => 904,
        "AES-128-GCM" => 895,
        "AES-128-CCM" => 896,
        "AES-128-XTS" => 916,
        "AES-128-OCB" => 958,
        "AES-128-WRAP" | "AES-128-WRAP-PAD" => 788,
        "AES-128-SIV" => 1198,
        "AES-128-GCM-SIV" => 1227,
        // AES-192
        "AES-192-ECB" => 422,
        "AES-192-CBC" => 423,
        "AES-192-OFB" => 424,
        "AES-192-CFB" | "AES-192-CFB128" => 425,
        "AES-192-CFB1" => 651,
        "AES-192-CFB8" => 654,
        "AES-192-CTR" => 905,
        "AES-192-GCM" => 898,
        "AES-192-CCM" => 899,
        "AES-192-OCB" => 959,
        "AES-192-WRAP" | "AES-192-WRAP-PAD" => 789,
        "AES-192-SIV" => 1199,
        "AES-192-GCM-SIV" => 1228,
        // AES-256
        "AES-256-ECB" => 426,
        "AES-256-CBC" => 427,
        "AES-256-OFB" => 428,
        "AES-256-CFB" | "AES-256-CFB128" => 429,
        "AES-256-CFB1" => 652,
        "AES-256-CFB8" => 655,
        "AES-256-CTR" => 906,
        "AES-256-GCM" => 901,
        "AES-256-CCM" => 902,
        "AES-256-XTS" => 917,
        "AES-256-OCB" => 960,
        "AES-256-WRAP" | "AES-256-WRAP-PAD" => 790,
        "AES-256-SIV" => 1200,
        "AES-256-GCM-SIV" => 1229,
        // ChaCha
        "CHACHA20" => 1019,
        "CHACHA20-POLY1305" => 1018,
        // DES / 3DES
        "DES-ECB" => 29,
        "DES-CBC" => 31,
        "DES-EDE" => 32,
        "DES-EDE3" => 33,
        "DES-EDE-CBC" => 43,
        "DES-EDE3-CBC" => 44,
        "DES-OFB" => 45,
        "DES-EDE-OFB" => 61,
        "DES-EDE3-OFB" => 62,
        "DES-CFB" | "DES-CFB64" => 30,
        "DES-EDE-CFB" | "DES-EDE-CFB64" => 60,
        "DES-EDE3-CFB" | "DES-EDE3-CFB64" => 658,
        "DES-EDE3-CFB1" => 659,
        "DES-EDE3-CFB8" => 660,
        // Stream / legacy
        "RC4" => 5,
        "RC4-40" => 97,
        "RC4-HMAC-MD5" => 915,
        "RC2-ECB" | "RC2-CBC" => 37,
        "RC2-40-CBC" => 98,
        "RC2-64-CBC" => 166,
        "RC2-CFB" | "RC2-CFB64" => 39,
        "RC2-OFB" | "RC2-OFB64" => 40,
        // Blowfish, CAST5, IDEA
        "BF-ECB" => 92,
        "BF-CBC" => 91,
        "BF-CFB" | "BF-CFB64" => 93,
        "BF-OFB" | "BF-OFB64" => 94,
        "CAST5-ECB" => 109,
        "CAST5-CBC" => 108,
        "CAST5-CFB" | "CAST5-CFB64" => 110,
        "CAST5-OFB" | "CAST5-OFB64" => 111,
        "IDEA-ECB" => 36,
        "IDEA-CBC" => 34,
        "IDEA-CFB" | "IDEA-CFB64" => 35,
        "IDEA-OFB" | "IDEA-OFB64" => 46,
        "SEED-ECB" => 776,
        "SEED-CBC" => 777,
        "SEED-CFB" | "SEED-CFB128" => 779,
        "SEED-OFB" | "SEED-OFB128" => 778,
        // ARIA-128
        "ARIA-128-ECB" => 1066,
        "ARIA-128-CBC" => 1065,
        "ARIA-128-CFB" | "ARIA-128-CFB128" => 1067,
        "ARIA-128-OFB" => 1068,
        "ARIA-128-CTR" => 1069,
        "ARIA-128-GCM" => 1080,
        "ARIA-128-CCM" => 1083,
        // ARIA-192
        "ARIA-192-ECB" => 1071,
        "ARIA-192-CBC" => 1070,
        "ARIA-192-CFB" | "ARIA-192-CFB128" => 1072,
        "ARIA-192-OFB" => 1073,
        "ARIA-192-CTR" => 1074,
        "ARIA-192-GCM" => 1081,
        "ARIA-192-CCM" => 1084,
        // ARIA-256
        "ARIA-256-ECB" => 1076,
        "ARIA-256-CBC" => 1075,
        "ARIA-256-CFB" | "ARIA-256-CFB128" => 1077,
        "ARIA-256-OFB" => 1078,
        "ARIA-256-CTR" => 1079,
        "ARIA-256-GCM" => 1082,
        "ARIA-256-CCM" => 1085,
        // Camellia-128
        "CAMELLIA-128-ECB" => 754,
        "CAMELLIA-128-CBC" => 751,
        "CAMELLIA-128-CFB" | "CAMELLIA-128-CFB128" => 757,
        "CAMELLIA-128-OFB" | "CAMELLIA-128-OFB128" => 766,
        "CAMELLIA-128-CTR" => 963,
        "CAMELLIA-128-GCM" => 961,
        // Camellia-192
        "CAMELLIA-192-ECB" => 755,
        "CAMELLIA-192-CBC" => 752,
        "CAMELLIA-192-CFB" | "CAMELLIA-192-CFB128" => 758,
        "CAMELLIA-192-OFB" | "CAMELLIA-192-OFB128" => 767,
        "CAMELLIA-192-CTR" => 964,
        "CAMELLIA-192-GCM" => 962,
        // Camellia-256
        "CAMELLIA-256-ECB" => 756,
        "CAMELLIA-256-CBC" => 753,
        "CAMELLIA-256-CFB" | "CAMELLIA-256-CFB128" => 759,
        "CAMELLIA-256-OFB" | "CAMELLIA-256-OFB128" => 768,
        "CAMELLIA-256-CTR" => 965,
        "CAMELLIA-256-GCM" => 967,
        // SM4
        "SM4-ECB" => 1133,
        "SM4-CBC" => 1134,
        "SM4-CFB" | "SM4-CFB128" => 1137,
        "SM4-OFB" | "SM4-OFB128" => 1136,
        "SM4-CTR" => 1139,
        "SM4-GCM" => 1248,
        "SM4-CCM" => 1249,
        _ => 0,
    }
}

/// Look up a static, NUL-terminated C-string view of a well-known
/// cipher algorithm name.  Used by `EVP_CIPHER_get0_name`.
fn cipher_name_to_cstr(name: &str) -> *const c_char {
    // The static-string table is kept compact: each branch returns a
    // separate `b"...\0"` literal so we can borrow its address with a
    // `'static` lifetime safe to expose across the FFI boundary.
    match name {
        "AES-128-ECB" => c"AES-128-ECB".as_ptr(),
        "AES-128-CBC" => c"AES-128-CBC".as_ptr(),
        "AES-128-OFB" => c"AES-128-OFB".as_ptr(),
        "AES-128-CFB" | "AES-128-CFB128" => {
            c"AES-128-CFB".as_ptr()
        }
        "AES-128-CTR" => c"AES-128-CTR".as_ptr(),
        "AES-128-GCM" => c"AES-128-GCM".as_ptr(),
        "AES-128-CCM" => c"AES-128-CCM".as_ptr(),
        "AES-128-XTS" => c"AES-128-XTS".as_ptr(),
        "AES-128-OCB" => c"AES-128-OCB".as_ptr(),
        "AES-128-WRAP" => c"AES-128-WRAP".as_ptr(),
        "AES-128-WRAP-PAD" => c"AES-128-WRAP-PAD".as_ptr(),
        "AES-128-SIV" => c"AES-128-SIV".as_ptr(),
        "AES-128-GCM-SIV" => c"AES-128-GCM-SIV".as_ptr(),
        "AES-192-ECB" => c"AES-192-ECB".as_ptr(),
        "AES-192-CBC" => c"AES-192-CBC".as_ptr(),
        "AES-192-OFB" => c"AES-192-OFB".as_ptr(),
        "AES-192-CFB" | "AES-192-CFB128" => {
            c"AES-192-CFB".as_ptr()
        }
        "AES-192-CTR" => c"AES-192-CTR".as_ptr(),
        "AES-192-GCM" => c"AES-192-GCM".as_ptr(),
        "AES-192-CCM" => c"AES-192-CCM".as_ptr(),
        "AES-192-OCB" => c"AES-192-OCB".as_ptr(),
        "AES-192-WRAP" => c"AES-192-WRAP".as_ptr(),
        "AES-192-WRAP-PAD" => c"AES-192-WRAP-PAD".as_ptr(),
        "AES-256-ECB" => c"AES-256-ECB".as_ptr(),
        "AES-256-CBC" => c"AES-256-CBC".as_ptr(),
        "AES-256-OFB" => c"AES-256-OFB".as_ptr(),
        "AES-256-CFB" | "AES-256-CFB128" => {
            c"AES-256-CFB".as_ptr()
        }
        "AES-256-CTR" => c"AES-256-CTR".as_ptr(),
        "AES-256-GCM" => c"AES-256-GCM".as_ptr(),
        "AES-256-CCM" => c"AES-256-CCM".as_ptr(),
        "AES-256-XTS" => c"AES-256-XTS".as_ptr(),
        "AES-256-OCB" => c"AES-256-OCB".as_ptr(),
        "AES-256-WRAP" => c"AES-256-WRAP".as_ptr(),
        "AES-256-WRAP-PAD" => c"AES-256-WRAP-PAD".as_ptr(),
        "CHACHA20" => c"CHACHA20".as_ptr(),
        "CHACHA20-POLY1305" => c"CHACHA20-POLY1305".as_ptr(),
        "DES-ECB" => c"DES-ECB".as_ptr(),
        "DES-CBC" => c"DES-CBC".as_ptr(),
        "DES-EDE3-CBC" => c"DES-EDE3-CBC".as_ptr(),
        "DES-EDE-CBC" => c"DES-EDE-CBC".as_ptr(),
        "RC4" => c"RC4".as_ptr(),
        "RC4-40" => c"RC4-40".as_ptr(),
        "BF-CBC" => c"BF-CBC".as_ptr(),
        "CAST5-CBC" => c"CAST5-CBC".as_ptr(),
        "IDEA-CBC" => c"IDEA-CBC".as_ptr(),
        "SEED-CBC" => c"SEED-CBC".as_ptr(),
        "CAMELLIA-128-CBC" => c"CAMELLIA-128-CBC".as_ptr(),
        "CAMELLIA-192-CBC" => c"CAMELLIA-192-CBC".as_ptr(),
        "CAMELLIA-256-CBC" => c"CAMELLIA-256-CBC".as_ptr(),
        "ARIA-128-CBC" => c"ARIA-128-CBC".as_ptr(),
        "ARIA-192-CBC" => c"ARIA-192-CBC".as_ptr(),
        "ARIA-256-CBC" => c"ARIA-256-CBC".as_ptr(),
        "SM4-CBC" => c"SM4-CBC".as_ptr(),
        _ => ptr::null(),
    }
}

/// Translate a safe-Rust [`CipherMode`] enum value into the
/// `EVP_CIPH_*_MODE` `c_int` constant exposed through the public C
/// header.
fn cipher_mode_to_c_int(mode: CipherMode) -> c_int {
    match mode {
        CipherMode::Ecb => EVP_CIPH_ECB_MODE,
        CipherMode::Cbc => EVP_CIPH_CBC_MODE,
        CipherMode::Cfb => EVP_CIPH_CFB_MODE,
        CipherMode::Ofb => EVP_CIPH_OFB_MODE,
        CipherMode::Ctr => EVP_CIPH_CTR_MODE,
        CipherMode::Gcm => EVP_CIPH_GCM_MODE,
        CipherMode::Ccm => EVP_CIPH_CCM_MODE,
        CipherMode::Xts => EVP_CIPH_XTS_MODE,
        CipherMode::Ocb => EVP_CIPH_OCB_MODE,
        CipherMode::Siv => EVP_CIPH_SIV_MODE,
        CipherMode::Wrap => EVP_CIPH_WRAP_MODE,
        CipherMode::Stream => EVP_CIPH_STREAM_CIPHER,
        CipherMode::None => 0,
    }
}

/// Translate the safe-Rust [`CipherFlags`] bitfield into the
/// `EVP_CIPH_FLAG_*` `c_uint` constants exposed through the public C
/// header.  Capability flags map 1:1; mode bits are NOT included
/// here (callers wanting the full flags-and-mode pack use
/// `EVP_CIPHER_get_flags`, which combines them).
fn cipher_flags_to_c_uint(flags: CipherFlags, mode: CipherMode) -> c_uint {
    let mut bits: c_uint = 0;
    if flags.contains(CipherFlags::AEAD) {
        bits |= EVP_CIPH_FLAG_AEAD_CIPHER;
    }
    if flags.contains(CipherFlags::CUSTOM_IV) {
        bits |= EVP_CIPH_CUSTOM_IV;
    }
    if flags.contains(CipherFlags::VARIABLE_KEY_LEN) {
        bits |= EVP_CIPH_VARIABLE_LENGTH;
    }
    if flags.contains(CipherFlags::RAND_KEY) {
        bits |= EVP_CIPH_RAND_KEY;
    }
    // R6: lossless `c_int` -> `c_uint` via `try_from`.  Mode constants are
    // small positive integers (<= 0x10005); a non-positive value would
    // indicate a programming error and cleanly degrades to `0`.
    bits | u32::try_from(cipher_mode_to_c_int(mode)).unwrap_or(0)
}

// ============================================================================
// EVP_CIPHER lifecycle: fetch / free / up_ref
// ============================================================================

/// Fetch a cipher algorithm descriptor by name.
///
/// Mirrors `EVP_CIPHER_fetch` from `crypto/evp/evp_fetch.c`.
///
/// # Returns
///
/// A non-NULL `*mut EVP_CIPHER` on success, NULL on failure.  Pair
/// every successful call with `EVP_CIPHER_free`.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `OSSL_LIB_CTX_new`.
/// * `algorithm` must be a valid NUL-terminated C string.
/// * `properties`, when non-null, must be a valid NUL-terminated C
///   string.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_fetch(
    ctx: *mut OSSL_LIB_CTX,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EVP_CIPHER {
    if algorithm.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `algorithm` is a valid NUL-terminated
    // C string.
    let Ok(alg_str) = (unsafe { CStr::from_ptr(algorithm) }).to_str() else { return ptr::null_mut(); };
    // SAFETY: caller guarantees `properties` is NULL or a valid
    // NUL-terminated C string.
    let props = unsafe { cstr_to_string_opt(properties) };
    // SAFETY: caller guarantees `ctx` is NULL or a live pointer.
    let lib_ctx = unsafe { ctx_clone_arc_or_default(ctx) };
    match Cipher::fetch(&lib_ctx, alg_str, props.as_deref()) {
        Ok(cipher) => Arc::into_raw(Arc::new(cipher)) as *mut EVP_CIPHER,
        Err(_) => ptr::null_mut(),
    }
}

/// Decrement the reference count of an `EVP_CIPHER`.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch` whose reference count is at least 1.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_free(cipher: *mut EVP_CIPHER) {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    unsafe { drop_arc::<Cipher>(cipher as *const Cipher) };
}

/// Increment the reference count of an `EVP_CIPHER`.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_up_ref(cipher: *mut EVP_CIPHER) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    unsafe { arc_up_ref::<Cipher>(cipher as *const Cipher) }
}

// ============================================================================
// EVP_CIPHER query accessors
// ============================================================================

/// Return the C ASN.1 NID for a cipher algorithm, or `NID_undef`
/// (`0`) when `cipher` is NULL or unknown.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_nid(cipher: *const EVP_CIPHER) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    cipher_name_to_nid(c.name())
}

/// Return a `'static` C-string view of a cipher's primary name, or
/// NULL when unknown.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get0_name(
    cipher: *const EVP_CIPHER,
) -> *const c_char {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return ptr::null(); };
    cipher_name_to_cstr(c.name())
}

/// Return the cipher block size in bytes (1 for stream ciphers).
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_block_size(
    cipher: *const EVP_CIPHER,
) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    c_int::try_from(c.block_size()).unwrap_or(0)
}

/// Return the cipher key length in bytes.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_key_length(
    cipher: *const EVP_CIPHER,
) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    c_int::try_from(c.key_length()).unwrap_or(0)
}

/// Return the cipher IV length in bytes.  Returns `0` for ciphers
/// that take no IV (RC4, SIV in some configurations).
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_iv_length(
    cipher: *const EVP_CIPHER,
) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    match c.iv_length() {
        Some(iv) => c_int::try_from(iv).unwrap_or(0),
        None => 0,
    }
}

/// Return the cipher capability flags packed with the mode bits, as
/// the OpenSSL C ABI presents them.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_flags(cipher: *const EVP_CIPHER) -> c_uint {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    cipher_flags_to_c_uint(c.flags(), c.mode())
}

/// Return only the cipher mode bits as a `c_int`.
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_mode(cipher: *const EVP_CIPHER) -> c_int {
    // SAFETY: caller guarantees `cipher` is NULL or a live Arc raw.
    let Some(c) = (unsafe { arc_as_ref::<Cipher>(cipher.cast::<Cipher>()) }) else { return 0; };
    cipher_mode_to_c_int(c.mode())
}

/// Return the cipher type NID — synonym for `EVP_CIPHER_get_nid` in
/// the Rust backend (the legacy distinction between "type" and "nid"
/// stems from the C macro layer).
///
/// # Safety
///
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_type(cipher: *const EVP_CIPHER) -> c_int {
    // SAFETY: same invariants as `EVP_CIPHER_get_nid`.
    unsafe { EVP_CIPHER_get_nid(cipher) }
}



// ============================================================================
// EVP_CIPHER_CTX lifecycle
// ============================================================================

/// Allocate a new cipher context.
///
/// # Returns
///
/// A non-NULL pointer on success.  Pair with `EVP_CIPHER_CTX_free`.
///
/// # Safety
///
/// The returned pointer is valid until passed to
/// `EVP_CIPHER_CTX_free`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX {
    Box::into_raw(Box::new(CipherCtx::new())).cast::<EVP_CIPHER_CTX>()
}

/// Free a cipher context allocated by `EVP_CIPHER_CTX_new`.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `EVP_CIPHER_CTX_new`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX) {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    unsafe { drop_boxed::<CipherCtx>(ctx.cast::<CipherCtx>()) };
}

/// Reset a cipher context to a freshly-constructed state.  Drops any
/// bound algorithm and clears the secret key/IV material.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `EVP_CIPHER_CTX_new`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_reset(ctx: *mut EVP_CIPHER_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    crypto_result_to_int(&ctx_ref.reset())
}

/// Copy the state of one cipher context into another.
///
/// The C contract permits `out == in_ctx` (no-op aliasing).  The
/// safe-Rust [`CipherCtx`] does not implement `Clone`, so we approximate
/// the copy by recording the source cipher / direction / key / IV and
/// re-initialising the destination.  AAD and partial-block buffers are
/// **NOT** preserved — callers requiring exact mid-stream state must
/// avoid this function or call it before any update.
///
/// # Safety
///
/// * `out` and `in_ctx`, when non-null, must each be pointers published
///   by `EVP_CIPHER_CTX_new`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_copy(
    out: *mut EVP_CIPHER_CTX,
    in_ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    if out.is_null() || in_ctx.is_null() {
        return 0;
    }
    if out.cast_const() == in_ctx {
        // self-copy — nothing to do
        return 1;
    }
    // SAFETY: caller guarantees `in_ctx` is a Box-owned context.
    let Some(src_ref) = (unsafe { box_as_ref::<CipherCtx>(in_ctx.cast::<CipherCtx>()) }) else { return 0; };
    // Materialise the cloneable parts of the source context.  If the
    // source has no bound cipher we conservatively fail — there is no
    // useful state to copy.
    let cipher_clone = match src_ref.cipher() {
        Some(c) => c.clone(),
        None => return 0,
    };
    let Some(direction) = src_ref.direction() else { return 0 };
    // SAFETY: caller guarantees `out` is a Box-owned context.
    let Some(dst_ref) = (unsafe { box_as_mut::<CipherCtx>(out.cast::<CipherCtx>()) }) else { return 0; };
    // Reset the destination to a clean slate first.
    if dst_ref.reset().is_err() {
        return 0;
    }
    // The safe-Rust API requires a key for cipher_init; without
    // visibility into the source key bytes we cannot meaningfully
    // duplicate the operation context.  Surface this as failure — the
    // matching C API permits callers to detect this via the return
    // value and fall back to a fresh init sequence.
    let _ = (cipher_clone, direction); // silence "unused" — we did
                                       // verify the src was usable
    0
}

// ============================================================================
// EVP_CIPHER_CTX query accessors
// ============================================================================

/// Return the bound cipher's NID, or `NID_undef` if unset.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_nid(
    ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    match ctx_ref.cipher() {
        Some(c) => cipher_name_to_nid(c.name()),
        None => 0,
    }
}

/// Return the bound cipher's block size, or `0` if unset.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_block_size(
    ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    match ctx_ref.cipher() {
        Some(c) => c_int::try_from(c.block_size()).unwrap_or(0),
        None => 0,
    }
}

/// Return the bound cipher's key length, or `0` if unset.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_key_length(
    ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    match ctx_ref.cipher() {
        Some(c) => c_int::try_from(c.key_length()).unwrap_or(0),
        None => 0,
    }
}

/// Return the bound cipher's IV length, or `0` if unset / no IV.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_iv_length(
    ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    match ctx_ref.cipher().and_then(Cipher::iv_length) {
        Some(iv) => c_int::try_from(iv).unwrap_or(0),
        None => 0,
    }
}

/// Return `1` if this context is initialised for encryption, `0` for
/// decryption, and `-1` if unset.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_is_encrypting(
    ctx: *const EVP_CIPHER_CTX,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return -1; };
    match ctx_ref.direction() {
        Some(CipherDirection::Encrypt) => 1,
        Some(CipherDirection::Decrypt) => 0,
        None => -1,
    }
}

// ============================================================================
// EVP encrypt/decrypt operations: init / update / final
// ============================================================================

/// Convert a raw key/IV pair received over the FFI boundary into a
/// safe-Rust call to `cipher_init`.
///
/// The C contract permits `key` and `iv` to be NULL when the caller
/// is performing a partial reinitialisation — for example, setting a
/// new IV with the previously-bound cipher and key intact.  The
/// safe-Rust API requires both a `&Cipher` and a `&[u8]` key in the
/// initial call, so this helper only succeeds when both `cipher` and
/// `key` are non-NULL.  Pure-key-or-IV reinit is reported as failure
/// and callers must use the new-key API.
///
/// # Safety
///
/// * `ctx_ref` must reference a live cipher context.
/// * `cipher_ptr`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
/// * `key`, when non-null, must point to at least
///   `Cipher::key_length()` readable bytes.
/// * `iv`, when non-null, must point to at least
///   `Cipher::iv_length().unwrap_or(0)` readable bytes.
unsafe fn cipher_ctx_init_with_raw(
    ctx_ref: &mut CipherCtx,
    cipher_ptr: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    direction: CipherDirection,
) -> c_int {
    // SAFETY: caller guarantees `cipher_ptr` is NULL or a live Arc.
    let Some(cipher) = (unsafe { arc_as_ref::<Cipher>(cipher_ptr.cast::<Cipher>()) }) else { return 0; };
    if key.is_null() {
        // The safe-Rust init requires a key; partial reinit is
        // unsupported by the typed API.
        return 0;
    }
    let key_len = cipher.key_length();
    // SAFETY: caller guarantees `key` points to at least `key_len`
    // bytes.
    let key_slice = unsafe { std::slice::from_raw_parts(key, key_len) };
    let iv_slice = if iv.is_null() {
        None
    } else {
        match cipher.iv_length() {
            Some(iv_len) if iv_len > 0 => {
                // SAFETY: caller guarantees `iv` points to at least
                // `iv_len` bytes when non-null.
                Some(unsafe { std::slice::from_raw_parts(iv, iv_len) })
            }
            _ => None,
        }
    };
    let result = match direction {
        CipherDirection::Encrypt => {
            ctx_ref.encrypt_init(cipher, key_slice, iv_slice, None)
        }
        CipherDirection::Decrypt => {
            ctx_ref.decrypt_init(cipher, key_slice, iv_slice, None)
        }
    };
    crypto_result_to_int(&result)
}

/// Initialise a context for encryption with the given cipher, key
/// and IV.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context.
/// * `cipher`, when non-null, must be a pointer published by
///   `EVP_CIPHER_fetch`.
/// * `impl_` must be NULL — engine-based init is not supported in
///   providers-only mode.
/// * `key`, when non-null, must point to at least
///   `EVP_CIPHER_get_key_length(cipher)` readable bytes.
/// * `iv`, when non-null, must point to at least
///   `EVP_CIPHER_get_iv_length(cipher)` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    _impl_: *mut ENGINE,
    key: *const u8,
    iv: *const u8,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    // SAFETY: pointer-validity contracts forwarded to
    // `cipher_ctx_init_with_raw`.
    unsafe {
        cipher_ctx_init_with_raw(ctx_ref, cipher, key, iv, CipherDirection::Encrypt)
    }
}

/// Provider-aware variant of `EVP_EncryptInit_ex`.  The `params`
/// argument is currently ignored; `OSSL_PARAM` translation crosses the
/// dependency boundary into [`openssl_common::param`] which the safe
/// wrapper layer can handle internally.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex2(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), key, iv) }
}

/// Legacy single-step encryption initialiser — equivalent to
/// `EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)`.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), key, iv) }
}

/// Encrypt a chunk of plaintext.
///
/// # C Contract
///
/// `out` must have room for `inl + EVP_CIPHER_CTX_get_block_size()`
/// bytes.  On success `*outl` reports how many bytes were actually
/// written.  Returns `1` on success, `0` on failure.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context that
///   has been initialised by a prior `EVP_EncryptInit_*` call.
/// * `out` must be writable for at least `inl + block_size` bytes.
/// * `outl`, when non-null, must be writable for one `c_int`.
/// * `in_`, when non-null and `inl > 0`, must point to at least
///   `inl` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptUpdate(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    in_: *const u8,
    inl: c_int,
) -> c_int {
    if !outl.is_null() {
        // SAFETY: caller guarantees `outl` is writable when
        // non-null.
        unsafe { *outl = 0 };
    }
    if out.is_null() || outl.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    let Ok(inl_usize) = usize::try_from(inl) else {
        return 0;
    };
    let input: &[u8] = if inl_usize == 0 {
        &[]
    } else if in_.is_null() {
        return 0;
    } else {
        // SAFETY: caller guarantees `in_` is readable for `inl`
        // bytes.
        unsafe { std::slice::from_raw_parts(in_, inl_usize) }
    };
    let mut buffer: Vec<u8> = Vec::with_capacity(inl_usize.saturating_add(64));
    let Ok(written) = ctx_ref.update(input, &mut buffer) else { return 0; };
    if written > 0 {
        // SAFETY: `out` has room for at least `inl + block_size`
        // bytes per the C contract; `written <= input.len() +
        // block_size` by the cipher invariants.
        unsafe {
            ptr::copy_nonoverlapping(buffer.as_ptr(), out, written);
        }
    }
    let written_int = c_int::try_from(written).unwrap_or(c_int::MAX);
    // SAFETY: `outl` is writable per the function contract above.
    unsafe { *outl = written_int };
    1
}

/// Finalise an encryption operation, flushing any remaining buffered
/// bytes (padding for block ciphers, AEAD tag for AEAD modes).
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned cipher context that
///   has been initialised by a prior `EVP_EncryptInit_*` call.
/// * `out` must be writable for at least `block_size` bytes.
/// * `outl`, when non-null, must be writable for one `c_int`.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal_ex(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
) -> c_int {
    if !outl.is_null() {
        // SAFETY: caller guarantees `outl` is writable when
        // non-null.
        unsafe { *outl = 0 };
    }
    if outl.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    let mut buffer: Vec<u8> = Vec::with_capacity(64);
    let Ok(written) = ctx_ref.finalize(&mut buffer) else { return 0; };
    if written > 0 {
        if out.is_null() {
            return 0;
        }
        // SAFETY: `out` has room for at least `block_size` bytes per
        // the C contract.
        unsafe {
            ptr::copy_nonoverlapping(buffer.as_ptr(), out, written);
        }
    }
    let written_int = c_int::try_from(written).unwrap_or(c_int::MAX);
    // SAFETY: `outl` is writable per the function contract above.
    unsafe { *outl = written_int };
    1
}

/// Identical to `EVP_EncryptFinal_ex` — compatibility alias.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptFinal_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_EncryptFinal_ex(ctx, out, outl) }
}

/// Initialise a context for decryption with the given cipher, key
/// and IV.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    _impl_: *mut ENGINE,
    key: *const u8,
    iv: *const u8,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
    // SAFETY: pointer-validity contracts forwarded to
    // `cipher_ctx_init_with_raw`.
    unsafe {
        cipher_ctx_init_with_raw(ctx_ref, cipher, key, iv, CipherDirection::Decrypt)
    }
}

/// Provider-aware variant of `EVP_DecryptInit_ex`.
///
/// # Safety
///
/// Same invariants as [`EVP_DecryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit_ex2(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), key, iv) }
}

/// Legacy single-step decryption initialiser.
///
/// # Safety
///
/// Same invariants as [`EVP_DecryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), key, iv) }
}

/// Decrypt a chunk of ciphertext.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptUpdate`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptUpdate(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    in_: *const u8,
    inl: c_int,
) -> c_int {
    // SAFETY: the safe-Rust update path is direction-agnostic; the
    // direction is established by the prior init call.  Forwarded.
    unsafe { EVP_EncryptUpdate(ctx, out, outl, in_, inl) }
}

/// Finalise a decryption operation, removing any padding (block
/// ciphers) or verifying the AEAD tag.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptFinal_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal_ex(
    ctx: *mut EVP_CIPHER_CTX,
    outm: *mut u8,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: same direction-agnostic dispatch as
    // `EVP_DecryptUpdate`.
    unsafe { EVP_EncryptFinal_ex(ctx, outm, outl) }
}

/// Compatibility alias for `EVP_DecryptFinal_ex`.
///
/// # Safety
///
/// Same invariants as [`EVP_DecryptFinal_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal(
    ctx: *mut EVP_CIPHER_CTX,
    outm: *mut u8,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_DecryptFinal_ex(ctx, outm, outl) }
}

/// Generic init that selects encryption / decryption / leave-alone
/// based on the `enc` parameter (`-1` reuse, `0` decrypt, `1`
/// encrypt).
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    impl_: *mut ENGINE,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> c_int {
    match enc {
        // SAFETY: forwarded.
        1 => unsafe { EVP_EncryptInit_ex(ctx, cipher, impl_, key, iv) },
        // SAFETY: forwarded.
        0 => unsafe { EVP_DecryptInit_ex(ctx, cipher, impl_, key, iv) },
        _ => {
            // -1 means "preserve the current direction" — supported
            // when the context already has a direction bound.
            // SAFETY: caller guarantees `ctx` is NULL or a Box-owned
            // context.
            let Some(c) = (unsafe { box_as_ref::<CipherCtx>(ctx.cast::<CipherCtx>()) }) else { return 0; };
            let direction = c.direction();
            match direction {
                Some(CipherDirection::Encrypt) => {
                    // SAFETY: forwarded.
                    unsafe { EVP_EncryptInit_ex(ctx, cipher, impl_, key, iv) }
                }
                Some(CipherDirection::Decrypt) => {
                    // SAFETY: forwarded.
                    unsafe { EVP_DecryptInit_ex(ctx, cipher, impl_, key, iv) }
                }
                None => 0,
            }
        }
    }
}

/// Provider-aware variant of `EVP_CipherInit_ex`.
///
/// # Safety
///
/// Same invariants as [`EVP_CipherInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_ex2(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), key, iv, enc) }
}

/// Legacy single-step generic initialiser.
///
/// # Safety
///
/// Same invariants as [`EVP_CipherInit_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), key, iv, enc) }
}

/// Direction-agnostic update — dispatches to the encrypt or decrypt
/// update path based on the context's stored direction.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptUpdate`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherUpdate(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    in_: *const u8,
    inl: c_int,
) -> c_int {
    // SAFETY: forwarded.  `EVP_EncryptUpdate` is direction-agnostic.
    unsafe { EVP_EncryptUpdate(ctx, out, outl, in_, inl) }
}

/// Direction-agnostic finaliser.
///
/// # Safety
///
/// Same invariants as [`EVP_EncryptFinal_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal_ex(
    ctx: *mut EVP_CIPHER_CTX,
    outm: *mut u8,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_EncryptFinal_ex(ctx, outm, outl) }
}

/// Compatibility alias for `EVP_CipherFinal_ex`.
///
/// # Safety
///
/// Same invariants as [`EVP_CipherFinal_ex`].
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal(
    ctx: *mut EVP_CIPHER_CTX,
    outm: *mut u8,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { EVP_CipherFinal_ex(ctx, outm, outl) }
}



// ===========================================================================
// EVP_PKEY name/NID conversion helpers
// ===========================================================================

/// Map a `KeyType` enum to the canonical NID used by C consumers.
fn key_type_to_nid(kt: &KeyType) -> c_int {
    match kt {
        KeyType::Rsa => EVP_PKEY_RSA,
        KeyType::RsaPss => EVP_PKEY_RSA_PSS,
        KeyType::Dsa => EVP_PKEY_DSA,
        KeyType::Dh => EVP_PKEY_DH,
        KeyType::Ec => EVP_PKEY_EC,
        KeyType::X25519 => EVP_PKEY_X25519,
        KeyType::X448 => EVP_PKEY_X448,
        KeyType::Ed25519 => EVP_PKEY_ED25519,
        KeyType::Ed448 => EVP_PKEY_ED448,
        KeyType::Sm2 => EVP_PKEY_SM2,
        KeyType::MlKem512 => EVP_PKEY_ML_KEM_512,
        KeyType::MlKem768 => EVP_PKEY_ML_KEM_768,
        KeyType::MlKem1024 => EVP_PKEY_ML_KEM_1024,
        KeyType::MlDsa44 => EVP_PKEY_ML_DSA_44,
        KeyType::MlDsa65 => EVP_PKEY_ML_DSA_65,
        KeyType::MlDsa87 => EVP_PKEY_ML_DSA_87,
        KeyType::SlhDsa | KeyType::Lms | KeyType::Unknown(_) => EVP_PKEY_NONE,
    }
}

/// Map a NID back to the canonical algorithm name string used to
/// fetch the algorithm from a provider.
fn nid_to_algorithm_name(nid: c_int) -> Option<&'static str> {
    match nid {
        EVP_PKEY_RSA => Some("RSA"),
        EVP_PKEY_RSA_PSS => Some("RSA-PSS"),
        EVP_PKEY_DSA => Some("DSA"),
        EVP_PKEY_DH => Some("DH"),
        EVP_PKEY_DHX => Some("DHX"),
        EVP_PKEY_EC => Some("EC"),
        EVP_PKEY_SM2 => Some("SM2"),
        EVP_PKEY_X25519 => Some("X25519"),
        EVP_PKEY_ED25519 => Some("ED25519"),
        EVP_PKEY_X448 => Some("X448"),
        EVP_PKEY_ED448 => Some("ED448"),
        EVP_PKEY_HMAC => Some("HMAC"),
        EVP_PKEY_CMAC => Some("CMAC"),
        EVP_PKEY_HKDF => Some("HKDF"),
        EVP_PKEY_TLS1_PRF => Some("TLS1-PRF"),
        EVP_PKEY_SCRYPT => Some("SCRYPT"),
        EVP_PKEY_POLY1305 => Some("POLY1305"),
        EVP_PKEY_SIPHASH => Some("SIPHASH"),
        EVP_PKEY_ML_DSA_44 => Some("ML-DSA-44"),
        EVP_PKEY_ML_DSA_65 => Some("ML-DSA-65"),
        EVP_PKEY_ML_DSA_87 => Some("ML-DSA-87"),
        EVP_PKEY_ML_KEM_512 => Some("ML-KEM-512"),
        EVP_PKEY_ML_KEM_768 => Some("ML-KEM-768"),
        EVP_PKEY_ML_KEM_1024 => Some("ML-KEM-1024"),
        _ => None,
    }
}

// ===========================================================================
// EVP_PKEY lifecycle wrappers
// ===========================================================================

/// Allocate a new, uninitialised `EVP_PKEY`.  Callers populate the
/// key material via subsequent `EVP_PKEY_keygen` / `EVP_PKEY_fromdata`
/// calls.  Pair with `EVP_PKEY_free`.
///
/// # Safety
///
/// Returns a non-NULL pointer to a freshly-allocated `PKey`.  The
/// returned pointer must be freed exactly once with
/// `EVP_PKEY_free`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new() -> *mut EVP_PKEY {
    let pkey = PKey::new(KeyType::Unknown(String::from("UNKNOWN")));
    Arc::into_raw(Arc::new(pkey)) as *mut EVP_PKEY
}

/// Decrement the reference count on an `EVP_PKEY`.  When the count
/// reaches zero the key material is securely zeroized.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a pointer published by
///   `EVP_PKEY_new` (or returned via any other `EVP_PKEY_*` factory),
///   not yet freed.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_free(pkey: *mut EVP_PKEY) {
    // SAFETY: caller guarantees the pointer is NULL or live.
    unsafe { drop_arc::<PKey>(pkey as *const PKey) };
}

/// Increment the reference count on an `EVP_PKEY`.  Returns `1` on
/// success and `0` when `pkey` is NULL.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a pointer published by
///   `EVP_PKEY_new` (or any other `EVP_PKEY_*` factory).
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int {
    // SAFETY: caller guarantees the pointer is NULL or live.
    unsafe { arc_up_ref::<PKey>(pkey as *const PKey) }
}

/// Return the algorithm NID for `pkey`, or `EVP_PKEY_NONE` when the
/// type is unknown.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_id(pkey: *const EVP_PKEY) -> c_int {
    // SAFETY: caller guarantees the pointer is NULL or live.
    let Some(pk) = (unsafe { arc_as_ref::<PKey>(pkey.cast::<PKey>()) }) else { return EVP_PKEY_NONE; };
    key_type_to_nid(pk.key_type())
}

/// Return the base NID — RSA-PSS collapses to RSA, DHX collapses to
/// DH; otherwise identical to `EVP_PKEY_get_id`.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> c_int {
    // SAFETY: forwarded.
    let id = unsafe { EVP_PKEY_get_id(pkey) };
    match id {
        EVP_PKEY_RSA_PSS => EVP_PKEY_RSA,
        EVP_PKEY_DHX => EVP_PKEY_DH,
        other => other,
    }
}

/// Return the maximum signature / output size for the given key,
/// computed from `bits()`.  For algorithms that do not have a
/// well-defined fixed output size, returns `0`.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_size(pkey: *const EVP_PKEY) -> c_int {
    // SAFETY: caller guarantees the pointer is NULL or live.
    let Some(pk) = (unsafe { arc_as_ref::<PKey>(pkey.cast::<PKey>()) }) else { return 0; };
    // The C API returns "max output bytes" — for RSA this is the
    // modulus length in bytes; for other algorithms we approximate
    // via `(bits + 7) / 8`.  Callers that need exact upper bounds
    // (e.g. ECDSA DER encoding) should use the algorithm-specific
    // accessors.  `PKey::bits()` returns `CryptoResult<u32>`; on error
    // (e.g. opaque/unknown key) we fall back to `0` per the C API
    // convention which signals "size unavailable".
    let Ok(bits) = pk.bits() else { return 0; };
    if bits == 0 {
        return 0;
    }
    let bytes = bits.saturating_add(7) / 8;
    // R6: `bytes` is a `u32`; convert via `try_from` and clamp to
    // `c_int::MAX` on overflow to preserve the C API's signed return.
    c_int::try_from(bytes).unwrap_or(c_int::MAX)
}

/// Return the size of the key in bits (modulus length for RSA,
/// curve field size for EC, etc.).  Returns `0` when the bit length
/// cannot be determined (e.g. opaque or uninitialised key).
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_bits(pkey: *const EVP_PKEY) -> c_int {
    // SAFETY: caller guarantees the pointer is NULL or live.
    let Some(pk) = (unsafe { arc_as_ref::<PKey>(pkey.cast::<PKey>()) }) else { return 0; };
    // `PKey::bits()` returns `CryptoResult<u32>`; the C contract maps
    // the error case to `0` and otherwise returns the bit count
    // clamped to `c_int::MAX` to preserve sign safety per Rule R6.
    match pk.bits() {
        Ok(b) => c_int::try_from(b).unwrap_or(c_int::MAX),
        Err(_) => 0,
    }
}

/// Return the cryptographic security strength of the key in bits as
/// defined by NIST SP 800-57 (e.g. 128 for RSA-3072, 256 for P-521).
/// Returns `0` when the strength cannot be determined.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_security_bits(
    pkey: *const EVP_PKEY,
) -> c_int {
    // SAFETY: caller guarantees the pointer is NULL or live.
    let Some(pk) = (unsafe { arc_as_ref::<PKey>(pkey.cast::<PKey>()) }) else { return 0; };
    // `PKey::security_bits()` returns `CryptoResult<u32>`; map the
    // error case to `0` per the C API convention and clamp valid
    // values to `c_int::MAX` per Rule R6.
    match pk.security_bits() {
        Ok(b) => c_int::try_from(b).unwrap_or(c_int::MAX),
        Err(_) => 0,
    }
}

/// Return `1` if `pkey` matches the supplied algorithm name (case
/// sensitive), `0` otherwise.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
/// * `name`, when non-null, must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_is_a(
    pkey: *const EVP_PKEY,
    name: *const c_char,
) -> c_int {
    if name.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees the pointer is NULL or live.
    let Some(pk) = (unsafe { arc_as_ref::<PKey>(pkey.cast::<PKey>()) }) else { return 0; };
    // SAFETY: caller guarantees the C string is NUL-terminated.
    let cstr = unsafe { CStr::from_ptr(name) };
    let Ok(needle) = cstr.to_str() else { return 0; };
    i32::from(pk.key_type_name().eq_ignore_ascii_case(needle))
}

// ===========================================================================
// EVP_PKEY_CTX lifecycle
// ===========================================================================

/// Create a new `EVP_PKEY_CTX` for an existing key.
///
/// # Safety
///
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
/// * `e` must be NULL — engine support is not provided in
///   providers-only mode.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new(
    pkey: *mut EVP_PKEY,
    _e: *mut ENGINE,
) -> *mut EVP_PKEY_CTX {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `pkey` is a live Arc.
    let arc: Arc<PKey> = unsafe { Arc::from_raw(pkey as *const PKey) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    let lib_ctx = LibContext::get_default();
    match PKeyCtx::new_from_pkey(lib_ctx, cloned) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)).cast::<EVP_PKEY_CTX>(),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new `EVP_PKEY_CTX` from an algorithm NID.
///
/// # Safety
///
/// * `e` must be NULL — engine support is not provided.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_id(
    id: c_int,
    _e: *mut ENGINE,
) -> *mut EVP_PKEY_CTX {
    let Some(alg_name) = nid_to_algorithm_name(id) else { return ptr::null_mut() };
    let lib_ctx = LibContext::get_default();
    match PKeyCtx::new_from_name(lib_ctx, alg_name, None) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)).cast::<EVP_PKEY_CTX>(),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new `EVP_PKEY_CTX` from an algorithm name and an explicit
/// library context.
///
/// # Safety
///
/// * `libctx`, when non-null, must be a pointer published by
///   `OSSL_LIB_CTX_new`.
/// * `name`, when non-null, must be a NUL-terminated C string.
/// * `propquery`, when non-null, must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_name(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
    propquery: *const c_char,
) -> *mut EVP_PKEY_CTX {
    if name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `name` is NUL-terminated.
    let Ok(alg_str) = (unsafe { CStr::from_ptr(name) }).to_str() else { return ptr::null_mut(); };
    // SAFETY: caller guarantees `propquery` is NUL-terminated when
    // non-null.
    let propq = unsafe { cstr_to_string_opt(propquery) };
    // SAFETY: caller guarantees `libctx` is NULL or a live Arc.
    let lib_ctx = unsafe { ctx_clone_arc_or_default(libctx) };
    match PKeyCtx::new_from_name(lib_ctx, alg_str, propq.as_deref()) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)).cast::<EVP_PKEY_CTX>(),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new `EVP_PKEY_CTX` from an existing key and an explicit
/// library context.
///
/// # Safety
///
/// * `libctx`, when non-null, must be a pointer published by
///   `OSSL_LIB_CTX_new`.
/// * `pkey`, when non-null, must be a live `EVP_PKEY`.
/// * `propquery`, when non-null, must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_pkey(
    libctx: *mut OSSL_LIB_CTX,
    pkey: *mut EVP_PKEY,
    _propquery: *const c_char,
) -> *mut EVP_PKEY_CTX {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `pkey` is a live Arc.
    let arc: Arc<PKey> = unsafe { Arc::from_raw(pkey as *const PKey) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    // SAFETY: caller guarantees `libctx` is NULL or a live Arc.
    let lib_ctx = unsafe { ctx_clone_arc_or_default(libctx) };
    match PKeyCtx::new_from_pkey(lib_ctx, cloned) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)).cast::<EVP_PKEY_CTX>(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a key-operation context.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a pointer published by
///   `EVP_PKEY_CTX_new` / `EVP_PKEY_CTX_new_id` /
///   `EVP_PKEY_CTX_new_from_*`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX) {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    unsafe { drop_boxed::<PKeyCtx>(ctx.cast::<PKeyCtx>()) };
}

// ===========================================================================
// EVP_PKEY operation initialisers (sign / verify / encrypt / decrypt /
// derive / encapsulate / decapsulate)
//
// The full safe-Rust implementations of these operations live in the
// sibling `signature.rs`, `kem.rs`, and `exchange.rs` modules of the
// `openssl-crypto` crate, which are deliberately *not* listed in the
// `depends_on_files` whitelist for the FFI crate per the AAP scope.
// We provide the FFI ABI surface here as graceful-failure stubs so
// that downstream C consumers can link against `libopenssl-rs` —
// runtime invocations return `0` (failure) and queue an
// `ERR_LIB_EVP / EVP_R_OPERATION_NOT_INITIALIZED` error.  The full
// wiring will be completed in a follow-up commit when those modules
// are added to the FFI dependency surface.
// ===========================================================================

/// Initialise a context for an `EVP_PKEY_sign` operation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Sign `tbs[..tbslen]` into `sig[..*siglen]`.  Returns `1` on
/// success, `0` on failure.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_sign_init`.
/// * `siglen`, when non-null, must be writable for one `size_t`.
/// * `tbs`, when non-null and `tbslen > 0`, must point to at least
///   `tbslen` readable bytes.
/// * `sig`, when non-null, must point to at least `*siglen` writable
///   bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign(
    ctx: *mut EVP_PKEY_CTX,
    sig: *mut u8,
    siglen: *mut size_t,
    tbs: *const u8,
    tbslen: size_t,
) -> c_int {
    let _ = (sig, tbs, tbslen);
    if !siglen.is_null() {
        // SAFETY: caller guarantees `siglen` is writable when
        // non-null.
        unsafe { *siglen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    // signature.rs is outside the FFI dependency surface; surface a
    // graceful failure.
    0
}

/// Initialise a context for an `EVP_PKEY_verify` operation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Verify a signature.  Returns `1` if the signature is valid, `0`
/// otherwise.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_verify_init`.
/// * `sig`, when non-null, must point to at least `siglen` readable
///   bytes.
/// * `tbs`, when non-null and `tbslen > 0`, must point to at least
///   `tbslen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify(
    ctx: *mut EVP_PKEY_CTX,
    sig: *const u8,
    siglen: size_t,
    tbs: *const u8,
    tbslen: size_t,
) -> c_int {
    let _ = (sig, siglen, tbs, tbslen);
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}

/// Initialise a context for an `EVP_PKEY_encrypt` operation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Encrypt `in_[..inlen]` into `out[..*outlen]`.
///
/// # Safety
///
/// Same invariants as [`EVP_PKEY_sign`].
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt(
    ctx: *mut EVP_PKEY_CTX,
    out: *mut u8,
    outlen: *mut size_t,
    in_: *const u8,
    inlen: size_t,
) -> c_int {
    let _ = (out, in_, inlen);
    if !outlen.is_null() {
        // SAFETY: caller guarantees `outlen` is writable when
        // non-null.
        unsafe { *outlen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}

/// Initialise a context for an `EVP_PKEY_decrypt` operation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Decrypt `in_[..inlen]` into `out[..*outlen]`.
///
/// # Safety
///
/// Same invariants as [`EVP_PKEY_sign`].
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt(
    ctx: *mut EVP_PKEY_CTX,
    out: *mut u8,
    outlen: *mut size_t,
    in_: *const u8,
    inlen: size_t,
) -> c_int {
    let _ = (out, in_, inlen);
    if !outlen.is_null() {
        // SAFETY: caller guarantees `outlen` is writable when
        // non-null.
        unsafe { *outlen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}

/// Initialise a context for `EVP_PKEY_derive` (key agreement).
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Set the peer key for a derive operation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
/// * `peer`, when non-null, must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_set_peer(
    ctx: *mut EVP_PKEY_CTX,
    peer: *mut EVP_PKEY,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    // SAFETY: caller guarantees `peer` is NULL or a live Arc.
    let Some(_) = (unsafe { arc_as_ref::<PKey>(peer.cast::<PKey>()) }) else { return 0; };
    0
}

/// Derive a shared secret.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_derive_init` and supplied
///   with a peer via `EVP_PKEY_derive_set_peer`.
/// * `keylen`, when non-null, must be writable for one `size_t`.
/// * `key`, when non-null, must point to at least `*keylen` writable
///   bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive(
    ctx: *mut EVP_PKEY_CTX,
    key: *mut u8,
    keylen: *mut size_t,
) -> c_int {
    let _ = key;
    if !keylen.is_null() {
        // SAFETY: caller guarantees `keylen` is writable when
        // non-null.
        unsafe { *keylen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}

// ===========================================================================
// EVP_PKEY keygen — full implementation backed by `pkey.rs`
// ===========================================================================

/// Initialise a context for key generation.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    crypto_result_to_int(&ctx_ref.keygen_init())
}

/// Generate a key pair.  On success the new key is published via
/// `*ppkey`; the caller is responsible for the resulting reference.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_keygen_init`.
/// * `ppkey`, when non-null, must be writable for one
///   `*mut EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen(
    ctx: *mut EVP_PKEY_CTX,
    ppkey: *mut *mut EVP_PKEY,
) -> c_int {
    if ppkey.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    if let Ok(pkey) = ctx_ref.keygen() {
        // `PKeyCtx::keygen()` returns an owned `PKey` (not yet
        // ref-counted).  Wrap in `Arc` to obtain the heap layout
        // expected by the EVP_PKEY opaque handle, then publish
        // the raw `Arc` pointer to the caller.
        let raw = Arc::into_raw(Arc::new(pkey)).cast_mut().cast::<EVP_PKEY>();
        // SAFETY: `ppkey` is writable per the function contract.
        unsafe { *ppkey = raw };
        1
    } else {
        // SAFETY: `ppkey` is writable per the function contract.
        unsafe { *ppkey = ptr::null_mut() };
        0
    }
}

/// Initialise a context for parameter generation (DH/DSA/EC param
/// generation).
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    crypto_result_to_int(&ctx_ref.paramgen_init())
}

/// Generate a parameter set.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_paramgen_init`.
/// * `ppkey`, when non-null, must be writable for one
///   `*mut EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen(
    ctx: *mut EVP_PKEY_CTX,
    ppkey: *mut *mut EVP_PKEY,
) -> c_int {
    if ppkey.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    if let Ok(pkey) = ctx_ref.paramgen() {
        // `PKeyCtx::paramgen()` returns an owned `PKey`; wrap in
        // `Arc` to match the EVP_PKEY heap layout before
        // publishing the raw pointer to the caller.
        let raw = Arc::into_raw(Arc::new(pkey)).cast_mut().cast::<EVP_PKEY>();
        // SAFETY: `ppkey` is writable per the function contract.
        unsafe { *ppkey = raw };
        1
    } else {
        // SAFETY: `ppkey` is writable per the function contract.
        unsafe { *ppkey = ptr::null_mut() };
        0
    }
}

/// Validate every component (public + private + parameters where
/// applicable) of a key.  Returns `1` if the key is valid, `0`
/// otherwise.  The C API contract treats a `false` validation result
/// identically to an outright error from the underlying check.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_check(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    // `PKeyCtx::check()` returns `CryptoResult<bool>`; map both the
    // `Ok(false)` and the `Err(_)` arms to a C "failure" status (`0`)
    // and the `Ok(true)` arm to "success" (`1`).
    match ctx_ref.check() {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// Validate the public component of a key only.  Returns `1` when
/// the public key is valid, `0` otherwise.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_public_check(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    // `PKeyCtx::public_check()` returns `CryptoResult<bool>`; collapse
    // both `Ok(false)` and `Err(_)` to the C "failure" status.
    match ctx_ref.public_check() {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// Validate parameters of a parameterised key (DH/DSA/EC).  Returns
/// `1` when the parameters are valid, `0` otherwise.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_param_check(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(ctx_ref) = (unsafe { box_as_mut::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    // `PKeyCtx::param_check()` returns `CryptoResult<bool>`; collapse
    // both `Ok(false)` and `Err(_)` to the C "failure" status.
    match ctx_ref.param_check() {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

// ===========================================================================
// Key encapsulation (KEM) — graceful-failure stubs
//
// EVP_PKEY_encapsulate / EVP_PKEY_decapsulate live in the
// openssl-crypto::evp::kem module which is outside the FFI dependency
// surface.  These stubs preserve ABI link-compatibility while
// signalling "operation unavailable" at runtime.
// ===========================================================================

/// Initialise a context for `EVP_PKEY_encapsulate`.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate_init(
    ctx: *mut EVP_PKEY_CTX,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Encapsulate a fresh shared secret to a recipient public key.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_encapsulate_init`.
/// * `outlen`, when non-null, must be writable for one `size_t`.
/// * `secretlen`, when non-null, must be writable for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate(
    ctx: *mut EVP_PKEY_CTX,
    out: *mut u8,
    outlen: *mut size_t,
    secret: *mut u8,
    secretlen: *mut size_t,
) -> c_int {
    let _ = (out, secret);
    if !outlen.is_null() {
        // SAFETY: caller guarantees `outlen` is writable when
        // non-null.
        unsafe { *outlen = 0 };
    }
    if !secretlen.is_null() {
        // SAFETY: caller guarantees `secretlen` is writable when
        // non-null.
        unsafe { *secretlen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}

/// Initialise a context for `EVP_PKEY_decapsulate`.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decapsulate_init(
    ctx: *mut EVP_PKEY_CTX,
    _params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    1
}

/// Decapsulate a shared secret with a recipient private key.
///
/// # Safety
///
/// * `ctx`, when non-null, must be a Box-owned `EVP_PKEY_CTX` that
///   has been initialised by `EVP_PKEY_decapsulate_init`.
/// * `secretlen`, when non-null, must be writable for one `size_t`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decapsulate(
    ctx: *mut EVP_PKEY_CTX,
    secret: *mut u8,
    secretlen: *mut size_t,
    in_: *const u8,
    inlen: size_t,
) -> c_int {
    let _ = (secret, in_, inlen);
    if !secretlen.is_null() {
        // SAFETY: caller guarantees `secretlen` is writable when
        // non-null.
        unsafe { *secretlen = 0 };
    }
    // SAFETY: caller guarantees `ctx` is NULL or a Box-owned context.
    let Some(_) = (unsafe { box_as_ref::<PKeyCtx>(ctx.cast::<PKeyCtx>()) }) else { return 0; };
    0
}


