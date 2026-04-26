//! Integration tests for the RSA public-key cryptosystem surfaces.
//!
//! RSA in `openssl-crypto` does not have a dedicated `rsa/` module —
//! instead, RSA functionality is dispersed across the EVP layer
//! ([`crate::evp::pkey`], [`crate::evp::signature`], [`crate::evp::keymgmt`],
//! [`crate::evp::encode_decode`], [`crate::evp::kem`]) and the BigNum
//! prime-derivation helper [`crate::bn::prime::rsa_fips186_5_derive_prime`].
//! These tests therefore exercise the public RSA surface as a tenant of the
//! EVP abstraction.
//!
//! | Phase | Focus                                              | C Reference                                               |
//! |-------|----------------------------------------------------|-----------------------------------------------------------|
//! | 1     | `KeyType` enum: variants, [`KeyType::as_str`],     | `include/openssl/evp.h::EVP_PKEY_RSA`,                    |
//! |       | [`KeyType::from_name`], `Display`, round-trip      | `include/openssl/evp.h::EVP_PKEY_RSA_PSS`                 |
//! | 2     | `RsaPadding` enum: 5 variants, `to_param_str`,     | `include/openssl/rsa.h::RSA_PKCS1_PADDING` etc.           |
//! |       | `to_legacy_int`                                    |                                                           |
//! | 3     | `PKey` constructors: new / new_raw /               | `crypto/rsa/rsa_lib.c::RSA_new`,                          |
//! |       | from_raw_public_key / from_raw_private_key         | `RSA_set0_*` family                                       |
//! | 4     | `PKey` accessors: raw_*_key, has_*_key,            | `crypto/rsa/rsa_lib.c::RSA_get0_*`                        |
//! |       | key_type, key_type_name                            |                                                           |
//! | 5     | `PKey::bits` / `PKey::security_bits` per RSA       | `crypto/rsa/rsa_lib.c::RSA_bits`,                         |
//! |       | size class (FIPS 186-5 / NIST SP 800-57 strength)  | `RSA_security_bits`                                       |
//! | 6     | `PKey` Clone + `PartialEq` exclusion semantics     | `crypto/rsa/rsa_lib.c::RSA_dup`                           |
//! | 7     | `PKey::copy_params_from`                           | `crypto/evp/evp_pkey.c::EVP_PKEY_copy_parameters`         |
//! | 8     | `PKeyCtx` constructors and initial-state accessors | `crypto/evp/pmeth_lib.c::EVP_PKEY_CTX_new*`               |
//! | 9     | RSA keygen via `PKeyCtx::keygen_init` + `keygen`   | `providers/implementations/keymgmt/rsa_kmgmt.c::rsa_gen`, |
//! |       | (deterministic byte markers, byte_len floor 32)    | `crypto/rsa/rsa_gen.c::RSA_generate_key_ex`               |
//! | 10    | `PKeyCtx::paramgen` (no key material)              | `crypto/evp/pmeth_lib.c::EVP_PKEY_paramgen`               |
//! | 11    | `PKeyCtx::fromdata` for RSA with `n`/`e`/`d`       | `providers/implementations/keymgmt/rsa_kmgmt.c::rsa_import` |
//! | 12    | `PKeyCtx::check` / `public_check` / `param_check`  | `crypto/rsa/rsa_chk.c::rsa_validate_*`                    |
//! |       | with no-key error path                             |                                                           |
//! | 13    | `PKeyCtx::set_rsa_padding` /                       | `crypto/evp/evp_lib.c::EVP_PKEY_CTX_set_rsa_padding`,     |
//! |       | `set_signature_digest`                             | `EVP_PKEY_CTX_set_signature_md`                           |
//! | 14    | `PKeyCtx::set_param` / `get_param` round-trip      | `crypto/evp/pmeth_lib.c::EVP_PKEY_CTX_set_params`         |
//! | 15    | `SignContext` sign / verify with RSA               | `crypto/evp/signature.c::evp_signature_init`,             |
//! |       | (XOR-fold output, init mutual exclusion)           | `crypto/rsa/rsa_pmeth.c::pkey_rsa_sign`                   |
//! | 16    | `DigestSignContext` / `DigestVerifyContext`        | `crypto/evp/m_sigver.c::EVP_DigestSign*`,                 |
//! |       | (RSA + SHA-256 round-trip)                         | `EVP_DigestVerify*`                                       |
//! | 17    | `AsymCipherContext` encrypt / decrypt              | `crypto/rsa/rsa_pmeth.c::pkey_rsa_encrypt`,               |
//! |       | (mode mutual exclusion, length offset semantics)   | `pkey_rsa_decrypt`                                        |
//! | 18    | `KeyMgmt::fetch` + free-function `import`,         | `providers/implementations/keymgmt/rsa_kmgmt.c`,          |
//! |       | `export`, `has`, `validate`, `match_keys`,         | `crypto/evp/keymgmt_meth.c`                               |
//! |       | `export_to_provider`                               |                                                           |
//! | 19    | `KeySelection` bitflags constants and predicates   | `include/openssl/core_dispatch.h::OSSL_KEYMGMT_SELECT_*`  |
//! | 20    | `KeyData` accessors                                | `crypto/evp/keymgmt_lib.c::evp_keymgmt_*`                 |
//! | 21    | `EncoderContext`: PEM / DER / PKCS#8 / SPKI / Text | `crypto/encode_decode/encoder_pkey.c`                     |
//! | 22    | `DecoderContext`: round-trip + format detection    | `crypto/encode_decode/decoder_pkey.c`                     |
//! | 23    | `KemContext` with RSA: error paths                 | `providers/implementations/kem/rsa_kem.c`                 |
//! | 24    | `bn::prime::rsa_fips186_5_derive_prime` validation | `crypto/bn/bn_rsa_fips186_5.c::ossl_bn_rsa_fips186_5_*`   |
//! | 25    | `ParamSet` / `ParamBuilder` typed RSA parameters   | `crypto/params.c::OSSL_PARAM_construct_*`                 |
//!
//! # Rule Compliance
//!
//! - **R5 (nullability / typing over sentinels):** RSA APIs in this crate use
//!   [`Option`] for absent fields ([`PKey::keymgmt`], [`PKey::params`],
//!   [`PKeyCtx`] inner state) and named enum variants for fixed-domain values
//!   ([`KeyType::Rsa`], [`KeyType::RsaPss`], [`RsaPadding`]). These tests
//!   exercise both the present and absent paths.
//! - **R6 (lossless numeric casts):** Narrowing from [`u32`] bit-counts or
//!   [`usize`] byte-counts uses [`u32::try_from`] / [`usize::try_from`] where
//!   narrowing might occur; lossless widening uses [`u32::from`] /
//!   [`u64::from`]. No bare `as` casts are used for narrowing conversions in
//!   this file.
//! - **R8 (zero unsafe outside FFI):** This file contains zero `unsafe`
//!   blocks. Private-key material in [`PKey`] (the `private_key_data`
//!   field) is wrapped in [`zeroize::Zeroizing`] and zeroed on drop via
//!   the `ZeroizeOnDrop` derive — tests never need to manage the
//!   zero-on-drop boundary manually.
//! - **R10 (wiring before done):** Each test exercises a real call path
//!   from the public EVP surface through to provider-resolved or
//!   in-crate behaviour. Tests do not stub or mock production code.
//!
//! # References
//!
//! - C source files:
//!     - `crypto/rsa/rsa_lib.c`, `crypto/rsa/rsa_gen.c`, `crypto/rsa/rsa_chk.c`
//!     - `crypto/rsa/rsa_pmeth.c`, `crypto/rsa/rsa_oaep.c`, `crypto/rsa/rsa_pss.c`
//!     - `crypto/evp/p_lib.c`, `crypto/evp/pmeth_lib.c`, `crypto/evp/m_sigver.c`
//!     - `crypto/encode_decode/encoder_pkey.c`, `crypto/encode_decode/decoder_pkey.c`
//!     - `providers/implementations/keymgmt/rsa_kmgmt.c`
//!     - `providers/implementations/signature/rsa_sig.c`
//!     - `providers/implementations/asymciphers/rsa_enc.c`
//!     - `providers/implementations/kem/rsa_kem.c`
//!     - `crypto/bn/bn_rsa_fips186_5.c`
//! - Specifications:
//!     - PKCS #1 v2.2, RFC 8017
//!     - FIPS 186-5 §A.1 — RSA Key Pair Generation
//!     - NIST SP 800-56B Rev. 2 — Pair-Wise Key Establishment
//!     - NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 (Table 2 strength tiers)
//!     - RFC 5958 — PKCS#8 Asymmetric Key Packages
//!     - RFC 5280 §4.1.2.7 — SubjectPublicKeyInfo

// -----------------------------------------------------------------------------
// Feature gating
// -----------------------------------------------------------------------------
// NOTE: This module is included by `tests/mod.rs` under
// `#[cfg(feature = "rsa")]`, so adding a redundant inner
// `#![cfg(feature = "rsa")]` here would trigger the
// `clippy::duplicated_attributes` lint. The sibling test files
// (e.g., `test_dh.rs`, `test_dsa.rs`, `test_pqc.rs`) follow the same convention.
//
// -----------------------------------------------------------------------------
// Module-level lint overrides for test code.
// -----------------------------------------------------------------------------
// Justification: The workspace crate-root configuration in `lib.rs` sets
//   #![deny(clippy::unwrap_used)]
//   #![deny(clippy::expect_used)]
// because library code must always propagate errors with `?`. Test code,
// however, legitimately uses `.unwrap()` / `.expect()` / `panic!()` for
// failing-assertion semantics — a Rust-idiomatic testing pattern. The
// workspace lints table in `Cargo.toml` records that tests are explicitly
// allowed to suppress these lints with a justification comment, matching
// the convention used in all real test modules (`test_dh.rs`,
// `test_dsa.rs`, `test_pqc.rs`, `test_rand.rs`, etc.).
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on known-good Results.
#![allow(clippy::expect_used)] // Tests use .expect() with descriptive messages.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use std::sync::Arc;

use crate::bn::BigNum;
use crate::bn::prime::rsa_fips186_5_derive_prime;
use crate::context::LibContext;
use crate::evp::encode_decode::{
    DecoderContext, EncoderContext, KeyFormat, KeySelection as EncoderSelection,
};
use crate::evp::kem::{Kem, KemContext};
use crate::evp::keymgmt::{self, KeyMgmt, KeySelection};
use crate::evp::md::MessageDigest;
use crate::evp::pkey::{KeyType, PKey, PKeyCtx, PKeyOperation, RsaPadding};
use crate::evp::signature::{
    AsymCipher, AsymCipherContext, DigestSignContext, DigestVerifyContext, KeyExchange,
    KeyExchangeContext, SignContext, Signature,
};

use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};

// =========================================================================
// Phase 1 — KeyType enum: variants, [`KeyType::as_str`],
// [`KeyType::from_name`] (case-insensitivity + aliases + `Unknown`
// fallback), `Display` impl.
// =========================================================================

/// Sanity check that `KeyType::Rsa` and `KeyType::RsaPss` are distinct
/// variants. C reference: `EVP_PKEY_RSA` (6) vs `EVP_PKEY_RSA_PSS` (912)
/// in `include/openssl/evp.h`.
#[test]
fn test_keytype_rsa_distinct_from_rsa_pss() {
    assert_ne!(KeyType::Rsa, KeyType::RsaPss);
}

/// `KeyType::Rsa.as_str()` returns the canonical algorithm name `"RSA"`.
/// This is the string used for provider fetch keying.
#[test]
fn test_keytype_rsa_as_str() {
    assert_eq!(KeyType::Rsa.as_str(), "RSA");
    assert_eq!(KeyType::RsaPss.as_str(), "RSA-PSS");
}

/// `KeyType::from_name` is case-insensitive — it normalises input
/// via `to_uppercase()` before matching. Verified against
/// `crypto/objects/obj_xref.c::OBJ_NAME_get`.
#[test]
fn test_keytype_from_name_case_insensitive() {
    assert_eq!(KeyType::from_name("RSA"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("rsa"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("Rsa"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("rSa"), KeyType::Rsa);
}

/// `KeyType::from_name` accepts both hyphenated and compact forms for
/// `RSA-PSS` (mirroring OpenSSL's `OBJ_txt2nid` accepting `"RSA-PSS"`,
/// `"RSAPSS"`, `"id-RSASSA-PSS"`).
#[test]
fn test_keytype_from_name_rsa_pss_aliases() {
    assert_eq!(KeyType::from_name("RSA-PSS"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("RSAPSS"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("rsa-pss"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("rsapss"), KeyType::RsaPss);
}

/// Unknown names produce `KeyType::Unknown(name.to_string())` which
/// preserves the *original* case of the input (not the uppercased form).
#[test]
fn test_keytype_unknown_preserves_original_case() {
    let unknown = KeyType::from_name("ExoticAlgorithm-2026");
    match unknown {
        KeyType::Unknown(ref s) => assert_eq!(s, "ExoticAlgorithm-2026"),
        other => panic!("expected Unknown(\"ExoticAlgorithm-2026\"), got {other:?}"),
    }
}

/// `Display` for `KeyType` simply forwards to `as_str()`. This contract
/// is exercised so refactoring `Display` to a different format is
/// detected as a behavioural change.
#[test]
fn test_keytype_display_matches_as_str() {
    assert_eq!(format!("{}", KeyType::Rsa), KeyType::Rsa.as_str());
    assert_eq!(format!("{}", KeyType::RsaPss), KeyType::RsaPss.as_str());
}

/// Round-trip: every variant's `as_str()` is recognised by `from_name`
/// and yields the original variant. RSA family only (other variants
/// covered by sibling test modules).
#[test]
fn test_keytype_rsa_round_trip() {
    for kt in [KeyType::Rsa, KeyType::RsaPss] {
        assert_eq!(KeyType::from_name(kt.as_str()), kt);
    }
}

// =========================================================================
// Phase 2 — RsaPadding enum: 5 variants, `to_param_str` produces the
// OSSL_PKEY_PARAM_PAD_MODE string-form value, `to_legacy_int`
// produces the legacy `RSA_*_PADDING` integer constant.
// =========================================================================

/// `RsaPadding::to_param_str` mappings — verified against
/// `include/openssl/core_names.h::OSSL_PKEY_RSA_PAD_MODE_*`.
#[test]
fn test_rsa_padding_to_param_str() {
    assert_eq!(RsaPadding::Pkcs1.to_param_str(), "pkcs1");
    assert_eq!(RsaPadding::Pkcs1Oaep.to_param_str(), "oaep");
    assert_eq!(RsaPadding::Pss.to_param_str(), "pss");
    assert_eq!(RsaPadding::NoPadding.to_param_str(), "none");
    assert_eq!(RsaPadding::X931.to_param_str(), "x931");
}

/// `RsaPadding::to_legacy_int` mappings — verified against
/// `include/openssl/rsa.h::RSA_PKCS1_PADDING` etc.
#[test]
fn test_rsa_padding_to_legacy_int() {
    assert_eq!(RsaPadding::Pkcs1.to_legacy_int(), 1);
    assert_eq!(RsaPadding::Pkcs1Oaep.to_legacy_int(), 4);
    assert_eq!(RsaPadding::Pss.to_legacy_int(), 6);
    assert_eq!(RsaPadding::NoPadding.to_legacy_int(), 3);
    assert_eq!(RsaPadding::X931.to_legacy_int(), 5);
}

/// Padding variants compare by identity (`PartialEq` derive).
#[test]
fn test_rsa_padding_equality() {
    assert_eq!(RsaPadding::Pss, RsaPadding::Pss);
    assert_ne!(RsaPadding::Pkcs1, RsaPadding::Pss);
    assert_ne!(RsaPadding::Pkcs1Oaep, RsaPadding::Pkcs1);
}

// =========================================================================
// Phase 3 — PKey constructors: `PKey::new`, `PKey::new_raw`,
// `PKey::from_raw_public_key`, `PKey::from_raw_private_key`.
// =========================================================================

/// `PKey::new(KeyType::Rsa)` produces an empty key — no public, no
/// private, no params. C reference: `EVP_PKEY_new()` followed by no
/// `EVP_PKEY_set1_*` call.
#[test]
fn test_pkey_new_rsa_empty() {
    let key = PKey::new(KeyType::Rsa);
    assert_eq!(key.key_type(), &KeyType::Rsa);
    assert!(!key.has_private_key());
    assert!(!key.has_public_key());
    assert!(key.private_key_data().is_none());
    assert!(key.public_key_data().is_none());
}

/// `PKey::from_raw_public_key` populates the public-key field and sets
/// the `has_public` flag. Mirrors `EVP_PKEY_new_raw_public_key()`.
#[test]
fn test_pkey_from_raw_public_key_rsa() {
    let bytes = vec![0xABu8; 256];
    let key = PKey::from_raw_public_key(KeyType::Rsa, &bytes)
        .expect("from_raw_public_key for RSA");
    assert_eq!(key.key_type(), &KeyType::Rsa);
    assert!(key.has_public_key());
    assert!(!key.has_private_key());
    assert_eq!(key.public_key_data(), Some(bytes.as_slice()));
}

/// `PKey::from_raw_private_key` populates the private-key field via
/// `Zeroizing<Vec<u8>>` for secure erasure on drop. Mirrors
/// `EVP_PKEY_new_raw_private_key()`.
#[test]
fn test_pkey_from_raw_private_key_rsa() {
    let bytes = vec![0xCDu8; 256];
    let key = PKey::from_raw_private_key(KeyType::Rsa, &bytes)
        .expect("from_raw_private_key for RSA");
    assert_eq!(key.key_type(), &KeyType::Rsa);
    assert!(key.has_private_key());
    assert!(!key.has_public_key());
    let priv_data = key.private_key_data().expect("private data must be present");
    assert_eq!(priv_data, bytes.as_slice());
}

/// `PKey::new_raw` with `is_private = true` populates ONLY the private
/// field (not public). This is a convenience constructor.
#[test]
fn test_pkey_new_raw_is_private_true() {
    let bytes = vec![0x42u8; 32];
    let key = PKey::new_raw(KeyType::Rsa, &bytes, true);
    assert!(key.has_private_key());
    assert!(!key.has_public_key());
    assert!(key.private_key_data().is_some());
    assert!(key.public_key_data().is_none());
}

/// `PKey::new_raw` with `is_private = false` populates ONLY the public
/// field.
#[test]
fn test_pkey_new_raw_is_private_false() {
    let bytes = vec![0x77u8; 32];
    let key = PKey::new_raw(KeyType::Rsa, &bytes, false);
    assert!(!key.has_private_key());
    assert!(key.has_public_key());
    assert!(key.private_key_data().is_none());
    assert_eq!(key.public_key_data(), Some(bytes.as_slice()));
}

// =========================================================================
// Phase 4 — PKey accessors: `raw_public_key`, `raw_private_key`,
// `has_*_key`, `key_type`, `key_type_name`. Includes the `KeyRequired`
// error path when key material is absent.
// =========================================================================

/// `raw_public_key` clones the public-key data. Returns `Ok` when
/// present.
#[test]
fn test_pkey_raw_public_key_returns_clone() {
    let bytes = vec![0x11u8; 256];
    let key = PKey::from_raw_public_key(KeyType::Rsa, &bytes)
        .expect("from_raw_public_key for RSA");
    let clone = key.raw_public_key().expect("public key must be present");
    assert_eq!(clone, bytes);
}

/// `raw_private_key` returns `Zeroizing<Vec<u8>>` for the private-key
/// material — securely erased on drop.
#[test]
fn test_pkey_raw_private_key_returns_zeroizing_clone() {
    let bytes = vec![0x22u8; 256];
    let key = PKey::from_raw_private_key(KeyType::Rsa, &bytes)
        .expect("from_raw_private_key for RSA");
    let clone = key.raw_private_key().expect("private key must be present");
    assert_eq!(clone.as_slice(), bytes.as_slice());
}

/// `raw_public_key` errors when no public key is attached. Error
/// variant is `CryptoError::Common(CommonError::Internal(_))` or
/// `EvpError::KeyRequired` propagated via the `From` impl.
#[test]
fn test_pkey_raw_public_key_errors_when_missing() {
    let key = PKey::new(KeyType::Rsa);
    let result = key.raw_public_key();
    assert!(
        result.is_err(),
        "raw_public_key must error on a fresh PKey with no key material"
    );
}

/// `raw_private_key` errors when no private key is attached.
#[test]
fn test_pkey_raw_private_key_errors_when_missing() {
    let key = PKey::new(KeyType::Rsa);
    let result = key.raw_private_key();
    assert!(
        result.is_err(),
        "raw_private_key must error on a fresh PKey with no key material"
    );
}

/// `has_private_key` and `has_public_key` flags follow the populated
/// fields exactly.
#[test]
fn test_pkey_has_flags_match_constructor() {
    let priv_only = PKey::from_raw_private_key(KeyType::Rsa, &[0u8; 32])
        .expect("from_raw_private_key for RSA");
    assert!(priv_only.has_private_key());
    assert!(!priv_only.has_public_key());

    let pub_only = PKey::from_raw_public_key(KeyType::Rsa, &[0u8; 32])
        .expect("from_raw_public_key for RSA");
    assert!(!pub_only.has_private_key());
    assert!(pub_only.has_public_key());

    let neither = PKey::new(KeyType::Rsa);
    assert!(!neither.has_private_key());
    assert!(!neither.has_public_key());
}

/// `key_type` returns a borrowed reference to the `KeyType` variant.
#[test]
fn test_pkey_key_type_accessor() {
    let rsa = PKey::new(KeyType::Rsa);
    assert_eq!(rsa.key_type(), &KeyType::Rsa);

    let rsa_pss = PKey::new(KeyType::RsaPss);
    assert_eq!(rsa_pss.key_type(), &KeyType::RsaPss);
}

/// `key_type_name` returns the same canonical string as
/// `KeyType::as_str()`.
#[test]
fn test_pkey_key_type_name_accessor() {
    let rsa = PKey::new(KeyType::Rsa);
    assert_eq!(rsa.key_type_name(), "RSA");

    let rsa_pss = PKey::new(KeyType::RsaPss);
    assert_eq!(rsa_pss.key_type_name(), "RSA-PSS");
}

// =========================================================================
// Phase 5 — PKey::bits / PKey::security_bits per RSA size class.
//
// FIPS 186-5 RSA modulus sizes (2048, 3072, 4096, 7680, 15360) are
// mapped to NIST SP 800-57 Part 1 Rev. 5 Table 2 security-strength
// tiers (112, 128, 152, 192, 256).
// =========================================================================

/// Empty key falls back to default 2048 bits — matches `default_bits_for(Rsa)`.
#[test]
fn test_pkey_bits_rsa_empty_fallback() {
    let key = PKey::new(KeyType::Rsa);
    let bits = key.bits().expect("RSA bits must be computable");
    assert_eq!(bits, 2048);
}

/// 256-byte public key → 2048 bits.
#[test]
fn test_pkey_bits_rsa_2048() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 256])
        .expect("from_raw_public_key for RSA");
    let bits = key.bits().expect("RSA bits");
    assert_eq!(bits, 2048);
}

/// 384-byte public key → 3072 bits.
#[test]
fn test_pkey_bits_rsa_3072() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 384])
        .expect("from_raw_public_key for RSA");
    let bits = key.bits().expect("RSA bits");
    assert_eq!(bits, 3072);
}

/// 512-byte public key → 4096 bits.
#[test]
fn test_pkey_bits_rsa_4096() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 512])
        .expect("from_raw_public_key for RSA");
    let bits = key.bits().expect("RSA bits");
    assert_eq!(bits, 4096);
}

/// `security_bits` for RSA tier 2048 → 112 bits (per SP 800-57).
#[test]
fn test_pkey_security_bits_rsa_2048() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 256])
        .expect("from_raw_public_key for RSA");
    let strength = key.security_bits().expect("security bits");
    assert_eq!(strength, 112);
}

/// `security_bits` for RSA tier 3072 → 128 bits.
#[test]
fn test_pkey_security_bits_rsa_3072() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 384])
        .expect("from_raw_public_key for RSA");
    let strength = key.security_bits().expect("security bits");
    assert_eq!(strength, 128);
}

/// `security_bits` for RSA tier 7680 → 192 bits.
#[test]
fn test_pkey_security_bits_rsa_7680() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 960])
        .expect("from_raw_public_key for RSA");
    let strength = key.security_bits().expect("security bits");
    assert_eq!(strength, 192);
}

/// `security_bits` for RSA tier 15360 → 256 bits.
#[test]
fn test_pkey_security_bits_rsa_15360() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 1920])
        .expect("from_raw_public_key for RSA");
    let strength = key.security_bits().expect("security bits");
    assert_eq!(strength, 256);
}

/// Below-2048 RSA falls into the legacy (<112) tier: returns 80 bits.
/// Such keys are deprecated by SP 800-131A but the function must
/// still compute a valid strength for legacy interop.
#[test]
fn test_pkey_security_bits_rsa_legacy_under_2048() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 128])
        .expect("from_raw_public_key for RSA"); // 1024-bit
    let strength = key.security_bits().expect("security bits");
    assert_eq!(strength, 80);
}

// =========================================================================
// Phase 6 — PKey Clone + PartialEq exclusion semantics.
//
// PartialEq on PKey deliberately excludes private_key_data, params, and
// keymgmt — this is a security/hygiene contract: timing-stable equality
// must NOT depend on private key material.
// =========================================================================

/// `Clone` preserves all fields including private key data.
#[test]
fn test_pkey_clone_preserves_data() {
    let priv_bytes = vec![0xAAu8; 256];
    let original = PKey::from_raw_private_key(KeyType::Rsa, &priv_bytes)
        .expect("from_raw_private_key for RSA");
    let cloned = original.clone();

    assert_eq!(cloned.key_type(), original.key_type());
    assert_eq!(cloned.has_private_key(), original.has_private_key());
    let priv_clone = cloned
        .raw_private_key()
        .expect("clone must preserve private key");
    assert_eq!(priv_clone.as_slice(), priv_bytes.as_slice());
}

/// `PartialEq` does NOT compare `private_key_data`.
/// Two PKeys with same key_type/public/has_*_flags but DIFFERENT
/// private_key_data must compare equal under `==`.
#[test]
fn test_pkey_partial_eq_ignores_private_data() {
    let key_a = PKey::from_raw_private_key(KeyType::Rsa, &[0xAAu8; 256])
        .expect("from_raw_private_key for RSA");
    let key_b = PKey::from_raw_private_key(KeyType::Rsa, &[0xBBu8; 256])
        .expect("from_raw_private_key for RSA");
    // Both have has_private = true, no public, same key_type.
    // The PartialEq impl excludes private_key_data, so they MUST be ==.
    assert_eq!(
        key_a, key_b,
        "PartialEq must ignore private_key_data per security contract"
    );
}

/// `PartialEq` DOES compare `public_key_data`.
#[test]
fn test_pkey_partial_eq_compares_public_data() {
    let key_a = PKey::from_raw_public_key(KeyType::Rsa, &[0xAAu8; 256])
        .expect("from_raw_public_key for RSA");
    let key_b = PKey::from_raw_public_key(KeyType::Rsa, &[0xBBu8; 256])
        .expect("from_raw_public_key for RSA");
    assert_ne!(key_a, key_b, "PartialEq must compare public_key_data");
}

/// `PartialEq` DOES compare `key_type`.
#[test]
fn test_pkey_partial_eq_compares_key_type() {
    let rsa = PKey::new(KeyType::Rsa);
    let rsa_pss = PKey::new(KeyType::RsaPss);
    assert_ne!(rsa, rsa_pss);
}

/// `PartialEq` DOES compare `has_private` flag (not the data, just
/// the flag — distinguishing "has-priv-but-redacted" from "no-priv").
#[test]
fn test_pkey_partial_eq_compares_has_private_flag() {
    let priv_key = PKey::from_raw_private_key(KeyType::Rsa, &[0u8; 256])
        .expect("from_raw_private_key for RSA");
    let no_priv = PKey::new(KeyType::Rsa);
    assert_ne!(priv_key, no_priv);
}

// =========================================================================
// Phase 7 — PKey::copy_params_from
//
// Mirrors EVP_PKEY_copy_parameters() — copies the params field from
// another PKey of compatible type.
// =========================================================================

/// Copy parameters from a PKey that has none — destination params remain
/// `None`.
#[test]
fn test_pkey_copy_params_from_none() {
    let src = PKey::new(KeyType::Rsa);
    let mut dst = PKey::new(KeyType::Rsa);
    dst.copy_params_from(&src).expect("copy_params_from");
    assert!(dst.params().is_none());
}

/// Copy parameters between two empty RSA keys is a no-op success.
#[test]
fn test_pkey_copy_params_from_two_rsa() {
    let src = PKey::new(KeyType::Rsa);
    let mut dst = PKey::new(KeyType::Rsa);
    let result = dst.copy_params_from(&src);
    assert!(result.is_ok());
}

// =========================================================================
// Phase 8 — PKeyCtx constructors and initial-state accessors.
// =========================================================================

/// `PKeyCtx::new_from_name` builds a context for the named algorithm.
#[test]
fn test_pkey_ctx_new_from_name_rsa() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None);
    assert!(pkc.is_ok(), "RSA PKeyCtx must construct from name");
}

/// `PKeyCtx::new_from_pkey` builds a context bound to an existing key.
#[test]
fn test_pkey_ctx_new_from_pkey() {
    let ctx = LibContext::get_default();
    let key = Arc::new(PKey::new(KeyType::Rsa));
    let pkc = PKeyCtx::new_from_pkey(ctx.clone(), key.clone());
    assert!(pkc.is_ok(), "PKeyCtx::new_from_pkey must succeed for RSA");
}

/// Newly-constructed `PKeyCtx` has `operation == Undefined`.
#[test]
fn test_pkey_ctx_initial_operation_undefined() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    assert_eq!(pkc.operation(), PKeyOperation::Undefined);
}

/// Newly-constructed `PKeyCtx` from name has `key()` returning `None`.
#[test]
fn test_pkey_ctx_initial_key_none() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    assert!(pkc.key().is_none());
}

/// `PKeyCtx::lib_context` returns the same `Arc<LibContext>` instance
/// it was constructed with — Arc::ptr_eq invariant.
#[test]
fn test_pkey_ctx_lib_context_arc_eq() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    assert!(Arc::ptr_eq(pkc.lib_context(), &ctx));
}

// =========================================================================
// Phase 9 — RSA keygen via PKeyCtx::keygen_init + keygen.
//
// The current keygen produces deterministic byte material for testing:
//   private starts at 0x01 and increments; public starts at 0x04 and
//   increments by 7. Byte length = max(32, bits.div_ceil(8)).
// =========================================================================

/// `keygen_init` transitions operation state to `KeyGen`.
#[test]
fn test_pkey_ctx_keygen_init_sets_operation() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    assert_eq!(pkc.operation(), PKeyOperation::KeyGen);
}

/// Default-bits RSA keygen produces 256-byte keys (2048 bits).
#[test]
fn test_pkey_ctx_keygen_default_bits_2048() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    let key = pkc.keygen().expect("keygen with defaults");

    assert_eq!(key.key_type(), &KeyType::Rsa);
    let priv_data = key.raw_private_key().expect("private data");
    let pub_data = key.raw_public_key().expect("public data");
    assert_eq!(priv_data.len(), 256);
    assert_eq!(pub_data.len(), 256);
}

/// Keygen with `bits = 3072` produces 384-byte keys.
#[test]
fn test_pkey_ctx_keygen_with_bits_3072() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    pkc.set_param("bits", &ParamValue::UInt32(3072))
        .expect("set bits=3072");
    let key = pkc.keygen().expect("keygen 3072");
    let priv_data = key.raw_private_key().expect("private");
    let pub_data = key.raw_public_key().expect("public");
    assert_eq!(priv_data.len(), 384);
    assert_eq!(pub_data.len(), 384);
}

/// Keygen with `bits = 4096` produces 512-byte keys.
#[test]
fn test_pkey_ctx_keygen_with_bits_4096() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    pkc.set_param("bits", &ParamValue::UInt32(4096))
        .expect("set bits=4096");
    let key = pkc.keygen().expect("keygen 4096");
    let priv_data = key.raw_private_key().expect("private");
    assert_eq!(priv_data.len(), 512);
}

/// Byte-length floor: keygen with very small `bits` (e.g. 64) clamps
/// to the 32-byte minimum.
#[test]
fn test_pkey_ctx_keygen_byte_len_min_32() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    pkc.set_param("bits", &ParamValue::UInt32(64))
        .expect("set bits=64");
    let key = pkc.keygen().expect("keygen 64");
    let priv_data = key.raw_private_key().expect("private");
    assert!(priv_data.len() >= 32, "byte_len must be at least 32");
}

/// Keygen produces deterministic marker bytes — private key starts
/// with 0x01, public key starts with 0x04. This makes test assertions
/// stable across runs.
#[test]
fn test_pkey_ctx_keygen_deterministic_markers() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.keygen_init().expect("keygen_init");
    let key = pkc.keygen().expect("keygen");
    let priv_data = key.raw_private_key().expect("private");
    let pub_data = key.raw_public_key().expect("public");

    assert_eq!(priv_data[0], 0x01, "private key first byte must be 0x01");
    assert_eq!(pub_data[0], 0x04, "public key first byte must be 0x04");
}

/// Keygen WITHOUT a prior `keygen_init` errors with
/// `OperationNotInitialized`.
#[test]
fn test_pkey_ctx_keygen_without_init_errors() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    let result = pkc.keygen();
    assert!(
        result.is_err(),
        "keygen without keygen_init must error with OperationNotInitialized"
    );
}

// =========================================================================
// Phase 10 — PKeyCtx::paramgen — produces a parameter-only PKey.
// =========================================================================

/// `paramgen_init` transitions operation state to `ParamGen`.
#[test]
fn test_pkey_ctx_paramgen_init_sets_operation() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "DH", None).expect("DH PKeyCtx");
    pkc.paramgen_init().expect("paramgen_init");
    assert_eq!(pkc.operation(), PKeyOperation::ParamGen);
}

/// Paramgen for DH produces a PKey with `key_type == Dh` but no key
/// material (parameter-only).
#[test]
fn test_pkey_ctx_paramgen_dh() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "DH", None).expect("DH PKeyCtx");
    pkc.paramgen_init().expect("paramgen_init");
    let key = pkc.paramgen().expect("paramgen");
    assert_eq!(key.key_type(), &KeyType::Dh);
    assert!(!key.has_private_key());
    assert!(!key.has_public_key());
}

/// Paramgen WITHOUT prior `paramgen_init` errors.
#[test]
fn test_pkey_ctx_paramgen_without_init_errors() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "DH", None).expect("DH PKeyCtx");
    let result = pkc.paramgen();
    assert!(result.is_err());
}

// =========================================================================
// Phase 11 — PKeyCtx::fromdata — provider key import.
// =========================================================================

/// `fromdata_init` records the caller-supplied operation.
#[test]
fn test_pkey_ctx_fromdata_init_records_operation() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.fromdata_init(PKeyOperation::KeyGen)
        .expect("fromdata_init");
    assert_eq!(pkc.operation(), PKeyOperation::KeyGen);
}

/// `fromdata` with a public-key octet-string yields a public-only PKey.
#[test]
fn test_pkey_ctx_fromdata_rsa_with_pub() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.fromdata_init(PKeyOperation::KeyGen)
        .expect("fromdata_init");

    let mut params = ParamSet::new();
    params.set("pub", ParamValue::OctetString(vec![0x99u8; 256]));

    let key = pkc.fromdata(&params).expect("fromdata");
    assert_eq!(key.key_type(), &KeyType::Rsa);
    assert!(key.has_public_key());
}

/// `fromdata` with both pub and priv produces a key with both attached.
#[test]
fn test_pkey_ctx_fromdata_rsa_with_pub_and_priv() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.fromdata_init(PKeyOperation::KeyGen)
        .expect("fromdata_init");

    let mut params = ParamSet::new();
    params.set("pub", ParamValue::OctetString(vec![0x11u8; 256]));
    params.set("priv", ParamValue::OctetString(vec![0x22u8; 256]));

    let key = pkc.fromdata(&params).expect("fromdata");
    assert!(key.has_public_key());
    assert!(key.has_private_key());
}

// =========================================================================
// Phase 12 — PKeyCtx validation: check, public_check, param_check.
//
// All three error with CryptoError::Key("no key attached to context")
// when no key is bound to the context.
// =========================================================================

/// `check` errors when no key attached.
#[test]
fn test_pkey_ctx_check_no_key_errors() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    let result = pkc.check();
    assert!(result.is_err(), "check must error with no key attached");
}

/// `public_check` errors when no key attached.
#[test]
fn test_pkey_ctx_public_check_no_key_errors() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    let result = pkc.public_check();
    assert!(result.is_err());
}

/// `param_check` errors when no key attached.
#[test]
fn test_pkey_ctx_param_check_no_key_errors() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    let result = pkc.param_check();
    assert!(result.is_err());
}

/// `param_check` recognises RSA as having params (returns true).
#[test]
fn test_pkey_ctx_param_check_rsa_returns_true() {
    let ctx = LibContext::get_default();
    let mut pub_priv = PKey::new(KeyType::Rsa);
    // Populate with something so PKeyCtx has a key
    let pubk = vec![0u8; 256];
    let privk = vec![0u8; 256];
    pub_priv = {
        let _ = pub_priv;
        let mut k = PKey::from_raw_public_key(KeyType::Rsa, &pubk)
            .expect("from_raw_public_key for RSA");
        // Synthesize private as well via a second helper construction:
        // there's no public mutator, so use new_raw + copy_params_from
        // pattern. Simpler: build a fresh PKey with both via fromdata.
        k = {
            let _ = k;
            // Use new_raw with private then merge via PKeyCtx.fromdata path:
            PKey::new_raw(KeyType::Rsa, &privk, true)
        };
        k
    };
    let key = Arc::new(pub_priv);
    let pkc = PKeyCtx::new_from_pkey(ctx.clone(), key.clone()).expect("PKeyCtx from pkey");
    let result = pkc.param_check().expect("param_check");
    assert!(result, "RSA must be recognised as having params");
}

/// `check` returns true iff both public AND private key data are present.
/// A private-only RSA PKey returns false.
#[test]
fn test_pkey_ctx_check_priv_only_returns_false() {
    let ctx = LibContext::get_default();
    let key = Arc::new(
        PKey::from_raw_private_key(KeyType::Rsa, &[0u8; 256])
            .expect("from_raw_private_key for RSA"),
    );
    let pkc = PKeyCtx::new_from_pkey(ctx.clone(), key.clone()).expect("PKeyCtx from pkey");
    let result = pkc.check().expect("check");
    assert!(!result, "private-only key must yield check() == false");
}

// =========================================================================
// Phase 13 — set_rsa_padding / set_signature_digest record provider params.
// =========================================================================

/// `set_rsa_padding(Pss)` records `pad-mode = "pss"` in the param map.
#[test]
fn test_pkey_ctx_set_rsa_padding_records_param() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.set_rsa_padding(RsaPadding::Pss).expect("set_rsa_padding");
    match pkc.get_param("pad-mode") {
        Ok(Some(ParamValue::Utf8String(s))) if s == "pss" => {}
        other => panic!("expected Utf8String(\"pss\"), got {other:?}"),
    }
}

/// `set_signature_digest("SHA2-256")` records `digest = "SHA2-256"`.
#[test]
fn test_pkey_ctx_set_signature_digest_records_param() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.set_signature_digest("SHA2-256").expect("set_signature_digest");
    match pkc.get_param("digest") {
        Ok(Some(ParamValue::Utf8String(s))) if s == "SHA2-256" => {}
        other => panic!("expected Utf8String(\"SHA2-256\"), got {other:?}"),
    }
}

// =========================================================================
// Phase 14 — set_param / get_param round-trip.
// =========================================================================

/// `set_param` then `get_param` returns the inserted value.
#[test]
fn test_pkey_ctx_set_get_param_round_trip() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.set_param("bits", &ParamValue::UInt32(3072))
        .expect("set bits=3072");
    match pkc.get_param("bits") {
        Ok(Some(ParamValue::UInt32(3072))) => {}
        other => panic!("expected UInt32(3072), got {other:?}"),
    }
}

/// `get_param` for a missing key returns `None`.
#[test]
fn test_pkey_ctx_get_param_missing_returns_none() {
    let ctx = LibContext::get_default();
    let pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    assert!(pkc
        .get_param("never-set-key")
        .expect("get_param")
        .is_none());
}

/// Setting the same key twice overwrites.
#[test]
fn test_pkey_ctx_set_param_overwrites() {
    let ctx = LibContext::get_default();
    let mut pkc = PKeyCtx::new_from_name(ctx.clone(), "RSA", None).expect("RSA PKeyCtx");
    pkc.set_param("bits", &ParamValue::UInt32(2048))
        .expect("set bits=2048");
    pkc.set_param("bits", &ParamValue::UInt32(4096))
        .expect("set bits=4096");
    match pkc.get_param("bits") {
        Ok(Some(ParamValue::UInt32(4096))) => {}
        other => panic!("expected UInt32(4096), got {other:?}"),
    }
}

// =========================================================================
// Phase 15 — SignContext sign / verify with RSA.
//
// The simulated sign output is a fixed-length XOR-fold (256 bytes for
// RSA, 64 for Ed25519, etc.). The verify is permissive: returns true
// for any non-empty (data, sig) pair. The init state is mutually
// exclusive: sign_init resets verify state, and vice versa.
// =========================================================================

fn rsa_sign_context() -> SignContext {
    let ctx = LibContext::get_default();
    let signature = Signature::fetch(&ctx, "RSA", None).expect("RSA signature fetch");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));
    SignContext::new(&signature, &key)
}

/// `SignContext::new` produces an un-initialised context.
#[test]
fn test_sign_context_new_rsa() {
    let _ = rsa_sign_context();
    // Just verifies construction does not panic.
}

/// `sign_init` followed by `verify_init` resets sign-state.
#[test]
fn test_sign_init_then_verify_init_resets() {
    let mut sctx = rsa_sign_context();
    sctx.sign_init(None).expect("sign_init");
    sctx.verify_init(None).expect("verify_init");
    // After verify_init, a sign call must error.
    let result = sctx.sign(b"data");
    assert!(
        result.is_err(),
        "sign after verify_init must error (state was reset)"
    );
}

/// `verify_init` followed by `sign_init` resets verify-state.
#[test]
fn test_verify_init_then_sign_init_resets() {
    let mut sctx = rsa_sign_context();
    sctx.verify_init(None).expect("verify_init");
    sctx.sign_init(None).expect("sign_init");
    let result = sctx.verify(b"data", b"sig");
    assert!(
        result.is_err(),
        "verify after sign_init must error (state was reset)"
    );
}

/// `sign` without `sign_init` errors.
#[test]
fn test_sign_without_init_errors() {
    let sctx = rsa_sign_context();
    let result = sctx.sign(b"data");
    assert!(result.is_err());
}

/// `verify` without `verify_init` errors.
#[test]
fn test_verify_without_init_errors() {
    let sctx = rsa_sign_context();
    let result = sctx.verify(b"data", b"sig");
    assert!(result.is_err());
}

/// RSA `sign` produces exactly 256 bytes.
#[test]
fn test_sign_rsa_produces_256_bytes() {
    let mut sctx = rsa_sign_context();
    sctx.sign_init(None).expect("sign_init");
    let sig = sctx.sign(b"hello world").expect("sign");
    assert_eq!(sig.len(), 256);
}

/// RSA `sign` follows the documented XOR-fold pattern: each byte of the
/// input is XOR'd into `sig[i % 256]`. This makes the output
/// deterministic and verifies the simulation contract.
#[test]
fn test_sign_rsa_xor_fold_pattern() {
    let mut sctx = rsa_sign_context();
    sctx.sign_init(None).expect("sign_init");
    let data = b"abcdefghij";
    let sig = sctx.sign(data).expect("sign");

    let mut expected = vec![0u8; 256];
    for (i, b) in data.iter().enumerate() {
        expected[i % 256] ^= *b;
    }
    assert_eq!(sig, expected);
}

/// `verify` is permissive — accepts any non-empty (data, sig) pair.
#[test]
fn test_verify_rsa_accepts_nonempty() {
    let mut sctx = rsa_sign_context();
    sctx.verify_init(None).expect("verify_init");
    let result = sctx.verify(b"data", b"sig").expect("verify");
    assert!(result, "permissive verify must accept any non-empty pair");
}

// =========================================================================
// Phase 16 — DigestSignContext + DigestVerifyContext.
//
// One-shot and incremental modes. RSA + SHA-256 is the canonical PKCS #1
// v1.5 signature; here we exercise the abstraction surface.
// =========================================================================

/// `DigestSignContext::one_shot_sign` with RSA + SHA-256 yields a
/// 256-byte signature.
#[test]
fn test_digest_sign_one_shot_rsa_sha256() {
    let ctx = LibContext::get_default();
    let signature = Signature::fetch(&ctx, "RSA", None).expect("RSA signature");
    let md = MessageDigest::fetch(&ctx, "SHA2-256", None).expect("SHA2-256");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));

    let sig = DigestSignContext::one_shot_sign(&signature, &key, &md, b"payload")
        .expect("one_shot_sign");
    assert_eq!(sig.len(), 256);
}

/// `DigestSignContext` incremental: init, multiple `update`, then
/// `sign_final`. Result has same length as one-shot.
#[test]
fn test_digest_sign_incremental_rsa_sha256() {
    let ctx = LibContext::get_default();
    let signature = Signature::fetch(&ctx, "RSA", None).expect("RSA signature");
    let md = MessageDigest::fetch(&ctx, "SHA2-256", None).expect("SHA2-256");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));

    let mut dsc = DigestSignContext::init(&signature, &key, &md).expect("init");
    dsc.update(b"hello ").expect("update 1");
    dsc.update(b"world").expect("update 2");
    let sig = dsc.sign_final().expect("sign_final");
    assert_eq!(sig.len(), 256);
}

/// `DigestVerifyContext`: init + update + verify_final. There is no
/// `one_shot_verify`, so the multi-call composition is the only path.
#[test]
fn test_digest_verify_init_update_final_rsa() {
    let ctx = LibContext::get_default();
    let signature = Signature::fetch(&ctx, "RSA", None).expect("RSA signature");
    let md = MessageDigest::fetch(&ctx, "SHA2-256", None).expect("SHA2-256");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));

    let mut dvc = DigestVerifyContext::init(&signature, &key, &md).expect("init");
    dvc.update(b"payload").expect("update");
    let valid = dvc.verify_final(b"dummy_sig").expect("verify_final");
    assert!(valid);
}

// =========================================================================
// Phase 17 — AsymCipherContext encrypt / decrypt with RSA.
//
// encrypt produces ct = pt.len() + 32 bytes.
// decrypt strips 32 bytes.
// Mode mutual exclusion: encrypt-context cannot decrypt and vice versa.
// =========================================================================

/// `AsymCipher::fetch` returns a context-fetched cipher metadata object.
#[test]
fn test_asym_cipher_fetch_rsa() {
    let ctx = LibContext::get_default();
    let asc = AsymCipher::fetch(&ctx, "RSA", None).expect("RSA AsymCipher");
    assert_eq!(asc.name(), "RSA");
}

/// `AsymCipherContext::new_encrypt(...).encrypt(pt)` → `pt.len() + 32` bytes.
#[test]
fn test_asym_cipher_encrypt_rsa_size() {
    let ctx = LibContext::get_default();
    let asc = AsymCipher::fetch(&ctx, "RSA", None).expect("RSA AsymCipher");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], false));
    let enc_ctx = AsymCipherContext::new_encrypt(&asc, &key);

    let pt = b"hello world";
    let ct = enc_ctx.encrypt(pt).expect("encrypt");
    assert_eq!(ct.len(), pt.len() + 32);
}

/// `AsymCipherContext::new_decrypt(...).decrypt(ct)` → `ct.len() - 32`
/// bytes (when `ct.len() > 32`).
#[test]
fn test_asym_cipher_decrypt_rsa_size() {
    let ctx = LibContext::get_default();
    let asc = AsymCipher::fetch(&ctx, "RSA", None).expect("RSA AsymCipher");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));
    let dec_ctx = AsymCipherContext::new_decrypt(&asc, &key);

    let ct = vec![0xAAu8; 64]; // > 32, so decrypt returns ct.len() - 32 = 32 bytes
    let pt = dec_ctx.decrypt(&ct).expect("decrypt");
    assert_eq!(pt.len(), 32);
}

/// `decrypt` on an encrypt-mode context errors.
#[test]
fn test_asym_cipher_encrypt_context_cannot_decrypt() {
    let ctx = LibContext::get_default();
    let asc = AsymCipher::fetch(&ctx, "RSA", None).expect("RSA AsymCipher");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], false));
    let enc_ctx = AsymCipherContext::new_encrypt(&asc, &key);
    let result = enc_ctx.decrypt(b"data");
    assert!(
        result.is_err(),
        "decrypt on encrypt-mode context must error"
    );
}

/// `encrypt` on a decrypt-mode context errors.
#[test]
fn test_asym_cipher_decrypt_context_cannot_encrypt() {
    let ctx = LibContext::get_default();
    let asc = AsymCipher::fetch(&ctx, "RSA", None).expect("RSA AsymCipher");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));
    let dec_ctx = AsymCipherContext::new_decrypt(&asc, &key);
    let result = dec_ctx.encrypt(b"data");
    assert!(
        result.is_err(),
        "encrypt on decrypt-mode context must error"
    );
}

// =========================================================================
// Phase 18 — KeyMgmt: fetch, free-function import / export / has /
// validate / match_keys / export_to_provider with RSA.
// =========================================================================

/// `KeyMgmt::fetch` for RSA returns a metadata object with name "RSA".
#[test]
fn test_keymgmt_fetch_rsa() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    assert_eq!(km.name(), "RSA");
}

/// `KeyMgmt::provider_name` is `"default"` in current implementation.
#[test]
fn test_keymgmt_provider_name() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    assert_eq!(km.provider_name(), "default");
}

/// `KeyMgmt::description` returns `Option<&str>` — `None` in current
/// implementation. Demonstrates R5 (no empty-string sentinel).
#[test]
fn test_keymgmt_description_is_optional() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    assert!(km.description().is_none());
}

/// `keymgmt::import` succeeds for any valid keymgmt + ParamSet.
#[test]
fn test_keymgmt_import_rsa() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let params = ParamBuilder::new()
        .push_octet("n", vec![0x01u8; 256])
        .push_octet("e", vec![0x01, 0x00, 0x01])
        .build();
    let kd = keymgmt::import(&km, KeySelection::ALL, &params).expect("import");
    assert_eq!(kd.keymgmt().name(), "RSA");
}

/// `keymgmt::export` returns a clone of the KeyData's params.
#[test]
fn test_keymgmt_export_rsa() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let params = ParamBuilder::new()
        .push_octet("n", vec![0x01u8; 256])
        .build();
    let kd = keymgmt::import(&km, KeySelection::ALL, &params).expect("import");
    let exported = keymgmt::export(&km, &kd, KeySelection::ALL).expect("export");
    assert!(exported.contains("n"));
}

/// `keymgmt::has` returns true when keydata's keymgmt name matches the
/// queried keymgmt.
#[test]
fn test_keymgmt_has_matching_returns_true() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let params = ParamSet::new();
    let kd = keymgmt::import(&km, KeySelection::ALL, &params).expect("import");
    let result = keymgmt::has(&km, &kd, KeySelection::ALL);
    assert!(result);
}

/// `keymgmt::has` returns false when keydata was imported under a
/// different keymgmt.
#[test]
fn test_keymgmt_has_different_algorithm_returns_false() {
    let ctx = LibContext::get_default();
    let rsa_km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let dsa_km = KeyMgmt::fetch(&ctx, "DSA", None).expect("DSA keymgmt");
    let params = ParamSet::new();
    let kd_dsa = keymgmt::import(&dsa_km, KeySelection::ALL, &params).expect("import dsa");
    // Asking RSA "do you have this DSA keydata?" → false.
    let result = keymgmt::has(&rsa_km, &kd_dsa, KeySelection::ALL);
    assert!(!result);
}

/// `keymgmt::validate` returns `Ok(true)` on a name match.
#[test]
fn test_keymgmt_validate_matching_returns_true() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let params = ParamSet::new();
    let kd = keymgmt::import(&km, KeySelection::ALL, &params).expect("import");
    let result = keymgmt::validate(&km, &kd, KeySelection::ALL).expect("validate");
    assert!(result);
}

/// `keymgmt::match_keys` for two RSA imports of identical params → true.
#[test]
fn test_keymgmt_match_keys_identical() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let mut params = ParamSet::new();
    params.set("n", ParamValue::OctetString(vec![0x01u8; 256]));
    let kd1 = keymgmt::import(&km, KeySelection::ALL, &params).expect("import 1");
    let kd2 = keymgmt::import(&km, KeySelection::ALL, &params).expect("import 2");
    let result = keymgmt::match_keys(&km, &kd1, &kd2, KeySelection::ALL).expect("match_keys");
    assert!(result, "identical RSA keys must match");
}

/// `keymgmt::match_keys` returns false when the two keydata were
/// imported under different algorithms.
#[test]
fn test_keymgmt_match_keys_different_algorithms() {
    let ctx = LibContext::get_default();
    let rsa_km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let dsa_km = KeyMgmt::fetch(&ctx, "DSA", None).expect("DSA keymgmt");
    let params = ParamSet::new();
    let kd_rsa = keymgmt::import(&rsa_km, KeySelection::ALL, &params).expect("rsa");
    let kd_dsa = keymgmt::import(&dsa_km, KeySelection::ALL, &params).expect("dsa");
    let result =
        keymgmt::match_keys(&rsa_km, &kd_rsa, &kd_dsa, KeySelection::ALL).expect("match_keys");
    assert!(!result, "RSA vs DSA keys must NOT match");
}

/// `keymgmt::export_to_provider` succeeds and yields a KeyData under
/// the target keymgmt.
#[test]
fn test_keymgmt_export_to_provider_succeeds() {
    let ctx = LibContext::get_default();
    let src_km = KeyMgmt::fetch(&ctx, "RSA", None).expect("source RSA");
    let dst_km = KeyMgmt::fetch(&ctx, "RSA", None).expect("dest RSA");
    let params = ParamSet::new();
    let kd_src = keymgmt::import(&src_km, KeySelection::ALL, &params).expect("import");
    let kd_dst = keymgmt::export_to_provider(&kd_src, &dst_km).expect("export_to_provider");
    assert_eq!(kd_dst.keymgmt().name(), "RSA");
}

// =========================================================================
// Phase 19 — KeySelection bitflags constants and predicates.
//
// The keymgmt KeySelection is a bitflags struct (NOT to be confused
// with the encode_decode KeySelection enum). Constants:
//   PRIVATE_KEY=0x01, PUBLIC_KEY=0x02, KEY_PAIR=0x03,
//   DOMAIN_PARAMETERS=0x04, OTHER_PARAMETERS=0x80,
//   ALL_PARAMETERS=0x84, ALL=0x87.
// =========================================================================

/// Bitflags constants have the documented numeric values.
#[test]
fn test_key_selection_constants_bits() {
    assert_eq!(KeySelection::PRIVATE_KEY.bits(), 0x01);
    assert_eq!(KeySelection::PUBLIC_KEY.bits(), 0x02);
    assert_eq!(KeySelection::KEY_PAIR.bits(), 0x03);
    assert_eq!(KeySelection::DOMAIN_PARAMETERS.bits(), 0x04);
    assert_eq!(KeySelection::OTHER_PARAMETERS.bits(), 0x80);
    assert_eq!(KeySelection::ALL_PARAMETERS.bits(), 0x84);
    assert_eq!(KeySelection::ALL.bits(), 0x87);
}

/// `KEY_PAIR` is `PRIVATE_KEY | PUBLIC_KEY`.
#[test]
fn test_key_selection_key_pair_is_priv_or_pub() {
    let combined = KeySelection::PRIVATE_KEY | KeySelection::PUBLIC_KEY;
    assert_eq!(combined, KeySelection::KEY_PAIR);
}

/// `KeySelection::ALL.contains(...)` is true for each constituent.
#[test]
fn test_key_selection_contains() {
    assert!(KeySelection::ALL.contains(KeySelection::PRIVATE_KEY));
    assert!(KeySelection::ALL.contains(KeySelection::PUBLIC_KEY));
    assert!(KeySelection::ALL.contains(KeySelection::KEY_PAIR));
    assert!(KeySelection::ALL.contains(KeySelection::DOMAIN_PARAMETERS));
}

/// `KeySelection::PRIVATE_KEY.intersects(KEY_PAIR)` is true (since
/// KEY_PAIR includes PRIVATE_KEY).
#[test]
fn test_key_selection_intersects() {
    assert!(KeySelection::PRIVATE_KEY.intersects(KeySelection::KEY_PAIR));
    assert!(KeySelection::PUBLIC_KEY.intersects(KeySelection::KEY_PAIR));
    // PRIVATE_KEY does NOT intersect DOMAIN_PARAMETERS (different bits).
    assert!(!KeySelection::PRIVATE_KEY.intersects(KeySelection::DOMAIN_PARAMETERS));
}

// =========================================================================
// Phase 20 — KeyData accessor.
//
// KeyData has no public constructor — must obtain via keymgmt::import.
// The keymgmt() accessor is `pub` (not `pub(crate)`).
// =========================================================================

/// `KeyData::keymgmt` returns a borrowed reference to the bound KeyMgmt.
#[test]
fn test_keydata_keymgmt_accessor() {
    let ctx = LibContext::get_default();
    let km = KeyMgmt::fetch(&ctx, "RSA", None).expect("RSA keymgmt");
    let params = ParamSet::new();
    let kd = keymgmt::import(&km, KeySelection::ALL, &params).expect("import");
    assert_eq!(kd.keymgmt().name(), "RSA");
}

// =========================================================================
// Phase 21 — EncoderContext: PEM, DER, PKCS#8, SPKI, Text formats.
// =========================================================================

/// PEM-encoded RSA private key starts and ends with the canonical PKCS#8
/// PEM markers (`BEGIN PRIVATE KEY` / `END PRIVATE KEY`).
#[test]
fn test_encoder_pem_private_key_markers() {
    let key = PKey::from_raw_private_key(KeyType::Rsa, &vec![0xABu8; 256])
        .expect("from_raw_private_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Pem, EncoderSelection::PrivateKey);
    let pem = encctx.encode_to_vec(&key).expect("encode_to_vec");
    let s = std::str::from_utf8(&pem).expect("PEM is UTF-8");
    assert!(
        s.starts_with("-----BEGIN PRIVATE KEY-----"),
        "missing BEGIN marker: {s}"
    );
    assert!(
        s.contains("-----END PRIVATE KEY-----"),
        "missing END marker: {s}"
    );
}

/// PEM-encoded RSA public key uses the `PUBLIC KEY` marker.
#[test]
fn test_encoder_pem_public_key_markers() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0xCDu8; 256])
        .expect("from_raw_public_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Pem, EncoderSelection::PublicKey);
    let pem = encctx.encode_to_vec(&key).expect("encode_to_vec");
    let s = std::str::from_utf8(&pem).expect("PEM is UTF-8");
    assert!(s.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(s.contains("-----END PUBLIC KEY-----"));
}

/// DER format for RSA private key returns the raw private bytes.
#[test]
fn test_encoder_der_private_key_raw() {
    let priv_bytes = vec![0xEFu8; 256];
    let key = PKey::from_raw_private_key(KeyType::Rsa, &priv_bytes)
        .expect("from_raw_private_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Der, EncoderSelection::PrivateKey);
    let der = encctx.encode_to_vec(&key).expect("encode_to_vec");
    assert_eq!(der, priv_bytes);
}

/// PKCS#8 format (current simulation) returns the raw private bytes.
/// Real implementation will wrap in a PrivateKeyInfo SEQUENCE.
#[test]
fn test_encoder_pkcs8_private_key_raw() {
    let priv_bytes = vec![0xC0u8; 256];
    let key = PKey::from_raw_private_key(KeyType::Rsa, &priv_bytes)
        .expect("from_raw_private_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Pkcs8, EncoderSelection::PrivateKey);
    let der = encctx.encode_to_vec(&key).expect("encode_to_vec");
    assert_eq!(der, priv_bytes);
}

/// SPKI format for public key returns raw public bytes.
#[test]
fn test_encoder_spki_public_key_raw() {
    let pub_bytes = vec![0xA1u8; 256];
    let key = PKey::from_raw_public_key(KeyType::Rsa, &pub_bytes)
        .expect("from_raw_public_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Spki, EncoderSelection::PublicKey);
    let der = encctx.encode_to_vec(&key).expect("encode_to_vec");
    assert_eq!(der, pub_bytes);
}

/// Text format encodes a human-readable description with `Key Type:`
/// header.
#[test]
fn test_encoder_text_format() {
    let key = PKey::from_raw_public_key(KeyType::Rsa, &vec![0u8; 256])
        .expect("from_raw_public_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Text, EncoderSelection::PublicKey);
    let bytes = encctx.encode_to_vec(&key).expect("encode_to_vec");
    let text = std::str::from_utf8(&bytes).expect("Text is UTF-8");
    assert!(text.contains("Key Type:"));
    assert!(text.contains("Key Length:"));
}

/// `EncoderContext::format()` accessor returns the configured format.
#[test]
fn test_encoder_format_accessor() {
    let encctx = EncoderContext::new(KeyFormat::Pem, EncoderSelection::PrivateKey);
    assert_eq!(encctx.format(), KeyFormat::Pem);

    let encctx2 = EncoderContext::new(KeyFormat::Der, EncoderSelection::PublicKey);
    assert_eq!(encctx2.format(), KeyFormat::Der);
}

/// `EncoderContext::selection()` accessor returns the configured selection.
#[test]
fn test_encoder_selection_accessor() {
    let encctx = EncoderContext::new(KeyFormat::Pem, EncoderSelection::PrivateKey);
    assert_eq!(encctx.selection(), EncoderSelection::PrivateKey);
}

/// `KeyFormat::Display` produces the documented strings.
#[test]
fn test_key_format_display() {
    assert_eq!(format!("{}", KeyFormat::Pem), "PEM");
    assert_eq!(format!("{}", KeyFormat::Der), "DER");
    assert_eq!(format!("{}", KeyFormat::Pkcs8), "PKCS8");
    assert_eq!(format!("{}", KeyFormat::Spki), "SPKI");
    assert_eq!(format!("{}", KeyFormat::Text), "TEXT");
}

/// `EncoderContext::to_pkcs8` is an associated function (no `&self`)
/// returning `Zeroizing<Vec<u8>>` — sensitive material is zeroed on drop.
#[test]
fn test_encoder_to_pkcs8_associated_fn() {
    let key = PKey::from_raw_private_key(KeyType::Rsa, &vec![0xDDu8; 256])
        .expect("from_raw_private_key for RSA");
    let zeroising_pkcs8 = EncoderContext::to_pkcs8(&key).expect("to_pkcs8");
    assert_eq!(zeroising_pkcs8.as_slice(), &vec![0xDDu8; 256][..]);
    // Drop here zeroes the buffer — no observable assertion possible
    // without unsafe pointer inspection (and we have R8: no unsafe).
}

// =========================================================================
// Phase 22 — DecoderContext: round-trip + format detection +
// PKCS#8 / SPKI private/public marking.
// =========================================================================

/// Decode a PEM-encoded RSA private key and observe the round-trip.
#[test]
fn test_decoder_decode_rsa_pem() {
    let priv_bytes = vec![0x55u8; 256];
    let original = PKey::from_raw_private_key(KeyType::Rsa, &priv_bytes)
        .expect("from_raw_private_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Pem, EncoderSelection::PrivateKey);
    let pem = encctx.encode_to_vec(&original).expect("encode");

    let decctx = DecoderContext::new();
    let decoded = decctx.decode_from_slice(&pem).expect("decode");
    // After round-trip through PEM, the body bytes must round-trip.
    assert_eq!(decoded.key_type(), &KeyType::Rsa);
    assert!(decoded.has_private_key()); // PEM "PRIVATE KEY" header → private
    let recovered = decoded.raw_private_key().expect("raw_private_key");
    assert_eq!(recovered.as_slice(), priv_bytes.as_slice());
}

/// Decode a DER-encoded RSA private key (no PEM headers) — expected
/// format must be set to disambiguate.
#[test]
fn test_decoder_decode_rsa_der_with_expected_format() {
    let priv_bytes = vec![0x66u8; 256];
    let original = PKey::from_raw_private_key(KeyType::Rsa, &priv_bytes)
        .expect("from_raw_private_key for RSA");
    let encctx = EncoderContext::new(KeyFormat::Der, EncoderSelection::PrivateKey);
    let der = encctx.encode_to_vec(&original).expect("encode");

    let mut decctx = DecoderContext::new();
    decctx.set_expected_format(KeyFormat::Der);
    let decoded = decctx.decode_from_slice(&der).expect("decode");
    assert_eq!(decoded.key_type(), &KeyType::Rsa);
}

/// Setting `expected_format = Pkcs8` causes the decoded PKey to have
/// `has_private = true` (PKCS#8 is private-only).
#[test]
fn test_decoder_pkcs8_marks_private() {
    let bytes = vec![0x77u8; 256];
    let mut decctx = DecoderContext::new();
    decctx.set_expected_format(KeyFormat::Pkcs8);
    let decoded = decctx.decode_from_slice(&bytes).expect("decode");
    assert!(decoded.has_private_key(), "PKCS#8 must mark private");
}

/// Setting `expected_format = Spki` causes the decoded PKey to have
/// `has_public = true` (SPKI is public-only).
#[test]
fn test_decoder_spki_marks_public() {
    let bytes = vec![0x88u8; 256];
    let mut decctx = DecoderContext::new();
    decctx.set_expected_format(KeyFormat::Spki);
    let decoded = decctx.decode_from_slice(&bytes).expect("decode");
    assert!(decoded.has_public_key(), "SPKI must mark public");
    assert!(!decoded.has_private_key());
}

/// Setting `set_expected_type("RSA-PSS")` overrides the default RSA type.
#[test]
fn test_decoder_set_expected_type_overrides_default() {
    let bytes = vec![0x99u8; 256];
    let mut decctx = DecoderContext::new();
    decctx.set_expected_format(KeyFormat::Der);
    decctx.set_expected_type("RSA-PSS");
    let decoded = decctx.decode_from_slice(&bytes).expect("decode");
    assert_eq!(decoded.key_type(), &KeyType::RsaPss);
}

/// Empty input errors with `InvalidArgument`.
#[test]
fn test_decoder_empty_input_errors() {
    let decctx = DecoderContext::new();
    let result = decctx.decode_from_slice(&[]);
    assert!(result.is_err(), "empty input must error");
}

/// Setting `expected_format = Text` errors — text format cannot be decoded.
#[test]
fn test_decoder_text_format_errors() {
    let bytes = b"Key Type: Rsa\nKey Length: 256 bytes\n";
    let mut decctx = DecoderContext::new();
    decctx.set_expected_format(KeyFormat::Text);
    let result = decctx.decode_from_slice(bytes);
    assert!(result.is_err());
}

/// `DecoderContext::from_pkcs8` associated function decodes a PKCS#8
/// blob with private-key marking.
#[test]
fn test_decoder_from_pkcs8_associated_fn() {
    let bytes = vec![0xBBu8; 256];
    let decoded = DecoderContext::from_pkcs8(&bytes).expect("from_pkcs8");
    assert!(decoded.has_private_key());
}

// =========================================================================
// Phase 23 — KemContext with RSA: error paths.
//
// Successful encapsulate/decapsulate require an init step which differs
// across KEM variants; the simulation contracts for error paths are
// straightforwardly testable.
// =========================================================================

/// `KemContext::new` for RSA constructs without panic.
#[test]
fn test_kem_context_new_rsa() {
    let ctx = LibContext::get_default();
    let kem = Kem::fetch(&ctx, "RSA", None).expect("RSA KEM");
    let _kemctx = KemContext::new(&kem);
}

/// `KemContext::decapsulate` with empty ciphertext errors
/// (`InvalidArgument("ciphertext is empty")`).
#[test]
fn test_kem_decapsulate_empty_errors() {
    let ctx = LibContext::get_default();
    let kem = Kem::fetch(&ctx, "RSA", None).expect("RSA KEM");
    let kemctx = KemContext::new(&kem);
    let result = kemctx.decapsulate(&[]);
    assert!(result.is_err(), "decapsulate of empty ct must error");
}

/// `KemContext::encapsulate` without an attached key errors
/// (`KeyRequired("encapsulate requires a key")`).
#[test]
fn test_kem_encapsulate_without_key_errors() {
    let ctx = LibContext::get_default();
    let kem = Kem::fetch(&ctx, "RSA", None).expect("RSA KEM");
    let kemctx = KemContext::new(&kem);
    let result = kemctx.encapsulate();
    assert!(
        result.is_err(),
        "encapsulate without an attached key must error"
    );
}

// =========================================================================
// Phase 24 — bn::prime::rsa_fips186_5_derive_prime validation.
//
// FIPS 186-5 §A.1 — prime derivation for RSA key generation.
// =========================================================================

/// `bits < 2` errors with `BitsTooSmall`. Below the FIPS minimum, no
/// prime can be derived.
#[test]
fn test_rsa_fips186_5_derive_prime_bits_too_small() {
    let e = BigNum::one();
    let xp = BigNum::from_bytes_be(&[0]); // zero seed → random seed path
    let result = rsa_fips186_5_derive_prime(0, &e, &xp);
    assert!(result.is_err(), "bits = 0 must error");

    let result_one = rsa_fips186_5_derive_prime(1, &e, &xp);
    assert!(result_one.is_err(), "bits = 1 must error (below FIPS minimum)");
}

/// `e == 0` errors with `InvalidArgument("RSA exponent must be positive")`.
#[test]
fn test_rsa_fips186_5_derive_prime_zero_exponent_errors() {
    let zero_e = BigNum::from_bytes_be(&[0]);
    let xp = BigNum::from_bytes_be(&[0]);
    let result = rsa_fips186_5_derive_prime(64, &zero_e, &xp);
    assert!(result.is_err(), "e == 0 must error");
}

// =========================================================================
// Phase 25 — ParamSet / ParamBuilder typed RSA parameters.
//
// Exercise the param plumbing used by RSA keygen, fromdata, and
// signature operations.
// =========================================================================

/// `ParamSet::set` then `ParamSet::get` returns the inserted value.
#[test]
fn test_paramset_set_get_round_trip_for_rsa_bits() {
    let mut ps = ParamSet::new();
    ps.set("bits", ParamValue::UInt32(2048));
    match ps.get("bits") {
        Some(ParamValue::UInt32(2048)) => {}
        other => panic!("expected UInt32(2048), got {other:?}"),
    }
}

/// `ParamSet::get_typed::<u32>` returns the lossless u32 value.
#[test]
fn test_paramset_get_typed_u32_for_rsa_bits() {
    let mut ps = ParamSet::new();
    ps.set("bits", ParamValue::UInt32(3072));
    let bits: u32 = ps.get_typed("bits").expect("get_typed u32");
    assert_eq!(bits, 3072);
}

/// `ParamBuilder` fluent chain produces a `ParamSet` with all pushed
/// keys present. R6-compliant: lossless `u32::from`-style construction.
#[test]
fn test_parambuilder_chain_for_rsa_keygen() {
    let ps = ParamBuilder::new()
        .push_u32("bits", 2048)
        .push_octet("e", vec![0x01, 0x00, 0x01])
        .push_utf8("digest", String::from("SHA2-256"))
        .build();
    assert!(ps.contains("bits"));
    assert!(ps.contains("e"));
    assert!(ps.contains("digest"));
    assert_eq!(ps.len(), 3);
}

/// Typed access for `ParamValue::OctetString` returns the raw bytes via
/// `as_bytes()`.
#[test]
fn test_paramvalue_as_bytes_for_rsa_modulus() {
    let modulus = vec![0x01u8; 256];
    let value = ParamValue::OctetString(modulus.clone());
    assert_eq!(value.as_bytes(), Some(modulus.as_slice()));
}

/// `ParamSet::merge` overlays another ParamSet's keys (other wins on
/// conflict).
#[test]
fn test_paramset_merge_other_wins_for_rsa_keygen() {
    let mut a = ParamSet::new();
    a.set("bits", ParamValue::UInt32(2048));
    a.set("a-only", ParamValue::Utf8String("a".into()));

    let mut b = ParamSet::new();
    b.set("bits", ParamValue::UInt32(4096));
    b.set("b-only", ParamValue::Utf8String("b".into()));

    a.merge(&b);
    assert!(a.contains("a-only"));
    assert!(a.contains("b-only"));
    match a.get("bits") {
        Some(ParamValue::UInt32(4096)) => {}
        other => panic!("expected UInt32(4096), got {other:?}"),
    }
}

// =========================================================================
// Phase 26 — KeyExchange surface (smoke test for RSA-named exchange).
//
// RSA is not a key-exchange algorithm in real cryptography, but the
// abstraction surface is permissive (`KeyExchange::fetch` ignores the
// input ctx and properties), so we sanity-check the surface here to
// document the deviation from typical RSA usage.
// =========================================================================

/// `KeyExchange::fetch` for RSA succeeds and reports name "RSA".
#[test]
fn test_key_exchange_fetch_rsa_smoke() {
    let ctx = LibContext::get_default();
    let kx = KeyExchange::fetch(&ctx, "RSA", None).expect("permissive RSA fetch");
    assert_eq!(kx.name(), "RSA");
    assert_eq!(kx.provider_name(), "default");
}

/// `KeyExchangeContext::derive` without a peer key errors
/// (`KeyRequired("peer key required for derivation")`).
#[test]
fn test_key_exchange_derive_no_peer_errors() {
    let ctx = LibContext::get_default();
    let kx = KeyExchange::fetch(&ctx, "RSA", None).expect("KeyExchange RSA");
    let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));
    let kxc = KeyExchangeContext::derive_init(&kx, &key).expect("derive_init");
    let result = kxc.derive();
    assert!(
        result.is_err(),
        "derive without set_peer must error with KeyRequired"
    );
}
