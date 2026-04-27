//! RSA public-key cryptosystem façade for the OpenSSL Rust workspace.
//!
//! Provides a single, ergonomic entry point for the RSA family of
//! algorithms — keygen, encryption (OAEP, PKCS#1 v1.5), signatures
//! (PSS, PKCS#1 v1.5, X9.31), key derivation (RSA-KEM), and key
//! serialisation (PEM/DER/PKCS#8/SPKI).
//!
//! In the Rust workspace, RSA is **not** a self-contained module the way
//! it was in upstream OpenSSL's `crypto/rsa/*.c`. Instead, RSA functionality
//! is dispersed across the EVP layer:
//!
//! - [`crate::evp::pkey`]            — `KeyType`, `RsaPadding`, `PKey`, `PKeyCtx`, `PKeyOperation`
//! - [`crate::evp::signature`]       — `Signature`, `AsymCipher`, `SignContext`, `AsymCipherContext`,
//!                                      `DigestSignContext`, `DigestVerifyContext`, `KeyExchange`,
//!                                      `KeyExchangeContext`
//! - [`crate::evp::keymgmt`]         — `KeyMgmt`, `KeyData`, `KeySelection` (bitflags),
//!                                      `import`, `export`, `has`, `validate`, `match_keys`,
//!                                      `export_to_provider`
//! - [`crate::evp::encode_decode`]   — `KeyFormat`, `EncoderSelection` (4-variant enum),
//!                                      `EncoderContext`, `DecoderContext`
//! - [`crate::evp::kem`]             — `Kem`, `KemContext`, `KemOperation`, `KemEncapsulateResult`
//! - [`crate::bn::prime`]            — `rsa_fips186_5_derive_prime`
//!
//! This façade re-exports the relevant types so that downstream callers
//! and the `openssl-ffi` C ABI bridge can write `use openssl_crypto::rsa::*`
//! to access the full RSA surface in one place. It also satisfies the
//! AAP §0.4.1 / §0.5.1 requirement that `rsa/{mod, oaep, pss}` exist as a
//! module in `crates/openssl-crypto/src/`.
//!
//! # Source Mapping
//!
//! This façade module replaces or surfaces the following C files from
//! upstream OpenSSL:
//!
//! | Rust Component                              | C Source File                                      | Purpose                                              |
//! |---------------------------------------------|----------------------------------------------------|------------------------------------------------------|
//! | `KeyType::Rsa` / `KeyType::RsaPss`          | `include/openssl/evp.h::EVP_PKEY_RSA(_PSS)`        | Algorithm-family identification                      |
//! | `RsaPadding`                                | `include/openssl/rsa.h::RSA_*_PADDING`             | Padding-mode enum                                    |
//! | `PKey` / `PKeyCtx`                          | `crypto/rsa/rsa_lib.c::RSA_*`,                     | Key container + context lifecycle                    |
//! |                                             | `crypto/evp/p_lib.c::EVP_PKEY_*`                   |                                                      |
//! | `SignContext` / `DigestSignContext`         | `crypto/rsa/rsa_pmeth.c::pkey_rsa_sign`,           | One-shot and digest-sign signature operations        |
//! |                                             | `crypto/evp/m_sigver.c::EVP_DigestSign*`           |                                                      |
//! | `AsymCipherContext`                         | `crypto/rsa/rsa_pmeth.c::pkey_rsa_encrypt`         | Asymmetric encryption / decryption                   |
//! | `KeyMgmt` + `KeySelection` + `KeyData`      | `providers/implementations/keymgmt/rsa_kmgmt.c`,   | Key-management dispatch + selection bitflags         |
//! |                                             | `crypto/evp/keymgmt_*.c`                           |                                                      |
//! | `EncoderContext` / `DecoderContext`         | `crypto/encode_decode/{encoder,decoder}_pkey.c`    | PEM / DER / PKCS#8 / SPKI serialisation              |
//! | `Kem` / `KemContext`                        | `providers/implementations/kem/rsa_kem.c`          | RSA-KEM (RFC 5990) wrap / unwrap                     |
//! | `rsa_fips186_5_derive_prime`                | `crypto/bn/bn_rsa_fips186_5.c`                     | FIPS 186-5 §A.1.3 prime derivation                   |
//! | `oaep`                                      | `crypto/rsa/rsa_oaep.c`                            | OAEP padding (RFC 8017 §7.1) — see submodule         |
//! | `pss`                                       | `crypto/rsa/rsa_pss.c`                             | PSS padding (RFC 8017 §8.1) — see submodule          |
//!
//! # Specifications
//!
//! - **RFC 8017** — PKCS #1 v2.2 (RSA Cryptography Specifications)
//! - **FIPS 186-5 §A.1** — RSA Key Pair Generation
//! - **NIST SP 800-56B Rev. 2** — Pair-Wise Key Establishment Using Integer-Factorisation Cryptography
//! - **NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 (Table 2)** — Key strength tiers
//! - **RFC 5958** — Asymmetric Key Packages (PKCS#8)
//! - **RFC 5280 §4.1.2.7** — Subject Public Key Info
//! - **RFC 5990** — RSA-KEM Algorithm in CMS
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All optional parameters (e.g. PSS salt length,
//!   OAEP label) on the underlying `PKeyCtx` are `Option<T>`. No sentinel
//!   integers (`-1`, `0`) encode "unset" — see [`crate::evp::pkey`] for
//!   the typed accessor surface.
//! - **R6 (Lossless Casts):** This façade introduces no `as` casts. The
//!   re-exported types from [`crate::evp::pkey`] use `try_from` /
//!   `saturating_cast` for all bit-length conversions.
//! - **R7 (Lock Granularity):** The re-exported `PKey` and `PKeyCtx`
//!   own their state directly; shared use across threads is via
//!   `Arc<PKey>` with explicit `// LOCK-SCOPE:` justifications in the
//!   underlying EVP modules.
//! - **R8 (Zero Unsafe):** This façade contains no `unsafe` blocks; the
//!   `forbid(unsafe_code)` attribute on the parent crate enforces this
//!   workspace-wide outside `openssl-ffi`.
//! - **R9 (Warning-Free):** All re-exports are exercised by
//!   `crates/openssl-crypto/src/tests/test_rsa.rs` (25 phases). Each
//!   re-exported item is a public symbol of its origin module; no
//!   `#[allow(unused)]` attributes appear in this file.
//! - **R10 (Wiring):** Reachable from the entry point via
//!   `openssl_crypto::rsa::*` (this module). The `openssl-ffi` crate
//!   re-exports these symbols across the C ABI boundary via `cbindgen`.
//!
//! # Security Considerations
//!
//! - **Private-key zeroisation.** `PKey` derives `ZeroizeOnDrop`; key
//!   material is overwritten before deallocation.
//! - **Constant-time comparison.** Signature verification uses
//!   `subtle::ConstantTimeEq` to avoid leaking signature/MAC mismatch
//!   timing.
//! - **Padding-oracle resistance.** PKCS#1 v1.5 decryption (where used)
//!   is implemented with the equivalent of OpenSSL's
//!   `RSA_padding_check_PKCS1_type_2()` which performs the unmask and
//!   error-handling in constant time per
//!   Klima-Pokorný-Rosa, ICALP 2003. Prefer `oaep` for new
//!   deployments.
//! - **Key sizes.** Per FIPS 186-5, RSA keys below 2048 bits are
//!   non-compliant; the underlying `PKeyCtx::keygen` enforces a
//!   minimum 2048-bit modulus when `keygen_init` is followed by the
//!   FIPS provider activation.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::rsa::{KeyType, PKey, RsaPadding};
//!
//! // Construct an empty `PKey` of the RSA family.  To populate it with key
//! // material, use the EVP key-generation, import, or decoder entry points
//! // in `crate::evp::pkey` (which require a `LibContext` and provider).
//! let _key = PKey::new(KeyType::Rsa);
//!
//! // Inspect padding modes — these are simple compile-time-known constants
//! // exposed via the re-exported `RsaPadding` enum.
//! assert_eq!(RsaPadding::Pkcs1.to_legacy_int(),     1);
//! assert_eq!(RsaPadding::Pkcs1Oaep.to_param_str(),  "oaep");
//! assert_eq!(RsaPadding::Pss.to_legacy_int(),       6);
//!
//! // The key is automatically zeroised when it goes out of scope (Rule R8 +
//! // `zeroize::ZeroizeOnDrop` derived on `PKey`).
//! ```
//!
//! # Submodules
//!
//! - `oaep` — OAEP padding (RFC 8017 §7.1) for asymmetric encryption.
//! - `pss`  — PSS padding (RFC 8017 §8.1) for digital signatures.

// ===========================================================================
// Submodule declarations
// ===========================================================================

/// OAEP (Optimal Asymmetric Encryption Padding) — RFC 8017 §7.1.
///
/// See the `oaep` submodule for the full RFC 8017 §7.1 OAEP-specific
/// re-exports and rationale. This is the recommended padding mode for new
/// RSA encryption deployments.
pub mod oaep;

/// PSS (Probabilistic Signature Scheme) — RFC 8017 §8.1.
///
/// See the `pss` submodule for the full RFC 8017 §8.1 PSS-specific
/// re-exports and rationale. This is the recommended padding mode for new
/// RSA signature deployments.
pub mod pss;

// ===========================================================================
// Re-exports — Key types and padding modes
// ===========================================================================
//
// The re-exports below surface the RSA-relevant subset of the EVP layer in
// one place so that callers — including `openssl-ffi` C ABI consumers — can
// write `use openssl_crypto::rsa::*` to access the full RSA surface.
//
// IMPORTANT: There are two distinct `KeySelection` types in the EVP layer:
//   1. `evp::keymgmt::KeySelection`     — a bitflags struct with constants
//                                         KEY_PAIR / PRIVATE_KEY / PUBLIC_KEY /
//                                         DOMAIN_PARAMETERS (maps to
//                                         OSSL_KEYMGMT_SELECT_* in C).
//   2. `evp::encode_decode::KeySelection` — a 4-variant enum used by the
//                                          encoder/decoder layer to choose
//                                          which part of the key to serialise.
//
// To prevent name collision in this façade, the encoder/decoder selection
// is re-exported under the alias `EncoderSelection`.

// --- Key type and padding -----------------------------------------------
pub use crate::evp::pkey::{KeyType, PKey, PKeyCtx, PKeyOperation, RsaPadding};

// --- Signature / asymmetric cipher / key exchange -----------------------
pub use crate::evp::signature::{
    AsymCipher, AsymCipherContext, DigestSignContext, DigestVerifyContext, KeyExchange,
    KeyExchangeContext, SignContext, Signature,
};

// --- Key management dispatch --------------------------------------------
pub use crate::evp::keymgmt::{
    export, export_to_provider, has, import, match_keys, validate, KeyData, KeyMgmt, KeySelection,
};

// --- Encoder / decoder framework ----------------------------------------
//
// The encoder/decoder `KeySelection` enum is aliased as `EncoderSelection`
// to disambiguate from the bitflags `keymgmt::KeySelection` re-exported
// above.
pub use crate::evp::encode_decode::{
    DecoderContext, EncoderContext, KeyFormat, KeySelection as EncoderSelection,
};

// --- Key encapsulation (RSA-KEM, RFC 5990) ------------------------------
pub use crate::evp::kem::{Kem, KemContext, KemEncapsulateResult, KemOperation};

// --- BigNum prime derivation (FIPS 186-5 §A.1.3) ------------------------
pub use crate::bn::prime::rsa_fips186_5_derive_prime;
