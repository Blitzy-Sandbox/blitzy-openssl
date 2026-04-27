//! RSA PSS signature scheme (Probabilistic Signature Scheme).
//!
//! Implements / surfaces the RSA-PSS signature scheme as specified in
//! **RFC 8017 §8.1** (PKCS #1 v2.2). RSA-PSS is the recommended signature
//! mode for new RSA deployments — unlike PKCS #1 v1.5, PSS has a tight
//! security reduction to the RSA assumption (Bellare-Rogaway, Eurocrypt
//! 1996; Coron, CRYPTO 2002) and the mandatory random salt prevents the
//! deterministic-signature pitfalls of v1.5.
//!
//! In the Rust workspace, the PSS padding mode is represented by the
//! [`RsaPadding::Pss`] variant of the [`RsaPadding`] enum (defined in
//! [`crate::evp::pkey`]). The associated key family
//! ([`KeyType::RsaPss`]) is a distinct algorithm identifier carrying
//! immutable PSS algorithm parameters in the SubjectPublicKeyInfo
//! per RFC 4055 §3.1. The actual sign / verify logic is implemented in
//! [`crate::evp::signature::SignContext`] and
//! [`crate::evp::signature::DigestSignContext`] /
//! [`crate::evp::signature::DigestVerifyContext`], dispatched via
//! [`crate::evp::pkey::PKeyCtx`].
//!
//! This submodule re-exports the PSS-specific symbols and provides
//! detailed RFC 8017 §8.1 documentation.
//!
//! # Source Mapping
//!
//! | Rust Component                  | C Source File                        | Purpose                                          |
//! |---------------------------------|--------------------------------------|--------------------------------------------------|
//! | `Padding::Pss`                  | `include/openssl/rsa.h::RSA_PKCS1_PSS_PADDING` | Padding-mode discriminator (integer 6) |
//! | `Padding::Pss::to_param_str`    | `include/openssl/core_names.h::OSSL_PKEY_RSA_PAD_MODE_PSS` | Provider-API parameter name `"pss"` |
//! | `KeyKind::RsaPss`               | `include/openssl/evp.h::EVP_PKEY_RSA_PSS` | RFC 4055 RSASSA-PSS key family identifier |
//! | PSS encode                      | `crypto/rsa/rsa_pss.c::RSA_padding_add_PKCS1_PSS_mgf1` | RFC 8017 §9.1.1 EMSA-PSS-Encode |
//! | PSS verify                      | `crypto/rsa/rsa_pss.c::RSA_verify_PKCS1_PSS_mgf1` | RFC 8017 §9.1.2 EMSA-PSS-Verify |
//! | MGF1 mask generation            | `crypto/rsa/rsa_pmeth.c::PKCS1_MGF1` | RFC 8017 §B.2.1 MGF1 implementation            |
//!
//! # PSS Encoding (RFC 8017 §9.1.1 EMSA-PSS-Encode)
//!
//! PSS encodes a message `M` of arbitrary length into an octet string
//! `EM` of length `emLen = ceil((modBits − 1) / 8)`, where `modBits` is
//! the bit length of the RSA modulus:
//!
//! ```text
//! 1. mHash = Hash(M)                                  // hLen octets
//! 2. salt  = random sLen octets                       // sLen ≥ 0
//! 3. M'    = (0x00)^8 || mHash || salt                // length 8 + hLen + sLen
//! 4. H     = Hash(M')                                  // hLen octets
//! 5. PS    = (emLen − sLen − hLen − 2) zero octets
//! 6. DB    = PS || 0x01 || salt                        // length emLen − hLen − 1
//! 7. dbMask  = MGF1(H, emLen − hLen − 1)
//! 8. maskedDB = DB ⊕ dbMask
//! 9. Set the leftmost (8 emLen − emBits) bits of maskedDB to zero
//!10. EM    = maskedDB || H || 0xbc                     // length emLen
//! ```
//!
//! The defaults in this Rust workspace (which match upstream OpenSSL
//! and RFC 8017 Appendix A.2.3 recommendations):
//!
//! - **Hash:** SHA-256 for new code (provider-configurable)
//! - **MGF1 hash:** same as the message hash (overrideable)
//! - **Salt length:** equals the hash output length `hLen` (RFC 8017
//!   §9.1 recommendation for maximum security; setting `sLen = 0`
//!   yields a deterministic PSS variant useful for re-signing tests)
//!
//! # PSS Verification (RFC 8017 §9.1.2 EMSA-PSS-Verify)
//!
//! Verification reverses the encoding process and validates:
//!
//! 1. The trailer field equals `0xbc`.
//! 2. The leftmost `(8 emLen − emBits)` bits of `maskedDB` are zero.
//! 3. The padding string `PS` is all zeros.
//! 4. The `0x01` separator octet is present.
//! 5. `Hash(0x0000000000000000 || mHash || salt) == H`.
//!
//! All comparisons are performed in **constant time** to prevent
//! signature-verification side channels.
//!
//! # RFC 4055 RSASSA-PSS Key Family
//!
//! RFC 4055 §1.2 defines a distinct algorithm OID
//! `id-RSASSA-PSS = 1.2.840.113549.1.1.10` whose `AlgorithmIdentifier`
//! parameters carry **immutable** PSS algorithm parameters (hash, MGF1
//! hash, salt length, trailer field). A key tagged with this OID
//! ([`KeyType::RsaPss`]) MUST be used only with the parameters
//! embedded in its SubjectPublicKeyInfo — the verifier MUST reject
//! signatures produced with different parameters.
//!
//! In contrast, a generic `KeyType::Rsa` key may be used with any
//! padding mode at the application's discretion.
//!
//! # Salt Length Considerations
//!
//! Per **NIST FIPS 186-5 §5.4** and **RFC 8017 §9.1**:
//!
//! - **`sLen = hLen`** (default) — maximum security; collision
//!   resistance of the hash equals the security parameter.
//! - **`sLen = 0`** (deterministic) — reduces randomness requirements
//!   but slightly weakens the security reduction.
//! - **`sLen = -1` (digest length)** in OpenSSL idiom — equivalent to
//!   `sLen = hLen`.
//! - **`sLen = -2` (auto)** — use the maximum salt that fits; useful
//!   for verification with unknown salt length.
//!
//! # Specifications
//!
//! - **RFC 8017 §8.1** — RSASSA-PSS Signature Scheme
//! - **RFC 8017 §9.1** — EMSA-PSS Encoding Method
//! - **RFC 8017 §B.2.1** — MGF1 Mask Generation Function
//! - **RFC 4055 §1.2, §3.1** — RSASSA-PSS algorithm identifier &
//!   parameters
//! - **NIST FIPS 186-5 §5.4** — RSA digital signatures
//! - **NIST SP 800-131A Rev. 2 §6** — Hash function transitions
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Optional MGF1-MD and salt-length parameters
//!   are `Option<T>`.
//! - **R6 (Lossless Casts):** No `as` casts in this submodule.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks; `forbid(unsafe_code)` on
//!   the parent crate enforces this.
//! - **R10 (Wiring):** Reachable from
//!   `openssl_crypto::rsa::pss::Padding::Pss` and
//!   `openssl_crypto::rsa::pss::KeyKind::RsaPss`.
//!
//! # Security Considerations
//!
//! - **PSS is preferred over PKCS #1 v1.5 for new code.** RFC 8017 §1
//!   "RECOMMENDS new applications use PSS for signatures."
//! - **Use `KeyType::RsaPss` when interoperating with strict verifiers**
//!   (e.g., TLS 1.3, X.509 EE certs with `id-RSASSA-PSS` OID).
//! - **Random salt is mandatory** for security; the random number
//!   generator must be cryptographically secure (this workspace uses
//!   the OS-backed RNG via [`crate::rand`]).
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::rsa::pss::{KeyKind, Padding};
//!
//! // PSS padding is integer code 6 / param string "pss" per RFC 8017.
//! assert_eq!(Padding::Pss.to_legacy_int(), 6);
//! assert_eq!(Padding::Pss.to_param_str(), "pss");
//!
//! // `KeyKind::RsaPss` is a distinct key-family identifier from the
//! // generic `KeyKind::Rsa` family — important for RFC 4055 strict-mode
//! // verifiers that reject non-PSS padding on a PSS-restricted key.
//! assert_ne!(KeyKind::RsaPss, KeyKind::Rsa);
//! ```
//!
//! [`KeyType::RsaPss`]: crate::evp::pkey::KeyType::RsaPss
//! [`PKeyCtx`]: crate::evp::pkey::PKeyCtx
//! [`RsaPadding`]: crate::evp::pkey::RsaPadding

// ===========================================================================
// Re-exports
// ===========================================================================
//
// The PSS padding mode is represented by `RsaPadding::Pss` and the
// PSS-restricted key family by `KeyType::RsaPss`. We expose these via
// stable local aliases (`Padding`, `KeyKind`) so that callers writing
// `openssl_crypto::rsa::pss::Padding::Pss` and
// `openssl_crypto::rsa::pss::KeyKind::RsaPss` get self-documenting
// PSS-focused references.

pub use crate::evp::pkey::KeyType as KeyKind;
pub use crate::evp::pkey::RsaPadding as Padding;

/// Convenience type alias for "sign with PSS padding".
///
/// `PssSign` is a marker alias for [`Padding`] used to express
/// "produce a PSS signature" intent in API signatures and tests. It is
/// equivalent to [`Padding`] / [`crate::evp::pkey::RsaPadding`].
pub type PssSign = Padding;

/// Convenience type alias for the RFC 4055 RSASSA-PSS key family.
///
/// `PssKey` aliases [`KeyKind`] (i.e. [`crate::evp::pkey::KeyType`]) and
/// is intended to be used as `pss::PssKey::RsaPss` in API signatures
/// requiring an RFC 4055 RSASSA-PSS-tagged key (as opposed to a generic
/// `KeyType::Rsa` that may be used with any padding mode).
pub type PssKey = KeyKind;

#[cfg(test)]
mod tests {
    //! Unit tests for the PSS submodule re-exports.
    //!
    //! These tests verify that `Padding::Pss` round-trips correctly to
    //! its provider-API parameter string and legacy integer code per
    //! RFC 8017 / OpenSSL `include/openssl/rsa.h`, and that the
    //! `KeyKind::RsaPss` variant is distinguishable from the generic
    //! `KeyKind::Rsa` family.

    use super::{KeyKind, Padding};

    /// Verifies the PSS padding mode parameter string per
    /// `OSSL_PKEY_RSA_PAD_MODE_PSS`.
    #[test]
    fn pss_param_str_is_pss() {
        assert_eq!(Padding::Pss.to_param_str(), "pss");
    }

    /// Verifies the PSS legacy integer code per
    /// `RSA_PKCS1_PSS_PADDING` in `include/openssl/rsa.h` (== 6).
    #[test]
    fn pss_legacy_int_is_6() {
        assert_eq!(Padding::Pss.to_legacy_int(), 6);
    }

    /// Verifies the [`PssSign`] alias resolves to [`Padding`].
    #[test]
    fn pss_sign_alias_resolves() {
        let p: super::PssSign = Padding::Pss;
        assert_eq!(p.to_param_str(), "pss");
    }

    /// Verifies that `KeyKind::RsaPss` is a distinct identifier from
    /// `KeyKind::Rsa` — important for RFC 4055 strict-mode verifiers
    /// that reject parameter substitution.
    #[test]
    fn pss_keykind_distinct_from_rsa() {
        assert_ne!(KeyKind::RsaPss, KeyKind::Rsa);
    }

    /// Verifies the [`PssKey`] alias resolves to [`KeyKind`].
    #[test]
    fn pss_key_alias_resolves() {
        let k: super::PssKey = KeyKind::RsaPss;
        assert_eq!(k, KeyKind::RsaPss);
    }

    /// Verifies that the PSS variant is distinguishable from PKCS#1 v1.5
    /// and from OAEP — critical for verifier-side dispatch logic.
    #[test]
    fn pss_distinct_from_other_paddings() {
        assert_ne!(Padding::Pss, Padding::Pkcs1);
        assert_ne!(Padding::Pss, Padding::Pkcs1Oaep);
        assert_ne!(Padding::Pss, Padding::NoPadding);
        assert_ne!(Padding::Pss, Padding::X931);
    }
}
