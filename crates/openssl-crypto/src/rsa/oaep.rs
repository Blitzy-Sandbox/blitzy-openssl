//! RSA OAEP padding (Optimal Asymmetric Encryption Padding).
//!
//! Implements / surfaces the OAEP encryption padding scheme as specified
//! in **RFC 8017 §7.1** (PKCS #1 v2.2). OAEP is the recommended padding
//! mode for RSA encryption in new deployments because it provides
//! IND-CCA2 security under the RSA assumption in the random oracle model
//! (Bellare-Rogaway, Eurocrypt 1994; Fujisaki-Okamoto-Pointcheval-Stern,
//! CRYPTO 2001).
//!
//! In the Rust workspace, the OAEP padding mode is represented by the
//! [`RsaPadding::Pkcs1Oaep`] variant of the [`RsaPadding`] enum (defined
//! in [`crate::evp::pkey`]). The actual encryption / decryption logic is
//! implemented in [`crate::evp::signature::AsymCipherContext`] and
//! dispatched to the underlying provider via the
//! [`crate::evp::pkey::PKeyCtx`] context.
//!
//! This submodule re-exports the OAEP-specific symbols and provides
//! detailed RFC 8017 §7.1 documentation.
//!
//! # Source Mapping
//!
//! | Rust Component                  | C Source File                        | Purpose                                          |
//! |---------------------------------|--------------------------------------|--------------------------------------------------|
//! | `Padding::Pkcs1Oaep`            | `include/openssl/rsa.h::RSA_PKCS1_OAEP_PADDING` | Padding-mode discriminator (integer 4) |
//! | `Padding::Pkcs1Oaep::to_param_str` | `include/openssl/core_names.h::OSSL_PKEY_RSA_PAD_MODE_OAEP` | Provider-API parameter name `"oaep"` |
//! | OAEP encode                     | `crypto/rsa/rsa_oaep.c::RSA_padding_add_PKCS1_OAEP_mgf1`| RFC 8017 §7.1.1 EME-OAEP encode |
//! | OAEP decode                     | `crypto/rsa/rsa_oaep.c::RSA_padding_check_PKCS1_OAEP_mgf1`| RFC 8017 §7.1.2 EME-OAEP decode |
//! | MGF1 mask generation            | `crypto/rsa/rsa_pmeth.c::PKCS1_MGF1` | RFC 8017 §B.2.1 MGF1 implementation            |
//!
//! # OAEP Encoding (RFC 8017 §7.1.1 EME-OAEP-Encode)
//!
//! OAEP transforms a message `M` of length `mLen ≤ k − 2hLen − 2` octets
//! (where `k` is the RSA modulus length in octets and `hLen` is the hash
//! function output length in octets) into an encoded message `EM` of
//! length `k` octets:
//!
//! ```text
//! 1. lHash = Hash(L)                            // L is the optional label
//! 2. PS    = (k − mLen − 2hLen − 2) zero octets
//! 3. DB    = lHash || PS || 0x01 || M           // length k − hLen − 1
//! 4. seed  = random hLen octets
//! 5. dbMask  = MGF1(seed, k − hLen − 1)
//! 6. maskedDB = DB ⊕ dbMask
//! 7. seedMask = MGF1(maskedDB, hLen)
//! 8. maskedSeed = seed ⊕ seedMask
//! 9. EM    = 0x00 || maskedSeed || maskedDB     // total length k
//! ```
//!
//! The defaults in this Rust workspace (which match upstream OpenSSL):
//!
//! - **Hash:** SHA-1 (legacy default; SHA-256 strongly recommended for
//!   new code via the OAEP-MD provider parameter)
//! - **MGF1 hash:** same as the OAEP hash (overrideable via the
//!   MGF1-MD provider parameter)
//! - **Label:** empty string (overrideable via the OAEP-LABEL parameter)
//!
//! # OAEP Decoding (RFC 8017 §7.1.2 EME-OAEP-Decode)
//!
//! Decoding mirrors the encoding steps but is implemented in
//! **constant time** to avoid the Manger attack (Manger, CRYPTO 2001),
//! which exploits timing differences in the leading-byte check
//! (`Y == 0x00`) to recover the plaintext bit-by-bit. The Rust
//! implementation treats all comparisons with `subtle::ConstantTimeEq`
//! and never branches on secret data.
//!
//! # Choice of Hash Function
//!
//! Per **NIST SP 800-131A Rev. 2 §6**, SHA-1 is **disallowed** for new
//! RSA-OAEP deployments after 2030. Use SHA-256 or SHA-384 by setting
//! the OAEP-MD and MGF1-MD parameters on the [`PKeyCtx`].
//!
//! # Specifications
//!
//! - **RFC 8017 §7.1** — RSAES-OAEP Encryption Scheme
//! - **RFC 8017 §B.2.1** — MGF1 Mask Generation Function
//! - **NIST SP 800-56B Rev. 2 §7.2.2.3** — RSA-OAEP-KEM Key-Transport
//! - **NIST SP 800-131A Rev. 2 §6** — Hash function transitions
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Optional label parameter is `Option<&[u8]>`.
//! - **R6 (Lossless Casts):** No `as` casts in this submodule.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks; `forbid(unsafe_code)` on
//!   the parent crate enforces this.
//! - **R10 (Wiring):** Reachable from
//!   `openssl_crypto::rsa::oaep::Padding::Pkcs1Oaep`.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::rsa::oaep::Padding;
//!
//! // OAEP padding is integer code 4 / param string "oaep" per RFC 8017.
//! assert_eq!(Padding::Pkcs1Oaep.to_legacy_int(), 4);
//! assert_eq!(Padding::Pkcs1Oaep.to_param_str(), "oaep");
//! ```
//!
//! [`PKeyCtx`]: crate::evp::pkey::PKeyCtx
//! [`RsaPadding`]: crate::evp::pkey::RsaPadding

// ===========================================================================
// Re-exports
// ===========================================================================
//
// The OAEP padding mode is represented by `RsaPadding::Pkcs1Oaep`. We
// alias the enum locally as `Padding` so that callers writing
// `openssl_crypto::rsa::oaep::Padding::Pkcs1Oaep` get a self-documenting
// reference to the OAEP variant alongside the broader padding family.

pub use crate::evp::pkey::RsaPadding as Padding;

/// Convenience type alias matching common `RFC 8017 §7.1` terminology.
///
/// `OaepEncrypt` is a marker type alias for [`Padding`] used to express
/// "encrypt with OAEP padding" intent in API signatures and tests. It is
/// equivalent to [`Padding`] / [`crate::evp::pkey::RsaPadding`].
pub type OaepEncrypt = Padding;

#[cfg(test)]
mod tests {
    //! Unit tests for the OAEP submodule re-exports.
    //!
    //! These tests verify that `Padding::Pkcs1Oaep` round-trips correctly
    //! to its provider-API parameter string and legacy integer code per
    //! RFC 8017 / OpenSSL `include/openssl/rsa.h`.

    use super::Padding;

    /// Verifies the OAEP padding mode parameter string per
    /// `OSSL_PKEY_RSA_PAD_MODE_OAEP`.
    #[test]
    fn oaep_param_str_is_oaep() {
        assert_eq!(Padding::Pkcs1Oaep.to_param_str(), "oaep");
    }

    /// Verifies the OAEP legacy integer code per
    /// `RSA_PKCS1_OAEP_PADDING` in `include/openssl/rsa.h` (== 4).
    #[test]
    fn oaep_legacy_int_is_4() {
        assert_eq!(Padding::Pkcs1Oaep.to_legacy_int(), 4);
    }

    /// Verifies the [`OaepEncrypt`] alias resolves to [`Padding`].
    #[test]
    fn oaep_encrypt_alias_resolves() {
        let p: super::OaepEncrypt = Padding::Pkcs1Oaep;
        assert_eq!(p.to_param_str(), "oaep");
    }

    /// Verifies that the OAEP variant is distinguishable from PKCS#1 v1.5
    /// — important for downstream code that branches on padding mode.
    #[test]
    fn oaep_distinct_from_pkcs1() {
        assert_ne!(Padding::Pkcs1Oaep, Padding::Pkcs1);
        assert_ne!(
            Padding::Pkcs1Oaep.to_legacy_int(),
            Padding::Pkcs1.to_legacy_int()
        );
    }
}
