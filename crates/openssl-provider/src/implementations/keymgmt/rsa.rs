//! RSA key management provider implementation.
//!
//! Translates the RSA key-management dispatch entries from
//! `providers/defltprov.c` (lines 605–608, where the C source registers two
//! `OSSL_DISPATCH` tables — `ossl_rsa_keymgmt_functions` for plain RSA and
//! `ossl_rsapss_keymgmt_functions` for RSA-PSS-restricted keys) into Rust
//! descriptors consumed by [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface lives in
//! `providers/implementations/keymgmt/rsa_kmgmt.c` (~823 lines) and provides
//! `KeyMgmtProvider`-equivalent operations (gen, free, export, import,
//! match, validate) for both the standard RSA key type and the PSS-restricted
//! variant — the latter pinning a fixed signing scheme/digest/MGF1 hash to a
//! key.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::rsa::rsa_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                | Rust Equivalent                                    |
//! |---------------------------------------------------------|-----------------------------------------------------|
//! | `providers/defltprov.c` lines 605–608                   | `rsa_descriptors` in this module                 |
//! | `providers/implementations/keymgmt/rsa_kmgmt.c`         | `openssl-crypto::evp::keymgmt` (algorithm logic)    |
//! | `PROV_NAMES_RSA` / `PROV_NAMES_RSA_PSS` in `prov/names.h` | the `names` slice on each `AlgorithmDescriptor` |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns RSA key management algorithm descriptors for provider registration.
///
/// Emits two descriptors:
///
/// * `RSA` — the standard PKCS #1 v1.5 / PKCS #1 v2.1 RSA key type
///   (canonical name `RSA`, alias `rsaEncryption`, OID `1.2.840.113549.1.1.1`).
/// * `RSA-PSS` — RSA keys restricted to the RSASSA-PSS signing scheme
///   (canonical name `RSA-PSS`, alias `RSASSA-PSS`, OID `1.2.840.113549.1.1.10`).
///
/// The order mirrors the C array order in `defltprov.c` so that downstream
/// fetch lookups produce identical iteration ordering.
#[must_use]
pub fn rsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA", "rsaEncryption", "1.2.840.113549.1.1.1"],
            DEFAULT_PROPERTY,
            "OpenSSL RSA implementation",
        ),
        algorithm(
            &["RSA-PSS", "RSASSA-PSS", "1.2.840.113549.1.1.10"],
            DEFAULT_PROPERTY,
            "OpenSSL RSA-PSS implementation",
        ),
    ]
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    #[test]
    fn rsa_descriptors_returns_two_entries() {
        let descs = rsa_descriptors();
        assert_eq!(descs.len(), 2, "expected RSA + RSA-PSS");
    }

    #[test]
    fn rsa_descriptors_first_entry_is_plain_rsa() {
        let descs = rsa_descriptors();
        assert_eq!(descs[0].names[0], "RSA");
        assert!(descs[0].names.contains(&"rsaEncryption"));
        assert!(descs[0].names.contains(&"1.2.840.113549.1.1.1"));
    }

    #[test]
    fn rsa_descriptors_second_entry_is_rsa_pss() {
        let descs = rsa_descriptors();
        assert_eq!(descs[1].names[0], "RSA-PSS");
        assert!(descs[1].names.contains(&"RSASSA-PSS"));
        assert!(descs[1].names.contains(&"1.2.840.113549.1.1.10"));
    }

    #[test]
    fn rsa_descriptors_have_default_property() {
        let descs = rsa_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }
}
