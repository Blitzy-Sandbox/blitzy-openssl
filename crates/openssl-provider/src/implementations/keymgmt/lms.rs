//! LMS (Leighton-Micali Hash-Based Signature) key management provider
//! implementation.
//!
//! Translates the LMS key-management dispatch entry from
//! `providers/defltprov.c` (the `OSSL_DISPATCH ossl_lms_keymgmt_functions[]`
//! table) into a Rust descriptor consumed by
//! [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/lms_kmgmt.c` (~213 lines) and provides
//! `KeyMgmtProvider`-equivalent operations for NIST SP 800-208 / RFC 8554
//! LMS hash-based signatures. The provider supports key import for
//! verification only — key generation and signing are out of scope per
//! SP 800-208 guidance because LMS is a stateful signature scheme whose
//! safe production use requires hardware-protected state.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::lms::lms_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                       | Rust Equivalent                                   |
//! |----------------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (LMS `KEYMGMT` entry)                  | `lms_descriptors` in this module                |
//! | `providers/implementations/keymgmt/lms_kmgmt.c`                | LMS keymgmt implementation (verify-only)          |
//! | `PROV_NAMES_LMS` macro in `prov/names.h`                       | the `names` slice on the `AlgorithmDescriptor`  |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns LMS key management algorithm descriptors for provider
/// registration.
///
/// Emits a single descriptor for the LMS algorithm. LMS is a stateful
/// hash-based signature scheme; this provider supports verification only.
#[must_use]
pub fn lms_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &[
            "LMS",
            "id-alg-hss-lms-hashsig",
            "1.2.840.113549.1.9.16.3.17",
        ],
        DEFAULT_PROPERTY,
        "OpenSSL LMS implementation (NIST SP 800-208 verify-only)",
    )]
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
    fn lms_descriptors_returns_one_entry() {
        let descs = lms_descriptors();
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn lms_descriptors_canonical_name_is_lms() {
        let descs = lms_descriptors();
        assert_eq!(descs[0].names[0], "LMS");
    }

    #[test]
    fn lms_descriptors_carry_oid_and_textual_alias() {
        let descs = lms_descriptors();
        assert!(descs[0]
            .names
            .iter()
            .any(|n| *n == "id-alg-hss-lms-hashsig"));
        assert!(descs[0]
            .names
            .iter()
            .any(|n| *n == "1.2.840.113549.1.9.16.3.17"));
    }

    #[test]
    fn lms_descriptors_have_default_property() {
        let descs = lms_descriptors();
        assert_eq!(descs[0].property, DEFAULT_PROPERTY);
        assert!(!descs[0].description.is_empty());
        assert!(
            descs[0].description.contains("verify-only"),
            "LMS description must reflect verify-only nature: {}",
            descs[0].description
        );
    }
}
