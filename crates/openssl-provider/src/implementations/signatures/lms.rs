//! LMS (Leighton-Micali Hash-Based Signatures) provider implementation.
//!
//! Translates the LMS signature dispatch entry from
//! `providers/defltprov.c` (line 540, `ALG(PROV_NAMES_LMS,
//! ossl_lms_signature_functions)`) into a Rust descriptor consumed by
//! [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/lms_signature.c` (~290 lines)
//! and provides verify-only support for LMS as defined in
//! NIST SP 800-208 / RFC 8554. LMS is a stateful hash-based signature
//! scheme: only verification is exposed by the default provider.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::lms::descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                             | Rust Equivalent                                  |
//! |------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` line 540                     | `descriptors` in this module                    |
//! | `providers/implementations/signatures/lms_signature.c` | `openssl-crypto::pqc::lms` (algorithm logic)    |
//! | `PROV_NAMES_LMS` in `prov/names.h`                   | `"LMS"` and `id-alg-hss-lms-hashsig` aliases     |

use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Property string registered by every default-provider LMS descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Returns LMS signature algorithm descriptors for provider registration.
///
/// LMS exposes a single `OSSL_DISPATCH ossl_lms_signature_functions[]`
/// table in the C provider (verify-only).  The canonical name is `LMS`,
/// with the IETF `id-alg-hss-lms-hashsig` alias and the corresponding
/// PKIX OID `1.2.840.113549.1.9.16.3.17`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["LMS", "id-alg-hss-lms-hashsig", "1.2.840.113549.1.9.16.3.17"],
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
    fn descriptors_returns_one_entry() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn descriptors_canonical_name_is_lms() {
        let descs = descriptors();
        assert_eq!(descs[0].names[0], "LMS");
    }

    #[test]
    fn descriptors_carry_oid_and_textual_alias() {
        let descs = descriptors();
        let names = &descs[0].names;
        assert!(names.contains(&"id-alg-hss-lms-hashsig"));
        assert!(names.contains(&"1.2.840.113549.1.9.16.3.17"));
    }

    #[test]
    fn descriptors_have_default_property() {
        let descs = descriptors();
        assert_eq!(descs[0].property, DEFAULT_PROPERTY);
        assert!(!descs[0].description.is_empty());
    }
}
