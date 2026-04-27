//! ML-DSA (FIPS 204) signature provider implementation.
//!
//! Translates the ML-DSA signature dispatch entries from
//! `providers/defltprov.c` lines 506–514 into Rust descriptors consumed by
//! [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/ml_dsa_sig.c` (~510 lines) and
//! provides the FIPS 204 Module-Lattice-Based Digital Signature Algorithm
//! across three security categories (level 2, 3, and 5).
//!
//! # Algorithm Coverage
//!
//! | Variant     | NIST Security Category | OID                              |
//! |-------------|------------------------|----------------------------------|
//! | ML-DSA-44   | 2                      | 2.16.840.1.101.3.4.3.17          |
//! | ML-DSA-65   | 3                      | 2.16.840.1.101.3.4.3.18          |
//! | ML-DSA-87   | 5                      | 2.16.840.1.101.3.4.3.19          |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::ml_dsa::descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                  | Rust Equivalent                                 |
//! |-----------------------------------------------------------|--------------------------------------------------|
//! | `providers/defltprov.c` lines 506–514 (deflt_signature)   | `descriptors` in this module                   |
//! | `providers/implementations/signatures/ml_dsa_sig.c`       | `openssl-crypto::pqc::ml_dsa` (algorithm logic)  |
//! | `PROV_NAMES_ML_DSA_*` macros in `prov/names.h`            | the `names` slice on each `AlgorithmDescriptor` |

use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Property string registered by every default-provider ML-DSA descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Returns ML-DSA signature algorithm descriptors for provider registration.
///
/// Emits one descriptor per parameter set
/// (`OSSL_DISPATCH ossl_ml_dsa_{44,65,87}_signature_functions[]`).
/// The order mirrors the C array so consumers iterating the results observe
/// the same precedence as the C build.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &[
                "ML-DSA-44",
                "MLDSA44",
                "2.16.840.1.101.3.4.3.17",
                "id-ml-dsa-44",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-44 implementation (FIPS 204, security category 2)",
        ),
        algorithm(
            &[
                "ML-DSA-65",
                "MLDSA65",
                "2.16.840.1.101.3.4.3.18",
                "id-ml-dsa-65",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-65 implementation (FIPS 204, security category 3)",
        ),
        algorithm(
            &[
                "ML-DSA-87",
                "MLDSA87",
                "2.16.840.1.101.3.4.3.19",
                "id-ml-dsa-87",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-87 implementation (FIPS 204, security category 5)",
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
    fn descriptors_returns_three_entries() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3, "expected three ML-DSA parameter sets");
    }

    #[test]
    fn descriptors_cover_all_security_levels() {
        let descs = descriptors();
        for canonical in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing ML-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_include_alias_and_oid() {
        let descs = descriptors();
        for d in &descs {
            // every descriptor carries at least canonical + compact + OID + id-ml-dsa-*
            assert!(d.names.len() >= 4, "expected canonical + 3 aliases");
        }
    }

    #[test]
    fn descriptors_have_default_property() {
        let descs = descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }
}
