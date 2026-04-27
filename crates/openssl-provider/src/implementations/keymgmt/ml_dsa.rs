//! ML-DSA (FIPS 204) key management provider implementation.
//!
//! Translates the ML-DSA key-management dispatch entries from
//! `providers/defltprov.c` (the three `OSSL_DISPATCH
//! ossl_ml_dsa_{44,65,87}_keymgmt_functions[]` tables) into Rust descriptors
//! consumed by [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/ml_dsa_kmgmt.c` (~594 lines) and
//! provides `KeyMgmtProvider`-equivalent operations for the three FIPS 204
//! parameter sets.
//!
//! | Parameter set | NIST security category | Public key | Signature |
//! |---------------|------------------------|------------|-----------|
//! | ML-DSA-44     | 2                      | 1312 B     | 2420 B    |
//! | ML-DSA-65     | 3                      | 1952 B     | 3309 B    |
//! | ML-DSA-87     | 5                      | 2592 B     | 4627 B    |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::ml_dsa::ml_dsa_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                  | Rust Equivalent                                  |
//! |-----------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (ML-DSA `KEYMGMT` entries)        | `ml_dsa_descriptors` in this module             |
//! | `providers/implementations/keymgmt/ml_dsa_kmgmt.c`        | `openssl-crypto::pqc::ml_dsa` (algorithm logic)   |
//! | `PROV_NAMES_ML_DSA_*` macros in `prov/names.h`            | the `names` slice on each `AlgorithmDescriptor` |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns ML-DSA key management algorithm descriptors for provider registration.
///
/// Emits one descriptor per FIPS 204 parameter set, matching the iteration
/// order used in `defltprov.c` (44 → 65 → 87).
#[must_use]
pub fn ml_dsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["ML-DSA-44", "MLDSA44", "id-ml-dsa-44", "2.16.840.1.101.3.4.3.17"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-44 implementation (FIPS 204, NIST cat 2)",
        ),
        algorithm(
            &["ML-DSA-65", "MLDSA65", "id-ml-dsa-65", "2.16.840.1.101.3.4.3.18"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-65 implementation (FIPS 204, NIST cat 3)",
        ),
        algorithm(
            &["ML-DSA-87", "MLDSA87", "id-ml-dsa-87", "2.16.840.1.101.3.4.3.19"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-87 implementation (FIPS 204, NIST cat 5)",
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
    fn ml_dsa_descriptors_returns_three_entries() {
        let descs = ml_dsa_descriptors();
        assert_eq!(descs.len(), 3, "expected ML-DSA-44 + ML-DSA-65 + ML-DSA-87");
    }

    #[test]
    fn ml_dsa_descriptors_cover_all_security_levels() {
        let descs = ml_dsa_descriptors();
        for canonical in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing ML-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn ml_dsa_descriptors_carry_oid_and_aliases() {
        let descs = ml_dsa_descriptors();
        for d in &descs {
            assert!(
                d.names.iter().any(|n| n.starts_with("2.16.840.1.101.3.4.3.")),
                "missing OID alias for {:?}",
                d.names[0]
            );
            assert!(
                d.names.iter().any(|n| n.starts_with("id-ml-dsa-")),
                "missing `id-ml-dsa-*` alias for {:?}",
                d.names[0]
            );
        }
    }

    #[test]
    fn ml_dsa_descriptors_have_default_property() {
        let descs = ml_dsa_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }
}
