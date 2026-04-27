//! ML-KEM (FIPS 203) key management provider implementation.
//!
//! Translates the ML-KEM key-management dispatch entries from
//! `providers/defltprov.c` (the three `OSSL_DISPATCH
//! ossl_ml_kem_{512,768,1024}_keymgmt_functions[]` tables) into Rust
//! descriptors consumed by [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/ml_kem_kmgmt.c` (~859 lines) and
//! provides `KeyMgmtProvider`-equivalent operations for the three FIPS 203
//! Module-Lattice-Based KEM parameter sets.
//!
//! | Parameter set | NIST security category | Public key | Ciphertext |
//! |---------------|------------------------|------------|------------|
//! | ML-KEM-512    | 1                      | 800 B      | 768 B      |
//! | ML-KEM-768    | 3                      | 1184 B     | 1088 B     |
//! | ML-KEM-1024   | 5                      | 1568 B     | 1568 B     |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::ml_kem::ml_kem_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                  | Rust Equivalent                                  |
//! |-----------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (ML-KEM `KEYMGMT` entries)        | `ml_kem_descriptors` in this module             |
//! | `providers/implementations/keymgmt/ml_kem_kmgmt.c`        | `openssl-crypto::pqc::ml_kem` (algorithm logic)   |
//! | `PROV_NAMES_ML_KEM_*` macros in `prov/names.h`            | the `names` slice on each `AlgorithmDescriptor` |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns ML-KEM key management algorithm descriptors for provider registration.
///
/// Emits one descriptor per FIPS 203 parameter set in iteration order
/// 512 → 768 → 1024, matching the C `defltprov.c` registration sequence.
#[must_use]
pub fn ml_kem_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["ML-KEM-512", "MLKEM512", "id-alg-ml-kem-512", "2.16.840.1.101.3.4.4.1"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-512 implementation (FIPS 203, NIST cat 1)",
        ),
        algorithm(
            &["ML-KEM-768", "MLKEM768", "id-alg-ml-kem-768", "2.16.840.1.101.3.4.4.2"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-768 implementation (FIPS 203, NIST cat 3)",
        ),
        algorithm(
            &["ML-KEM-1024", "MLKEM1024", "id-alg-ml-kem-1024", "2.16.840.1.101.3.4.4.3"],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-1024 implementation (FIPS 203, NIST cat 5)",
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
    fn ml_kem_descriptors_returns_three_entries() {
        let descs = ml_kem_descriptors();
        assert_eq!(descs.len(), 3);
    }

    #[test]
    fn ml_kem_descriptors_cover_all_security_levels() {
        let descs = ml_kem_descriptors();
        for canonical in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing ML-KEM descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn ml_kem_descriptors_carry_oid_and_aliases() {
        let descs = ml_kem_descriptors();
        for d in &descs {
            assert!(
                d.names.iter().any(|n| n.starts_with("2.16.840.1.101.3.4.4.")),
                "missing OID alias for {:?}",
                d.names[0]
            );
            assert!(
                d.names.iter().any(|n| n.starts_with("id-alg-ml-kem-")),
                "missing `id-alg-ml-kem-*` alias for {:?}",
                d.names[0]
            );
        }
    }

    #[test]
    fn ml_kem_descriptors_have_default_property() {
        let descs = ml_kem_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }
}
