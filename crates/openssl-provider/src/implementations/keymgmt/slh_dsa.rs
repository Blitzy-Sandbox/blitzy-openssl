//! SLH-DSA (FIPS 205) key management provider implementation.
//!
//! Translates the SLH-DSA key-management dispatch entries from
//! `providers/defltprov.c` (12 `OSSL_DISPATCH ossl_slh_dsa_*_keymgmt_functions[]`
//! tables, one per (hash family, security category, sign profile) tuple) into
//! Rust descriptors consumed by
//! [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/slh_dsa_kmgmt.c` (~481 lines) and
//! provides `KeyMgmtProvider`-equivalent operations for FIPS 205 SLH-DSA
//! (Stateless Hash-Based Digital Signature Algorithm).
//!
//! # Parameter sets and OIDs
//!
//! SLH-DSA defines 12 parameter sets covering two hash families
//! (SHA-2 and SHAKE), three NIST security categories (1, 3, 5), and two
//! sign-time/signature-size profiles (`s` = small signatures slow signing,
//! `f` = fast signing larger signatures).
//!
//! | Parameter set        | Cat | Hash family | Profile | OID                              |
//! |---------------------|-----|-------------|---------|----------------------------------|
//! | `SLH-DSA-SHA2-128s` | 1   | SHA-2       | small   | 2.16.840.1.101.3.4.3.20          |
//! | `SLH-DSA-SHA2-128f` | 1   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.21          |
//! | `SLH-DSA-SHA2-192s` | 3   | SHA-2       | small   | 2.16.840.1.101.3.4.3.22          |
//! | `SLH-DSA-SHA2-192f` | 3   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.23          |
//! | `SLH-DSA-SHA2-256s` | 5   | SHA-2       | small   | 2.16.840.1.101.3.4.3.24          |
//! | `SLH-DSA-SHA2-256f` | 5   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.25          |
//! | `SLH-DSA-SHAKE-128s`| 1   | SHAKE       | small   | 2.16.840.1.101.3.4.3.26          |
//! | `SLH-DSA-SHAKE-128f`| 1   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.27          |
//! | `SLH-DSA-SHAKE-192s`| 3   | SHAKE       | small   | 2.16.840.1.101.3.4.3.28          |
//! | `SLH-DSA-SHAKE-192f`| 3   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.29          |
//! | `SLH-DSA-SHAKE-256s`| 5   | SHAKE       | small   | 2.16.840.1.101.3.4.3.30          |
//! | `SLH-DSA-SHAKE-256f`| 5   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.31          |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::slh_dsa::slh_dsa_descriptors`
//! (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                       | Rust Equivalent                                   |
//! |----------------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (SLH-DSA `KEYMGMT` entries)            | `slh_dsa_descriptors` in this module            |
//! | `providers/implementations/keymgmt/slh_dsa_kmgmt.c`            | per parameter-set keymgmt implementation          |
//! | `PROV_NAMES_SLH_DSA_*` macros in `prov/names.h`                | the `names` slice on each `AlgorithmDescriptor` |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns SLH-DSA key management algorithm descriptors for provider
/// registration.
///
/// Emits 12 descriptors covering all FIPS 205 parameter sets in iteration
/// order matching the C `defltprov.c` registration sequence: first all SHA-2
/// variants in security-category order, then all SHAKE variants in the same
/// order.
#[must_use]
pub fn slh_dsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // ---- SHA-2 family ----
        algorithm(
            &[
                "SLH-DSA-SHA2-128s",
                "id-slh-dsa-sha2-128s",
                "2.16.840.1.101.3.4.3.20",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128s implementation (FIPS 205, NIST cat 1, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-128f",
                "id-slh-dsa-sha2-128f",
                "2.16.840.1.101.3.4.3.21",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128f implementation (FIPS 205, NIST cat 1, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192s",
                "id-slh-dsa-sha2-192s",
                "2.16.840.1.101.3.4.3.22",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192s implementation (FIPS 205, NIST cat 3, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192f",
                "id-slh-dsa-sha2-192f",
                "2.16.840.1.101.3.4.3.23",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192f implementation (FIPS 205, NIST cat 3, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256s",
                "id-slh-dsa-sha2-256s",
                "2.16.840.1.101.3.4.3.24",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256s implementation (FIPS 205, NIST cat 5, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256f",
                "id-slh-dsa-sha2-256f",
                "2.16.840.1.101.3.4.3.25",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256f implementation (FIPS 205, NIST cat 5, fast)",
        ),
        // ---- SHAKE family ----
        algorithm(
            &[
                "SLH-DSA-SHAKE-128s",
                "id-slh-dsa-shake-128s",
                "2.16.840.1.101.3.4.3.26",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128s implementation (FIPS 205, NIST cat 1, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-128f",
                "id-slh-dsa-shake-128f",
                "2.16.840.1.101.3.4.3.27",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128f implementation (FIPS 205, NIST cat 1, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192s",
                "id-slh-dsa-shake-192s",
                "2.16.840.1.101.3.4.3.28",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192s implementation (FIPS 205, NIST cat 3, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192f",
                "id-slh-dsa-shake-192f",
                "2.16.840.1.101.3.4.3.29",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192f implementation (FIPS 205, NIST cat 3, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256s",
                "id-slh-dsa-shake-256s",
                "2.16.840.1.101.3.4.3.30",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256s implementation (FIPS 205, NIST cat 5, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256f",
                "id-slh-dsa-shake-256f",
                "2.16.840.1.101.3.4.3.31",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256f implementation (FIPS 205, NIST cat 5, fast)",
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
    fn slh_dsa_descriptors_returns_twelve_entries() {
        let descs = slh_dsa_descriptors();
        assert_eq!(descs.len(), 12, "expected 12 SLH-DSA parameter sets");
    }

    #[test]
    fn slh_dsa_descriptors_cover_sha2_family() {
        let descs = slh_dsa_descriptors();
        for canonical in [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SHA-2 variant: {canonical}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_cover_shake_family() {
        let descs = slh_dsa_descriptors();
        for canonical in [
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SHAKE variant: {canonical}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_carry_oid_aliases() {
        let descs = slh_dsa_descriptors();
        let expected_oids = [
            "2.16.840.1.101.3.4.3.20",
            "2.16.840.1.101.3.4.3.21",
            "2.16.840.1.101.3.4.3.22",
            "2.16.840.1.101.3.4.3.23",
            "2.16.840.1.101.3.4.3.24",
            "2.16.840.1.101.3.4.3.25",
            "2.16.840.1.101.3.4.3.26",
            "2.16.840.1.101.3.4.3.27",
            "2.16.840.1.101.3.4.3.28",
            "2.16.840.1.101.3.4.3.29",
            "2.16.840.1.101.3.4.3.30",
            "2.16.840.1.101.3.4.3.31",
        ];
        for oid in expected_oids {
            assert!(
                descs.iter().any(|d| d.names.iter().any(|n| *n == oid)),
                "missing OID alias: {oid}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_have_default_property() {
        let descs = slh_dsa_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
            assert_eq!(
                d.names.len(),
                3,
                "every SLH-DSA descriptor should have canonical name + textual id alias + OID"
            );
        }
    }
}
