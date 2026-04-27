//! SLH-DSA (FIPS 205) signature provider implementation.
//!
//! Translates the SLH-DSA signature dispatch entries from
//! `providers/defltprov.c` lines 515–540 into Rust descriptors consumed by
//! [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/slh_dsa_sig.c` (~390 lines) and
//! provides the FIPS 205 Stateless Hash-Based Digital Signature Algorithm,
//! which exposes 12 parameter sets across two hash families and three
//! security levels.
//!
//! # Algorithm Coverage
//!
//! Each parameter set is named `SLH-DSA-<HASH>-<LEVEL><MODE>` where:
//! - `<HASH>` is `SHA2` or `SHAKE`
//! - `<LEVEL>` is `128`, `192`, or `256` (security category 1, 3, 5)
//! - `<MODE>` is `s` (small/slow signing) or `f` (fast signing)
//!
//! All twelve combinations are registered.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::slh_dsa::descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                  | Rust Equivalent                                  |
//! |-----------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` lines 515–540                     | `descriptors` in this module                    |
//! | `providers/implementations/signatures/slh_dsa_sig.c`      | `openssl-crypto::pqc::slh_dsa` (algorithm logic)  |
//! | `PROV_NAMES_SLH_DSA_*` macros in `prov/names.h`           | the `names` slice on each `AlgorithmDescriptor` |

use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Property string registered by every default-provider SLH-DSA descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Returns SLH-DSA signature algorithm descriptors for provider registration.
///
/// Emits one descriptor per parameter set (`OSSL_DISPATCH
/// ossl_slh_dsa_{sha2,shake}_{128,192,256}{s,f}_signature_functions[]`).
/// The order mirrors the C array — SHA-2 family first, then SHAKE family,
/// each iterated through 128/192/256 bits with `s` (slow) before `f` (fast).
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // --- SHA-2 family (lines 516–527 in defltprov.c) ---
        algorithm(
            &[
                "SLH-DSA-SHA2-128s",
                "id-slh-dsa-sha2-128s",
                "2.16.840.1.101.3.4.3.20",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-128f",
                "id-slh-dsa-sha2-128f",
                "2.16.840.1.101.3.4.3.21",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192s",
                "id-slh-dsa-sha2-192s",
                "2.16.840.1.101.3.4.3.22",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192f",
                "id-slh-dsa-sha2-192f",
                "2.16.840.1.101.3.4.3.23",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256s",
                "id-slh-dsa-sha2-256s",
                "2.16.840.1.101.3.4.3.24",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256f",
                "id-slh-dsa-sha2-256f",
                "2.16.840.1.101.3.4.3.25",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256f implementation (FIPS 205)",
        ),
        // --- SHAKE family (lines 528–539 in defltprov.c) ---
        algorithm(
            &[
                "SLH-DSA-SHAKE-128s",
                "id-slh-dsa-shake-128s",
                "2.16.840.1.101.3.4.3.26",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-128f",
                "id-slh-dsa-shake-128f",
                "2.16.840.1.101.3.4.3.27",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192s",
                "id-slh-dsa-shake-192s",
                "2.16.840.1.101.3.4.3.28",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192f",
                "id-slh-dsa-shake-192f",
                "2.16.840.1.101.3.4.3.29",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256s",
                "id-slh-dsa-shake-256s",
                "2.16.840.1.101.3.4.3.30",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256f",
                "id-slh-dsa-shake-256f",
                "2.16.840.1.101.3.4.3.31",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256f implementation (FIPS 205)",
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
    fn descriptors_returns_twelve_entries() {
        let descs = descriptors();
        assert_eq!(descs.len(), 12, "expected 12 SLH-DSA parameter sets");
    }

    #[test]
    fn descriptors_cover_sha2_family() {
        let descs = descriptors();
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
                "missing SLH-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_cover_shake_family() {
        let descs = descriptors();
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
                "missing SLH-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_carry_oid_aliases() {
        let descs = descriptors();
        for d in &descs {
            assert!(
                d.names.iter().any(|n| n.starts_with("2.16.840.1.101.3.4.3.")),
                "every SLH-DSA descriptor must carry an OID alias"
            );
            assert!(
                d.names.iter().any(|n| n.starts_with("id-slh-dsa-")),
                "every SLH-DSA descriptor must carry an `id-slh-dsa-*` alias"
            );
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
