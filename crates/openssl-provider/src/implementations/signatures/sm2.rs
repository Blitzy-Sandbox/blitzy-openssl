//! SM2 signature provider implementation.
//!
//! Translates the SM2 signature dispatch entry from `providers/defltprov.c`
//! line 493 (`PROV_NAMES_SM2`, `ossl_sm2_signature_functions`) into a Rust
//! descriptor consumed by [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/sm2_sig.c` (~593 lines) and provides
//! the SM2 digital signature algorithm defined by GB/T 32918.2-2016 (the
//! Chinese national elliptic-curve standard).
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::sm2::descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                | Rust Equivalent                                     |
//! |---------------------------------------------------------|------------------------------------------------------|
//! | `providers/defltprov.c` line 493 (deflt_signature SM2)  | `descriptors` in this module                       |
//! | `providers/implementations/signatures/sm2_sig.c`        | `openssl-crypto::ec::sm2` + EVP signature dispatch   |
//! | `PROV_NAMES_SM2` in `prov/names.h`                      | the `names` slice on the `AlgorithmDescriptor`     |

use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Property string registered by every default-provider SM2 descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Returns SM2 signature algorithm descriptors for provider registration.
///
/// Emits a single descriptor mirroring the
/// `OSSL_DISPATCH ossl_sm2_signature_functions[]` entry registered at
/// `providers/defltprov.c:493`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["SM2", "1.2.156.10197.1.301"],
        DEFAULT_PROPERTY,
        "OpenSSL SM2 implementation",
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
        assert_eq!(descs.len(), 1, "SM2 should register exactly one descriptor");
    }

    #[test]
    fn descriptors_canonical_name_is_sm2() {
        let descs = descriptors();
        let first = descs.first().expect("at least one descriptor");
        assert_eq!(first.names[0], "SM2");
    }

    #[test]
    fn descriptors_carry_oid_alias() {
        let descs = descriptors();
        assert!(
            descs.iter().any(|d| d.names.contains(&"1.2.156.10197.1.301")),
            "SM2 OID alias must be registered"
        );
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
