//! Hybrid ML-KEM + ECDH/XDH key management provider implementation.
//!
//! Translates the MLX (ML-KEM hybrid) key-management dispatch entries from
//! `providers/defltprov.c` (the five `OSSL_DISPATCH
//! ossl_mlx_*_keymgmt_functions[]` tables) into Rust descriptors consumed by
//! [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/mlx_kmgmt.c` (~807 lines) and provides
//! `KeyMgmtProvider`-equivalent operations for hybrid post-quantum/classical
//! key exchange combinations as specified for use in TLS 1.3 and IKEv2.
//!
//! | Hybrid combination              | Classical component | PQ component |
//! |---------------------------------|---------------------|--------------|
//! | `X25519MLKEM768`                | X25519              | ML-KEM-768   |
//! | `X448MLKEM1024`                 | X448                | ML-KEM-1024  |
//! | `SecP256r1MLKEM768`             | NIST P-256          | ML-KEM-768   |
//! | `SecP384r1MLKEM1024`            | NIST P-384          | ML-KEM-1024  |
//! | `curveSM2MLKEM768`              | curveSM2            | ML-KEM-768   |
//!
//! Each hybrid produces a shared secret by concatenating the classical and
//! the PQ derived secrets — providing security as long as either the
//! classical or the PQ component remains unbroken.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::mlx::mlx_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                  | Rust Equivalent                                  |
//! |-----------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (MLX `KEYMGMT` entries)           | `mlx_descriptors` in this module                |
//! | `providers/implementations/keymgmt/mlx_kmgmt.c`           | hybrid composition logic per crypto layer         |
//! | `PROV_NAMES_*MLKEM*` macros in `prov/names.h`             | the `names` slice on each `AlgorithmDescriptor` |

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns hybrid ML-KEM key management algorithm descriptors for provider
/// registration.
///
/// Emits one descriptor per (`classical_curve`, `ml_kem_param_set`) hybrid in
/// iteration order matching the C `defltprov.c` registration sequence:
/// X25519MLKEM768, X448MLKEM1024, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`,
/// curveSM2MLKEM768.
#[must_use]
pub fn mlx_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["X25519MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL X25519+ML-KEM-768 TLS hybrid implementation",
        ),
        algorithm(
            &["X448MLKEM1024"],
            DEFAULT_PROPERTY,
            "OpenSSL X448+ML-KEM-1024 TLS hybrid implementation",
        ),
        algorithm(
            &["SecP256r1MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL P-256+ML-KEM-768 TLS hybrid implementation",
        ),
        algorithm(
            &["SecP384r1MLKEM1024"],
            DEFAULT_PROPERTY,
            "OpenSSL P-384+ML-KEM-1024 TLS hybrid implementation",
        ),
        algorithm(
            &["curveSM2MLKEM768"],
            DEFAULT_PROPERTY,
            "OpenSSL curveSM2+ML-KEM-768 TLS hybrid implementation",
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
    fn mlx_descriptors_returns_five_entries() {
        let descs = mlx_descriptors();
        assert_eq!(descs.len(), 5, "expected 5 hybrid combinations");
    }

    #[test]
    fn mlx_descriptors_cover_all_hybrids() {
        let descs = mlx_descriptors();
        for canonical in [
            "X25519MLKEM768",
            "X448MLKEM1024",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
            "curveSM2MLKEM768",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing MLX descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn mlx_descriptors_descriptions_mention_hybrid() {
        let descs = mlx_descriptors();
        for d in &descs {
            assert!(
                d.description.contains("hybrid"),
                "every MLX description must mention hybrid composition: {}",
                d.description
            );
        }
    }

    #[test]
    fn mlx_descriptors_have_default_property() {
        let descs = mlx_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }
}
