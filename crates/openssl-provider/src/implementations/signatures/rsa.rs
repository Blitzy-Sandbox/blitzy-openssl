//! RSA signature provider implementation.
//!
//! Translates the RSA signature dispatch entries from `providers/defltprov.c`
//! lines 457–473 (the `deflt_signature[]` array) into Rust descriptors
//! consumed by [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/rsa_sig.c` (~2,087 lines) and exports
//! many `OSSL_DISPATCH ossl_rsa_*_signature_functions[]` tables — one for the
//! generic RSA algorithm (used with an explicit digest via `EVP_DigestSignInit`)
//! plus a family of pre-bound combined `RSA-<digest>` tables that pair RSA
//! PKCS#1 v1.5 signing with a fixed message digest.
//!
//! # Architecture
//!
//! - **Provider registration**: this module produces the `AlgorithmDescriptor`
//!   list for every variant the default provider exposes; the actual sign
//!   and verify code paths are dispatched through the EVP layer in
//!   `openssl-crypto::evp::signature` for production use.
//! - **Trait conformance**: full `SignatureProvider` trait implementations
//!   are layered above the EVP hooks; this descriptor module is the
//!   discovery surface used by `MethodStore::fetch`.
//! - **Algorithm coverage**: the descriptors enumerate the standalone `RSA`
//!   algorithm, every `RSA-<digest>` combined sigalg, and the explicit
//!   `RSA-PSS` algorithm so callers can fetch any of them by name.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::rsa::descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                 | Rust Equivalent                                     |
//! |----------------------------------------------------------|------------------------------------------------------|
//! | `providers/defltprov.c` lines 457–473 (deflt_signature)  | `descriptors` in this module                       |
//! | `providers/implementations/signatures/rsa_sig.c`         | `openssl-crypto::evp::signature` (algorithm logic)   |
//! | `PROV_NAMES_RSA*` macros in `prov/names.h`               | the `names` slice on each `AlgorithmDescriptor`    |

use crate::implementations::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Property string registered by every default-provider RSA descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Returns RSA signature algorithm descriptors for provider registration.
///
/// Emits one descriptor for each `OSSL_DISPATCH ossl_rsa_*_signature_functions[]`
/// table the C default provider registers between
/// `providers/defltprov.c:457` and `:473`. The order mirrors the C array so
/// callers iterating the results observe the same precedence as the C build.
///
/// Returned `AlgorithmDescriptor` values are cheap to clone and bear no
/// lifetime tying them to the library context; they may be aggregated or
/// filtered freely.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // Generic RSA — used with `EVP_DigestSignInit`/`EVP_DigestVerifyInit`
        // when the caller binds the digest at runtime.
        algorithm(
            &["RSA", "rsaEncryption", "1.2.840.113549.1.1.1"],
            DEFAULT_PROPERTY,
            "OpenSSL RSA implementation",
        ),
        // Combined RSA + RIPEMD-160.
        algorithm(
            &["RSA-RIPEMD160", "ripemd160WithRSA", "1.3.36.3.3.1.2"],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with RIPEMD-160",
        ),
        // Combined RSA + SHA-1 (legacy but widely deployed).
        algorithm(
            &[
                "RSA-SHA1",
                "RSA-SHA-1",
                "sha1WithRSAEncryption",
                "1.2.840.113549.1.1.5",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-1",
        ),
        // Combined RSA + SHA-2 family.
        algorithm(
            &[
                "RSA-SHA2-224",
                "RSA-SHA224",
                "sha224WithRSAEncryption",
                "1.2.840.113549.1.1.14",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-224",
        ),
        algorithm(
            &[
                "RSA-SHA2-256",
                "RSA-SHA256",
                "sha256WithRSAEncryption",
                "1.2.840.113549.1.1.11",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-256",
        ),
        algorithm(
            &[
                "RSA-SHA2-384",
                "RSA-SHA384",
                "sha384WithRSAEncryption",
                "1.2.840.113549.1.1.12",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-384",
        ),
        algorithm(
            &[
                "RSA-SHA2-512",
                "RSA-SHA512",
                "sha512WithRSAEncryption",
                "1.2.840.113549.1.1.13",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-512",
        ),
        algorithm(
            &[
                "RSA-SHA2-512/224",
                "RSA-SHA512-224",
                "sha512-224WithRSAEncryption",
                "1.2.840.113549.1.1.15",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-512/224",
        ),
        algorithm(
            &[
                "RSA-SHA2-512/256",
                "RSA-SHA512-256",
                "sha512-256WithRSAEncryption",
                "1.2.840.113549.1.1.16",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA-512/256",
        ),
        // Combined RSA + SHA-3 family.
        algorithm(
            &[
                "RSA-SHA3-224",
                "id-rsassa-pkcs1-v1_5-with-sha3-224",
                "2.16.840.1.101.3.4.3.13",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA3-224",
        ),
        algorithm(
            &[
                "RSA-SHA3-256",
                "id-rsassa-pkcs1-v1_5-with-sha3-256",
                "2.16.840.1.101.3.4.3.14",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA3-256",
        ),
        algorithm(
            &[
                "RSA-SHA3-384",
                "id-rsassa-pkcs1-v1_5-with-sha3-384",
                "2.16.840.1.101.3.4.3.15",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA3-384",
        ),
        algorithm(
            &[
                "RSA-SHA3-512",
                "id-rsassa-pkcs1-v1_5-with-sha3-512",
                "2.16.840.1.101.3.4.3.16",
            ],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SHA3-512",
        ),
        // Combined RSA + SM3 (Chinese national standard).
        algorithm(
            &["RSA-SM3", "sm3WithRSAEncryption", "1.2.156.10197.1.504"],
            DEFAULT_PROPERTY,
            "RSA PKCS#1 v1.5 signature with SM3",
        ),
        // Standalone RSA-PSS — uses PSS padding regardless of the signing API.
        algorithm(
            &["RSA-PSS", "RSASSA-PSS", "rsassaPss", "1.2.840.113549.1.1.10"],
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
    fn descriptors_non_empty() {
        let descs = descriptors();
        assert!(!descs.is_empty(), "expected at least one RSA descriptor");
    }

    #[test]
    fn descriptors_first_entry_is_generic_rsa() {
        let descs = descriptors();
        let first = descs.first().expect("at least one descriptor");
        assert_eq!(first.names[0], "RSA");
        assert!(first.names.iter().any(|n| *n == "rsaEncryption"));
        assert!(first.names.iter().any(|n| *n == "1.2.840.113549.1.1.1"));
    }

    #[test]
    fn descriptors_include_rsa_pss() {
        let descs = descriptors();
        assert!(
            descs.iter().any(|d| d.names.contains(&"RSA-PSS")),
            "RSA-PSS descriptor must be registered"
        );
    }

    #[test]
    fn descriptors_cover_sha2_family() {
        let descs = descriptors();
        for n in [
            "RSA-SHA2-224",
            "RSA-SHA2-256",
            "RSA-SHA2-384",
            "RSA-SHA2-512",
        ] {
            assert!(
                descs.iter().any(|d| d.names.contains(&n)),
                "missing combined RSA descriptor: {n}"
            );
        }
    }

    #[test]
    fn descriptors_cover_sha3_family() {
        let descs = descriptors();
        for n in [
            "RSA-SHA3-224",
            "RSA-SHA3-256",
            "RSA-SHA3-384",
            "RSA-SHA3-512",
        ] {
            assert!(
                descs.iter().any(|d| d.names.contains(&n)),
                "missing combined RSA descriptor: {n}"
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
