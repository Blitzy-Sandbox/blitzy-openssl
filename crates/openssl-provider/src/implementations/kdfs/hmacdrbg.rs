//! HMAC-DRBG based Key Derivation Function (SP 800-90A).
//!
//! Source: `providers/implementations/kdfs/hmacdrbg_kdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for HMAC-DRBG-KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HMAC-DRBG-KDF"],
            "provider=default",
            "HMAC-DRBG based Key Derivation Function (SP 800-90A)",
        ),
    ]
}
