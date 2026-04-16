//! Kerberos Key Derivation Function (RFC 3961).
//!
//! Source: `providers/implementations/kdfs/krb5kdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for KRB5KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["KRB5KDF"],
            "provider=default",
            "Kerberos Key Derivation Function (RFC 3961)",
        ),
    ]
}
