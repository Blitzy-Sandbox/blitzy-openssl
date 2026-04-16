//! Argon2 password hashing function (RFC 9106).
//!
//! Source: `providers/implementations/kdfs/argon2.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for Argon2d, Argon2i, and Argon2id.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["ARGON2D"],
            "provider=default",
            "Argon2d password hashing (data-dependent addressing, RFC 9106)",
        ),
        algorithm(
            &["ARGON2I"],
            "provider=default",
            "Argon2i password hashing (data-independent addressing, RFC 9106)",
        ),
        algorithm(
            &["ARGON2ID"],
            "provider=default",
            "Argon2id password hashing (hybrid, RFC 9106)",
        ),
    ]
}
