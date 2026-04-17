//! Elliptic curve cryptography module.
//!
//! Provides implementations for Curve25519/Curve448 family algorithms:
//! - X25519/X448 Diffie-Hellman key exchange (RFC 7748)
//! - Ed25519/Ed448 `EdDSA` signatures (RFC 8032)

pub mod curve25519;
