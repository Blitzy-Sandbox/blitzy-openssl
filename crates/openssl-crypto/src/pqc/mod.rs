//! Post-Quantum Cryptography (PQC) algorithm implementations.
//!
//! This module hosts the Rust translations of OpenSSL's post-quantum cryptographic
//! algorithms originally implemented in C under `crypto/ml_kem/`, `crypto/ml_dsa/`,
//! `crypto/slh_dsa/`, and `crypto/lms/`.
//!
//! # Included Algorithms
//!
//! - [`ml_kem`] — Module-Lattice-Based Key Encapsulation Mechanism (FIPS 203).
//!   Provides ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation.
//! - [`ml_dsa`] — Module-Lattice-Based Digital Signature Algorithm (FIPS 204).
//!   Provides ML-DSA-44, ML-DSA-65, and ML-DSA-87 digital signatures.
//! - [`slh_dsa`] — Stateless Hash-Based Digital Signature Algorithm (FIPS 205).
//!   Provides all 12 standardised parameter sets across the SHA-2 and SHAKE
//!   families at 128/192/256-bit security in both slow (`s`) and fast (`f`)
//!   variants.
//! - [`lms`] — Leighton-Micali Hash-Based Signature scheme (NIST SP 800-208,
//!   RFC 8554). **Verification-only** — this matches OpenSSL's upstream
//!   implementation which also provides only verification. Supports all 5
//!   RFC 8554 LMS parameter sets plus 15 SP 800-208 SHAKE-based additions
//!   (20 total LMS parameter sets) and all 16 LM-OTS parameter sets.
//!
//! # Feature Gating
//!
//! The entire `pqc` module is gated behind the `pqc` Cargo feature (enabled by
//! default). This allows constrained builds to exclude the post-quantum
//! algorithms when they are not required.
//!
//! # References
//!
//! - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//!   (August 2024).
//! - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard.
//! - NIST FIPS 205: Stateless Hash-Based Digital Signature Standard.
//! - NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes.

pub mod lms;
pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;
