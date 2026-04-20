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

pub mod ml_kem;
