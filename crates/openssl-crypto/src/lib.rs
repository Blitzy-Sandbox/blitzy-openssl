//! OpenSSL Crypto - libcrypto equivalent providing core cryptographic algorithms.
//!
//! This crate implements the cryptographic library layer of the OpenSSL Rust workspace,
//! including EVP abstraction, BIO I/O, X.509, ASN.1, and all algorithm families.

#![forbid(unsafe_code)]

pub mod provider;
pub mod thread;

#[cfg(test)]
mod tests;
