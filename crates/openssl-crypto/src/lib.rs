//! OpenSSL Crypto - libcrypto equivalent providing core cryptographic algorithms.
//!
//! This crate implements the cryptographic library layer of the OpenSSL Rust workspace,
//! including EVP abstraction, BIO I/O, X.509, ASN.1, and all algorithm families.

#![forbid(unsafe_code)]

pub mod bn;
pub mod context;
pub mod cpu_detect;
pub mod ec;
pub mod evp;
pub mod init;
pub mod kdf;
pub mod mac;
pub mod provider;
pub mod rand;
pub mod pem;
pub mod thread;

#[cfg(feature = "hpke")]
pub mod hpke;

#[cfg(feature = "ocsp")]
pub mod ocsp;

#[cfg(feature = "ts")]
pub mod ts;

#[cfg(test)]
mod tests;
