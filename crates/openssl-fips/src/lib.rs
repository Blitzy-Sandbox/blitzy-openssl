//! OpenSSL FIPS - FIPS module providing self-test, KATs, and integrity verification.
//!
//! This crate implements the FIPS 140-3 compliant module for the OpenSSL Rust workspace.
//! It is independently compilable and depends only on openssl-common and selected openssl-crypto items.

#![forbid(unsafe_code)]

pub mod indicator;
pub mod kats;
pub mod provider;
pub mod self_test;
pub mod state;

#[cfg(test)]
mod tests;
