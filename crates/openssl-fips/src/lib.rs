//! OpenSSL FIPS - FIPS module providing self-test, KATs, and integrity verification.
//!
//! This crate implements the FIPS 140-3 compliant module for the OpenSSL Rust workspace.
//! It is independently compilable and depends only on openssl-common and selected openssl-crypto items.

#![forbid(unsafe_code)]

pub mod state;
