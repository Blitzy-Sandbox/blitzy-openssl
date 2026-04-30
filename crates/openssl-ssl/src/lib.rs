//! OpenSSL SSL - libssl equivalent providing TLS/DTLS/QUIC protocol implementation.
//!
//! This crate implements the protocol stack layer of the OpenSSL Rust workspace,
//! including TLS 1.0-1.3, DTLS, QUIC v1, and ECH support.

#![forbid(unsafe_code)]

pub mod cipher;
pub mod method;
pub mod record;
pub mod tls13;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "srtp")]
pub mod srtp;

#[cfg(test)]
mod tests;
