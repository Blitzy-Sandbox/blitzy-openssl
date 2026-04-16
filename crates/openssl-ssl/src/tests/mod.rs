//! Test modules for the openssl-ssl protocol stack crate.
//!
//! Provides integration test infrastructure for TLS, DTLS, and QUIC
//! protocol validation, exercising the `method`, `srtp`, and `quic`
//! modules through their public APIs per Rule R10 (wiring verification).

mod quic_integration;
mod tls_integration;
