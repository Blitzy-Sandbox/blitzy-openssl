//! QUIC v1 transport protocol implementation (RFC 9000).
//!
//! This module contains the Rust rewrite of OpenSSL's QUIC stack
//! (`ssl/quic/` — 42 C source files), providing:
//!
//! - Stream map, buffering, and flow control ([`stream`])
//! - Congestion control with pluggable algorithms ([`cc`])
//!
//! Gated behind the `quic` feature flag.

pub mod cc;
pub mod stream;

pub use cc::{CcState, CongestionController, NewRenoCc};
pub use stream::{StreamId, StreamMap, StreamType};
