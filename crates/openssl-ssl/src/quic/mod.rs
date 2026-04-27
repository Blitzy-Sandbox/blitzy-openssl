//! QUIC v1 transport protocol implementation (RFC 9000).
//!
//! This module contains the Rust rewrite of OpenSSL's QUIC stack
//! (`ssl/quic/` — 42 C source files), providing:
//!
//! - ACK management, loss detection, and RTT estimation (`ack`)
//! - Stream map, buffering, and flow control (`stream`)
//! - Congestion control with pluggable algorithms (`cc`)
//!
//! Gated behind the `quic` feature flag.

pub mod ack;
pub mod cc;
pub mod reactor;
pub mod stream;

pub use ack::{
    AckFrameData, AckManager, AckRange, EcnCounts, PnSpace, RttEstimator, TxPacketRecord, UintSet,
};
pub use cc::{CcState, CongestionController, NewRenoCc};
pub use reactor::{
    BlockFlags, PollDescriptor, QuicReactor, QuicTickResult, ReactorWaitCtx, WaitGuard,
    QUIC_REACTOR_FLAG_USE_NOTIFIER,
};
pub use stream::{StreamId, StreamMap, StreamType};
