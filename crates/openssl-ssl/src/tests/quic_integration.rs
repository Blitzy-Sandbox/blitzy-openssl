//! QUIC integration tests for the openssl-ssl crate.
//!
//! Validates the QUIC module infrastructure when the `quic` feature is
//! enabled.  Full QUIC engine, channel, and stream tests will be added
//! when the `quic/engine.rs`, `quic/channel.rs`, and `quic/port.rs`
//! modules are implemented.

/// Verify that the QUIC stream type enum is accessible and has distinct
/// Debug representations for each variant.
#[test]
#[cfg(feature = "quic")]
fn quic_stream_type_accessible() {
    use crate::quic::StreamType;
    let variants = [
        StreamType::ClientBidi,
        StreamType::ServerBidi,
        StreamType::ClientUni,
        StreamType::ServerUni,
    ];
    // All four stream types must be distinct.
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "Stream type variants should be distinct");
            }
        }
    }
}

/// Verify that the NewReno congestion controller can be constructed with
/// a standard max datagram size.
#[test]
#[cfg(feature = "quic")]
fn quic_congestion_controller_constructable() {
    use crate::quic::NewRenoCc;
    // 1200 bytes is the QUIC minimum max datagram size (RFC 9000 §14).
    let cc = NewRenoCc::new(1200);
    let debug = format!("{cc:?}");
    assert!(!debug.is_empty(), "NewRenoCc Debug should be non-empty");
}

/// Verify that the QUIC reactor wait context can be constructed.
#[test]
#[cfg(feature = "quic")]
fn quic_reactor_wait_ctx_constructable() {
    use crate::quic::ReactorWaitCtx;
    // Construct and immediately drop — validates that the type is
    // publicly accessible and constructible.  ReactorWaitCtx does not
    // derive Debug, so we verify existence via `drop` rather than
    // format!.
    let ctx = ReactorWaitCtx::new();
    drop(ctx);
}
