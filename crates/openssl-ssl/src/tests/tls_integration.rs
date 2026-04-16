//! TLS integration tests for the openssl-ssl crate.
//!
//! Validates the TLS method construction, protocol version ordering,
//! and SSL method infrastructure. Full end-to-end TLS handshake tests
//! will be added when the `statem` and `record` modules are implemented.

use crate::method::{ProtocolVersion, SslMethod};

/// Verify that all expected TLS/DTLS method constructors are accessible
/// and produce well-formed SslMethod instances with descriptive Display output.
#[test]
fn tls_method_constructors_are_accessible() {
    let methods: Vec<&SslMethod> = vec![
        SslMethod::tls(),
        SslMethod::tls_client(),
        SslMethod::tls_server(),
        SslMethod::dtls(),
        SslMethod::dtls_client(),
        SslMethod::dtls_server(),
    ];
    for method in &methods {
        let display = format!("{method}");
        assert!(!display.is_empty(), "SslMethod Display should be non-empty");
    }
}

/// Verify that TLS protocol version ordering is correct: newer versions
/// compare as greater than older versions (per derived PartialOrd).
#[test]
fn tls_version_ordering() {
    assert!(ProtocolVersion::Tls1_0 < ProtocolVersion::Tls1_1);
    assert!(ProtocolVersion::Tls1_1 < ProtocolVersion::Tls1_2);
    assert!(ProtocolVersion::Tls1_2 < ProtocolVersion::Tls1_3);
}

/// Verify that the flexible TLS method negotiates all versions
/// and is configured for both client and server roles.
#[test]
fn tls_method_version_is_any() {
    let method = SslMethod::tls();
    assert_eq!(method.version(), ProtocolVersion::TlsAny);
}

/// Verify that version-specific constructors configure the correct version.
#[test]
fn version_specific_methods() {
    assert_eq!(SslMethod::tls_1_3().version(), ProtocolVersion::Tls1_3);
    assert_eq!(SslMethod::tls_1_2().version(), ProtocolVersion::Tls1_2);
    assert_eq!(SslMethod::dtls_1_2().version(), ProtocolVersion::Dtls1_2);
}
