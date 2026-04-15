//! Tests for the `openssl_common::error` module.
//!
//! These tests exercise the error types, error stack, error detail,
//! macro, and conversion chains through the crate's public API.
//! They complement the inline unit tests in `error.rs` by verifying
//! cross-module integration and serialization behavior.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use crate::error::{
    CommonError, CryptoError, ErrorDetail, ErrorLibrary, ErrorStack, FipsError, ProviderError,
    SslError,
};
use crate::{err_detail, error};

// =============================================================================
// ErrorLibrary — Display and Variant Coverage
// =============================================================================

#[test]
fn error_library_display_covers_all_variants() {
    // Verify every ErrorLibrary variant produces a non-empty display string.
    let variants = [
        ErrorLibrary::None,
        ErrorLibrary::Sys,
        ErrorLibrary::Bn,
        ErrorLibrary::Rsa,
        ErrorLibrary::Dh,
        ErrorLibrary::Evp,
        ErrorLibrary::Buf,
        ErrorLibrary::Obj,
        ErrorLibrary::Pem,
        ErrorLibrary::Dsa,
        ErrorLibrary::X509,
        ErrorLibrary::Asn1,
        ErrorLibrary::Conf,
        ErrorLibrary::Crypto,
        ErrorLibrary::Ec,
        ErrorLibrary::Ssl,
        ErrorLibrary::Bio,
        ErrorLibrary::Pkcs7,
        ErrorLibrary::X509v3,
        ErrorLibrary::Pkcs12,
        ErrorLibrary::Rand,
        ErrorLibrary::Dso,
        ErrorLibrary::Ts,
        ErrorLibrary::Engine,
        ErrorLibrary::Ocsp,
        ErrorLibrary::Ui,
        ErrorLibrary::Fips,
        ErrorLibrary::Cms,
        ErrorLibrary::Crmf,
        ErrorLibrary::Cmp,
        ErrorLibrary::Hmac,
        ErrorLibrary::Ct,
        ErrorLibrary::Async,
        ErrorLibrary::Kdf,
        ErrorLibrary::Store,
        ErrorLibrary::Sm2,
        ErrorLibrary::Ess,
        ErrorLibrary::Provider,
        ErrorLibrary::Encoder,
        ErrorLibrary::Decoder,
        ErrorLibrary::Http,
    ];

    for variant in variants {
        let display = format!("{variant}");
        assert!(
            !display.is_empty(),
            "ErrorLibrary::{variant:?} should have a non-empty Display"
        );
    }
}

#[test]
fn error_library_known_display_values() {
    // Display matches the C `ERR_str_libraries[]` array strings.
    assert_eq!(format!("{}", ErrorLibrary::None), "unknown library");
    assert_eq!(format!("{}", ErrorLibrary::Rsa), "rsa routines");
    assert_eq!(format!("{}", ErrorLibrary::Ssl), "SSL routines");
    assert_eq!(format!("{}", ErrorLibrary::Fips), "FIPS routines");
    assert_eq!(format!("{}", ErrorLibrary::Crypto), "common libcrypto routines");
}

#[test]
fn error_library_clone_and_eq() {
    let a = ErrorLibrary::Evp;
    let b = a; // Copy semantics
    assert_eq!(a, b);
    assert_ne!(a, ErrorLibrary::Rsa);
}

// =============================================================================
// CommonError — Variant Construction and Display
// =============================================================================

#[test]
fn common_error_io_wraps_std_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
    let common: CommonError = io_err.into();
    let display = format!("{common}");
    assert!(
        display.contains("missing file"),
        "CommonError::Io should include the underlying I/O error message"
    );
}

#[test]
fn common_error_config_display() {
    let err = CommonError::Config {
        message: "bad section".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("bad section"));
}

#[test]
fn common_error_param_type_mismatch_display() {
    let err = CommonError::ParamTypeMismatch {
        key: "iterations".to_string(),
        expected: "u32",
        actual: "string",
    };
    let display = format!("{err}");
    assert!(display.contains("iterations"));
    assert!(display.contains("u32"));
    assert!(display.contains("string"));
}

#[test]
fn common_error_param_not_found_display() {
    let err = CommonError::ParamNotFound {
        key: "missing_key".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("missing_key"));
}

#[test]
fn common_error_arithmetic_overflow_display() {
    let err = CommonError::ArithmeticOverflow {
        operation: "u64 addition",
    };
    let display = format!("{err}");
    assert!(display.contains("u64 addition"));
}

#[test]
fn common_error_cast_overflow_from_try_from_int_error() {
    // Force a TryFromIntError by attempting an invalid conversion.
    let try_err = u8::try_from(256u16).unwrap_err();
    let err = CommonError::CastOverflow(try_err);
    let display = format!("{err}");
    assert!(!display.is_empty());
}

#[test]
fn common_error_invalid_argument_display() {
    let err = CommonError::InvalidArgument("key_size must be > 0".to_string());
    let display = format!("{err}");
    assert!(display.contains("key_size"));
}

#[test]
fn common_error_memory_display() {
    let err = CommonError::Memory("secure heap exhausted".to_string());
    assert!(!format!("{err}").is_empty());
}

#[test]
fn common_error_not_initialized_display() {
    let err = CommonError::NotInitialized("crypto subsystem");
    assert!(!format!("{err}").is_empty());
}

#[test]
fn common_error_already_initialized_display() {
    let err = CommonError::AlreadyInitialized("tracing");
    assert!(!format!("{err}").is_empty());
}

#[test]
fn common_error_unsupported_display() {
    let err = CommonError::Unsupported("ChaCha20 not available".to_string());
    let display = format!("{err}");
    assert!(display.contains("ChaCha20"));
}

#[test]
fn common_error_internal_display() {
    let err = CommonError::Internal("unexpected state".to_string());
    assert!(!format!("{err}").is_empty());
}

// =============================================================================
// Error Conversion Chains — #[from] Attribute Verification
// =============================================================================

#[test]
fn common_error_converts_to_crypto_error() {
    let common = CommonError::NotInitialized("provider");
    let crypto: CryptoError = common.into();
    match crypto {
        CryptoError::Common(inner) => {
            assert!(matches!(inner, CommonError::NotInitialized(_)));
        }
        _ => panic!("Expected CryptoError::Common variant"),
    }
}

#[test]
fn io_error_converts_to_crypto_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
    let crypto: CryptoError = io_err.into();
    match crypto {
        CryptoError::Io(inner) => {
            assert_eq!(inner.kind(), std::io::ErrorKind::BrokenPipe);
        }
        _ => panic!("Expected CryptoError::Io variant"),
    }
}

#[test]
fn common_error_converts_to_ssl_error() {
    let common = CommonError::AlreadyInitialized("ssl");
    let ssl: SslError = common.into();
    assert!(matches!(ssl, SslError::Common(_)));
}

#[test]
fn crypto_error_converts_to_ssl_error() {
    let crypto = CryptoError::AlgorithmNotFound("AES-512".to_string());
    let ssl: SslError = crypto.into();
    assert!(matches!(ssl, SslError::Crypto(_)));
}

#[test]
fn common_error_converts_to_provider_error() {
    let common = CommonError::Unsupported("operation".to_string());
    let provider: ProviderError = common.into();
    assert!(matches!(provider, ProviderError::Common(_)));
}

#[test]
fn common_error_converts_to_fips_error() {
    let common = CommonError::Internal("fips failure".to_string());
    let fips: FipsError = common.into();
    assert!(matches!(fips, FipsError::Common(_)));
}

#[test]
fn error_chain_common_through_crypto_to_ssl() {
    // Tests a two-level conversion chain:
    // CommonError → CryptoError → SslError
    let common = CommonError::NotInitialized("engine");
    let crypto: CryptoError = common.into();
    let ssl: SslError = crypto.into();
    match &ssl {
        SslError::Crypto(CryptoError::Common(CommonError::NotInitialized(_))) => {}
        other => panic!("Expected nested conversion chain, got {other:?}"),
    }
}

// =============================================================================
// CryptoError, SslError, ProviderError, FipsError — Direct Variants
// =============================================================================

#[test]
fn crypto_error_algorithm_not_found_display() {
    let err = CryptoError::AlgorithmNotFound("SM4-XTS".to_string());
    let display = format!("{err}");
    assert!(display.contains("SM4-XTS"));
}

#[test]
fn ssl_error_handshake_display() {
    let err = SslError::Handshake("unexpected message".to_string());
    let display = format!("{err}");
    assert!(display.contains("unexpected message"));
}

#[test]
fn ssl_error_connection_closed_display() {
    let err = SslError::ConnectionClosed;
    assert!(!format!("{err}").is_empty());
}

#[test]
fn provider_error_not_found_display() {
    let err = ProviderError::NotFound("legacy".to_string());
    let display = format!("{err}");
    assert!(display.contains("legacy"));
}

#[test]
fn fips_error_self_test_failed_display() {
    let err = FipsError::SelfTestFailed("AES-GCM KAT".to_string());
    let display = format!("{err}");
    assert!(display.contains("AES-GCM KAT"));
}

#[test]
fn fips_error_integrity_check_failed_display() {
    let err = FipsError::IntegrityCheckFailed;
    assert!(!format!("{err}").is_empty());
}

#[test]
fn fips_error_not_operational_display() {
    let err = FipsError::NotOperational("SelfTesting".to_string());
    let display = format!("{err}");
    assert!(display.contains("SelfTesting"));
}

#[test]
fn fips_error_not_approved_display() {
    let err = FipsError::NotApproved("DES".to_string());
    let display = format!("{err}");
    assert!(display.contains("DES"));
}

// =============================================================================
// ErrorDetail — Construction, Display, Serialization
// =============================================================================

#[test]
fn error_detail_display_format() {
    let detail = ErrorDetail {
        library: ErrorLibrary::Rsa,
        reason: "key too short".to_string(),
        file: "test.rs",
        line: 42,
        function: "test_module",
        data: None,
    };
    let display = format!("{detail}");
    // ErrorLibrary::Rsa displays as "rsa routines" (matching C ERR_str_libraries[]).
    assert!(display.contains("rsa routines"));
    assert!(display.contains("key too short"));
    assert!(display.contains("test.rs"));
    assert!(display.contains("42"));
    assert!(display.contains("test_module"));
}

#[test]
fn error_detail_display_with_data() {
    let detail = ErrorDetail {
        library: ErrorLibrary::Evp,
        reason: "unsupported".to_string(),
        file: "evp.rs",
        line: 100,
        function: "evp::init",
        data: Some("algorithm: RC5".to_string()),
    };
    let display = format!("{detail}");
    assert!(display.contains("algorithm: RC5"));
}

#[test]
fn error_detail_serializes_to_json() {
    let detail = ErrorDetail {
        library: ErrorLibrary::Ssl,
        reason: "handshake timeout".to_string(),
        file: "ssl.rs",
        line: 77,
        function: "ssl::handshake",
        data: Some("peer: 10.0.0.1".to_string()),
    };
    let json = serde_json::to_string(&detail).expect("ErrorDetail should serialize to JSON");
    assert!(json.contains("handshake timeout"));
    assert!(json.contains("ssl.rs"));
    assert!(json.contains("77"));
}

// =============================================================================
// ErrorStack — Operations
// =============================================================================

#[test]
fn error_stack_new_is_empty() {
    let stack = ErrorStack::new();
    assert!(stack.is_empty());
    assert_eq!(stack.len(), 0);
}

#[test]
fn error_stack_default_is_empty() {
    let stack = ErrorStack::default();
    assert!(stack.is_empty());
}

#[test]
fn error_stack_push_and_pop() {
    let mut stack = ErrorStack::new();
    stack.push(make_detail(ErrorLibrary::Rsa, "first"));
    stack.push(make_detail(ErrorLibrary::Ssl, "second"));
    assert_eq!(stack.len(), 2);

    // Pop returns most recent (LIFO).
    let popped = stack.pop().expect("stack should not be empty");
    assert_eq!(popped.reason, "second");
    assert_eq!(stack.len(), 1);

    let popped = stack.pop().expect("stack should have one remaining");
    assert_eq!(popped.reason, "first");
    assert!(stack.is_empty());
}

#[test]
fn error_stack_pop_empty_returns_none() {
    let mut stack = ErrorStack::new();
    assert!(stack.pop().is_none());
}

#[test]
fn error_stack_clear() {
    let mut stack = ErrorStack::new();
    stack.push(make_detail(ErrorLibrary::Bio, "a"));
    stack.push(make_detail(ErrorLibrary::Bio, "b"));
    stack.push(make_detail(ErrorLibrary::Bio, "c"));
    assert_eq!(stack.len(), 3);

    stack.clear();
    assert!(stack.is_empty());
    assert_eq!(stack.len(), 0);
}

#[test]
fn error_stack_iter_order() {
    let mut stack = ErrorStack::new();
    stack.push(make_detail(ErrorLibrary::None, "oldest"));
    stack.push(make_detail(ErrorLibrary::None, "middle"));
    stack.push(make_detail(ErrorLibrary::None, "newest"));

    let reasons: Vec<&str> = stack.iter().map(|d| d.reason.as_str()).collect();
    assert_eq!(reasons, vec!["oldest", "middle", "newest"]);
}

#[test]
fn error_stack_display_multiline() {
    let mut stack = ErrorStack::new();
    stack.push(make_detail(ErrorLibrary::Rsa, "first error"));
    stack.push(make_detail(ErrorLibrary::Ssl, "second error"));

    let display = format!("{stack}");
    assert!(display.contains("first error"));
    assert!(display.contains("second error"));
    // Multi-entry display should have a newline between entries.
    assert!(display.contains('\n'));
}

#[test]
fn error_stack_display_single_entry_no_trailing_newline() {
    let mut stack = ErrorStack::new();
    stack.push(make_detail(ErrorLibrary::Rsa, "only error"));
    let display = format!("{stack}");
    assert!(!display.contains('\n'));
}

// =============================================================================
// err_detail! Macro
// =============================================================================

#[test]
fn err_detail_macro_without_data() {
    let detail: ErrorDetail = err_detail!(ErrorLibrary::Rsa, "key too short");
    assert_eq!(detail.library, ErrorLibrary::Rsa);
    assert_eq!(detail.reason, "key too short");
    assert!(detail.data.is_none());
    // file!() and line!() should be captured from this test file.
    assert!(detail.file.contains("error_tests.rs"));
}

#[test]
fn err_detail_macro_with_data() {
    let detail: ErrorDetail = err_detail!(
        ErrorLibrary::Evp,
        "unsupported algorithm",
        "requested: CHACHA20-POLY1305"
    );
    assert_eq!(detail.library, ErrorLibrary::Evp);
    assert_eq!(detail.reason, "unsupported algorithm");
    assert_eq!(
        detail.data.as_deref(),
        Some("requested: CHACHA20-POLY1305")
    );
}

// =============================================================================
// Result Type Aliases — Ergonomics Verification
// =============================================================================

#[test]
fn common_result_alias_works() {
    let ok: error::CommonResult<u32> = Ok(42);
    assert_eq!(ok.unwrap(), 42);

    let err: error::CommonResult<u32> = Err(CommonError::NotInitialized("subsystem"));
    assert!(err.is_err());
}

#[test]
fn crypto_result_alias_works() {
    let ok: error::CryptoResult<&str> = Ok("success");
    assert_eq!(ok.unwrap(), "success");

    let err: error::CryptoResult<&str> = Err(CryptoError::Key("bad key".to_string()));
    assert!(err.is_err());
}

#[test]
fn ssl_result_alias_works() {
    let ok: error::SslResult<bool> = Ok(true);
    assert!(ok.unwrap());
}

#[test]
fn provider_result_alias_works() {
    let err: error::ProviderResult<()> =
        Err(ProviderError::AlgorithmUnavailable("DES".to_string()));
    assert!(err.is_err());
}

#[test]
fn fips_result_alias_works() {
    let err: error::FipsResult<()> = Err(FipsError::NotApproved("MD5".to_string()));
    assert!(err.is_err());
}

// =============================================================================
// std::error::Error Trait — Source Chain
// =============================================================================

#[test]
fn common_error_implements_std_error() {
    let err = CommonError::NotInitialized("crypto");
    let _: &dyn std::error::Error = &err;
}

#[test]
fn crypto_error_source_chain_for_common() {
    // CryptoError::Common uses #[error(transparent)], so source() delegates
    // to the inner CommonError's source().  Use CommonError::Io which wraps
    // an io::Error (#[from]) and thus has a real source chain.
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test io");
    let common = CommonError::Io(io_err);
    let crypto: CryptoError = common.into();
    let source = std::error::Error::source(&crypto);
    assert!(
        source.is_some(),
        "CryptoError::Common(Io(..)) source chain should include the io::Error"
    );
}

#[test]
fn ssl_error_source_chain_for_crypto() {
    // SslError::Crypto uses #[error(transparent)], so source() delegates
    // to the inner CryptoError's source().  Use CryptoError::Io which
    // wraps an io::Error (#[from]) and thus has a real source chain.
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
    let crypto = CryptoError::Io(io_err);
    let ssl: SslError = crypto.into();
    let source = std::error::Error::source(&ssl);
    assert!(
        source.is_some(),
        "SslError::Crypto(Io(..)) source chain should include the io::Error"
    );
}

// =============================================================================
// Debug Derivation
// =============================================================================

#[test]
fn error_types_implement_debug() {
    let _ = format!("{:?}", CommonError::NotInitialized("debug"));
    let _ = format!("{:?}", CryptoError::Rand("entropy".to_string()));
    let _ = format!("{:?}", SslError::Quic("flow control".to_string()));
    let _ = format!("{:?}", ProviderError::Dispatch("bad fn".to_string()));
    let _ = format!("{:?}", FipsError::IntegrityCheckFailed);
    let _ = format!("{:?}", ErrorStack::new());
}

// =============================================================================
// Helpers
// =============================================================================

/// Creates an `ErrorDetail` with the given library and reason for test use.
fn make_detail(library: ErrorLibrary, reason: &str) -> ErrorDetail {
    ErrorDetail {
        library,
        reason: reason.to_string(),
        file: file!(),
        line: line!(),
        function: module_path!(),
        data: None,
    }
}
