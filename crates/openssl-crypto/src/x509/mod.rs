//! X.509 certificate and Certificate Revocation List (CRL) processing.
//!
//! This module translates the OpenSSL `crypto/x509/*.c` sources (98 files
//! in the original C tree) into idiomatic Rust.  The initial scope covers
//! Certificate Revocation List (CRL) processing per RFC 5280 §5 via the
//! [`crl`] submodule — additional sub-modules (certificate parsing, chain
//! verification, extension handling, etc.) will be added as the C→Rust
//! migration progresses.
//!
//! ## Rule compliance
//!
//! * **R5** — Nullability is expressed via `Option<T>` in place of C
//!   sentinel values (`NULL`, `-1`, `CRL_REASON_NONE`, etc.).
//! * **R6** — All numeric conversions use checked/lossless patterns
//!   (`try_from`, `i64::from`, `saturating_*`); no bare `as` casts for
//!   narrowing operations.
//! * **R8** — Zero `unsafe` blocks in this module or its descendants.
//! * **R9** — All public items carry `///` doc comments; the code is
//!   warning-free under `#![deny(warnings)]`.
//! * **R10** — Every exported item is reachable from the crate root via
//!   `openssl_crypto::x509::...` and is exercised by the CRL test suite.
//!
//! ## Module layout
//!
//! | Submodule | Purpose | C source analogue |
//! |-----------|---------|-------------------|
//! | [`crl`]   | Certificate Revocation List processing | `crypto/x509/x_crl.c`, `x509cset.c`, `t_crl.c` |

#![allow(clippy::module_inception)]

pub mod crl;

// Re-export the six required public items at the `x509::` namespace so
// downstream consumers can write `use openssl_crypto::x509::X509Crl;` and
// similar succinct imports.
pub use crl::{
    CrlMethod, DefaultCrlMethod, IssuingDistPoint, RevocationReason, RevokedEntry, X509Crl,
};
