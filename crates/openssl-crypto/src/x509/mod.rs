//! X.509 certificate and Certificate Revocation List (CRL) processing.
//!
//! This module translates the OpenSSL `crypto/x509/*.c` sources (98 files
//! in the original C tree) into idiomatic Rust.  It is organised into the
//! following submodules:
//!
//! | Submodule       | Purpose                                         | C source analogue                                         |
//! |-----------------|-------------------------------------------------|-----------------------------------------------------------|
//! | `certificate`   | Full RFC 5280 certificate parse + accessors     | `crypto/x509/x_x509.c`, `x509_cmp.c`, `x509_set.c`        |
//! | `crl`           | Certificate Revocation List processing          | `crypto/x509/x_crl.c`, `x509cset.c`, `t_crl.c`            |
//! | `store`         | Trust anchor & intermediate certificate store   | `crypto/x509/x509_lu.c`, `x509_local.h::X509_STORE`       |
//! | `verify`        | RFC 5280 §6 PKIX chain validation               | `crypto/x509/x509_vfy.c`, `v3_purp.c`, `x509_vpm.c`       |
//!
//! ## Relationship between `certificate` and `crl`
//!
//! The `crl` module pre-dates the `certificate` module and contains a
//! minimal internal `X509Certificate` type that carries only
//! `{issuer, serial}` — the bare minimum needed to query a revocation
//! list.  The richer `certificate::Certificate` type bridges the two
//! via `certificate::Certificate::to_crl_lookup_handle` so that CRL
//! lookups remain ergonomic for callers who have already parsed the full
//! certificate.
//!
//! ## Rule compliance
//!
//! * **R5** — Nullability is expressed via `Option<T>` in place of C
//!   sentinel values (`NULL`, `-1`, `CRL_REASON_NONE`, etc.).
//! * **R6** — All numeric conversions use checked/lossless patterns
//!   (`try_from`, `i64::from`, `saturating_*`); no bare `as` casts for
//!   narrowing operations.
//! * **R7** — Every shared-mutable data structure carries an explicit
//!   `// LOCK-SCOPE:` annotation documenting its contention model.
//! * **R8** — Zero `unsafe` blocks anywhere in this submodule tree.
//! * **R9** — All public items carry `///` doc comments; the code is
//!   warning-free under `#![deny(warnings)]`.
//! * **R10** — Every exported item is reachable from the crate root via
//!   `openssl_crypto::x509::...` and is exercised by the submodule test
//!   suites.

#![allow(clippy::module_inception)]

pub mod certificate;
pub mod crl;
pub mod store;
pub mod verify;

// Re-export the common public types at the `x509::` namespace so that
// downstream consumers can write `use openssl_crypto::x509::Certificate;`
// and similar succinct imports.
pub use certificate::{
    Certificate, CertificateValidity, CertificateVersion, PublicKeyInfo, SignatureAlgorithmId,
};
pub use crl::{
    CrlMethod, DefaultCrlMethod, IssuingDistPoint, RevocationReason, RevokedEntry, X509Crl,
};
pub use store::{TrustAnchor, X509Store};
// Original `Verifier`-centric API (pre-schema) — preserved for downstream
// callers (notably `crate::x509::store` and the `tests::test_x509`
// integration suite) until the schema-driven API below is fully adopted.
pub use verify::{
    Purpose, VerificationError, VerificationOptions, VerificationResult, VerifiedChain, Verifier,
};

// Schema-driven RFC 5280 verification API exported by
// `crates/openssl-crypto/src/x509/verify.rs`.  These items are listed as
// the assigned exports for the verification module per the Agent Action
// Plan and must be reachable from the crate root for downstream
// consumers (`openssl-ssl`, `openssl-cli`, `openssl-ffi`).
pub use verify::{
    check_email, check_host, check_ip, check_ip_asc, check_purpose, check_trust, self_signed,
    verify, verify_cert, DaneVerification, HostFlags, InheritanceFlags, PolicyTree, SuiteBError,
    TrustLevel, TrustResult, TrustSetting, VerifyCallback, VerifyContext, VerifyError, VerifyFlags,
    VerifyParams,
};
