//! PKCS — Public-Key Cryptography Standards.
//!
//! Aggregates the PKCS series implementations:
//!
//! - [`pkcs7`] — PKCS#7 (RFC 2315) Cryptographic Message Syntax: signing,
//!   verification, encryption, decryption, and S/MIME.
//!
//! Future siblings of this module are planned per the AAP §0.5.1 file map:
//!
//! - `pkcs12` — PKCS#12 (RFC 7292) personal information exchange (depends on
//!   `pkcs7` types).
//! - `cms` — Cryptographic Message Syntax (RFC 5652) (depends on `pkcs7`
//!   types).
//!
//! `pkcs7` is the foundational module — both upcoming `pkcs12` and `cms`
//! reference its core types ([`pkcs7::Pkcs7`](pkcs7::Pkcs7),
//! [`pkcs7::Pkcs7SignerInfo`](pkcs7::Pkcs7SignerInfo),
//! [`pkcs7::IssuerAndSerialNumber`](pkcs7::IssuerAndSerialNumber)).

pub mod pkcs7;
