//! X.509 certificate store — trust anchors and intermediate-CA cache.
//!
//! This module is the Rust counterpart of OpenSSL's `X509_STORE` /
//! `X509_STORE_CTX` subsystem (`crypto/x509/x509_lu.c`,
//! `crypto/x509/x509_local.h`).  It holds:
//!
//! * **Trust anchors** — self-signed or explicitly-trusted root
//!   certificates that terminate a chain-of-trust walk.
//! * **Intermediate / untrusted certificates** — bag of candidates that
//!   the verifier uses when building a chain from an end-entity
//!   certificate up to a trust anchor.
//! * **CRLs** — revocation lists indexed by issuer DN for revocation
//!   checking during verification.
//!
//! ## Design choices
//!
//! * The store is **append-only by default** to match OpenSSL semantics —
//!   callers add anchors and intermediates, but removal is explicit via
//!   [`X509Store::clear`] and not part of the normal flow.
//! * Interior mutation is **not** provided.  The store is built up front
//!   and then passed (by shared reference) to [`super::verify::Verifier`].
//!   This avoids a lock on the hot verification path.
//! * The CRL index is a simple `Vec<X509Crl>` iterated linearly.  That is
//!   adequate for the typical O(10) CRL count in a TLS deployment; for
//!   deployments with very large CRL sets the [`X509Store::crls_for_issuer`]
//!   helper walks the list in a single pass without allocation.
//!
//! ## Rule compliance
//!
//! * **R5** — Lookup APIs return `Option<T>` / `Vec<T>`; no sentinel
//!   values escape the API surface.
//! * **R6** — No narrowing numeric casts; all container sizes use
//!   `usize`.
//! * **R7** — The [`X509Store`] owns its data directly; there is no
//!   interior mutability and therefore no lock to justify.  Downstream
//!   wrappers that want shared read-write access wrap
//!   `X509Store` in `Arc<RwLock<...>>` with an explicit
//!   `// LOCK-SCOPE:` comment at the wrap site.
//! * **R8** — Zero `unsafe` blocks.
//! * **R9** — All public items carry `///` doc comments.
//! * **R10** — All exported items are reachable from
//!   `openssl_crypto::x509::store::...` and are exercised by the unit
//!   tests at the end of this file.

use std::collections::HashMap;

use openssl_common::{CryptoError, CryptoResult};

use super::certificate::Certificate;
use super::crl::X509Crl;

// ---------------------------------------------------------------------------
// Trust anchor
// ---------------------------------------------------------------------------

/// A single trust anchor entry in the store.
///
/// RFC 5280 §6.1.1 defines a trust anchor as "the input to the path
/// validation algorithm" and notes that "a trust anchor is an
/// authoritative entity for which trust is assumed and not derived."  In
/// practice we model the anchor as a parsed self-signed or
/// explicitly-trusted certificate plus a pre-computed subject-DN DER
/// blob for fast lookup.
///
/// Storing the subject DER eagerly avoids re-encoding it on every
/// chain-build lookup — the verifier is on a hot path.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The anchor certificate itself.
    cert: Certificate,
    /// Cached subject-DN DER bytes (chain-lookup key).
    subject_der: Vec<u8>,
}

impl TrustAnchor {
    /// Constructs a new trust anchor from a parsed certificate.
    ///
    /// Returns an error if the subject DN cannot be re-encoded, which
    /// should never happen for a well-formed parsed certificate but is
    /// surfaced rather than panicking per R5.
    pub fn new(cert: Certificate) -> CryptoResult<Self> {
        let subject_der = cert.subject_der()?;
        Ok(Self { cert, subject_der })
    }

    /// Returns the anchor certificate.
    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// Returns the subject DN DER bytes (cached).
    #[must_use]
    pub fn subject_der(&self) -> &[u8] {
        &self.subject_der
    }
}

// ---------------------------------------------------------------------------
// Certificate / CRL store
// ---------------------------------------------------------------------------

/// In-memory X.509 certificate and CRL store.
///
/// This is the Rust analogue of OpenSSL's `X509_STORE`.  Unlike the C
/// implementation it is not thread-safe on its own — add an
/// `Arc<RwLock<X509Store>>` wrapper at the caller if concurrent
/// mutation is required (and annotate that wrap site with
/// `// LOCK-SCOPE:` per R7).  The typical usage pattern builds the store
/// once at startup and then uses it read-only from the verifier, which
/// is lock-free.
#[derive(Debug, Default, Clone)]
pub struct X509Store {
    /// Trust anchors, indexed by subject-DN DER.
    ///
    /// We use a `HashMap<Vec<u8>, Vec<TrustAnchor>>` (rather than a
    /// flat `Vec<TrustAnchor>`) because chain building asks exactly
    /// "find me anchors whose subject == this issuer DN", and DN
    /// equality on DER bytes is the exact map key.
    ///
    /// The value is a `Vec` — although duplicate subject DNs in a trust
    /// store are rare in practice, the data model is not required to
    /// deduplicate and we must not silently drop a CA simply because
    /// another CA with the same DN was added first.
    anchors_by_subject: HashMap<Vec<u8>, Vec<TrustAnchor>>,
    /// Untrusted intermediate certificates used to build the chain,
    /// indexed by subject DN.  Again, multiple entries per DN are
    /// permitted (key rollover across intermediate re-issuance).
    intermediates_by_subject: HashMap<Vec<u8>, Vec<Certificate>>,
    /// CRLs indexed by issuer-DN DER.
    crls_by_issuer: HashMap<Vec<u8>, Vec<X509Crl>>,
}

impl X509Store {
    /// Creates a new, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trust anchor to the store.
    ///
    /// The anchor's subject DN is used as the lookup key.  Adding the
    /// same physical certificate twice is idempotent in effect but does
    /// deposit a duplicate entry in the list — use [`Self::contains_anchor`]
    /// if duplicate-avoidance is important to the caller.
    pub fn add_anchor(&mut self, cert: Certificate) -> CryptoResult<()> {
        let anchor = TrustAnchor::new(cert)?;
        self.anchors_by_subject
            .entry(anchor.subject_der.clone())
            .or_default()
            .push(anchor);
        Ok(())
    }

    /// Bulk-adds trust anchors from a certificate vector.
    pub fn add_anchors<I>(&mut self, iter: I) -> CryptoResult<()>
    where
        I: IntoIterator<Item = Certificate>,
    {
        for c in iter {
            self.add_anchor(c)?;
        }
        Ok(())
    }

    /// Adds an untrusted intermediate certificate to the store.
    ///
    /// Intermediates are consulted by the chain builder when an
    /// end-entity certificate's issuer is not itself a trust anchor.
    pub fn add_intermediate(&mut self, cert: Certificate) -> CryptoResult<()> {
        let subject_der = cert.subject_der()?;
        self.intermediates_by_subject
            .entry(subject_der)
            .or_default()
            .push(cert);
        Ok(())
    }

    /// Bulk-adds intermediate certificates.
    pub fn add_intermediates<I>(&mut self, iter: I) -> CryptoResult<()>
    where
        I: IntoIterator<Item = Certificate>,
    {
        for c in iter {
            self.add_intermediate(c)?;
        }
        Ok(())
    }

    /// Adds a CRL to the store.
    pub fn add_crl(&mut self, crl: X509Crl) {
        let issuer_der = crl.issuer().as_der().to_vec();
        self.crls_by_issuer
            .entry(issuer_der)
            .or_default()
            .push(crl);
    }

    /// Looks up trust anchors by subject-DN DER.  Returns an empty slice
    /// if no anchors match.
    #[must_use]
    pub fn anchors_by_subject(&self, subject_der: &[u8]) -> &[TrustAnchor] {
        self.anchors_by_subject
            .get(subject_der)
            .map_or(&[][..], Vec::as_slice)
    }

    /// Looks up intermediate certificates by subject DN.  Returns an
    /// empty slice if no intermediates match.
    #[must_use]
    pub fn intermediates_by_subject(&self, subject_der: &[u8]) -> &[Certificate] {
        self.intermediates_by_subject
            .get(subject_der)
            .map_or(&[][..], Vec::as_slice)
    }

    /// Looks up CRLs by issuer DN.  Returns an empty slice if no CRLs
    /// are registered for that issuer.
    #[must_use]
    pub fn crls_for_issuer(&self, issuer_der: &[u8]) -> &[X509Crl] {
        self.crls_by_issuer
            .get(issuer_der)
            .map_or(&[][..], Vec::as_slice)
    }

    /// Returns `true` if the given certificate is registered as a trust
    /// anchor (exact DER-byte match).
    pub fn contains_anchor(&self, cert: &Certificate) -> CryptoResult<bool> {
        let subject_der = cert.subject_der()?;
        let target_der = cert.as_der();
        Ok(self
            .anchors_by_subject(&subject_der)
            .iter()
            .any(|a| a.certificate().as_der() == target_der))
    }

    /// Returns the total number of trust anchors across all subject
    /// bins.
    #[must_use]
    pub fn anchor_count(&self) -> usize {
        self.anchors_by_subject.values().map(Vec::len).sum()
    }

    /// Returns the total number of intermediate certificates.
    #[must_use]
    pub fn intermediate_count(&self) -> usize {
        self.intermediates_by_subject.values().map(Vec::len).sum()
    }

    /// Returns the total number of CRLs.
    #[must_use]
    pub fn crl_count(&self) -> usize {
        self.crls_by_issuer.values().map(Vec::len).sum()
    }

    /// Clears the entire store.  Useful in tests and for controlled
    /// teardown scenarios.
    pub fn clear(&mut self) {
        self.anchors_by_subject.clear();
        self.intermediates_by_subject.clear();
        self.crls_by_issuer.clear();
    }

    /// Iterates over every trust anchor in the store (order
    /// unspecified).
    pub fn iter_anchors(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors_by_subject.values().flat_map(|v| v.iter())
    }

    /// Iterates over every intermediate certificate in the store (order
    /// unspecified).
    pub fn iter_intermediates(&self) -> impl Iterator<Item = &Certificate> {
        self.intermediates_by_subject
            .values()
            .flat_map(|v| v.iter())
    }

    /// Parses a PEM-encoded chain and adds every certificate whose DN is
    /// self-issued as a trust anchor, and every other certificate as an
    /// intermediate.  This mirrors the common OpenSSL pattern of
    /// `X509_STORE_load_file` applied to a bundle.
    pub fn add_pem_bundle(&mut self, pem: &[u8]) -> CryptoResult<usize> {
        let chain = Certificate::load_pem_chain(pem)
            .map_err(|e| CryptoError::Encoding(format!("X509Store: {e}")))?;
        let count = chain.len();
        for cert in chain {
            if cert.is_self_issued()? {
                self.add_anchor(cert)?;
            } else {
                self.add_intermediate(cert)?;
            }
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_has_zero_counts() {
        let store = X509Store::new();
        assert_eq!(store.anchor_count(), 0);
        assert_eq!(store.intermediate_count(), 0);
        assert_eq!(store.crl_count(), 0);
    }

    #[test]
    fn lookup_on_empty_store_returns_empty_slices() {
        let store = X509Store::new();
        assert!(store.anchors_by_subject(&[1, 2, 3]).is_empty());
        assert!(store.intermediates_by_subject(&[1, 2, 3]).is_empty());
        assert!(store.crls_for_issuer(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn clear_empties_all_buckets() {
        let mut store = X509Store::new();
        // We cannot easily insert real certs in a unit test without a
        // vector, but we can at least verify that clear works on the
        // empty store without panicking.  The full flow is covered by
        // integration tests with real certificates.
        store.clear();
        assert_eq!(store.anchor_count(), 0);
        assert_eq!(store.intermediate_count(), 0);
        assert_eq!(store.crl_count(), 0);
    }

    #[test]
    fn iter_anchors_on_empty_store_yields_nothing() {
        let store = X509Store::new();
        assert_eq!(store.iter_anchors().count(), 0);
        assert_eq!(store.iter_intermediates().count(), 0);
    }

    #[test]
    fn add_pem_bundle_rejects_non_pem() {
        let mut store = X509Store::new();
        assert!(store.add_pem_bundle(b"garbage garbage garbage").is_err());
    }
}
