//! # Windows Certificate Store Adapter
//!
//! Provider-side store loader exposing the Windows system certificate store
//! via URIs prefixed `org.openssl.winstore:`.  Maps to the CryptoAPI "ROOT"
//! store, providing access to system-trusted root certificates.
//!
//! ## Platform Availability
//!
//! This module is **intended for Windows only**.  On Windows targets the
//! `openssl-ffi` crate registers a certificate loader that calls the
//! CryptoAPI (`CertOpenSystemStoreW`, `CertFindCertificateInStore`,
//! `CertCloseStore`).  On non-Windows targets the module still compiles
//! and passes all type checks, but the store returns no certificates
//! unless an alternative loader is injected for testing.
//!
//! ## URI Scheme
//!
//! `org.openssl.winstore:` — Opens the Windows "ROOT" system certificate
//! store.  No path component is required (the store name is fixed to
//! "ROOT").
//!
//! ## Context Lifecycle
//!
//! ```text
//! open(uri) → set_params(propq, subject) → load() (repeat) → eof() → close()
//! ```
//!
//! ## State Machine
//!
//! ```text
//! IDLE → (advance) → READ → (advance) → READ → … → EOF
//!   ↑                                                   │
//!   └──────────────── (reset) ←─────────────────────────┘
//! ```
//!
//! ## Source
//!
//! Replaces C `providers/implementations/storemgmt/winstore_store.c`
//! (336 lines).
//!
//! ## Design Notes
//!
//! Because the `openssl-provider` crate enforces `#![forbid(unsafe_code)]`,
//! direct Windows CryptoAPI calls cannot be made here.  Instead,
//! certificate loading is delegated to a pluggable loader function
//! registered via `register_certificate_loader`.  The `openssl-ffi`
//! crate is responsible for registering the actual CryptoAPI
//! implementation at application startup.
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` blocks (Rule R8).

use std::sync::OnceLock;

use crate::traits::{AlgorithmDescriptor, StoreContext, StoreObject, StoreProvider};
use openssl_common::{ProviderError, ProviderResult};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// URI prefix that identifies the Windows certificate store.
///
/// Matches the C constant used in
/// `HAS_CASE_PREFIX(uri, "org.openssl.winstore:")`.
const URI_PREFIX: &str = "org.openssl.winstore:";

/// Provider name used in algorithm registration and
/// [`StoreProvider::name`].
const PROVIDER_NAME: &str = "org.openssl.winstore";

/// Property string for the algorithm descriptor.
///
/// Indicates this store is provided by the default provider.
const PROPERTY_DEFINITION: &str = "provider=default";

/// Human-readable description for the algorithm descriptor.
const DESCRIPTION: &str = "Windows certificate store";

// ═══════════════════════════════════════════════════════════════════════════════
// Certificate Loader Abstraction
// ═══════════════════════════════════════════════════════════════════════════════

/// Function signature for the platform-specific certificate loader.
///
/// The loader receives an optional DER-encoded subject name filter
/// and returns a vector of DER-encoded certificates matching that
/// filter from the Windows ROOT system certificate store.
///
/// # Arguments
///
/// * `subject_filter` — If `Some(bytes)`, only certificates whose
///   subject matches the given DER-encoded name are returned.  If
///   `None`, the loader should return **no** certificates (matching
///   the C behaviour where `CertFindCertificateInStore` with NULL
///   criteria returns nothing).
///
/// # Returns
///
/// A `ProviderResult<Vec<Vec<u8>>>` containing zero or more
/// DER-encoded X.509 certificates.
type CertLoaderFn = fn(Option<&[u8]>) -> ProviderResult<Vec<Vec<u8>>>;

/// Global registration point for the certificate loader function.
///
/// Uses `OnceLock` for one-time, thread-safe initialisation.  The
/// FFI crate registers the Windows CryptoAPI-based loader at startup
/// via `register_certificate_loader`.
static CERT_LOADER: OnceLock<CertLoaderFn> = OnceLock::new();

/// Registers the platform-specific certificate loader.
///
/// This must be called once during application initialisation,
/// typically by the `openssl-ffi` crate's library init function.
/// Only the first call takes effect; subsequent calls are silently
/// ignored (matching `OnceLock::set` semantics).
///
/// # Arguments
///
/// * `loader` — A function that queries the Windows certificate
///   store and returns DER-encoded certificates.
///
/// # Example
///
/// ```ignore
/// // In the FFI crate (the only crate allowed to use unsafe):
/// fn windows_load_certs(
///     subject: Option<&[u8]>,
/// ) -> ProviderResult<Vec<Vec<u8>>> {
///     // unsafe { CertOpenSystemStoreW(...) ... }
///     # Ok(Vec::new())
/// }
/// openssl_provider::implementations::store::winstore::register_certificate_loader(
///     windows_load_certs,
/// );
/// ```
pub fn register_certificate_loader(loader: CertLoaderFn) {
    // OnceLock::set returns Err if already set — we discard the error
    // because double-init is a no-op, not a failure.
    let _ = CERT_LOADER.set(loader);
}

/// Loads certificates from the Windows ROOT system store via the
/// registered loader function.
///
/// Returns an empty vector if no loader has been registered.  This
/// allows the store to degrade gracefully during testing or when the
/// FFI layer has not been initialised.
///
/// # Arguments
///
/// * `subject_filter` — Optional DER-encoded subject name filter.
fn load_windows_root_certificates(
    subject_filter: Option<&[u8]>,
) -> ProviderResult<Vec<Vec<u8>>> {
    match CERT_LOADER.get() {
        Some(loader) => loader(subject_filter),
        None => {
            // No loader registered — the store is effectively empty.
            // This matches the behaviour of a Windows machine with an
            // empty ROOT store: zero certificates, immediate EOF.
            Ok(Vec::new())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// State Machine
// ═══════════════════════════════════════════════════════════════════════════════

/// State machine for the Windows store iterator.
///
/// Replaces the C `enum { STATE_IDLE, STATE_READ, STATE_EOF }` from
/// `winstore_store.c` line 34.
///
/// ```text
/// IDLE → (advance) → READ → (advance) → READ → … → EOF
///   ↑                                                   │
///   └──────────────── (reset) ←─────────────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinStoreState {
    /// Initial state or after reset — no certificate loaded.
    Idle,
    /// A certificate is available for reading via
    /// [`WinStoreContext::load`].
    Read,
    /// No more certificates — iteration complete.
    Eof,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Settable / gettable context parameters for the Windows certificate
/// store.
///
/// Replaces the C `winstore_set_ctx_params_list` parameter table.
/// Encapsulates the property query and optional subject filter used to
/// configure certificate iteration.
///
/// # Fields
///
/// * `propq` — Property query string for decoder configuration (e.g.,
///   `"provider=default"`).
/// * `subject` — DER-encoded X.509 subject name for certificate
///   filtering.  If `None`, the store returns no certificates (matching
///   C behaviour where `CertFindCertificateInStore` with NULL criteria
///   returns nothing).
#[derive(Debug, Clone, Default)]
pub struct WinStoreParams {
    /// Property query string passed to the decoder context.
    pub propq: Option<String>,
    /// DER-encoded X.509 subject name for certificate filtering.
    pub subject: Option<Vec<u8>>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Store Context
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-handle context for the Windows certificate store.
///
/// Manages the certificate iteration state, subject filter, property
/// query, and pre-loaded certificate list.  Each context represents a
/// single open session against the Windows ROOT certificate store.
///
/// Replaces the C `struct winstore_ctx_st` from `winstore_store.c`
/// line 40.
///
/// # Thread Safety
///
/// This type is `Send + Sync` because all fields are owned types
/// (`Option<String>`, `Option<Vec<u8>>`, `Vec<Vec<u8>>`, `Copy` enum,
/// `usize`).
///
/// # Design Notes
///
/// Unlike the C version which holds a live `HCERTSTORE` handle and
/// iterates one certificate at a time via `CertFindCertificateInStore`,
/// this Rust version pre-loads all matching certificates as DER bytes
/// at [`set_params`](Self::set_params) time.  This avoids holding a
/// Windows store handle across the context's lifetime and eliminates
/// any need for `unsafe` code in the provider crate.
pub struct WinStoreContext {
    /// Property query string for decoder configuration.
    propq: Option<String>,
    /// DER-encoded subject name filter.
    subject: Option<Vec<u8>>,
    /// Current state machine state.
    state: WinStoreState,
    /// Pre-loaded DER-encoded certificates from the Windows store.
    certificates: Vec<Vec<u8>>,
    /// Current index into the `certificates` list.
    current_index: usize,
}

impl WinStoreContext {
    /// Creates a new context in the `WinStoreState::Idle` state with
    /// no certificates loaded and no filters applied.
    fn new() -> Self {
        Self {
            propq: None,
            subject: None,
            state: WinStoreState::Idle,
            certificates: Vec::new(),
            current_index: 0,
        }
    }

    /// Resets the iterator to the `WinStoreState::Idle` state.
    ///
    /// Clears the current index but does **not** clear the loaded
    /// certificates or filters — those persist until explicitly changed
    /// via [`set_params`](Self::set_params) or
    /// [`close`](WinStoreContext::close).
    ///
    /// Replaces C `winstore_win_reset()` (lines 53–61).
    fn reset(&mut self) {
        self.current_index = 0;
        self.state = WinStoreState::Idle;
    }

    /// Advances the iterator to the next available certificate.
    ///
    /// If more certificates remain in the pre-loaded list, transitions
    /// to `WinStoreState::Read`.  Otherwise transitions to
    /// `WinStoreState::Eof`.
    ///
    /// When in the `WinStoreState::Eof` state the call is a no-op,
    /// preventing inadvertent re-entry.
    ///
    /// Replaces C `winstore_win_advance()` (lines 63–76).
    fn advance(&mut self) {
        if self.state == WinStoreState::Eof {
            return;
        }
        if self.current_index < self.certificates.len() {
            self.state = WinStoreState::Read;
        } else {
            self.state = WinStoreState::Eof;
        }
    }

    /// Updates the context parameters and reloads certificates.
    ///
    /// If either `propq` or `subject` changes, the certificate list is
    /// reloaded from the Windows store and the iterator is reset to
    /// point at the first matching certificate.
    ///
    /// Replaces C `winstore_set_ctx_params()` (lines 110–154).
    ///
    /// # Arguments
    ///
    /// * `propq` — If `Some`, update the property query string.
    /// * `subject` — If `Some`, update the DER-encoded subject filter.
    ///   Pass `Some(&[])` (empty slice) to clear the filter (resulting
    ///   in no matches, matching C behaviour).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the certificate loader fails
    /// (e.g., the Windows store cannot be opened).
    pub fn set_params(
        &mut self,
        propq: Option<&str>,
        subject: Option<&[u8]>,
    ) -> ProviderResult<()> {
        let mut changed = false;

        // Update propq if provided.
        if let Some(pq) = propq {
            let new_propq = Some(pq.to_owned());
            if self.propq != new_propq {
                self.propq = new_propq;
                changed = true;
            }
        }

        // Update subject if provided.
        // An empty subject slice is treated as "no filter" (None),
        // matching the C behaviour where cbData == 0 → NULL criteria.
        if let Some(sub) = subject {
            let new_subject = if sub.is_empty() { None } else { Some(sub.to_vec()) };
            if self.subject != new_subject {
                self.subject = new_subject;
                changed = true;
            }
        }

        // Reload certificates and reset iterator if parameters changed.
        if changed {
            self.reload_certificates()?;
        }

        Ok(())
    }

    /// Returns the current context parameters.
    ///
    /// Provides read access to the property query and subject filter
    /// currently configured on this context.
    pub fn get_params(&self) -> WinStoreParams {
        WinStoreParams {
            propq: self.propq.clone(),
            subject: self.subject.clone(),
        }
    }

    /// Reloads certificates from the Windows store using the current
    /// subject filter, resets the iterator, and advances to the first
    /// matching certificate.
    ///
    /// Called internally when parameters change via
    /// [`set_params`](Self::set_params).
    fn reload_certificates(&mut self) -> ProviderResult<()> {
        // Load certificates using the registered loader.
        let subject_ref = self.subject.as_deref();
        self.certificates = load_windows_root_certificates(subject_ref)?;

        // Reset iterator and advance to the first certificate.
        self.reset();
        self.advance();

        Ok(())
    }
}

// ─── StoreContext trait implementation ───────────────────────────────────────

impl StoreContext for WinStoreContext {
    /// Loads the next certificate from the Windows store.
    ///
    /// Returns `Ok(Some(StoreObject::Certificate(der_bytes)))` if a
    /// certificate is available, or `Ok(None)` if the iterator is not
    /// in the `WinStoreState::Read` state (either idle or exhausted).
    ///
    /// After successfully loading a certificate, the iterator advances
    /// to the next certificate.  If no more certificates remain, the
    /// state transitions to `WinStoreState::Eof`.
    ///
    /// Replaces C `winstore_load()` (lines 287–305).
    fn load(&mut self) -> ProviderResult<Option<StoreObject>> {
        if self.state != WinStoreState::Read {
            return Ok(None);
        }

        // Retrieve the current certificate's DER bytes.
        // The index is guaranteed valid because advance() only sets
        // Read state when current_index < certificates.len().
        let cert_der = if let Some(der) = self.certificates.get(self.current_index) {
            der.clone()
        } else {
            // Defensive: should not happen given the advance()
            // invariant, but handle gracefully by moving to EOF.
            self.state = WinStoreState::Eof;
            return Ok(None);
        };

        // Move to the next position and advance the state machine.
        self.current_index += 1;
        self.advance();

        Ok(Some(StoreObject::Certificate(cert_der)))
    }

    /// Returns `true` when no more certificates are available.
    ///
    /// Specifically, returns `true` whenever the state is **not**
    /// `WinStoreState::Read`, which includes both the initial
    /// `WinStoreState::Idle` state and the terminal
    /// `WinStoreState::Eof` state.
    ///
    /// Replaces C `winstore_eof()` (lines 307–312).
    fn eof(&self) -> bool {
        self.state != WinStoreState::Read
    }

    /// Closes the store context and releases all resources.
    ///
    /// Clears the certificate list, subject filter, property query,
    /// and transitions to `WinStoreState::Eof`.
    ///
    /// After closing, the context must not be reused.  Any subsequent
    /// calls to [`load`](Self::load) will return `Ok(None)` and
    /// [`eof`](Self::eof) will return `true`.
    ///
    /// Replaces C `winstore_close()` (lines 314–325).
    fn close(&mut self) -> ProviderResult<()> {
        self.reset();
        self.certificates.clear();
        self.propq = None;
        self.subject = None;
        self.state = WinStoreState::Eof;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Store Provider
// ═══════════════════════════════════════════════════════════════════════════════

/// Windows certificate store provider.
///
/// Implements `StoreProvider` for the `org.openssl.winstore:` URI
/// scheme.  The store opens the system "ROOT" certificate store, which
/// contains trusted root CA certificates installed by the operating
/// system and system administrator.
///
/// Replaces the C `ossl_winstore_store_functions[]` dispatch table
/// from `winstore_store.c`.
///
/// # Entry-Point Reachability (Rule R10)
///
/// Reachable via: `openssl_cli::main()` → provider loading →
/// `DefaultProvider::query_operation(Store)` → `WinStore::open()` →
/// `WinStoreContext::load()`
#[derive(Debug, Clone, Default)]
pub struct WinStore;

impl WinStore {
    /// Creates a new Windows certificate store provider instance.
    pub fn new() -> Self {
        Self
    }
}

impl StoreProvider for WinStore {
    /// Returns the unique name of this store provider.
    ///
    /// Returns `"org.openssl.winstore"`.
    fn name(&self) -> &'static str {
        PROVIDER_NAME
    }

    /// Opens a Windows certificate store session for the given URI.
    ///
    /// The URI must start with `"org.openssl.winstore:"` (compared
    /// case-insensitively, matching the C `HAS_CASE_PREFIX` macro).
    /// Returns a `WinStoreContext` in the `WinStoreState::Idle`
    /// state.
    ///
    /// After opening, the caller should configure the context via
    /// [`WinStoreContext::set_params`] before iterating with
    /// [`StoreContext::load`].
    ///
    /// # Errors
    ///
    /// * [`ProviderError::NotFound`] — if the URI prefix does not
    ///   match `"org.openssl.winstore:"`.
    ///
    /// Replaces C `winstore_open()` (lines 78–98).
    fn open(&self, uri: &str) -> ProviderResult<Box<dyn StoreContext>> {
        if !uri_matches_prefix(uri) {
            return Err(ProviderError::NotFound(format!(
                "URI does not match expected prefix '{URI_PREFIX}': '{uri}'"
            )));
        }

        Ok(Box::new(WinStoreContext::new()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Algorithm Descriptors
// ═══════════════════════════════════════════════════════════════════════════════

/// Returns the algorithm descriptor for the Windows certificate store.
///
/// Registers a single store algorithm:
///
/// | Field           | Value                        |
/// |-----------------|------------------------------|
/// | **names**       | `["org.openssl.winstore"]`   |
/// | **property**    | `"provider=default"`         |
/// | **description** | `"Windows certificate store"`|
///
/// This descriptor is included in the provider's algorithm enumeration
/// so that the `EVP_STORE` fetch mechanism can locate this store by
/// name or URI scheme.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec![PROVIDER_NAME],
        property: PROPERTY_DEFINITION,
        description: DESCRIPTION,
    }]
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Checks whether the given URI starts with the Windows store prefix.
///
/// The comparison is ASCII case-insensitive, matching the C
/// `HAS_CASE_PREFIX(uri, "org.openssl.winstore:")` macro.
fn uri_matches_prefix(uri: &str) -> bool {
    uri.get(..URI_PREFIX.len())
        .map_or(false, |prefix| prefix.eq_ignore_ascii_case(URI_PREFIX))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI Matching ────────────────────────────────────────────────────

    #[test]
    fn uri_matches_prefix_exact() {
        assert!(uri_matches_prefix("org.openssl.winstore:"));
    }

    #[test]
    fn uri_matches_prefix_case_insensitive() {
        assert!(uri_matches_prefix("ORG.OPENSSL.WINSTORE:"));
        assert!(uri_matches_prefix("Org.OpenSSL.WinStore:"));
    }

    #[test]
    fn uri_matches_prefix_with_path() {
        assert!(uri_matches_prefix("org.openssl.winstore://ROOT"));
    }

    #[test]
    fn uri_matches_prefix_wrong_scheme() {
        assert!(!uri_matches_prefix("file:///etc/certs"));
        assert!(!uri_matches_prefix("org.openssl.filestore:"));
    }

    #[test]
    fn uri_matches_prefix_empty() {
        assert!(!uri_matches_prefix(""));
    }

    #[test]
    fn uri_matches_prefix_too_short() {
        assert!(!uri_matches_prefix("org.openssl"));
    }

    // ── WinStoreState ───────────────────────────────────────────────────

    #[test]
    fn state_new_is_idle() {
        let ctx = WinStoreContext::new();
        assert_eq!(ctx.state, WinStoreState::Idle);
        assert!(ctx.certificates.is_empty());
        assert_eq!(ctx.current_index, 0);
        assert!(ctx.propq.is_none());
        assert!(ctx.subject.is_none());
    }

    #[test]
    fn state_reset_returns_to_idle() {
        let mut ctx = WinStoreContext::new();
        ctx.state = WinStoreState::Read;
        ctx.current_index = 5;
        ctx.reset();
        assert_eq!(ctx.state, WinStoreState::Idle);
        assert_eq!(ctx.current_index, 0);
    }

    #[test]
    fn advance_empty_goes_to_eof() {
        let mut ctx = WinStoreContext::new();
        ctx.advance();
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    #[test]
    fn advance_with_certs_goes_to_read() {
        let mut ctx = WinStoreContext::new();
        ctx.certificates = vec![vec![1, 2, 3]];
        ctx.advance();
        assert_eq!(ctx.state, WinStoreState::Read);
    }

    #[test]
    fn advance_past_end_goes_to_eof() {
        let mut ctx = WinStoreContext::new();
        ctx.certificates = vec![vec![1, 2, 3]];
        ctx.current_index = 1;
        ctx.advance();
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    #[test]
    fn advance_noop_when_already_eof() {
        let mut ctx = WinStoreContext::new();
        ctx.state = WinStoreState::Eof;
        ctx.certificates = vec![vec![1, 2, 3]];
        ctx.current_index = 0;
        ctx.advance();
        // Still Eof — advance is a no-op once Eof is reached.
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    // ── StoreContext — eof() ────────────────────────────────────────────

    #[test]
    fn eof_true_when_idle() {
        let ctx = WinStoreContext::new();
        assert!(ctx.eof());
    }

    #[test]
    fn eof_false_when_read() {
        let mut ctx = WinStoreContext::new();
        ctx.state = WinStoreState::Read;
        assert!(!ctx.eof());
    }

    #[test]
    fn eof_true_when_eof_state() {
        let mut ctx = WinStoreContext::new();
        ctx.state = WinStoreState::Eof;
        assert!(ctx.eof());
    }

    // ── StoreContext — load() ───────────────────────────────────────────

    #[test]
    fn load_returns_none_when_idle() {
        let mut ctx = WinStoreContext::new();
        let result = ctx.load();
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());
    }

    #[test]
    fn load_returns_certificates_in_order() {
        let cert1 = vec![0x30, 0x82, 0x01, 0x00];
        let cert2 = vec![0x30, 0x82, 0x02, 0x00];
        let mut ctx = WinStoreContext::new();
        ctx.certificates = vec![cert1.clone(), cert2.clone()];
        ctx.state = WinStoreState::Read;

        // First load
        let obj1 = ctx.load().ok().flatten();
        match obj1 {
            Some(StoreObject::Certificate(der)) => assert_eq!(der, cert1),
            other => panic!("Expected Certificate, got {other:?}"),
        }

        // Second load
        let obj2 = ctx.load().ok().flatten();
        match obj2 {
            Some(StoreObject::Certificate(der)) => assert_eq!(der, cert2),
            other => panic!("Expected Certificate, got {other:?}"),
        }

        // Third load — should be None (EOF)
        assert!(ctx.eof());
        assert!(ctx.load().ok().flatten().is_none());
    }

    #[test]
    fn load_returns_none_when_eof() {
        let mut ctx = WinStoreContext::new();
        ctx.state = WinStoreState::Eof;
        assert!(ctx.load().ok().flatten().is_none());
    }

    // ── StoreContext — close() ──────────────────────────────────────────

    #[test]
    fn close_clears_all_state() {
        let mut ctx = WinStoreContext::new();
        ctx.propq = Some("test".to_owned());
        ctx.subject = Some(vec![1, 2, 3]);
        ctx.certificates = vec![vec![0x30]];
        ctx.state = WinStoreState::Read;

        let _ = ctx.close();

        assert!(ctx.propq.is_none());
        assert!(ctx.subject.is_none());
        assert!(ctx.certificates.is_empty());
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    // ── WinStoreParams ─────────────────────────────────────────────────

    #[test]
    fn params_default_is_empty() {
        let params = WinStoreParams::default();
        assert!(params.propq.is_none());
        assert!(params.subject.is_none());
    }

    #[test]
    fn get_params_reflects_state() {
        let mut ctx = WinStoreContext::new();
        ctx.propq = Some("provider=default".to_owned());
        ctx.subject = Some(vec![0x30, 0x0a]);

        let params = ctx.get_params();
        assert_eq!(params.propq, Some("provider=default".to_owned()));
        assert_eq!(params.subject, Some(vec![0x30, 0x0a]));
    }

    #[test]
    fn get_params_empty_context() {
        let ctx = WinStoreContext::new();
        let params = ctx.get_params();
        assert!(params.propq.is_none());
        assert!(params.subject.is_none());
    }

    // ── set_params ─────────────────────────────────────────────────────

    #[test]
    fn set_params_no_change_keeps_idle() {
        let mut ctx = WinStoreContext::new();
        let result = ctx.set_params(None, None);
        assert!(result.is_ok());
        assert_eq!(ctx.state, WinStoreState::Idle);
    }

    #[test]
    fn set_params_propq_only() {
        let mut ctx = WinStoreContext::new();
        let result = ctx.set_params(Some("provider=default"), None);
        assert!(result.is_ok());
        assert_eq!(ctx.propq, Some("provider=default".to_owned()));
        // propq change alone triggers reload → no loader → empty → EOF
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    #[test]
    fn set_params_empty_subject_clears_filter() {
        let mut ctx = WinStoreContext::new();
        ctx.subject = Some(vec![0x30]);
        let result = ctx.set_params(None, Some(&[]));
        assert!(result.is_ok());
        assert!(ctx.subject.is_none());
    }

    #[test]
    fn set_params_subject() {
        let mut ctx = WinStoreContext::new();
        let subject = vec![0x30, 0x0a, 0x31, 0x08];
        let result = ctx.set_params(None, Some(&subject));
        assert!(result.is_ok());
        assert_eq!(ctx.subject, Some(subject));
        // With no loader registered, reload returns empty → EOF
        assert_eq!(ctx.state, WinStoreState::Eof);
    }

    #[test]
    fn set_params_same_value_no_reload() {
        let mut ctx = WinStoreContext::new();
        ctx.propq = Some("test".to_owned());
        // Setting the same propq should not trigger reload.
        ctx.state = WinStoreState::Idle;
        let result = ctx.set_params(Some("test"), None);
        assert!(result.is_ok());
        assert_eq!(ctx.state, WinStoreState::Idle); // unchanged
    }

    // ── WinStore ────────────────────────────────────────────────────────

    #[test]
    fn store_name() {
        let store = WinStore::new();
        assert_eq!(store.name(), "org.openssl.winstore");
    }

    #[test]
    fn store_open_valid_uri() {
        let store = WinStore::new();
        let result = store.open("org.openssl.winstore:");
        assert!(result.is_ok());
    }

    #[test]
    fn store_open_case_insensitive_uri() {
        let store = WinStore::new();
        let result = store.open("ORG.OPENSSL.WINSTORE:");
        assert!(result.is_ok());
    }

    #[test]
    fn store_open_wrong_uri() {
        let store = WinStore::new();
        let result = store.open("file:///some/path");
        assert!(result.is_err());
    }

    #[test]
    fn store_open_empty_uri() {
        let store = WinStore::new();
        let result = store.open("");
        assert!(result.is_err());
    }

    // ── descriptors ─────────────────────────────────────────────────────

    #[test]
    fn descriptors_returns_one_entry() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["org.openssl.winstore"]);
        assert_eq!(descs[0].property, "provider=default");
        assert_eq!(descs[0].description, "Windows certificate store");
    }

    // ── Full Lifecycle ──────────────────────────────────────────────────

    #[test]
    fn full_iteration_cycle() {
        // Simulate a full lifecycle with manually loaded certificates.
        let mut ctx = WinStoreContext::new();

        // Simulate certificates being loaded (as if by a registered
        // loader triggered via set_params).
        ctx.certificates = vec![
            vec![0x30, 0x82, 0x01, 0x01],
            vec![0x30, 0x82, 0x01, 0x02],
            vec![0x30, 0x82, 0x01, 0x03],
        ];
        ctx.state = WinStoreState::Idle;
        ctx.advance();

        assert!(!ctx.eof());

        // Load first cert
        let obj1 = ctx.load().ok().flatten();
        assert!(matches!(obj1, Some(StoreObject::Certificate(_))));

        // Load second cert
        let obj2 = ctx.load().ok().flatten();
        assert!(matches!(obj2, Some(StoreObject::Certificate(_))));

        // Load third cert
        let obj3 = ctx.load().ok().flatten();
        assert!(matches!(obj3, Some(StoreObject::Certificate(_))));

        // No more certs
        assert!(ctx.eof());
        assert!(ctx.load().ok().flatten().is_none());

        // Close
        let _ = ctx.close();
        assert_eq!(ctx.state, WinStoreState::Eof);
        assert!(ctx.certificates.is_empty());
    }

    #[test]
    fn open_then_load_without_params_returns_none() {
        // Matches C behaviour: open → load without set_params → nothing
        let store = WinStore::new();
        let result = store.open("org.openssl.winstore:");
        let mut ctx = result.ok().unwrap();
        assert!(ctx.eof()); // Idle → eof is true
        assert!(ctx.load().ok().flatten().is_none());
    }

    #[test]
    fn close_then_load_returns_none() {
        let mut ctx = WinStoreContext::new();
        ctx.certificates = vec![vec![0x30]];
        ctx.state = WinStoreState::Read;

        let _ = ctx.close();
        assert!(ctx.eof());
        assert!(ctx.load().ok().flatten().is_none());
    }
}
