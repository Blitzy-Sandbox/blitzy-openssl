//! # Store Provider Implementations
//!
//! Contains all store implementations for the OpenSSL Rust provider system.
//! Stores are responsible for loading keys, certificates, CRLs, and other
//! objects from external sources (filesystem, Windows certificate store,
//! etc.).
//!
//! ## Store Implementations
//!
//! | Module          | Source                     | Store Name              | URI Scheme                  |
//! |-----------------|----------------------------|-------------------------|-----------------------------|
//! | [`file_store`]  | `file_store.c` (828 lines) | `"file"`                | `file:///path` or plain path |
//! | [`any2obj`]     | `file_store_any2obj.c` (368 lines) | (internal)      | N/A — used by file_store     |
//! | [`winstore`]    | `winstore_store.c` (336 lines) | `"org.openssl.winstore"` | `org.openssl.winstore:`  |
//!
//! ## Architecture
//!
//! Store implementations implement the [`StoreProvider`](crate::traits::StoreProvider)
//! trait from [`crate::traits`], which provides:
//!
//! - `name()` — Store identifier for URI scheme matching.
//! - `open(uri)` — Creates a [`StoreContext`](crate::traits::StoreContext)
//!   for the given URI.
//!
//! Store contexts implement the [`StoreContext`](crate::traits::StoreContext)
//! trait lifecycle:
//!
//! ```text
//! open(uri) → set_params() → load() → load() → … → eof() → close()
//! ```
//!
//! The [`any2obj`] module is an internal decoder used by both [`file_store`]
//! and [`winstore`] as a last-resort decoder for unrecognized binary content.
//!
//! ## Store Objects
//!
//! Stores return [`StoreObject`](crate::traits::StoreObject) enum variants:
//!
//! - [`StoreObject::Key`](crate::traits::StoreObject::Key) — Key material
//!   (public, private, or symmetric).
//! - [`StoreObject::Certificate`](crate::traits::StoreObject::Certificate) —
//!   X.509 certificate (DER bytes).
//! - [`StoreObject::Crl`](crate::traits::StoreObject::Crl) — Certificate
//!   Revocation List (DER bytes).
//! - [`StoreObject::Params`](crate::traits::StoreObject::Params) — Algorithm
//!   parameters.
//!
//! ## Platform Gating Strategy
//!
//! - [`any2obj`] — always compiled (used as internal decoder on all platforms).
//! - [`file_store`] — always compiled (filesystem access is universal).
//! - [`winstore`] — the Rust module compiles on every platform because it
//!   uses a pluggable certificate-loader registration pattern (the
//!   `openssl-provider` crate enforces `#![forbid(unsafe_code)]` so the
//!   module cannot invoke the Windows CryptoAPI directly).  However, its
//!   algorithm descriptors are only advertised on Windows targets and the
//!   [`WinStore`] / [`WinStoreContext`] convenience re-exports at this
//!   module's root are gated with `#[cfg(target_os = "windows")]` to
//!   surface the public API only where it is expected to be used.
//!   Non-Windows callers that still need the types can always reach them
//!   via the fully-qualified path [`winstore::WinStore`] etc.
//!
//! ## Wiring (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(Store)
//!         → implementations::all_store_descriptors()
//!           → store::descriptors()
//!             → file_store::descriptors()
//!             → any2obj::algorithm_descriptors()
//!             → [windows-only] winstore::descriptors()
//! ```
//!
//! ## Source
//!
//! Replaces C `providers/implementations/storemgmt/` directory (3 files,
//! 1532 lines total).

use super::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, StoreObject};

// =============================================================================
// Submodule Declarations
// =============================================================================

/// Any-to-object decoder chain passthrough.
///
/// Internal "last-resort" decoder that turns unrecognized binary content
/// (DER, MSBLOB, PVK, RAW) into a typed [`DecodedObject`] for further
/// processing in the decoder chain.  Used by both [`file_store`] and
/// [`winstore`] when no more specialized decoder recognizes the data.
///
/// Always compiled — this module is platform-agnostic and is the
/// building block for all store implementations in this tree.
///
/// Source: `providers/implementations/storemgmt/file_store_any2obj.c`
/// (368 lines).
pub mod any2obj;

/// File system store implementation.
///
/// Loads keys, certificates, CRLs from filesystem paths and `file:` URIs.
/// Supports both single-file and directory-based loading with automatic
/// PEM/DER format detection.
///
/// Always compiled — filesystem access is universal across all supported
/// platforms.
///
/// Source: `providers/implementations/storemgmt/file_store.c` (828 lines).
pub mod file_store;

/// Windows certificate store adapter.
///
/// Provides access to the Windows system "ROOT" certificate store via
/// the `org.openssl.winstore:` URI scheme.  Certificate loading is
/// delegated to a pluggable loader function because the
/// `openssl-provider` crate enforces `#![forbid(unsafe_code)]` and
/// therefore cannot invoke the Windows CryptoAPI directly; the
/// `openssl-ffi` crate is responsible for registering the actual
/// CryptoAPI implementation at application startup.
///
/// The Rust module itself compiles on every platform so that the
/// integration tests and the loader-registration machinery are
/// reachable from non-Windows hosts.  See the module's documentation
/// for details on the loader-registration pattern.
///
/// Source: `providers/implementations/storemgmt/winstore_store.c`
/// (336 lines).
pub mod winstore;

// =============================================================================
// Re-exports — Schema-required public convenience types
// =============================================================================

// -- file_store ---------------------------------------------------------------

/// Re-export: the filesystem store provider struct.
///
/// See [`file_store::FileStore`] for full documentation.
pub use file_store::FileStore;

/// Re-export: the per-URI iteration context produced by
/// [`FileStore::open()`](crate::traits::StoreProvider::open).
///
/// See [`file_store::FileStoreContext`] for full documentation.
pub use file_store::FileStoreContext;

/// Re-export: expected-object-type filter applied by the file store
/// loader to return only objects of a particular kind.
///
/// See [`file_store::ExpectedType`] for full documentation.
pub use file_store::ExpectedType;

// -- any2obj ------------------------------------------------------------------

/// Re-export: decoder context for the any-to-object passthrough.
///
/// See [`any2obj::Any2ObjContext`] for full documentation.
pub use any2obj::Any2ObjContext;

/// Re-export: decoded-object result produced by the any-to-object decoder.
///
/// See [`any2obj::DecodedObject`] for full documentation.
pub use any2obj::DecodedObject;

/// Re-export: object-type classification for decoded content.
///
/// See [`any2obj::ObjectType`] for full documentation.
pub use any2obj::ObjectType;

/// Re-export: supported input-format discriminants for the any-to-object
/// decoder (DER, MSBLOB, PVK, RAW).
///
/// See [`any2obj::InputFormat`] for full documentation.
pub use any2obj::InputFormat;

// -- winstore -----------------------------------------------------------------

/// Re-export: the Windows certificate store provider struct.
///
/// Only re-exported on Windows targets; non-Windows callers can still
/// reach this type via [`winstore::WinStore`] if required.
///
/// See [`winstore::WinStore`] for full documentation.
#[cfg(target_os = "windows")]
pub use winstore::WinStore;

/// Re-export: the Windows certificate store iteration context produced by
/// [`WinStore::open()`](crate::traits::StoreProvider::open).
///
/// Only re-exported on Windows targets; non-Windows callers can still
/// reach this type via [`winstore::WinStoreContext`] if required.
///
/// See [`winstore::WinStoreContext`] for full documentation.
#[cfg(target_os = "windows")]
pub use winstore::WinStoreContext;

// =============================================================================
// Algorithm Descriptor Aggregation
// =============================================================================

/// Returns every algorithm descriptor advertised by the store subsystem.
///
/// Called by
/// [`super::all_store_descriptors()`](super::all_store_descriptors) when
/// the `"store"` feature is enabled.  Replaces the role of collecting
/// `ossl_file_store_functions` and `ossl_winstore_store_functions`
/// dispatch tables in C `defltprov.c` / `baseprov.c`.
///
/// # Descriptors returned
///
/// - `"file"`              — the filesystem store (always included).
/// - any-to-object passthrough descriptors (`DER` / `MSBLOB` / `PVK` /
///   `RAW`) (always included).
/// - `"org.openssl.winstore"` — Windows system-certificate store
///   (Windows targets only).
///
/// # Rule R10 (Wiring)
///
/// This function is the single aggregation point that makes every store
/// backend reachable from the provider entry point.  The call chain is:
///
/// ```text
/// DefaultProvider::query_operation(Store)
///   → implementations::all_store_descriptors()
///     → store::descriptors()  (this function)
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    // The `mut` binding is conditionally required — the
    // `#[cfg(target_os = "windows")]` block below extends the vector
    // with Windows-only descriptors.  On non-Windows targets the
    // compiler would otherwise emit an `unused_mut` warning.
    #[allow(unused_mut)]
    let mut descs = vec![algorithm(
        &["file"],
        "provider=default",
        "File-based key and certificate store (PEM/DER directory)",
    )];

    // Any-to-object decoder passthrough descriptors (DER, MSBLOB, PVK,
    // RAW).  Compiled on every platform.
    descs.extend(any2obj::algorithm_descriptors());

    // Windows certificate store — only advertised on Windows targets
    // because the store is only meaningful when the CryptoAPI loader
    // has been registered by the `openssl-ffi` crate.
    #[cfg(target_os = "windows")]
    descs.extend(winstore::descriptors());

    descs
}

// =============================================================================
// StoreObject Classification Helper
// =============================================================================

/// Opaque wrapper used as the payload inside a [`StoreObject::Key`] when
/// [`classify_store_object`] successfully recognizes key material but
/// does not have access to the algorithm-specific key-management
/// machinery required to build a strongly-typed [`KeyData`] instance.
///
/// Consumers such as `OSSL_STORE` receive the full byte slice (via the
/// [`Debug`] representation or via the existing decoder pipeline in
/// [`file_store`]) and pass the wrapper down to the next decoder in the
/// chain, which is responsible for turning the raw bytes into a concrete
/// key implementation.  Storing the [`ObjectType`] alongside the bytes
/// preserves the classification decision made by the any-to-object
/// decoder so that downstream consumers can distinguish asymmetric
/// (public/private) from symmetric (raw) material without reparsing the
/// data.
///
/// The struct is crate-private because its only purpose is to satisfy
/// the [`KeyData`] trait object requirement of
/// [`StoreObject::Key`](crate::traits::StoreObject::Key); downstream
/// decoders work through [`std::any::Any`]-style downcasts and do not
/// need to name this type.
#[derive(Debug, Clone)]
struct GenericKeyMaterial {
    /// The raw bytes of the key, as recovered by the any-to-object
    /// decoder.
    ///
    /// The `allow(dead_code)` is required because the downstream
    /// consumers access the payload only via trait-object downcasts
    /// that the compiler cannot follow statically.
    #[allow(dead_code)]
    data: Vec<u8>,

    /// The object-type classification that produced this wrapper.
    ///
    /// Same justification as `data` above.
    #[allow(dead_code)]
    object_type: ObjectType,

    /// The optional structure hint from the any-to-object decoder
    /// (e.g. `"SubjectPublicKeyInfo"`, `"PrivateKeyInfo"`,
    /// `"EncryptedPrivateKeyInfo"`).
    ///
    /// Same justification as `data` above.
    #[allow(dead_code)]
    data_structure: Option<String>,
}

impl KeyData for GenericKeyMaterial {}

/// Classifies a [`DecodedObject`] into a [`StoreObject`] enum variant.
///
/// Shared helper used by both [`file_store`] and [`winstore`] decoder
/// callbacks to translate the output of the any-to-object decoder
/// passthrough into the high-level store-object taxonomy.
///
/// # Classification rules
///
/// | `decoded.object_type`           | `decoded.data_structure` hint                                  | Result                                       |
/// |---------------------------------|----------------------------------------------------------------|----------------------------------------------|
/// | [`ObjectType::Pkey`]            | any                                                            | [`StoreObject::Key`] (asymmetric key material) |
/// | [`ObjectType::Skey`]            | any                                                            | [`StoreObject::Key`] (symmetric key material)  |
/// | [`ObjectType::Unknown`]         | `"Certificate"`                                                | [`StoreObject::Certificate`]                  |
/// | [`ObjectType::Unknown`]         | `"CertificateList"`                                            | [`StoreObject::Crl`]                          |
/// | [`ObjectType::Unknown`]         | `"SubjectPublicKeyInfo"` / `"PrivateKeyInfo"` / `"EncryptedPrivateKeyInfo"` | [`StoreObject::Key`]          |
/// | [`ObjectType::Unknown`]         | anything else (including `None`)                               | `None` (deferred to other decoders)          |
///
/// The returned [`StoreObject::Key`] variant carries a crate-internal
/// [`KeyData`] wrapper (`GenericKeyMaterial`) that preserves the raw
/// bytes and the decoder's classification decision.  Downstream
/// consumers (e.g. the `OSSL_STORE` layer) are expected to re-decode the
/// payload through a type-specific key-management decoder to obtain a
/// fully-constructed key instance.
///
/// Returns `None` when the decoder produced a generic blob that cannot
/// be confidently classified into one of the [`StoreObject`] variants;
/// callers typically continue trying other decoders in the chain rather
/// than surfacing this as an error.
///
/// # Rule R5 (Nullability over Sentinels)
///
/// This function returns `Option<StoreObject>` rather than a dedicated
/// sentinel value for the "cannot classify" case.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::store::{
///     classify_store_object, DecodedObject, ObjectType,
/// };
///
/// let decoded = DecodedObject {
///     object_type: ObjectType::Unknown,
///     input_type: None,
///     data_type: None,
///     data_structure: Some("Certificate".to_string()),
///     data: vec![0x30, 0x82, /* … DER bytes … */],
/// };
/// let classified = classify_store_object(&decoded);
/// assert!(matches!(classified, Some(StoreObject::Certificate(_))));
/// ```
#[must_use]
pub fn classify_store_object(decoded: &DecodedObject) -> Option<StoreObject> {
    match decoded.object_type {
        // Asymmetric and symmetric key material — recognized by the
        // any-to-object decoder (MSBLOB / PVK produce Pkey; RAW
        // produces Skey).
        ObjectType::Pkey | ObjectType::Skey => {
            Some(StoreObject::Key(Box::new(GenericKeyMaterial {
                data: decoded.data.clone(),
                object_type: decoded.object_type,
                data_structure: decoded.data_structure.clone(),
            })))
        }

        // Unknown object type — classify by the optional structure hint
        // that the caller may have set via
        // [`Any2ObjContext::set_data_structure`](any2obj::Any2ObjContext::set_data_structure).
        ObjectType::Unknown => match decoded.data_structure.as_deref() {
            Some("Certificate") => Some(StoreObject::Certificate(decoded.data.clone())),
            Some("CertificateList") => Some(StoreObject::Crl(decoded.data.clone())),
            Some("SubjectPublicKeyInfo" | "PrivateKeyInfo" | "EncryptedPrivateKeyInfo") => {
                Some(StoreObject::Key(Box::new(GenericKeyMaterial {
                    data: decoded.data.clone(),
                    object_type: decoded.object_type,
                    data_structure: decoded.data_structure.clone(),
                })))
            }
            // No recognized structure hint — defer to other decoders in
            // the chain rather than producing a misleading classification.
            _ => None,
        },
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Classification of an asymmetric key material object produced by
    /// the MSBLOB / PVK any-to-object decoder.
    #[test]
    fn classify_pkey_produces_store_object_key() {
        let decoded = DecodedObject {
            object_type: ObjectType::Pkey,
            input_type: Some("msblob".to_string()),
            data_type: Some("RSA".to_string()),
            data_structure: None,
            data: vec![0x01, 0x02, 0x03, 0x04],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Key(_))),
            "expected StoreObject::Key for ObjectType::Pkey"
        );
    }

    /// Classification of a symmetric key material object produced by
    /// the RAW any-to-object decoder.
    #[test]
    fn classify_skey_produces_store_object_key() {
        let decoded = DecodedObject {
            object_type: ObjectType::Skey,
            input_type: Some("raw".to_string()),
            data_type: Some("SKEY".to_string()),
            data_structure: None,
            data: vec![0xAA; 32],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Key(_))),
            "expected StoreObject::Key for ObjectType::Skey"
        );
    }

    /// Classification of an unknown object whose structure hint is
    /// `"Certificate"` — yields [`StoreObject::Certificate`].
    #[test]
    fn classify_unknown_certificate_hint_produces_certificate() {
        let der_bytes = vec![0x30u8, 0x82, 0x00, 0x10];
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("Certificate".to_string()),
            data: der_bytes.clone(),
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Certificate(ref b)) if b == &der_bytes),
            "expected StoreObject::Certificate with matching bytes",
        );
    }

    /// Classification of an unknown object whose structure hint is
    /// `"CertificateList"` — yields [`StoreObject::Crl`].
    #[test]
    fn classify_unknown_crl_hint_produces_crl() {
        let der_bytes = vec![0x30u8, 0x82, 0x00, 0x20];
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("CertificateList".to_string()),
            data: der_bytes.clone(),
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Crl(ref b)) if b == &der_bytes),
            "expected StoreObject::Crl with matching bytes",
        );
    }

    /// Classification of an unknown object whose structure hint is
    /// `"SubjectPublicKeyInfo"` — yields [`StoreObject::Key`].
    #[test]
    fn classify_unknown_spki_hint_produces_key() {
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("SubjectPublicKeyInfo".to_string()),
            data: vec![0x30u8, 0x59],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Key(_))),
            "expected StoreObject::Key for SubjectPublicKeyInfo hint"
        );
    }

    /// Classification of an unknown object whose structure hint is
    /// `"PrivateKeyInfo"` — yields [`StoreObject::Key`].
    #[test]
    fn classify_unknown_pki_hint_produces_key() {
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("PrivateKeyInfo".to_string()),
            data: vec![0x30u8, 0x41],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Key(_))),
            "expected StoreObject::Key for PrivateKeyInfo hint"
        );
    }

    /// Classification of an unknown object whose structure hint is
    /// `"EncryptedPrivateKeyInfo"` — yields [`StoreObject::Key`].
    #[test]
    fn classify_unknown_epki_hint_produces_key() {
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("EncryptedPrivateKeyInfo".to_string()),
            data: vec![0x30u8, 0x82, 0x00, 0x30],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            matches!(classified, Some(StoreObject::Key(_))),
            "expected StoreObject::Key for EncryptedPrivateKeyInfo hint"
        );
    }

    /// Classification of an unknown object with no structure hint
    /// returns `None`.
    #[test]
    fn classify_unknown_without_hint_returns_none() {
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: None,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            classified.is_none(),
            "expected None for Unknown without structure hint"
        );
    }

    /// Classification of an unknown object with an unrecognized
    /// structure hint returns `None`.
    #[test]
    fn classify_unknown_with_unrecognized_hint_returns_none() {
        let decoded = DecodedObject {
            object_type: ObjectType::Unknown,
            input_type: None,
            data_type: None,
            data_structure: Some("SomeUnknownStructure".to_string()),
            data: vec![0x01, 0x02],
        };
        let classified = classify_store_object(&decoded);
        assert!(
            classified.is_none(),
            "expected None for Unknown with unrecognized hint"
        );
    }

    /// Verifies that [`descriptors()`] includes the file store and any
    /// any-to-object passthrough descriptors on every platform, and the
    /// winstore descriptor on Windows targets.
    #[test]
    fn descriptors_includes_expected_stores() {
        let descs = descriptors();

        // "file" store is always present.
        let has_file = descs.iter().any(|d| d.names.contains(&"file"));
        assert!(has_file, "'file' store descriptor must always be present");

        // Any-to-object descriptors use the name "obj".
        let has_obj = descs.iter().any(|d| d.names.contains(&"obj"));
        assert!(has_obj, "'obj' any-to-object descriptor must be present");

        // Windows-only: the winstore descriptor.
        #[cfg(target_os = "windows")]
        {
            let has_winstore = descs
                .iter()
                .any(|d| d.names.contains(&"org.openssl.winstore"));
            assert!(
                has_winstore,
                "'org.openssl.winstore' descriptor must be present on Windows"
            );
        }
    }

    /// Sanity check: the re-exported types from [`file_store`] are
    /// accessible via the crate root module.
    ///
    /// Each assignment uses the `let _: Type = value;` pattern (without a
    /// `_`-prefixed name binding) which does not trigger
    /// `clippy::no_effect_underscore_binding` and serves as a compile-time
    /// assertion that the named re-export resolves to the expected type.
    #[test]
    fn reexports_are_accessible() {
        let _: FileStore = FileStore;
        let _: ExpectedType = ExpectedType::Unspecified;
        let _: Any2ObjContext = Any2ObjContext::new();
        let _: InputFormat = InputFormat::Der;
        let _: ObjectType = ObjectType::Unknown;
    }
}
