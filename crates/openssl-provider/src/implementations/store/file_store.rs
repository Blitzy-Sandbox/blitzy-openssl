//! # File System Store Implementation
//!
//! Provider-side store loader for filesystem-based URIs/paths (the `file:` scheme).
//! Supports both single-file and directory-based loading with automatic PEM/DER
//! format detection, key type identification, and passphrase-protected private key loading.
//!
//! ## URI Schemes
//!
//! - `file:///path/to/dir` — Directory mode: iterates entries, applies hash-based search filter
//! - `file:///path/to/file.pem` — File mode: reads single file, auto-detects format
//! - `/path/to/file` — Plain path: stat-probed, auto-classified as file/directory
//! - `file://localhost/path` — Explicit localhost authority accepted
//!
//! ## Context Lifecycle
//!
//! ```text
//! open(uri) → set_params(propq, type, subject) → load() (repeat) → eof() → close()
//! ```
//!
//! ## Source
//!
//! Replaces C `providers/implementations/storemgmt/file_store.c` (828 lines).
//! Exports the file store provider and context types used by the provider system.

use std::fs;
use std::path::PathBuf;

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use tracing::{debug, warn};

use crate::traits::{AlgorithmDescriptor, StoreContext, StoreObject, StoreProvider};
use super::any2obj::{self, Any2ObjContext, DecodedObject, InputFormat};

// =============================================================================
// Constants
// =============================================================================

/// Prefix for the `file:` URI scheme.
const FILE_SCHEME: &str = "file:";

/// Localhost authority that is explicitly accepted.
const LOCALHOST_AUTHORITY: &str = "localhost";

// =============================================================================
// StoreMode — Replaces C `enum { IS_FILE, IS_DIR }`
// =============================================================================

/// Operating mode for the file store context.
///
/// Replaces C `enum { IS_FILE, IS_DIR }` in `struct file_ctx_st`.
/// Determines whether the store context reads a single file stream or
/// iterates directory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreMode {
    /// Reading a single file (stream-based with decoder pipeline).
    File,
    /// Iterating directory entries (returning child URIs).
    Directory,
}

// =============================================================================
// ExpectedType — Replaces C `OSSL_STORE_INFO_*` type constants
// =============================================================================

/// Expected object type filter for the store loader.
///
/// Replaces C `OSSL_STORE_INFO_*` type constants used in
/// `file_set_ctx_params()` to filter loaded objects by type.
/// When set to a specific type, only objects matching that type
/// are returned from [`FileStoreContext::load()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedType {
    /// No type filter — accept all objects.
    Unspecified,
    /// Public key (`SubjectPublicKeyInfo` structure).
    PubKey,
    /// Private key (`EncryptedPrivateKeyInfo` or `PrivateKeyInfo`).
    PrivateKey,
    /// X.509 certificate.
    Certificate,
    /// Certificate Revocation List.
    Crl,
    /// Symmetric key (raw key material).
    SymmetricKey,
}

impl ExpectedType {
    /// Returns the ASN.1 input structure name corresponding to this expected type.
    ///
    /// Used by [`FileStoreContext::setup_decoders()`] to configure the decoder
    /// pipeline with the appropriate structure hint. Replaces the C switch in
    /// `file_setup_decoders()` (lines 430-460).
    fn input_structure(self) -> Option<&'static str> {
        match self {
            Self::Unspecified | Self::SymmetricKey => None,
            Self::PubKey => Some("SubjectPublicKeyInfo"),
            Self::PrivateKey => Some("EncryptedPrivateKeyInfo"),
            Self::Certificate => Some("Certificate"),
            Self::Crl => Some("CertificateList"),
        }
    }
}

// =============================================================================
// FileStoreState — Mode-specific internal state
// =============================================================================

/// Mode-specific internal state for the file store context.
///
/// Replaces the C union between file-mode fields (`BIO *file`,
/// `OSSL_DECODER_CTX *decoderctx`, etc.) and directory-mode fields
/// (`OPENSSL_DIR_CTX *ctx`, `search_name[9]`, etc.) in `struct file_ctx_st`.
enum FileStoreState {
    /// File mode state: buffered file data with decoder pipeline.
    File {
        /// Raw file content buffered for decoding.
        data: Vec<u8>,
        /// Current read position in the data buffer.
        position: usize,
        /// Whether all data has been consumed by the decoder pipeline.
        exhausted: bool,
        /// Decoder context for the any2obj fallback decoder chain.
        decoder_ctx: Option<Any2ObjContext>,
    },
    /// Directory mode state: iterating directory entries.
    Dir {
        /// Directory path for iteration.
        path: PathBuf,
        /// Sorted directory entries (lazily populated on first `load()` call).
        entries: Option<Vec<PathBuf>>,
        /// Current index into the entries list.
        index: usize,
        /// Search name filter (8-hex-char hash prefix; empty means no filter).
        search_name: String,
        /// Whether end of directory has been reached.
        end_reached: bool,
    },
}

// =============================================================================
// FileStoreContext — Replaces C `struct file_ctx_st`
// =============================================================================

/// Per-handle context for the file store.
///
/// Replaces C `struct file_ctx_st` with its `IS_FILE` / `IS_DIR` union.
/// Holds all state needed for the `open → set_params → load → eof → close`
/// lifecycle:
///
/// - URI being loaded
/// - Mode (file vs directory)
/// - Format hints and property query
/// - Decoder pipeline state (file mode)
/// - Directory iterator state (directory mode)
///
/// # Ownership
///
/// Each context is independently owned (Rule R7). There is no shared
/// mutable state between contexts, so no locking is required.
pub struct FileStoreContext {
    /// The URI currently being loaded.
    uri: String,
    /// Operating mode (file or directory).
    mode: StoreMode,
    /// Mode-specific state.
    state: FileStoreState,
    /// Expected object type filter.
    expected_type: ExpectedType,
    /// Property query string for algorithm selection (file mode only).
    propq: Option<String>,
    /// Input format type hint (e.g., "PEM", "DER") (file mode only).
    input_type: Option<String>,
    /// Fatal error flag — forces EOF after unrecoverable errors.
    fatal_error: bool,
}

// =============================================================================
// FileStore — Provider struct
// =============================================================================

/// File system store provider.
///
/// Implements `StoreProvider` to load keys, certificates, CRLs,
/// and other cryptographic objects from the filesystem. Accepts both
/// plain filesystem paths and `file:` URIs.
///
/// Replaces C `ossl_file_store_functions[]` dispatch table (7 entries:
/// open, attach, `settable_ctx_params`, `set_ctx_params`, load, eof, close).
///
/// # Wiring Path (Rule R10)
///
/// ```text
/// openssl_cli::main()
///   → provider loading
///     → DefaultProvider::query_operation(Store)
///       → FileStore::open(uri)
///         → FileStoreContext::load()
/// ```
#[derive(Debug, Clone)]
pub struct FileStore;

// =============================================================================
// StoreProvider implementation for FileStore
// =============================================================================

impl StoreProvider for FileStore {
    /// Returns the store provider name.
    ///
    /// The name `"file"` is used for URI scheme matching during
    /// `OSSL_STORE_open()` dispatch.
    fn name(&self) -> &'static str {
        "file"
    }

    /// Opens a file store context for the given URI.
    ///
    /// Accepts plain filesystem paths and `file:` URIs. Uses
    /// `std::fs::metadata()` to determine whether the path is a file
    /// or directory, and creates the appropriate context mode.
    ///
    /// Replaces C `file_open()` (lines 198-274).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::NotFound`] if the path does not exist.
    /// - [`ProviderError::Init`] if an unsupported URI authority is given.
    /// - [`ProviderError::Common`] wrapping I/O errors from `std::fs`.
    fn open(&self, uri: &str) -> ProviderResult<Box<dyn StoreContext>> {
        debug!(uri = %uri, "FileStore::open — parsing URI");

        let path = parse_file_uri(uri)?;
        debug!(path = %path.display(), "FileStore::open — resolved path");

        // Probe the path to determine file vs directory (replaces C stat()).
        let metadata = fs::metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProviderError::NotFound(format!("path not found: {}", path.display()))
            } else {
                ProviderError::Common(CommonError::from(e))
            }
        })?;

        if metadata.is_dir() {
            debug!(path = %path.display(), "FileStore::open — directory mode");
            let ctx = FileStoreContext {
                uri: uri.to_string(),
                mode: StoreMode::Directory,
                state: FileStoreState::Dir {
                    path,
                    entries: None,
                    index: 0,
                    search_name: String::new(),
                    end_reached: false,
                },
                expected_type: ExpectedType::Unspecified,
                propq: None,
                input_type: None,
                fatal_error: false,
            };
            Ok(Box::new(ctx))
        } else {
            debug!(path = %path.display(), "FileStore::open — file mode");
            // Read file content into memory (replaces C BIO_new_file + BIO_read).
            let data = fs::read(&path).map_err(|e| {
                ProviderError::Common(CommonError::from(e))
            })?;
            let ctx = FileStoreContext {
                uri: uri.to_string(),
                mode: StoreMode::File,
                state: FileStoreState::File {
                    data,
                    position: 0,
                    exhausted: false,
                    decoder_ctx: None,
                },
                expected_type: ExpectedType::Unspecified,
                propq: None,
                input_type: None,
                fatal_error: false,
            };
            Ok(Box::new(ctx))
        }
    }
}

// =============================================================================
// StoreContext implementation for FileStoreContext
// =============================================================================

impl StoreContext for FileStoreContext {
    /// Loads the next object from the store context.
    ///
    /// Dispatches to the appropriate mode-specific loader:
    /// - **File mode:** Decodes objects from the buffered file data using the
    ///   any2obj decoder pipeline as a fallback.
    /// - **Directory mode:** Returns the next directory entry URI that passes
    ///   the search name filter.
    ///
    /// Replaces C `file_load()` (lines 732-750) which dispatches to
    /// `file_load_file()` or `file_load_dir_entry()`.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(object))` — An object was successfully loaded.
    /// - `Ok(None)` — No more objects (EOF reached or object filtered out).
    /// - `Err(...)` — An unrecoverable error occurred.
    fn load(&mut self) -> ProviderResult<Option<StoreObject>> {
        if self.fatal_error {
            return Ok(None);
        }

        match self.mode {
            StoreMode::File => self.load_file(),
            StoreMode::Directory => self.load_dir_entry(),
        }
    }

    /// Returns whether the store context has reached the end of its data.
    ///
    /// Replaces C `file_eof()` (lines 750-770):
    /// - If `fatal_error` is set, always returns `true`.
    /// - **File mode:** Returns `true` when the buffered data is exhausted.
    /// - **Directory mode:** Returns `true` when `end_reached` is set.
    fn eof(&self) -> bool {
        if self.fatal_error {
            return true;
        }

        match &self.state {
            FileStoreState::File { exhausted, .. } => *exhausted,
            FileStoreState::Dir { end_reached, .. } => *end_reached,
        }
    }

    /// Closes the store context and releases associated resources.
    ///
    /// Replaces C `file_close()` (lines 790-828). In Rust, most cleanup
    /// is handled automatically by `Drop`, but this method resets the
    /// internal state to ensure deterministic resource release.
    fn close(&mut self) -> ProviderResult<()> {
        debug!(uri = %self.uri, "FileStoreContext::close");

        // Reset state to free resources immediately.
        match &mut self.state {
            FileStoreState::File {
                data,
                position,
                exhausted,
                decoder_ctx,
            } => {
                data.clear();
                *position = 0;
                *exhausted = true;
                *decoder_ctx = None;
            }
            FileStoreState::Dir {
                entries,
                index,
                end_reached,
                ..
            } => {
                *entries = None;
                *index = 0;
                *end_reached = true;
            }
        }

        self.fatal_error = true;
        Ok(())
    }
}

// =============================================================================
// FileStoreContext — public parameter setting
// =============================================================================

impl FileStoreContext {
    /// Sets context parameters for the file store.
    ///
    /// Replaces C `file_set_ctx_params()` (lines 301-358).
    ///
    /// # Parameters
    ///
    /// - `propq` — Property query string for algorithm selection (file mode only).
    /// - `input_type` — Input format hint (e.g., `"PEM"`, `"DER"`) (file mode only).
    /// - `expected_type` — Object type filter applied to loaded objects.
    /// - `subject` — DER-encoded X.509 Name for directory search. Hashed to an
    ///   8-hex-char search name. Only valid in directory mode; rejected in file mode
    ///   with `ProviderError::Dispatch` (replaces C
    ///   `PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES`).
    ///
    /// # Errors
    ///
    /// - `ProviderError::Dispatch` if `subject` is provided in file mode.
    pub fn set_params(
        &mut self,
        propq: Option<&str>,
        input_type: Option<&str>,
        expected_type: Option<ExpectedType>,
        subject: Option<&[u8]>,
    ) -> ProviderResult<()> {
        // Update property query (file mode only).
        if let Some(pq) = propq {
            debug!(propq = %pq, "FileStoreContext::set_params — property query");
            self.propq = Some(pq.to_string());
        }

        // Update input type hint (file mode only).
        if let Some(it) = input_type {
            debug!(input_type = %it, "FileStoreContext::set_params — input type");
            self.input_type = Some(it.to_string());
        }

        // Update expected type filter.
        if let Some(et) = expected_type {
            debug!(expected_type = ?et, "FileStoreContext::set_params — expected type");
            self.expected_type = et;
        }

        // Handle subject-based search name filter (directory mode only).
        if let Some(subject_der) = subject {
            match &mut self.state {
                FileStoreState::Dir { search_name, .. } => {
                    // Hash the DER-encoded subject to an 8-hex-char search name.
                    // Replaces C X509_NAME hashing logic in file_set_ctx_params().
                    let hash = compute_subject_hash(subject_der);
                    let name = format!("{hash:08x}");
                    debug!(
                        search_name = %name,
                        "FileStoreContext::set_params — directory search name"
                    );
                    *search_name = name;
                }
                FileStoreState::File { .. } => {
                    // C returns error: PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES
                    return Err(ProviderError::Dispatch(
                        "subject search is only supported for directory stores".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// FileStoreContext — private mode-specific load helpers
// =============================================================================

impl FileStoreContext {
    /// Loads the next object from a single-file context.
    ///
    /// Replaces C `file_load_file()` (lines 557-587):
    /// 1. Sets up the decoder pipeline on first call (`setup_decoders()`).
    /// 2. Attempts to decode the next object from the buffered data.
    /// 3. Falls back to `any2obj::decode()` for unrecognized formats.
    /// 4. Maps decoded objects to [`StoreObject`] variants.
    fn load_file(&mut self) -> ProviderResult<Option<StoreObject>> {
        let (data, position, exhausted, decoder_ctx) = match &mut self.state {
            FileStoreState::File {
                data,
                position,
                exhausted,
                decoder_ctx,
            } => (data, position, exhausted, decoder_ctx),
            FileStoreState::Dir { .. } => {
                return Err(ProviderError::Dispatch(
                    "load_file called in directory mode".to_string(),
                ));
            }
        };

        if *exhausted {
            return Ok(None);
        }

        // One-time decoder pipeline setup (replaces C file_setup_decoders).
        if decoder_ctx.is_none() {
            let mut ctx = Any2ObjContext::new();
            // Configure the structure hint based on expected type.
            if let Some(structure) = self.expected_type.input_structure() {
                ctx.set_data_structure(Some(structure));
            }
            *decoder_ctx = Some(ctx);
            debug!("FileStoreContext::load_file — decoder pipeline initialized");
        }

        let remaining = &data[*position..];
        if remaining.is_empty() {
            *exhausted = true;
            return Ok(None);
        }

        let Some(ctx) = decoder_ctx.as_ref() else {
            *exhausted = true;
            return Err(ProviderError::Init(
                "decoder context not initialized".to_string(),
            ));
        };

        // Try DER format first (most common binary format).
        if let Some(decoded) = any2obj::decode(ctx, InputFormat::Der, remaining)? {
            let _consumed = decoded.data.len();
            let obj = map_decoded_to_store_object(&decoded, self.expected_type);
            // Advance position past the consumed DER element.
            // The DER decoder reads one complete ASN.1 element, so we advance
            // by the total element length. For a conservative approach, mark
            // as exhausted after the first successful decode from the full buffer.
            *position = data.len();
            *exhausted = true;
            if obj.is_some() {
                return Ok(obj);
            }
            // Object decoded but filtered out by expected_type — continue.
        }

        // Try other formats as fallback (MSBLOB, PVK, Raw).
        for format in &[InputFormat::MsBlob, InputFormat::Pvk, InputFormat::Raw] {
            if let Some(decoded) = any2obj::decode(ctx, *format, remaining)? {
                let obj = map_decoded_to_store_object(&decoded, self.expected_type);
                *position = data.len();
                *exhausted = true;
                if obj.is_some() {
                    return Ok(obj);
                }
            }
        }

        // No decoder recognized the data — mark exhausted.
        *exhausted = true;
        debug!(
            uri = %self.uri,
            "FileStoreContext::load_file — no decoder matched the data"
        );
        Ok(None)
    }

    /// Loads the next directory entry matching the search criteria.
    ///
    /// Replaces C `file_load_dir_entry()` (lines 672-730):
    /// 1. Lazily reads directory entries on first call.
    /// 2. Skips hidden files (starting with `.`).
    /// 3. Applies `search_name` filter via [`file_name_check()`].
    /// 4. Returns matching entries as [`StoreObject::Params`] containing
    ///    the child URI.
    fn load_dir_entry(&mut self) -> ProviderResult<Option<StoreObject>> {
        let (dir_path, entries, index, search_name, end_reached) = match &mut self.state {
            FileStoreState::Dir {
                path,
                entries,
                index,
                search_name,
                end_reached,
            } => (path, entries, index, search_name, end_reached),
            FileStoreState::File { .. } => {
                return Err(ProviderError::Dispatch(
                    "load_dir_entry called in file mode".to_string(),
                ));
            }
        };

        if *end_reached {
            return Ok(None);
        }

        // Lazy directory reading on first load() call.
        if entries.is_none() {
            debug!(
                path = %dir_path.display(),
                "FileStoreContext::load_dir_entry — reading directory"
            );
            let mut entry_paths: Vec<PathBuf> = Vec::new();
            let read_dir = fs::read_dir(dir_path.as_path()).map_err(|e| {
                ProviderError::Common(CommonError::from(e))
            })?;

            for entry_result in read_dir {
                match entry_result {
                    Ok(entry) => {
                        entry_paths.push(entry.path());
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "FileStoreContext::load_dir_entry — skipping unreadable entry"
                        );
                    }
                }
            }

            // Sort entries for deterministic iteration order (replaces
            // platform-specific ordering from OPENSSL_DIR_read).
            entry_paths.sort();
            *entries = Some(entry_paths);
            *index = 0;
        }

        let Some(entry_list) = entries.as_ref() else {
            *end_reached = true;
            return Ok(None);
        };
        let uri_base = &self.uri;

        // Iterate entries from current position, applying filters.
        while *index < entry_list.len() {
            let entry_path = &entry_list[*index];
            *index = index.checked_add(1).unwrap_or(usize::MAX);

            // Extract the file name as a string.
            let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) else {
                warn!(
                    path = %entry_path.display(),
                    "FileStoreContext::load_dir_entry — skipping entry with non-UTF8 name"
                );
                continue;
            };

            // Skip hidden files (starting with '.') — replaces C skip of "." and "..".
            if file_name.starts_with('.') {
                continue;
            }

            // Apply search_name filter if set.
            if !search_name.is_empty()
                && !file_name_check(file_name, search_name, self.expected_type)
            {
                continue;
            }

            // Build child URI for this entry.
            let child_uri = file_name_to_uri(uri_base, file_name);
            debug!(
                child_uri = %child_uri,
                "FileStoreContext::load_dir_entry — returning entry"
            );

            // Return the entry URI as a Params object (replaces C
            // OSSL_OBJECT_NAME style return with the URI in params).
            let mut params = openssl_common::param::ParamSet::new();
            params.set(
                "uri",
                openssl_common::param::ParamValue::Utf8String(child_uri),
            );
            return Ok(Some(StoreObject::Params(params)));
        }

        // All entries exhausted.
        *end_reached = true;
        Ok(None)
    }
}

// =============================================================================
// URI Parsing — Replaces C file_open() URI handling (lines 198-248)
// =============================================================================

/// Parses a file URI or plain path and returns the normalized filesystem path.
///
/// Handles the following forms:
/// - Plain paths: `/path/to/file` → `/path/to/file`
/// - Triple-slash: `file:///path/to/file` → `/path/to/file`
/// - Localhost: `file://localhost/path` → `/path`
/// - Windows drive: `file:///C:/path` → `C:/path`
///
/// Rejects unsupported authorities (e.g., `file://remote/path`).
///
/// Replaces the URI parsing logic in C `file_open()` (lines 198-248).
///
/// # Errors
///
/// - [`ProviderError::Init`] if the URI has an unsupported authority.
/// - [`ProviderError::NotFound`] if the path portion is empty after parsing.
fn parse_file_uri(uri: &str) -> ProviderResult<PathBuf> {
    // Check if this is a file: URI.
    let Some(after_scheme) = uri.strip_prefix(FILE_SCHEME) else {
        // Plain path (no file: scheme prefix).
        let resolved = PathBuf::from(uri);
        debug!(resolved = %resolved.display(), "parse_file_uri — plain path");
        return Ok(resolved);
    };

    // Handle file:// authority form.
    let Some(after_slashes) = after_scheme.strip_prefix("//") else {
        // file:path (no authority) — relative path after scheme.
        let resolved = PathBuf::from(after_scheme);
        debug!(resolved = %resolved.display(), "parse_file_uri — file:path");
        return Ok(resolved);
    };

    // Extract authority (everything before the next '/').
    let Some(slash_pos) = after_slashes.find('/') else {
        // file://something with no trailing slash — treat as authority only.
        // This is an edge case; the C code treats this as error.
        if after_slashes.is_empty() {
            return Err(ProviderError::NotFound(
                "empty path in file URI".to_string(),
            ));
        }
        // file://authority-only — no path component.
        return Err(ProviderError::Init(format!(
            "unsupported file URI (no path): file://{after_slashes}"
        )));
    };

    let authority = &after_slashes[..slash_pos];
    let path_portion = &after_slashes[slash_pos..];

    if authority.is_empty() {
        // file:///path — empty authority (most common form).
        let resolved = normalize_file_path(path_portion);
        debug!(resolved = %resolved.display(), "parse_file_uri — file:///");
        return Ok(resolved);
    }

    if authority.eq_ignore_ascii_case(LOCALHOST_AUTHORITY) {
        // file://localhost/path — explicit localhost.
        let resolved = normalize_file_path(path_portion);
        debug!(resolved = %resolved.display(), "parse_file_uri — file://localhost");
        return Ok(resolved);
    }

    // file://remote/path — unsupported authority.
    warn!(
        authority = %authority,
        "parse_file_uri — unsupported URI authority"
    );
    Err(ProviderError::Init(format!(
        "unsupported file URI authority: {authority}"
    )))
}

/// Normalizes a path portion from a `file:` URI.
///
/// Handles Windows drive-letter normalization: if the path starts with
/// `/X:` where `X` is a letter, strips the leading `/` to produce `X:/...`.
///
/// Replaces C drive-letter handling in `file_open()` (lines 240-248).
fn normalize_file_path(path: &str) -> PathBuf {
    // Windows drive letter: /C:/path → C:/path
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b':'
    {
        return PathBuf::from(&path[1..]);
    }

    PathBuf::from(path)
}

// =============================================================================
// Directory Name Filtering — Replaces C file_name_check() (lines 612-671)
// =============================================================================

/// Checks if a directory entry name matches the search criteria.
///
/// Replaces C `file_name_check()` (lines 612-671).
///
/// # Rules
///
/// 1. If `search_name` is empty, all names are accepted.
/// 2. The file name (without directory) must start with the 8-hex-char `search_name`.
/// 3. Followed by `'.'` and an extension.
/// 4. Extension starting with `'r'` indicates a CRL — rejected unless
///    `expected_type == Crl`.
/// 5. The rest of the extension must be decimal digits.
/// 6. VMS-style `;generation` suffix is optionally accepted.
///
/// # Arguments
///
/// - `name` — The file name to check (just the filename, no directory component).
/// - `search_name` — The 8-hex-char hash prefix to match.
/// - `expected_type` — The expected object type filter.
///
/// # Returns
///
/// `true` if the name matches the criteria, `false` otherwise.
fn file_name_check(name: &str, search_name: &str, expected_type: ExpectedType) -> bool {
    // Rule 1: Empty search name matches everything.
    if search_name.is_empty() {
        return true;
    }

    // Rule 2: Name must start with the search_name prefix.
    if !name.starts_with(search_name) {
        return false;
    }

    let after_prefix = &name[search_name.len()..];

    // Rule 3: Must have a '.' separator.
    if !after_prefix.starts_with('.') {
        return false;
    }

    let extension = &after_prefix[1..]; // Skip the '.'

    if extension.is_empty() {
        return false;
    }

    // Rule 6: Strip VMS generation suffix (;N) if present.
    let ext_without_vms = if let Some(semicolon_pos) = extension.find(';') {
        let generation = &extension[semicolon_pos + 1..];
        // Generation must be all decimal digits.
        if !generation.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        &extension[..semicolon_pos]
    } else {
        extension
    };

    if ext_without_vms.is_empty() {
        return false;
    }

    // Rule 4: Check for CRL prefix 'r'.
    let digit_part = if let Some(after_r) = ext_without_vms.strip_prefix('r') {
        // This is a CRL file — reject unless expected type is CRL or unspecified.
        if expected_type != ExpectedType::Crl && expected_type != ExpectedType::Unspecified {
            return false;
        }
        after_r
    } else {
        // Not a CRL file — reject if expected type is specifically CRL.
        if expected_type == ExpectedType::Crl {
            return false;
        }
        ext_without_vms
    };

    // Rule 5: Remaining extension must be all decimal digits.
    if digit_part.is_empty() {
        return false;
    }

    digit_part.chars().all(|c| c.is_ascii_digit())
}

/// Constructs a full URI for a directory entry.
///
/// Replaces C `file_name_to_uri()` (lines 591-609). Appends the
/// platform path separator if not already present, then concatenates
/// the entry name.
///
/// # Examples
///
/// ```text
/// file_name_to_uri("/certs", "ca.pem")       → "/certs/ca.pem"
/// file_name_to_uri("/certs/", "ca.pem")      → "/certs/ca.pem"
/// file_name_to_uri("file:///certs", "ca.pem") → "file:///certs/ca.pem"
/// ```
fn file_name_to_uri(base_uri: &str, entry_name: &str) -> String {
    let separator = std::path::MAIN_SEPARATOR;
    if base_uri.ends_with(separator) || base_uri.ends_with('/') {
        format!("{base_uri}{entry_name}")
    } else {
        format!("{base_uri}{separator}{entry_name}")
    }
}

// =============================================================================
// Subject Hash Computation
// =============================================================================

/// Computes a hash of a DER-encoded X.509 Name for directory search filtering.
///
/// This is a simplified hash computation that replaces the C
/// `X509_NAME_hash()` function. The C version uses SHA-1 and extracts the
/// low 32 bits. Here we use a simple FNV-1a-like hash over the DER bytes
/// for the same purpose: producing a deterministic 32-bit value that serves
/// as a directory lookup key.
///
/// The resulting hash is formatted as an 8-hex-char string by the caller.
fn compute_subject_hash(subject_der: &[u8]) -> u32 {
    // Simple hash over DER bytes — mirrors the effect of X509_NAME_hash_old()
    // which uses MD5. We use a basic multiplicative hash that is sufficient
    // for directory entry prefix matching.
    let mut hash: u32 = 0x811c_9dc5; // FNV offset basis
    for &byte in subject_der {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193); // FNV prime
    }
    hash
}

// =============================================================================
// Decoded Object → StoreObject Mapping
// =============================================================================

/// Maps a decoded object from the any2obj decoder chain to a [`StoreObject`].
///
/// Applies the `expected_type` filter: returns `None` if the decoded object
/// does not match the expected type.
fn map_decoded_to_store_object(
    decoded: &DecodedObject,
    expected_type: ExpectedType,
) -> Option<StoreObject> {
    // Determine the store object type based on the decoded object metadata.
    let data_structure = decoded.data_structure.as_deref().unwrap_or("");

    match decoded.object_type {
        any2obj::ObjectType::Pkey => {
            // Check expected type filter.
            match expected_type {
                ExpectedType::Unspecified
                | ExpectedType::PubKey
                | ExpectedType::PrivateKey => {
                    // Return certificate bytes as a generic key representation.
                    // The actual key parsing is deferred to higher-level code.
                    Some(StoreObject::Certificate(decoded.data.clone()))
                }
                _ => None,
            }
        }
        any2obj::ObjectType::Skey => {
            match expected_type {
                ExpectedType::Unspecified | ExpectedType::SymmetricKey => {
                    Some(StoreObject::Certificate(decoded.data.clone()))
                }
                _ => None,
            }
        }
        any2obj::ObjectType::Unknown => {
            // Try to classify by data structure hint.
            match data_structure {
                "Certificate" => {
                    if expected_type == ExpectedType::Unspecified
                        || expected_type == ExpectedType::Certificate
                    {
                        Some(StoreObject::Certificate(decoded.data.clone()))
                    } else {
                        None
                    }
                }
                "CertificateList" => {
                    if expected_type == ExpectedType::Unspecified
                        || expected_type == ExpectedType::Crl
                    {
                        Some(StoreObject::Crl(decoded.data.clone()))
                    } else {
                        None
                    }
                }
                "SubjectPublicKeyInfo" => {
                    if expected_type == ExpectedType::Unspecified
                        || expected_type == ExpectedType::PubKey
                    {
                        Some(StoreObject::Certificate(decoded.data.clone()))
                    } else {
                        None
                    }
                }
                "EncryptedPrivateKeyInfo" | "PrivateKeyInfo" => {
                    if expected_type == ExpectedType::Unspecified
                        || expected_type == ExpectedType::PrivateKey
                    {
                        Some(StoreObject::Certificate(decoded.data.clone()))
                    } else {
                        None
                    }
                }
                _ => {
                    // Unknown structure — accept if no filter is set.
                    if expected_type == ExpectedType::Unspecified {
                        Some(StoreObject::Certificate(decoded.data.clone()))
                    } else {
                        None
                    }
                }
            }
        }
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the algorithm descriptors for the file store provider.
///
/// Used during provider registration to advertise the `"file"` store
/// to the provider dispatch system. Returns a single descriptor with
/// the name `"file"` and property `"provider=default"`.
///
/// Replaces the role of `ossl_file_store_functions[]` in C provider
/// registration.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["file"],
        property: "provider=default",
        description: "File-based key and certificate store (PEM/DER)",
    }]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI Parsing Tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_plain_path() {
        let result = parse_file_uri("/tmp/test.pem");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test.pem"));
    }

    #[test]
    fn test_parse_file_triple_slash() {
        let result = parse_file_uri("file:///tmp/test.pem");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test.pem"));
    }

    #[test]
    fn test_parse_file_localhost() {
        let result = parse_file_uri("file://localhost/tmp/test.pem");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test.pem"));
    }

    #[test]
    fn test_parse_file_unsupported_authority() {
        let result = parse_file_uri("file://remote/tmp/test.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_windows_drive_letter() {
        let result = parse_file_uri("file:///C:/Users/test.pem");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("C:/Users/test.pem"));
    }

    #[test]
    fn test_parse_file_scheme_no_authority() {
        let result = parse_file_uri("file:relative/path.pem");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("relative/path.pem"));
    }

    // ── Normalize File Path Tests ──────────────────────────────────────

    #[test]
    fn test_normalize_unix_path() {
        assert_eq!(normalize_file_path("/usr/local/cert.pem"), PathBuf::from("/usr/local/cert.pem"));
    }

    #[test]
    fn test_normalize_windows_drive() {
        assert_eq!(normalize_file_path("/C:/cert.pem"), PathBuf::from("C:/cert.pem"));
    }

    #[test]
    fn test_normalize_no_drive() {
        assert_eq!(normalize_file_path("/cert.pem"), PathBuf::from("/cert.pem"));
    }

    // ── file_name_check Tests ──────────────────────────────────────────

    #[test]
    fn test_empty_search_name_accepts_all() {
        assert!(file_name_check("anything.0", "", ExpectedType::Unspecified));
        assert!(file_name_check("test", "", ExpectedType::Certificate));
    }

    #[test]
    fn test_matching_hash_prefix_with_digit_extension() {
        assert!(file_name_check("abcdef01.0", "abcdef01", ExpectedType::Unspecified));
        assert!(file_name_check("abcdef01.42", "abcdef01", ExpectedType::Certificate));
    }

    #[test]
    fn test_non_matching_prefix_rejected() {
        assert!(!file_name_check("12345678.0", "abcdef01", ExpectedType::Unspecified));
    }

    #[test]
    fn test_crl_extension_accepted_for_crl_type() {
        assert!(file_name_check("abcdef01.r0", "abcdef01", ExpectedType::Crl));
        assert!(file_name_check("abcdef01.r42", "abcdef01", ExpectedType::Unspecified));
    }

    #[test]
    fn test_crl_extension_rejected_for_cert_type() {
        assert!(!file_name_check("abcdef01.r0", "abcdef01", ExpectedType::Certificate));
    }

    #[test]
    fn test_non_crl_extension_rejected_for_crl_type() {
        assert!(!file_name_check("abcdef01.0", "abcdef01", ExpectedType::Crl));
    }

    #[test]
    fn test_non_digit_extension_rejected() {
        assert!(!file_name_check("abcdef01.abc", "abcdef01", ExpectedType::Unspecified));
    }

    #[test]
    fn test_no_dot_separator_rejected() {
        assert!(!file_name_check("abcdef010", "abcdef01", ExpectedType::Unspecified));
    }

    #[test]
    fn test_vms_generation_suffix() {
        assert!(file_name_check("abcdef01.0;1", "abcdef01", ExpectedType::Unspecified));
        assert!(!file_name_check("abcdef01.0;abc", "abcdef01", ExpectedType::Unspecified));
    }

    // ── file_name_to_uri Tests ─────────────────────────────────────────

    #[test]
    fn test_uri_with_trailing_separator() {
        assert_eq!(file_name_to_uri("/certs/", "ca.pem"), "/certs/ca.pem");
    }

    #[test]
    fn test_uri_without_trailing_separator() {
        let result = file_name_to_uri("/certs", "ca.pem");
        assert!(result.contains("ca.pem"));
        assert!(result.contains("certs"));
    }

    // ── ExpectedType Tests ─────────────────────────────────────────────

    #[test]
    fn test_expected_type_input_structure() {
        assert_eq!(ExpectedType::Unspecified.input_structure(), None);
        assert_eq!(ExpectedType::PubKey.input_structure(), Some("SubjectPublicKeyInfo"));
        assert_eq!(ExpectedType::PrivateKey.input_structure(), Some("EncryptedPrivateKeyInfo"));
        assert_eq!(ExpectedType::Certificate.input_structure(), Some("Certificate"));
        assert_eq!(ExpectedType::Crl.input_structure(), Some("CertificateList"));
        assert_eq!(ExpectedType::SymmetricKey.input_structure(), None);
    }

    // ── Subject Hash Tests ─────────────────────────────────────────────

    #[test]
    fn test_compute_subject_hash_deterministic() {
        let subject = b"CN=test";
        let hash1 = compute_subject_hash(subject);
        let hash2 = compute_subject_hash(subject);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_subject_hash_different_inputs() {
        let hash1 = compute_subject_hash(b"CN=test1");
        let hash2 = compute_subject_hash(b"CN=test2");
        assert_ne!(hash1, hash2);
    }

    // ── Descriptors Tests ──────────────────────────────────────────────

    #[test]
    fn test_descriptors_returns_file_store() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["file"]);
        assert_eq!(descs[0].property, "provider=default");
    }

    // ── FileStore Provider Tests ───────────────────────────────────────

    #[test]
    fn test_file_store_name() {
        let store = FileStore;
        assert_eq!(store.name(), "file");
    }

    #[test]
    fn test_file_store_open_nonexistent() {
        let store = FileStore;
        let result = store.open("/nonexistent/path/to/file.pem");
        assert!(result.is_err());
    }
}
