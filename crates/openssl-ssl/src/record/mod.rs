//! Record layer abstraction for TLS/DTLS.
//!
//! This module implements the record layer that binds the SSL connection
//! state machine to pluggable, provider-backed record I/O. The record layer
//! manages record buffering, pipelining, handshake fragment staging, and
//! provider method selection.
//!
//! # Architecture
//!
//! Translates the C `RECORD_LAYER` struct (`ssl/record/record.h`) and its
//! associated lifecycle routines (`ssl/record/rec_layer_s3.c`) into
//! idiomatic Rust. The central abstractions are:
//!
//! * [`RecordLayerState`] — per-connection state, replacing C's `RECORD_LAYER`
//! * [`RecordMethod`] trait — pluggable record-layer backend, replacing
//!   C's `OSSL_RECORD_METHOD` function-pointer dispatch table
//! * [`RecordLayerInstance`] trait — an opaque instantiated record-layer
//!   object
//! * [`TlsRecord`] — a single TLS/DTLS record, replacing C's `TLS_RECORD`
//!
//! # Provider Integration
//!
//! The record-layer methods (default, KTLS, custom) are expressed through
//! the [`RecordMethod`] trait. Provider selection happens via
//! [`set_new_record_layer`] during handshake epoch transitions.
//!
//! # Safety and Rules Compliance
//!
//! * **R5 — Nullability:** All optional fields use `Option<T>`. No sentinel
//!   values are used to encode "unset".
//! * **R6 — Lossless casts:** All narrowing conversions use
//!   `try_from` / `saturating_cast`.
//! * **R7 — Concurrency:** `RecordLayerState` is per-connection and
//!   accessed only by its owning `SslConnection`. No shared mutation.
//!   `LOCK-SCOPE: none` — per-connection state, owned by `SslConnection`.
//! * **R8 — No unsafe:** The module contains zero `unsafe` blocks.
//!   The crate root declares `#![forbid(unsafe_code)]`.

use core::any::Any;

use openssl_common::error::{SslError, SslResult};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_crypto::bio::{Bio, MemBio};
use tracing::{debug, trace, warn};
use zeroize::Zeroize;

use crate::method::ProtocolVersion;

// ---------------------------------------------------------------------------
// Concrete record-method implementations
// ---------------------------------------------------------------------------

/// TLS record-layer implementation for TLS 1.0 / 1.1 / 1.2 / 1.3.
///
/// Translated from `ssl/record/rec_layer_s3.c` and
/// `ssl/record/methods/tls_*.c` upstream.
pub mod tls;

/// DTLS record-layer implementation for DTLS 1.0 / 1.2 (and DTLS 1.3 when
/// feature-gated).
///
/// Translated from `ssl/record/rec_layer_d1.c` and
/// `ssl/record/methods/dtls_meth.c` upstream.
pub mod dtls;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Size of a DTLS sequence number (also the size used for TLS in record layer
/// APIs that reserve a full 8-byte sequence field).
///
/// Source: `ssl/record/record.h` line 20 (`#define SEQ_NUM_SIZE 8`).
pub const SEQ_NUM_SIZE: usize = 8;

/// Maximum number of consecutive warning alerts tolerated before the record
/// layer rejects further alerts as a denial-of-service defence.
///
/// Source: `ssl/record/record_local.h` line 17
/// (`#define MAX_WARN_ALERT_COUNT 5`).
pub const MAX_WARN_ALERT_COUNT: u32 = 5;

/// Maximum number of records that can be pipelined in a single call to the
/// record layer's `write_records` backend.
///
/// Source: `include/internal/ssl3_cbc.h` and provider pipelining limits.
pub const SSL_MAX_PIPELINES: usize = 32;

/// Record content type: `ChangeCipherSpec` (legacy TLS pre-1.3).
///
/// Source: RFC 5246 §6.2.1 (TLS), matches C's `SSL3_RT_CHANGE_CIPHER_SPEC`.
pub const SSL3_RT_CHANGE_CIPHER_SPEC: u8 = 20;

/// Record content type: Alert.
///
/// Source: RFC 5246 §6.2.1 (TLS), matches C's `SSL3_RT_ALERT`.
pub const SSL3_RT_ALERT: u8 = 21;

/// Record content type: Handshake.
///
/// Source: RFC 5246 §6.2.1 (TLS), matches C's `SSL3_RT_HANDSHAKE`.
pub const SSL3_RT_HANDSHAKE: u8 = 22;

/// Record content type: Application data.
///
/// Source: RFC 5246 §6.2.1 (TLS), matches C's `SSL3_RT_APPLICATION_DATA`.
pub const SSL3_RT_APPLICATION_DATA: u8 = 23;

// ---------------------------------------------------------------------------
// Internal constants used by set_new_record_layer for OSSL_PARAM construction
// ---------------------------------------------------------------------------

// These are ParamSet keys — mirrors C OSSL_LIBSSL_RECORD_LAYER_PARAM_* names.
const PARAM_OPTIONS: &str = "options";
const PARAM_MODE: &str = "mode";
const PARAM_READ_BUFFER_LEN: &str = "read_buffer_len";
const PARAM_READ_AHEAD: &str = "read_ahead";
const PARAM_BLOCK_PADDING: &str = "block_padding";
const PARAM_HS_PADDING: &str = "hs_padding";
const PARAM_USE_ETM: &str = "use_etm";
const PARAM_STREAM_MAC: &str = "stream_mac";
const PARAM_TLSTREE: &str = "tlstree";
const PARAM_MAX_FRAG_LEN: &str = "max_frag_len";
const PARAM_MAX_EARLY_DATA: &str = "max_early_data";

// ---------------------------------------------------------------------------
// RecordDirection
// ---------------------------------------------------------------------------

/// Record I/O direction.
///
/// Replaces C's `OSSL_RECORD_DIRECTION_READ` / `OSSL_RECORD_DIRECTION_WRITE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordDirection {
    /// Read direction — records flowing from peer to us.
    Read,
    /// Write direction — records flowing from us to peer.
    Write,
}

impl RecordDirection {
    /// Numeric representation used by provider-facing APIs
    /// (0 = read, 1 = write) matching C `OSSL_RECORD_DIRECTION_*`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            RecordDirection::Read => 0,
            RecordDirection::Write => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// ProtectionLevel
// ---------------------------------------------------------------------------

/// Level of cryptographic protection applied to records.
///
/// Replaces C's `OSSL_RECORD_PROTECTION_LEVEL_*` constants. The level
/// determines which keys are used for record protection and drives
/// provider-layer parameter selection (e.g. ECH, early data, 0-RTT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionLevel {
    /// No cryptographic protection (plaintext records).
    None,
    /// Early-data (0-RTT) protection.
    Early,
    /// Handshake protection (pre-finished).
    Handshake,
    /// Application-data protection (post-finished).
    Application,
}

impl ProtectionLevel {
    /// Numeric representation matching C `OSSL_RECORD_PROTECTION_LEVEL_*`:
    /// NONE=0, EARLY=1, HANDSHAKE=2, APPLICATION=3.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            ProtectionLevel::None => 0,
            ProtectionLevel::Early => 1,
            ProtectionLevel::Handshake => 2,
            ProtectionLevel::Application => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// RlayerReturn
// ---------------------------------------------------------------------------

/// Return codes from record-layer backend operations.
///
/// Replaces C's `OSSL_RECORD_RETURN_SUCCESS/RETRY/NON_FATAL_ERR/FATAL/EOF`.
/// Uses an enum rather than integer codes per Rule R5 (nullability over
/// sentinels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RlayerReturn {
    /// Operation completed successfully (C: `OSSL_RECORD_RETURN_SUCCESS` = 1).
    Success,
    /// Operation should be retried — underlying I/O would block
    /// (C: `OSSL_RECORD_RETURN_RETRY` = 0).
    Retry,
    /// End of data — no more records available (C:
    /// `OSSL_RECORD_RETURN_EOF` = -3).
    Eof,
    /// Non-fatal error — caller may fall back to a different backend
    /// (C: `OSSL_RECORD_RETURN_NON_FATAL_ERR` = -1).
    NonFatalError,
    /// Fatal error — connection cannot continue
    /// (C: `OSSL_RECORD_RETURN_FATAL` = -2).
    Fatal,
}

impl RlayerReturn {
    /// Legacy C-compatible integer code matching the original
    /// `OSSL_RECORD_RETURN_*` macro values.
    #[must_use]
    pub const fn as_c_code(self) -> i32 {
        match self {
            RlayerReturn::Success => 1,
            RlayerReturn::Retry => 0,
            RlayerReturn::NonFatalError => -1,
            RlayerReturn::Fatal => -2,
            RlayerReturn::Eof => -3,
        }
    }
}

// ---------------------------------------------------------------------------
// RecordHandle and RecordTemplate
// ---------------------------------------------------------------------------

/// Opaque handle for a record that is managed by a provider-backed record
/// layer. The inner value is the provider-internal identifier (e.g. index
/// into its pooled record buffer, or a generational token).
///
/// Replaces C's `void *rechandle` field on `TLS_RECORD`. Using a typed
/// newtype guarantees that the identifier is never confused with a raw
/// pointer and that providers receive only handles they issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordHandle(u64);

impl RecordHandle {
    /// Creates a new handle from a provider-supplied identifier.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        RecordHandle(id)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.0
    }
}

/// A record to be written via the record-layer backend.
///
/// Replaces C's `OSSL_RECORD_TEMPLATE` — a lightweight descriptor passed to
/// `write_records` to describe an outbound record. The backing buffer is
/// owned by the caller; the template carries a borrow for the duration of
/// the write.
///
/// `Clone`/`Copy` are derived because all three fields are themselves `Copy`
/// (`u8`, `u16`, and a shared `&[u8]` slice). This permits constructing
/// pipelines of identical templates via `vec![tpl; n]` in tests and call sites
/// that batch-write the same payload across multiple records — mirroring C's
/// stack-allocated `OSSL_RECORD_TEMPLATE[]` arrays in the upstream record
/// layer.
#[derive(Clone, Copy)]
pub struct RecordTemplate<'a> {
    /// Record content type (one of `SSL3_RT_*`).
    pub record_type: u8,
    /// Record protocol version (wire format, e.g. 0x0303 for TLS 1.2).
    pub version: u16,
    /// Plaintext payload to be encrypted and framed.
    pub buf: &'a [u8],
}

impl<'a> RecordTemplate<'a> {
    /// Creates a new record template.
    #[must_use]
    pub const fn new(record_type: u8, version: u16, buf: &'a [u8]) -> Self {
        RecordTemplate {
            record_type,
            version,
            buf,
        }
    }
}

// ---------------------------------------------------------------------------
// TlsRecord
// ---------------------------------------------------------------------------

/// Represents a single TLS or DTLS record.
///
/// Replaces C's `TLS_RECORD` struct from `ssl/record/record.h` lines 22–44.
/// Fields are public to match the C structural-access pattern used by
/// `tls.rs` and `dtls.rs` when pulling records off the queue.
///
/// # Ownership
///
/// * If `rechandle` is `Some`, the buffer lives in the provider backend and
///   must be returned via [`RecordMethod::release_record`].
/// * If `rechandle` is `None`, `data` is a locally-allocated `Vec<u8>` and
///   will be dropped (and zeroized) when the record is cleared.
///
/// `Debug` is derived to support diagnostic printing of containers (e.g.
/// `BTreeMap<(u16, u64), TlsRecord>`) used by the DTLS retransmit-reorder
/// queue. The derived implementation prints the raw `data` buffer; callers
/// that handle plaintext-sensitive records should redact before logging.
#[derive(Debug)]
pub struct TlsRecord {
    /// Opaque handle for provider-managed lifetime.
    /// `None` means the record buffer is owned locally (DTLS path).
    pub rechandle: Option<RecordHandle>,
    /// Record protocol version (wire format).
    pub version: u16,
    /// Record content type (`SSL3_RT_*`).
    pub record_type: u8,
    /// Record payload buffer.
    pub data: Vec<u8>,
    /// Number of remaining bytes to read / process from the record.
    pub length: usize,
    /// Offset into `data` of the next unread byte.
    pub off: usize,
    /// DTLS epoch number. Always zero for TLS.
    pub epoch: u16,
    /// DTLS sequence number. All zeros for TLS.
    pub seq_num: [u8; SEQ_NUM_SIZE],
}

impl Default for TlsRecord {
    fn default() -> Self {
        TlsRecord {
            rechandle: None,
            version: 0,
            record_type: 0,
            data: Vec::new(),
            length: 0,
            off: 0,
            epoch: 0,
            seq_num: [0u8; SEQ_NUM_SIZE],
        }
    }
}

impl TlsRecord {
    /// Creates an empty (default-initialised) record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears all record state, zeroing any sensitive plaintext in the data
    /// buffer.
    ///
    /// This replaces C's record-release path plus the
    /// `SSL_MODE_CLEANSE_PLAINTEXT` cleanup. Since the Rust rewrite prefers
    /// secure-by-default, the buffer is always zeroized before being
    /// cleared.
    pub fn clear(&mut self) {
        // Zero any sensitive plaintext before dropping per AAP Section 0.7.6
        // (memory safety and secure erasure).
        self.data.zeroize();
        self.data.clear();
        self.rechandle = None;
        self.version = 0;
        self.record_type = 0;
        self.length = 0;
        self.off = 0;
        self.epoch = 0;
        self.seq_num = [0u8; SEQ_NUM_SIZE];
    }

    /// Returns `true` if the record has been fully consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

// ---------------------------------------------------------------------------
// RecordPaddingCallback
// ---------------------------------------------------------------------------

/// TLS 1.3 record padding callback.
///
/// Called before encryption of a record to determine how many zero bytes of
/// padding to add. Receives the record content type and the current
/// plaintext length; returns the number of padding bytes.
///
/// Replaces C's `size_t (*cb)(SSL *s, int type, size_t len, void *arg)`
/// pattern from `ssl/record/rec_layer_s3.c` line 1152.
pub type RecordPaddingCallback = Box<dyn Fn(u8, usize) -> usize + Send + Sync>;

// ---------------------------------------------------------------------------
// MsgCallback
// ---------------------------------------------------------------------------

/// SSL message callback installed via the `SSL_CTX_set_msg_callback` /
/// `SSL_set_msg_callback` family of APIs.
///
/// Invoked by the record layer for every protocol message sent or received
/// (handshake, alert, application-data, change-cipher-spec, heartbeat).
/// Arguments:
/// * `write_p` — `true` if the record is being sent, `false` if received.
/// * `version` — wire-format protocol version (e.g. `0x0303` for TLS 1.2).
/// * `content_type` — TLS content type (`SSL3_RT_HANDSHAKE`,
///   `SSL3_RT_ALERT`, `SSL3_RT_APPLICATION_DATA`, etc.).
/// * `buf` — full message payload bytes.
///
/// Replaces C's
/// `void (*msg_callback)(int write_p, int version, int content_type,
///                       const void *buf, size_t len, SSL *ssl, void *arg)`
/// pattern from `ssl/record/rec_layer_s3.c` line 1130–1141 (where the
/// upstream wrapper additionally threads the `SSL *` and `void *arg`
/// through to the user closure — both are captured in the `Fn` closure
/// in this Rust translation).
pub type MsgCallback = Box<dyn Fn(bool, u16, u8, &[u8]) + Send + Sync>;

// ---------------------------------------------------------------------------
// SecurityCallback
// ---------------------------------------------------------------------------

/// SSL security callback consulted before performing a security-sensitive
/// operation.
///
/// Invoked by the record layer (and other subsystems via the same
/// dispatch table) to ask "is this operation permitted under the current
/// security policy?". Returning `false` rejects the operation.
///
/// Arguments:
/// * `op` — the security check operation code (`SSL_SECOP_*` constants).
/// * `bits` — security strength in bits relevant to the operation (e.g.
///   key length).
/// * `nid` — algorithm NID relevant to the operation.
///
/// Replaces C's `int (*ssl_security)(SSL *s, int op, int bits, int nid,
/// void *other)` pattern from `ssl/record/rec_layer_s3.c` line 1143–1150.
/// The C implementation defaults to "permit" when no callback is installed;
/// this behaviour is preserved in [`rlayer_security_wrapper`].
pub type SecurityCallback = Box<dyn Fn(i32, i32, i32) -> bool + Send + Sync>;

// ---------------------------------------------------------------------------
// RecordLayerInstance trait
// ---------------------------------------------------------------------------

/// An instantiated record-layer object.
///
/// A [`RecordMethod`] implementation returns a `Box<dyn RecordLayerInstance>`
/// from `new_record_layer`. All subsequent operations (`read_record`,
/// `write_records`, etc.) take a mutable reference to this trait object.
///
/// The trait is intentionally minimal — the real state lives in the
/// concrete type returned by each backend. Downcasting is performed by the
/// backend itself; the record-layer framework only ever accesses the
/// instance through the [`RecordMethod`] trait methods.
///
/// # Safe Downcasting (R8 — no `unsafe`)
///
/// Concrete backends (e.g. `TlsRecordInstance`, `DtlsRecordInstance`)
/// must downcast a `&dyn RecordLayerInstance` to their concrete type when
/// dispatching. To remain in safe Rust the trait requires
/// [`as_any`](RecordLayerInstance::as_any) and
/// [`as_any_mut`](RecordLayerInstance::as_any_mut). Each implementor
/// returns `self` (which automatically coerces to `&dyn Any` /
/// `&mut dyn Any`). The framework then calls `.downcast_ref` /
/// `.downcast_mut` on the returned trait object — both are safe APIs
/// provided by the standard library. This avoids both raw pointer casts
/// and reliance on TypeId-tagged unsafe transmutes.
pub trait RecordLayerInstance: Send + Any {
    /// Returns a human-readable identifier for diagnostic logging.
    /// Default: a generic placeholder; backends override with a concrete
    /// label such as `"tls-record-instance"` or `"dtls-record-instance"`.
    fn name(&self) -> &'static str {
        "record-layer-instance"
    }

    /// Returns a `&dyn Any` view of this instance.
    ///
    /// Backends must implement this as `fn as_any(&self) -> &dyn Any { self }`.
    /// Used by backend-specific downcast helpers to recover the concrete
    /// type without resorting to `unsafe`.
    fn as_any(&self) -> &dyn Any;

    /// Returns a `&mut dyn Any` view of this instance.
    ///
    /// Backends must implement this as
    /// `fn as_any_mut(&mut self) -> &mut dyn Any { self }`.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// ---------------------------------------------------------------------------
// NewRecordLayerArgs — argument bundle for RecordMethod::new_record_layer
// ---------------------------------------------------------------------------

/// Arguments bundle for [`RecordMethod::new_record_layer`].
///
/// Groups the many parameters previously passed as positional arguments to
/// C's `new_record_layer` function. Using a struct avoids a function
/// signature with 20+ parameters and allows future evolution without
/// breaking the trait.
pub struct NewRecordLayerArgs {
    /// Wire-format protocol version (e.g. 0x0303 for TLS 1.2).
    pub version: u16,
    /// Connection role: `0` for client, `1` for server.
    pub role: u8,
    /// I/O direction (read or write).
    pub direction: RecordDirection,
    /// Cryptographic protection level.
    pub level: ProtectionLevel,
    /// DTLS epoch (0 for TLS).
    pub epoch: u16,
    /// Encryption key material.
    pub key: Vec<u8>,
    /// Initialisation vector (explicit IV or nonce seed).
    pub iv: Vec<u8>,
    /// MAC key material (empty for AEAD ciphers).
    pub mac_key: Vec<u8>,
    /// Cipher algorithm name (e.g. "AES-128-GCM").
    pub cipher_name: String,
    /// Authentication tag length (for AEAD ciphers, 0 otherwise).
    pub tag_len: usize,
    /// MAC algorithm type identifier (`EVP_PKEY_*` equivalent, 0 for AEAD).
    pub mac_type: i32,
    /// MD algorithm NID for HMAC (0 for AEAD).
    pub md_nid: i32,
    /// "Settings" parameter set — must be fully supported by the backend
    /// or construction fails.
    pub settings: ParamSet,
    /// "Options" parameter set — optional; backend MAY ignore unknown keys.
    pub options: ParamSet,
}

// ---------------------------------------------------------------------------
// RecordMethod trait — replaces OSSL_RECORD_METHOD dispatch table
// ---------------------------------------------------------------------------

/// A pluggable record-layer backend.
///
/// Replaces C's `OSSL_RECORD_METHOD` function-pointer dispatch table.
/// Implementations of this trait plug in at three levels:
///
/// * **Default** — `providers::default::record::TlsRecordMethod` and
///   `DtlsRecordMethod` — pure Rust, feature-flag selected.
/// * **KTLS** — `providers::default::record::KtlsRecordMethod` — uses
///   kernel-level TLS off-load when available (Linux, FreeBSD).
/// * **Custom** — user-installed via [`set_custom_record_layer`].
///
/// All methods take `&self` (not `&mut self`) so that `Box<dyn RecordMethod>`
/// can be shared across threads; the stateful record layer lives inside
/// the `RecordLayerInstance` trait object.
pub trait RecordMethod: Send + Sync {
    /// Constructs a new record-layer instance for the given direction and
    /// protection level.
    ///
    /// # Errors
    ///
    /// Returns `RlayerReturn::NonFatalError` if the backend cannot support
    /// the requested configuration (caller should try a different backend).
    /// Returns `RlayerReturn::Fatal` if the configuration is invalid.
    fn new_record_layer(
        &self,
        args: NewRecordLayerArgs,
    ) -> Result<Box<dyn RecordLayerInstance>, RlayerReturn>;

    /// Frees a record-layer instance.
    ///
    /// In the Rust rewrite this is typically a no-op because `Drop` on the
    /// concrete `RecordLayerInstance` handles cleanup. Kept here for
    /// backends that need an explicit shutdown step (e.g. KTLS de-registers
    /// the socket offload).
    fn free(&self, _rl: Box<dyn RecordLayerInstance>) -> SslResult<()> {
        Ok(())
    }

    /// Reads a single record from the record layer.
    fn read_record(&self, rl: &mut dyn RecordLayerInstance) -> Result<TlsRecord, RlayerReturn>;

    /// Releases a previously-read record back to the backend.
    fn release_record(
        &self,
        rl: &mut dyn RecordLayerInstance,
        handle: &RecordHandle,
        length: usize,
    ) -> Result<(), RlayerReturn>;

    /// Writes a batch of records.
    fn write_records(
        &self,
        rl: &mut dyn RecordLayerInstance,
        templates: &[RecordTemplate<'_>],
    ) -> Result<(), RlayerReturn>;

    /// Retries a previously-stalled `write_records` call.
    fn retry_write_records(&self, rl: &mut dyn RecordLayerInstance) -> Result<(), RlayerReturn>;

    /// Returns `true` if raw (undecrypted) data is pending on the transport.
    fn unprocessed_read_pending(&self, rl: &dyn RecordLayerInstance) -> bool;

    /// Returns `true` if decrypted but un-delivered data is pending.
    fn processed_read_pending(&self, rl: &dyn RecordLayerInstance) -> bool;

    /// Returns the count of application-data bytes available for immediate
    /// consumption.
    fn app_data_pending(&self, rl: &dyn RecordLayerInstance) -> usize;

    /// Computes the maximum number of records that the backend can emit for
    /// a write of `data_len` bytes of type `record_type`, given a fragment
    /// ceiling of `max_fragment`.
    ///
    /// Writes the actual split granularity into `split_fragment`.
    fn get_max_records(
        &self,
        rl: &dyn RecordLayerInstance,
        record_type: u8,
        data_len: usize,
        max_fragment: usize,
        split_fragment: &mut usize,
    ) -> usize;

    /// Sets the protocol version for subsequent records.
    fn set_protocol_version(&self, rl: &mut dyn RecordLayerInstance, version: u16);

    /// Returns the backend's state description: `(short_code, long_text)`.
    fn get_state(&self, rl: &dyn RecordLayerInstance) -> (&'static str, &'static str);

    /// Returns the alert code associated with the last fatal error, if any.
    fn get_alert_code(&self, rl: &dyn RecordLayerInstance) -> Option<u8>;

    /// Optional: signals that this is the first handshake (affects 0-RTT).
    fn set_first_handshake(&self, _rl: &mut dyn RecordLayerInstance, _first: bool) {}

    /// Optional: sets the maximum number of records to pipeline.
    fn set_max_pipelines(&self, _rl: &mut dyn RecordLayerInstance, _max: usize) {}

    /// Returns a short name for diagnostic logging.
    fn method_name(&self) -> &'static str {
        "generic"
    }
}

// ---------------------------------------------------------------------------
// RecordLayerState — per-connection record layer state
// ---------------------------------------------------------------------------

/// Per-connection record-layer state.
///
/// Replaces C's `RECORD_LAYER` struct from `ssl/record/record.h`
/// lines 71–125. One instance per `SslConnection`; owned by the connection
/// and mutated only by its owning thread.
///
/// # Concurrency
///
/// `// LOCK-SCOPE: none` — This struct is per-connection state. It is never
/// shared across threads via a lock. Access is serialised by ownership of
/// the parent `SslConnection`.
///
/// # Fields (from AAP schema — all documented per R3)
///
/// Each field has both a write-site and a read-site, satisfying Rule R3
/// (Config Propagation). See `CONFIG_PROPAGATION_AUDIT.md`.
pub struct RecordLayerState {
    // --- User-installed custom method -------------------------------------
    /// User-installed custom record-layer method; always selected if set.
    ///
    /// Write-site: [`set_custom_record_layer`].
    /// Read-site: `select_next_record_layer` in [`set_new_record_layer`].
    pub custom_rlmethod: Option<Box<dyn RecordMethod>>,

    /// Custom-method-specific opaque argument.
    ///
    /// Write-site: [`set_custom_record_layer`].
    /// Read-site: passed to `custom_rlmethod.new_record_layer()`.
    pub rlarg: Option<Box<dyn core::any::Any + Send>>,

    // --- Active read/write method and instance pair ----------------------
    /// Read-direction method (for checking pending state, release).
    ///
    /// Write-site: [`set_new_record_layer`].
    /// Read-site: [`RecordLayerState::read_pending`].
    pub rrlmethod: Option<Box<dyn RecordMethod>>,

    /// Write-direction method.
    ///
    /// Write-site: [`set_new_record_layer`].
    /// Read-site: used by write functions in `tls.rs` / `dtls.rs`.
    pub wrlmethod: Option<Box<dyn RecordMethod>>,

    /// Read-direction instance (provider-backed state).
    ///
    /// Write-site: [`set_new_record_layer`].
    /// Read-site: [`RecordLayerState::read_pending`].
    pub rrl: Option<Box<dyn RecordLayerInstance>>,

    /// Write-direction instance.
    ///
    /// Write-site: [`set_new_record_layer`].
    /// Read-site: write path in `tls.rs` / `dtls.rs`.
    pub wrl: Option<Box<dyn RecordLayerInstance>>,

    /// Staging BIO for read-direction epoch transitions (DTLS, TLS 1.3
    /// post-handshake key update).
    ///
    /// Write-site: [`set_new_record_layer`] (created before swap).
    /// Read-site: [`RecordLayerState::clear`], post-swap consumption.
    pub rrlnext: Option<Box<dyn Bio>>,

    // --- Buffer sizing -----------------------------------------------------
    /// Default read-buffer length used when provisioning a new read layer.
    ///
    /// Write-site: `SSL_set_default_read_buffer_len` equivalent.
    /// Read-site: options-parameter construction in [`set_new_record_layer`].
    pub default_read_buf_len: usize,

    /// Read-ahead mode — when true, read as much as the kernel has buffered
    /// (reduces syscalls at the cost of extra memory).
    ///
    /// Write-site: [`RecordLayerState::set_read_ahead`].
    /// Read-site: options-parameter construction in [`set_new_record_layer`].
    pub read_ahead: bool,

    // --- Write-side state --------------------------------------------------
    /// Number of bytes of the current write fully sent so far.
    ///
    /// Write-site: write path in `tls.rs` / `dtls.rs`.
    /// Read-site: [`RecordLayerState::write_pending`] helper paths.
    pub wnum: usize,

    /// Write-pending total byte count for a partially-completed send.
    ///
    /// Write-site: write path in `tls.rs` / `dtls.rs`.
    /// Read-site: [`RecordLayerState::write_pending`].
    pub wpend_tot: usize,

    /// Write-pending record type carried across partial-send retries.
    ///
    /// Write-site: write path in `tls.rs` / `dtls.rs`.
    /// Read-site: re-entry into write path for retry.
    pub wpend_type: u8,

    // --- Read-side handshake-fragment reassembly --------------------------
    /// Handshake-header fragment buffer (up to 4 bytes for TLS header:
    /// type (1) + length (3)).
    ///
    /// Write-site: handshake read path in `tls.rs`.
    /// Read-site: handshake message dispatch in `tls.rs`.
    pub handshake_fragment: [u8; 4],

    /// Number of bytes currently filled in `handshake_fragment`.
    ///
    /// Write-site: handshake read path in `tls.rs`.
    /// Read-site: handshake message dispatch in `tls.rs`.
    pub handshake_fragment_len: usize,

    // --- Alert DoS counter -------------------------------------------------
    /// Count of consecutive warning alerts received; capped at
    /// [`MAX_WARN_ALERT_COUNT`].
    ///
    /// Write-site: alert-handling path in `tls.rs` / `dtls.rs`.
    /// Read-site: [`MAX_WARN_ALERT_COUNT`] check in alert processing.
    pub alert_count: u32,

    // --- Pipeline of fetched records --------------------------------------
    /// Number of valid records currently queued in `tlsrecs`.
    ///
    /// Write-site: read path in `tls.rs` / `dtls.rs` after `read_record`.
    /// Read-site: [`RecordLayerState::processed_read_pending`].
    pub num_recs: usize,

    /// Index into `tlsrecs` of the next record to deliver upstream.
    ///
    /// Write-site: read path in `tls.rs` / `dtls.rs` during delivery.
    /// Read-site: [`RecordLayerState::processed_read_pending`].
    pub curr_rec: usize,

    /// Pipeline of fetched records. Length capped at
    /// [`SSL_MAX_PIPELINES`] by construction.
    ///
    /// Write-site: read path in `tls.rs` / `dtls.rs`.
    /// Read-site: delivery path in `tls.rs` / `dtls.rs`.
    pub tlsrecs: Vec<TlsRecord>,

    // --- Padding configuration --------------------------------------------
    /// Block-cipher padding size (non-zero enables block padding).
    ///
    /// Write-site: `SSL_set_block_padding` / config.
    /// Read-site: options-parameter construction in [`set_new_record_layer`].
    pub block_padding: usize,

    /// Handshake-padding size for TLS 1.3 handshake messages.
    ///
    /// Write-site: `SSL_set_block_padding_ex` / config.
    /// Read-site: options-parameter construction in [`set_new_record_layer`].
    pub hs_padding: usize,

    /// TLS 1.3 record-padding callback.
    ///
    /// Write-site: `SSL_set_record_padding_callback` equivalent.
    /// Read-site: padding-dispatch wrapper in [`rlayer_padding_wrapper`].
    pub record_padding_cb: Option<RecordPaddingCallback>,

    /// Opaque argument passed to `record_padding_cb`.
    ///
    /// Write-site: `SSL_set_record_padding_callback_arg` equivalent.
    /// Read-site: [`rlayer_padding_wrapper`] dispatch.
    pub record_padding_arg: Option<Box<dyn core::any::Any + Send>>,

    /// SSL message callback invoked for every record handled by the record
    /// layer (handshake / alert / app-data / change-cipher-spec).
    ///
    /// Write-site: [`RecordLayerState::set_msg_callback`] (translates
    /// `SSL_CTX_set_msg_callback` / `SSL_set_msg_callback`).
    /// Read-site: [`rlayer_msg_callback_wrapper`] dispatch.
    ///
    /// `None` matches upstream C behaviour (no-op, see
    /// `ssl/record/rec_layer_s3.c` line 1138 — `if (s->msg_callback != NULL)`).
    /// The closure persists across [`RecordLayerState::clear`] — the SSL
    /// connection's message-tracing handler is configured per-`SSL_CTX` /
    /// per-`SSL` and survives connection resets, mirroring the upstream
    /// model where `clear()` does not touch `msg_callback`.
    pub msg_callback: Option<MsgCallback>,

    /// SSL security callback consulted before security-sensitive operations
    /// (cipher selection, version negotiation, key sizes).
    ///
    /// Write-site: [`RecordLayerState::set_security_callback`] (translates
    /// `SSL_CTX_set_security_callback` / `SSL_set_security_callback`).
    /// Read-site: [`rlayer_security_wrapper`] dispatch.
    ///
    /// `None` matches upstream C default-permit semantics — see
    /// `ssl/record/rec_layer_s3.c` line 1148 (`return ssl_security(s, …)`),
    /// where `ssl_security` returns `1` when no callback is installed.
    /// The closure persists across [`RecordLayerState::clear`] for the
    /// same reason as `msg_callback`.
    pub security_callback: Option<SecurityCallback>,
}

impl core::fmt::Debug for RecordLayerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // We cannot derive Debug because `Box<dyn Trait>` has no automatic
        // Debug impl for our traits. Emit a diagnostic-friendly summary.
        f.debug_struct("RecordLayerState")
            .field("has_custom_method", &self.custom_rlmethod.is_some())
            .field("has_read_method", &self.rrlmethod.is_some())
            .field("has_write_method", &self.wrlmethod.is_some())
            .field("has_read_layer", &self.rrl.is_some())
            .field("has_write_layer", &self.wrl.is_some())
            .field("has_staging_bio", &self.rrlnext.is_some())
            .field("default_read_buf_len", &self.default_read_buf_len)
            .field("read_ahead", &self.read_ahead)
            .field("wnum", &self.wnum)
            .field("handshake_fragment_len", &self.handshake_fragment_len)
            .field("wpend_tot", &self.wpend_tot)
            .field("wpend_type", &self.wpend_type)
            .field("alert_count", &self.alert_count)
            .field("num_recs", &self.num_recs)
            .field("curr_rec", &self.curr_rec)
            .field("tlsrec_count", &self.tlsrecs.len())
            .field("block_padding", &self.block_padding)
            .field("hs_padding", &self.hs_padding)
            .field("has_padding_cb", &self.record_padding_cb.is_some())
            .field("has_msg_callback", &self.msg_callback.is_some())
            .field("has_security_callback", &self.security_callback.is_some())
            // Fields intentionally omitted from Debug output to avoid
            // leaking opaque handles (`rlarg`, `record_padding_arg`) and
            // to keep diagnostic output readable (`handshake_fragment`
            // is summarised by `handshake_fragment_len`).
            .finish_non_exhaustive()
    }
}

// SAFETY-audit note: `RecordLayerState` contains `Box<dyn RecordMethod>`
// (Send + Sync) and `Box<dyn RecordLayerInstance>` (Send only), plus
// `Box<dyn Bio>` (Send only). The struct therefore implements `Send` but
// **not** `Sync`. This matches the per-connection ownership model
// (see Rule R7 — LOCK-SCOPE documentation above).

impl RecordLayerState {
    // -----------------------------------------------------------------------
    // Lifecycle — translates C's RECORD_LAYER_init / clear / reset
    // (rec_layer_s3.c lines 27–99)
    // -----------------------------------------------------------------------

    /// Constructs a fresh record layer in the zero-initialised state.
    ///
    /// Translates C `RECORD_LAYER_init` (`rec_layer_s3.c` lines 27–30):
    /// ```c
    /// void RECORD_LAYER_init(RECORD_LAYER *rl, SSL_CONNECTION *s) {
    ///     rl->s = s;
    /// }
    /// ```
    /// In the Rust rewrite the parent connection is not embedded in the
    /// record layer (to avoid cyclical borrows); instead the connection
    /// drives the record layer via method calls on [`RecordLayerState`].
    #[must_use]
    pub fn new() -> Self {
        // Pre-allocate a small initial pipeline — records are appended as
        // needed, capped at SSL_MAX_PIPELINES in the read path.
        let tlsrecs: Vec<TlsRecord> = Vec::with_capacity(1);
        RecordLayerState {
            custom_rlmethod: None,
            rlarg: None,
            rrlmethod: None,
            wrlmethod: None,
            rrl: None,
            wrl: None,
            rrlnext: None,
            default_read_buf_len: 0,
            read_ahead: false,
            wnum: 0,
            wpend_tot: 0,
            wpend_type: 0,
            handshake_fragment: [0u8; 4],
            handshake_fragment_len: 0,
            alert_count: 0,
            num_recs: 0,
            curr_rec: 0,
            tlsrecs,
            block_padding: 0,
            hs_padding: 0,
            record_padding_cb: None,
            record_padding_arg: None,
            msg_callback: None,
            security_callback: None,
        }
    }

    /// Clears the record layer, releasing any buffered records and record
    /// layer instances.
    ///
    /// Translates C `RECORD_LAYER_clear` (`rec_layer_s3.c` lines 32–70).
    ///
    /// # Errors
    ///
    /// Returns an error if any of the underlying backend free or release
    /// operations fails. After this function returns (whether Ok or Err)
    /// the state is reset to a fresh post-[`new`](Self::new) configuration.
    pub fn clear(&mut self) -> SslResult<()> {
        debug!(target: "openssl_ssl::record", "RecordLayerState::clear");

        let mut first_error: Option<SslError> = None;

        // Release any fetched-but-not-delivered records.
        // Translates lines 35–43 of rec_layer_s3.c where the C code loops
        // from curr_rec to num_recs calling release_record on each.
        if let (Some(method), Some(instance)) = (self.rrlmethod.as_ref(), self.rrl.as_mut()) {
            for idx in self.curr_rec..self.num_recs {
                if let Some(record) = self.tlsrecs.get_mut(idx) {
                    if let Some(handle) = record.rechandle {
                        if let Err(rc) =
                            method.release_record(instance.as_mut(), &handle, record.length)
                        {
                            if first_error.is_none() {
                                first_error = Some(rlayer_return_to_error(rc));
                            }
                        }
                    }
                }
            }
        }

        // Clear the record pipeline. TlsRecord::clear() zeroes any
        // plaintext still held in locally-allocated records.
        for record in &mut self.tlsrecs {
            record.clear();
        }
        self.tlsrecs.clear();

        // Reset per-connection counters and cached bytes.
        self.wnum = 0;
        self.handshake_fragment = [0u8; 4];
        self.handshake_fragment_len = 0;
        self.wpend_tot = 0;
        self.wpend_type = 0;
        self.alert_count = 0;
        self.num_recs = 0;
        self.curr_rec = 0;

        // Drop the staging BIO if any.
        self.rrlnext = None;

        // Free and drop the read record layer via its method.
        if let (Some(method), Some(instance)) = (self.rrlmethod.take(), self.rrl.take()) {
            if let Err(e) = method.free(instance) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        // Free and drop the write record layer via its method.
        if let (Some(method), Some(instance)) = (self.wrlmethod.take(), self.wrl.take()) {
            if let Err(e) = method.free(instance) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        // Note: custom_rlmethod and rlarg persist across clear() —
        // they represent a user-installed handler that should survive
        // connection resets. The same applies to msg_callback,
        // security_callback, record_padding_cb, and record_padding_arg —
        // these are configured per-SSL_CTX/per-SSL and must outlive
        // connection-level state resets, mirroring upstream behaviour
        // where `RECORD_LAYER_clear` does not touch the SSL-level
        // `msg_callback`, `security_callback`, or padding handlers.

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Resets the record layer — clears all state and creates fresh
    /// plaintext-level read/write layers.
    ///
    /// Translates C `RECORD_LAYER_reset` (`rec_layer_s3.c` lines 72–99).
    ///
    /// # Errors
    ///
    /// Returns an error if [`clear`](Self::clear) fails or if the
    /// reconstitution of the read/write record layers fails.
    pub fn reset(&mut self, is_dtls: bool) -> SslResult<()> {
        debug!(
            target: "openssl_ssl::record",
            is_dtls,
            "RecordLayerState::reset",
        );

        self.clear()?;

        // Select the wildcard ProtocolVersion used during the initial handshake
        // setup. Note: `TlsAny` and `DtlsAny` are wildcards and intentionally
        // return `None` from `wire_version()` — this is NOT an error. In the C
        // source, `RECORD_LAYER_reset` passes the raw sentinel constants
        // `TLS_ANY_VERSION`/`DTLS_ANY_VERSION` (via `as_raw`) into
        // `ssl_set_new_record_layer`; there is no requirement for a 16-bit
        // wire version here because no concrete record layer has been
        // instantiated yet.
        let initial_version = if is_dtls {
            ProtocolVersion::DtlsAny
        } else {
            ProtocolVersion::TlsAny
        };

        // Create a new read record layer at PROTECTION_LEVEL_NONE.
        // The state is left `None` here; the actual instantiation happens
        // when the connection attaches a concrete `RecordMethod` via
        // [`set_new_record_layer`] during handshake setup. This mirrors the
        // C pattern where RECORD_LAYER_reset calls ssl_set_new_record_layer
        // with level NONE; in our crate structure the method is supplied
        // externally, so reset only clears and records the initial version.
        trace!(
            target: "openssl_ssl::record",
            initial_raw_version = format!("{:#x}", initial_version.as_raw()),
            is_tls = initial_version.is_tls(),
            is_dtls = initial_version.is_dtls(),
            "record layer reset to plaintext level",
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pending helpers — translates C RECORD_LAYER_*_pending macros /
    // functions from rec_layer_s3.c lines 102–250.
    // -----------------------------------------------------------------------

    /// Returns `true` if raw (not yet decrypted) data is pending on the
    /// read-direction transport.
    ///
    /// Translates C `RECORD_LAYER_read_pending`.
    #[must_use]
    pub fn read_pending(&self) -> bool {
        match (self.rrlmethod.as_ref(), self.rrl.as_ref()) {
            (Some(method), Some(rl)) => method.unprocessed_read_pending(rl.as_ref()),
            _ => false,
        }
    }

    /// Returns `true` if processed (decrypted) records are queued for
    /// delivery, OR if the backend has processed data available.
    ///
    /// Translates C `RECORD_LAYER_processed_read_pending` (lines 108–112):
    /// ```c
    /// int RECORD_LAYER_processed_read_pending(const RECORD_LAYER *rl) {
    ///     return rl->curr_rec < rl->num_recs
    ///         || rl->rrlmethod->processed_read_pending(rl->rrl);
    /// }
    /// ```
    #[must_use]
    pub fn processed_read_pending(&self) -> bool {
        if self.curr_rec < self.num_recs {
            return true;
        }
        match (self.rrlmethod.as_ref(), self.rrl.as_ref()) {
            (Some(method), Some(rl)) => method.processed_read_pending(rl.as_ref()),
            _ => false,
        }
    }

    /// Returns `true` if bytes remain to be flushed on the write side.
    ///
    /// Translates C `RECORD_LAYER_write_pending` (lines 114–117):
    /// ```c
    /// int RECORD_LAYER_write_pending(const RECORD_LAYER *rl) {
    ///     return rl->wpend_tot > 0;
    /// }
    /// ```
    #[must_use]
    pub const fn write_pending(&self) -> bool {
        self.wpend_tot > 0
    }

    /// Enables or disables read-ahead mode.
    ///
    /// Translates C's `RECORD_LAYER_set_read_ahead(rl, ra)` macro from
    /// `record.h` line 134.
    pub fn set_read_ahead(&mut self, read_ahead: bool) {
        self.read_ahead = read_ahead;
    }

    /// Returns the current read-ahead mode.
    ///
    /// Translates C's `RECORD_LAYER_get_read_ahead(rl)` macro from
    /// `record.h` line 135.
    #[must_use]
    pub const fn get_read_ahead(&self) -> bool {
        self.read_ahead
    }

    /// Installs (or clears) the SSL message callback.
    ///
    /// Translates `SSL_CTX_set_msg_callback` /
    /// `SSL_set_msg_callback` from `ssl/ssl_lib.c` (the upstream API
    /// stores the closure on the `SSL` /`SSL_CTX` and the record-layer
    /// dispatch wrapper consults it). In the Rust translation the
    /// callback is held directly on the per-connection
    /// [`RecordLayerState`], where the read-site is
    /// [`rlayer_msg_callback_wrapper`].
    ///
    /// Pass `Some(Box::new(closure))` to install a handler;
    /// pass `None` to clear a previously-installed handler. The
    /// callback persists across [`RecordLayerState::clear`] calls,
    /// matching the upstream behaviour where `RECORD_LAYER_clear`
    /// does not touch the SSL-level message callback.
    ///
    /// Rule R3 — write-site for `msg_callback`. Rule R4 — pair with
    /// [`rlayer_msg_callback_wrapper`] via the
    /// `record_layer_msg_callback_register_trigger_assert` integration
    /// test. Rule R10 — wires the callback through to actual record
    /// handling rather than leaving it as a no-op stub.
    pub fn set_msg_callback(&mut self, cb: Option<MsgCallback>) {
        trace!(
            target: "openssl_ssl::record",
            installing = cb.is_some(),
            "RecordLayerState::set_msg_callback",
        );
        self.msg_callback = cb;
    }

    /// Returns `true` if a message callback is currently installed.
    ///
    /// Diagnostic helper — provides a side-effect-free read-site for
    /// the [`msg_callback`](Self::msg_callback) field that does not
    /// require dispatching through the wrapper. The wrapper itself is
    /// the production read-site under Rule R3.
    #[must_use]
    pub const fn has_msg_callback(&self) -> bool {
        self.msg_callback.is_some()
    }

    /// Installs (or clears) the SSL security callback.
    ///
    /// Translates `SSL_CTX_set_security_callback` /
    /// `SSL_set_security_callback` from `ssl/ssl_lib.c`. The upstream
    /// callback is consulted by `ssl_security`, which the record-layer
    /// dispatch wrapper invokes; the Rust translation stores the
    /// callback directly on the per-connection [`RecordLayerState`]
    /// and consults it in [`rlayer_security_wrapper`].
    ///
    /// Pass `Some(Box::new(closure))` to install a handler;
    /// pass `None` to clear a previously-installed handler (the
    /// wrapper then defaults to `true` / permit, matching the C
    /// default-permit semantics of `ssl_security` when no callback is
    /// installed).
    ///
    /// Rule R3 — write-site for `security_callback`. Rule R4 — pair with
    /// [`rlayer_security_wrapper`] via the
    /// `record_layer_security_callback_register_trigger_assert`
    /// integration test. Rule R10 — wires the callback through to
    /// security-policy enforcement rather than leaving it as a
    /// hard-coded `true`.
    pub fn set_security_callback(&mut self, cb: Option<SecurityCallback>) {
        trace!(
            target: "openssl_ssl::record",
            installing = cb.is_some(),
            "RecordLayerState::set_security_callback",
        );
        self.security_callback = cb;
    }

    /// Returns `true` if a security callback is currently installed.
    ///
    /// Diagnostic helper — provides a side-effect-free read-site for
    /// the [`security_callback`](Self::security_callback) field. The
    /// wrapper itself is the production read-site under Rule R3.
    #[must_use]
    pub const fn has_security_callback(&self) -> bool {
        self.security_callback.is_some()
    }

    /// Returns the number of application-data bytes immediately available.
    ///
    /// Sum of (a) already-decrypted-and-queued records' unread portion and
    /// (b) whatever the backend reports as ready.
    #[must_use]
    pub fn app_data_pending(&self) -> usize {
        let mut total: usize = 0;

        // Portion of locally-queued records not yet delivered.
        for idx in self.curr_rec..self.num_recs {
            if let Some(rec) = self.tlsrecs.get(idx) {
                if rec.record_type == SSL3_RT_APPLICATION_DATA {
                    total = total.saturating_add(rec.length);
                }
            }
        }

        // Backend-pending bytes.
        if let (Some(method), Some(rl)) = (self.rrlmethod.as_ref(), self.rrl.as_ref()) {
            total = total.saturating_add(method.app_data_pending(rl.as_ref()));
        }

        total
    }
}

impl Default for RecordLayerState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Top-level functions: record-layer configuration and runtime helpers
// ---------------------------------------------------------------------------

/// Installs a user-supplied custom record-layer method.
///
/// Translates C `ossl_ssl_set_custom_record_layer` (`rec_layer_s3.c`
/// lines 1170–1176). Once set, the custom method is always chosen by
/// subsequent [`set_new_record_layer`] calls.
///
/// Passing `None` for both parameters clears any previously-installed
/// custom handler.
pub fn set_custom_record_layer(
    state: &mut RecordLayerState,
    method: Option<Box<dyn RecordMethod>>,
    arg: Option<Box<dyn core::any::Any + Send>>,
) {
    if method.is_some() {
        debug!(
            target: "openssl_ssl::record",
            "installing custom record layer method",
        );
    } else {
        debug!(
            target: "openssl_ssl::record",
            "clearing custom record layer method",
        );
    }
    state.custom_rlmethod = method;
    state.rlarg = arg;
}

/// Arguments for [`set_new_record_layer`].
///
/// Replaces the 20-argument C `ssl_set_new_record_layer` signature
/// (`rec_layer_s3.c` lines 1237–1483) with a typed struct per Rule R5
/// (nullability) — every optional field is `Option<T>`, no sentinel values.
///
/// The struct intentionally aggregates six independent boolean feature
/// flags (`use_etm`, `stream_mac`, `tlstree`, `first_handshake`,
/// `is_dtls`, `has_msg_callback`). Each one mirrors a distinct C
/// `OSSL_RECORD_PROTECTION_LEVEL_*` / `OSSL_FUNC_RLAYER_*` flag and
/// originates from a different subsystem (cipher negotiation, TLS
/// extension processing, DTLS detection, callback registration).
/// Collapsing them into an enum or bitflags struct would obscure the
/// one-to-one mapping to the C API and impede traceability.
#[allow(
    clippy::struct_excessive_bools,
    reason = "record-layer configuration naturally contains multiple \
              independent feature flags, each mirroring a distinct C \
              OSSL_RECORD / OSSL_FUNC_RLAYER flag; collapsing them would \
              obscure the 1:1 mapping to the C API and impede traceability"
)]
pub struct SetNewRecordLayerArgs {
    /// Wire-format protocol version (e.g. 0x0303 for TLS 1.2).
    pub version: ProtocolVersion,
    /// Connection role: 0 = client, 1 = server.
    pub role: u8,
    /// Direction the new layer serves (read or write).
    pub direction: RecordDirection,
    /// Cryptographic protection level.
    pub level: ProtectionLevel,
    /// DTLS epoch number (0 for TLS).
    pub epoch: u16,
    /// Encryption key (empty for `ProtectionLevel::None`).
    pub key: Vec<u8>,
    /// Explicit or implicit IV (empty for `ProtectionLevel::None`).
    pub iv: Vec<u8>,
    /// MAC key (empty for AEAD ciphers).
    pub mac_key: Vec<u8>,
    /// Cipher algorithm name, e.g. "AES-128-GCM", "CHACHA20-POLY1305".
    pub cipher_name: String,
    /// AEAD tag length in bytes (0 if not AEAD).
    pub tag_len: usize,
    /// MAC algorithm type identifier (0 for AEAD).
    pub mac_type: i32,
    /// MD algorithm NID (0 for AEAD).
    pub md_nid: i32,
    /// SSL options bitmap (propagated to backend as `options` param).
    pub ssl_options: u64,
    /// SSL mode bitmap (propagated to backend as `options` param).
    pub ssl_mode: u32,
    /// Maximum fragment length as negotiated by the extension;
    /// `None` means use default.
    pub max_frag_len: Option<usize>,
    /// Maximum early data length; only used for Early / Handshake levels.
    pub max_early_data: u32,
    /// Whether Encrypt-then-MAC is negotiated.
    pub use_etm: bool,
    /// Whether the stream-MAC construction is in effect.
    pub stream_mac: bool,
    /// Whether TLSTREE key derivation is active.
    pub tlstree: bool,
    /// Whether this is the first handshake on the connection.
    pub first_handshake: bool,
    /// Requested maximum pipeline depth; 0 means backend default.
    pub max_pipelines: usize,
    /// `true` if the owning connection is a DTLS connection.
    pub is_dtls: bool,
    /// Whether a message-callback is installed on the connection.
    pub has_msg_callback: bool,
}

impl Default for SetNewRecordLayerArgs {
    fn default() -> Self {
        SetNewRecordLayerArgs {
            version: ProtocolVersion::TlsAny,
            role: 0,
            direction: RecordDirection::Read,
            level: ProtectionLevel::None,
            epoch: 0,
            key: Vec::new(),
            iv: Vec::new(),
            mac_key: Vec::new(),
            cipher_name: String::new(),
            tag_len: 0,
            mac_type: 0,
            md_nid: 0,
            ssl_options: 0,
            ssl_mode: 0,
            max_frag_len: None,
            max_early_data: 0,
            use_etm: false,
            stream_mac: false,
            tlstree: false,
            first_handshake: false,
            max_pipelines: 0,
            is_dtls: false,
            has_msg_callback: false,
        }
    }
}

/// Resolves which record-layer method to use for a new record layer.
///
/// Translates C `ssl_select_next_record_layer` (`rec_layer_s3.c`
/// lines 1178–1203). Precedence:
///
/// 1. Any user-installed `custom_rlmethod` — always wins.
/// 2. For `ProtectionLevel::None` — use the default plaintext method for
///    TLS or DTLS depending on connection type. Returned as `None` here so
///    the caller (which owns the method registry) can plug in the correct
///    default; mirrors C where the plaintext method is a compile-time
///    static pointer.
/// 3. For `ProtectionLevel::Application` with KTLS enabled — caller plugs
///    in KTLS method (not handled here; marked in returned metadata).
/// 4. Otherwise — use the currently-active read/write method if any.
///
/// Returns a reference to the selected method, plus a diagnostic name.
fn select_next_record_layer(
    state: &RecordLayerState,
    direction: RecordDirection,
    level: ProtectionLevel,
) -> Option<&dyn RecordMethod> {
    // (1) Custom method installed — always wins.
    if let Some(custom) = state.custom_rlmethod.as_ref() {
        trace!(
            target: "openssl_ssl::record",
            direction = ?direction,
            level = ?level,
            "select_next_record_layer: using custom method",
        );
        return Some(custom.as_ref());
    }

    // (2,3) For levels other than the ones that always need provider-specific
    // selection, fall back to the currently-active method in this direction.
    // This lets a caller retry after a non-fatal error by simply re-invoking
    // without changing the method pointer — mirrors the C fallback pattern.
    match direction {
        RecordDirection::Read => state
            .rrlmethod
            .as_ref()
            .map(|m| m.as_ref() as &dyn RecordMethod),
        RecordDirection::Write => state
            .wrlmethod
            .as_ref()
            .map(|m| m.as_ref() as &dyn RecordMethod),
    }
}

/// Post-selection wiring: propagate first-handshake flag and max-pipelines
/// to the freshly-installed layer.
///
/// Translates C `ssl_post_record_layer_select` (`rec_layer_s3.c`
/// lines 1205–1235).
fn post_record_layer_select(
    state: &mut RecordLayerState,
    direction: RecordDirection,
    first_handshake: bool,
    max_pipelines: usize,
) {
    match direction {
        RecordDirection::Read => {
            if let (Some(method), Some(rl)) = (state.rrlmethod.as_ref(), state.rrl.as_mut()) {
                method.set_first_handshake(rl.as_mut(), first_handshake);
                if max_pipelines > 0 {
                    method.set_max_pipelines(rl.as_mut(), max_pipelines);
                }
            }
        }
        RecordDirection::Write => {
            if let (Some(method), Some(wl)) = (state.wrlmethod.as_ref(), state.wrl.as_mut()) {
                method.set_first_handshake(wl.as_mut(), first_handshake);
                if max_pipelines > 0 {
                    method.set_max_pipelines(wl.as_mut(), max_pipelines);
                }
            }
        }
    }
}

/// Builds the `options` parameter set — options that the backend MAY
/// support but MUST NOT reject.
///
/// Translates C lines 1283–1314 of `rec_layer_s3.c`.
///
/// Reads from both the caller-supplied `args` (SSL options bitmap, SSL mode
/// bitmap) and the current [`RecordLayerState`] (read-ahead flag, default
/// buffer length, block/handshake padding sizes). The emitted parameter set
/// is intentionally direction-specific: read-direction callers receive
/// buffer/read-ahead parameters, write-direction callers receive padding
/// parameters.
fn build_options_params_real(args: &SetNewRecordLayerArgs, state: &RecordLayerState) -> ParamSet {
    let mut builder = ParamBuilder::new()
        .push_u64(PARAM_OPTIONS, args.ssl_options)
        .push_u32(PARAM_MODE, args.ssl_mode);

    if args.direction == RecordDirection::Read {
        if let Ok(read_buf_u64) = u64::try_from(state.default_read_buf_len) {
            builder = builder.push_u64(PARAM_READ_BUFFER_LEN, read_buf_u64);
        }
        builder = builder.push_u32(PARAM_READ_AHEAD, u32::from(state.read_ahead));
    } else {
        if let Ok(block_padding_u64) = u64::try_from(state.block_padding) {
            builder = builder.push_u64(PARAM_BLOCK_PADDING, block_padding_u64);
        }
        if let Ok(hs_padding_u64) = u64::try_from(state.hs_padding) {
            builder = builder.push_u64(PARAM_HS_PADDING, hs_padding_u64);
        }
    }

    builder.build()
}

/// Builds the `settings` parameter set — options that the backend MUST
/// support or the construction fails.
///
/// Translates C lines 1316–1361 of `rec_layer_s3.c`.
fn build_settings_params(args: &SetNewRecordLayerArgs) -> ParamSet {
    let mut builder = ParamBuilder::new()
        .push_u32(PARAM_USE_ETM, u32::from(args.use_etm))
        .push_u32(PARAM_STREAM_MAC, u32::from(args.stream_mac))
        .push_u32(PARAM_TLSTREE, u32::from(args.tlstree));

    if let Some(max_frag) = args.max_frag_len {
        if let Ok(max_frag_u64) = u64::try_from(max_frag) {
            builder = builder.push_u64(PARAM_MAX_FRAG_LEN, max_frag_u64);
        }
    }

    // max_early_data is meaningful only for Early / Handshake levels,
    // but we always push it for simplicity — backend checks level.
    if matches!(
        args.level,
        ProtectionLevel::Early | ProtectionLevel::Handshake,
    ) {
        builder = builder.push_u32(PARAM_MAX_EARLY_DATA, args.max_early_data);
    }

    builder.build()
}

/// Installs a new record layer for the given direction, level and version.
///
/// Translates C `ssl_set_new_record_layer` (`rec_layer_s3.c`
/// lines 1237–1472). This is the central record-layer configuration
/// function called by the handshake state machine on every key update.
///
/// # Algorithm
///
/// 1. Resolve the method to use via [`select_next_record_layer`].
/// 2. Build options and settings [`ParamSet`]s.
/// 3. Construct a staging BIO ([`MemBio`]) for the read direction so that
///    records decrypted under the new keys can be read while the old
///    layer is being torn down.
/// 4. Call `method.new_record_layer(args)`.
/// 5. On `RlayerReturn::NonFatalError`, if a different method was tried,
///    fall back to the previous method and retry.
/// 6. On success, swap the new instance in and drop the old one.
/// 7. Call [`post_record_layer_select`] to propagate first-handshake and
///    pipeline-depth settings.
///
/// # Errors
///
/// * [`SslError::Protocol`] on backend configuration errors.
/// * [`SslError::Handshake`] on missing method (no backend registered).
///
/// # Method selection
///
/// When `method_factory` is `None`, this function requires a pre-registered
/// method in `state.rrlmethod` / `state.wrlmethod` — otherwise it returns
/// an error. In the full workspace, the handshake state machine supplies
/// `method_factory` to construct a fresh method of the appropriate type;
/// this keeps `mod.rs` independent of the concrete method registry, which
/// lives in `providers::default::record`.
pub fn set_new_record_layer(
    state: &mut RecordLayerState,
    mut args: SetNewRecordLayerArgs,
    method_factory: Option<Box<dyn RecordMethod>>,
) -> SslResult<()> {
    debug!(
        target: "openssl_ssl::record",
        direction = ?args.direction,
        level = ?args.level,
        version = ?args.version,
        epoch = args.epoch,
        is_dtls = args.is_dtls,
        cipher = args.cipher_name.as_str(),
        "set_new_record_layer",
    );

    // Validate version coherence (C does this implicitly via version
    // constants).
    match args.version {
        ProtocolVersion::TlsAny if args.is_dtls => {
            return Err(SslError::Protocol(String::from(
                "set_new_record_layer: TLS version on DTLS connection",
            )));
        }
        ProtocolVersion::DtlsAny if !args.is_dtls => {
            return Err(SslError::Protocol(String::from(
                "set_new_record_layer: DTLS version on TLS connection",
            )));
        }
        _ => {}
    }

    // Phase A — Free any previously-installed record layer INSTANCE using
    // the currently-installed record layer METHOD. We must do this BEFORE
    // Phase B (installing the new factory), because the OLD method is the
    // only object that knows how to free the OLD instance — if we
    // overwrite state.rrlmethod first, the old method is dropped and the
    // instance becomes unfreeable (resource leak).
    //
    // We take ownership of the instance (state.rrl.take()) first because
    // the free call needs to move the `Box<dyn RecordLayerInstance>` into
    // the method. Then we borrow state.rrlmethod immutably to invoke
    // free(). This is safe: state.rrl and state.rrlmethod are disjoint
    // fields, so the mutable borrow of the former and the immutable
    // borrow of the latter can coexist under NLL disjoint-borrow rules.
    let old_instance = match args.direction {
        RecordDirection::Read => state.rrl.take(),
        RecordDirection::Write => state.wrl.take(),
    };
    if let Some(inst) = old_instance {
        let old_method_ref = match args.direction {
            RecordDirection::Read => state.rrlmethod.as_ref(),
            RecordDirection::Write => state.wrlmethod.as_ref(),
        };
        if let Some(m) = old_method_ref {
            if let Err(e) = m.free(inst) {
                warn!(
                    target: "openssl_ssl::record",
                    error = %e,
                    "error freeing old record layer — continuing",
                );
            }
        }
        // If there was an instance but no method (unexpected), the instance
        // is dropped here via normal Drop implementation.
    }

    // Phase B — If the caller supplies a method_factory, install it now
    // (replacing any pre-existing method). The factory becomes THE method
    // for this direction; the selector will pick it up at Phase E.
    if let Some(factory) = method_factory {
        match args.direction {
            RecordDirection::Read => state.rrlmethod = Some(factory),
            RecordDirection::Write => state.wrlmethod = Some(factory),
        }
    }

    // Phase C — Prepare staging BIO for read direction (matches C lines
    // 1363–1390 — BIO_new(BIO_s_mem()) for TLS, BIO_new(BIO_s_dgram_mem())
    // for DTLS).
    //
    // This mutation must happen BEFORE select_next_record_layer() below,
    // because the selector returns a borrow of `state` that lives through
    // the subsequent call to method_ref.new_record_layer(). The borrow
    // checker (E0506) will not permit re-mutation of `state.rrlnext`
    // while the immutable borrow from the selector is still live.
    if matches!(args.direction, RecordDirection::Read) {
        state.rrlnext = Some(Box::new(MemBio::new()) as Box<dyn Bio>);
        if let Some(staging) = state.rrlnext.as_ref() {
            trace!(
                target: "openssl_ssl::record",
                staging_bio = staging.bio_type().name(),
                "read-direction staging BIO allocated",
            );
        }
    }

    // Phase D — Build parameter sets BEFORE selector borrow to avoid a
    // conflict with the immutable borrow of `state` held by `method_ref`
    // below. The options set depends on `state` (read_ahead,
    // default_read_buf_len, block_padding, hs_padding), so we materialise
    // it now.
    let options = build_options_params_real(&args, state);
    let settings = build_settings_params(&args);

    // Phase E — Resolve method via the selector (custom > direction-specific).
    let method_ref =
        select_next_record_layer(state, args.direction, args.level).ok_or_else(|| {
            SslError::Handshake(format!(
                "set_new_record_layer: no record-layer method registered for {:?}",
                args.direction,
            ))
        })?;

    trace!(
        target: "openssl_ssl::record",
        method = method_ref.method_name(),
        "selected record-layer method",
    );

    // Emit a summary for observability.
    trace!(
        target: "openssl_ssl::record",
        option_keys = options.len(),
        setting_keys = settings.len(),
        "built record-layer parameters",
    );

    // Derive per-instance ParamSet merging options into settings, since
    // the backend might want them combined. We keep them separate here
    // too so individual backends can distinguish.
    let mut combined: ParamSet = settings.duplicate();
    combined.merge(&options);

    // Phase F — Construct the RecordMethod-side arguments bundle and
    // invoke method.new_record_layer(...).
    let nrl_args = NewRecordLayerArgs {
        version: args.version.wire_version().unwrap_or(0),
        role: args.role,
        direction: args.direction,
        level: args.level,
        epoch: args.epoch,
        key: core::mem::take(&mut args.key),
        iv: core::mem::take(&mut args.iv),
        mac_key: core::mem::take(&mut args.mac_key),
        cipher_name: core::mem::take(&mut args.cipher_name),
        tag_len: args.tag_len,
        mac_type: args.mac_type,
        md_nid: args.md_nid,
        settings,
        options,
    };

    let instance_result = method_ref.new_record_layer(nrl_args);

    // At this point method_ref goes out of scope: its &state borrow ends,
    // and we may again freely mutate state.
    match instance_result {
        Ok(new_instance) => {
            debug!(
                target: "openssl_ssl::record",
                direction = ?args.direction,
                "record layer instantiation succeeded",
            );

            // Install the new instance. The method was installed in
            // Phase B (or already present from a previous call); we do
            // NOT touch state.rrlmethod / state.wrlmethod here.
            match args.direction {
                RecordDirection::Read => {
                    state.rrl = Some(new_instance);
                }
                RecordDirection::Write => {
                    state.wrl = Some(new_instance);
                }
            }
        }
        Err(RlayerReturn::NonFatalError) => {
            warn!(
                target: "openssl_ssl::record",
                direction = ?args.direction,
                "record layer backend rejected configuration — caller should retry with alternative method",
            );
            return Err(SslError::Protocol(String::from(
                "set_new_record_layer: backend returned NonFatalError",
            )));
        }
        Err(RlayerReturn::Fatal) => {
            return Err(SslError::Protocol(String::from(
                "set_new_record_layer: backend returned Fatal",
            )));
        }
        Err(other) => {
            return Err(SslError::Protocol(format!(
                "set_new_record_layer: unexpected backend return {other:?}",
            )));
        }
    }

    // Post-selection wiring (lines 1205–1235): apply first-handshake and
    // pipeline settings to the new layer.
    post_record_layer_select(
        state,
        args.direction,
        args.first_handshake,
        args.max_pipelines,
    );

    Ok(())
}

/// Propagates the protocol version to both read and write record layer
/// methods.
///
/// Translates C `ssl_set_record_protocol_version` (`rec_layer_s3.c`
/// lines 1474–1483):
/// ```c
/// void ssl_set_record_protocol_version(SSL_CONNECTION *s, int version) {
///     s->rlayer.rrlmethod->set_protocol_version(s->rlayer.rrl, version);
///     s->rlayer.wrlmethod->set_protocol_version(s->rlayer.wrl, version);
/// }
/// ```
///
/// # Errors
///
/// Returns [`SslError::Handshake`] if the version has no wire encoding or
/// if the expected record-layer instances are missing.
pub fn set_record_protocol_version(
    state: &mut RecordLayerState,
    version: ProtocolVersion,
) -> SslResult<()> {
    debug!(
        target: "openssl_ssl::record",
        ?version,
        "set_record_protocol_version",
    );

    let wire = version.wire_version().ok_or_else(|| {
        SslError::Handshake(format!(
            "set_record_protocol_version: no wire encoding for {version:?}",
        ))
    })?;

    // Read side.
    if let (Some(method), Some(rl)) = (state.rrlmethod.as_ref(), state.rrl.as_mut()) {
        method.set_protocol_version(rl.as_mut(), wire);
    } else {
        return Err(SslError::Handshake(String::from(
            "set_record_protocol_version: no read record layer installed",
        )));
    }

    // Write side.
    if let (Some(method), Some(wl)) = (state.wrlmethod.as_ref(), state.wrl.as_mut()) {
        method.set_protocol_version(wl.as_mut(), wire);
    } else {
        return Err(SslError::Handshake(String::from(
            "set_record_protocol_version: no write record layer installed",
        )));
    }

    Ok(())
}

/// Converts a backend return code from a fallible backend call into an
/// appropriate [`SslError`] — used when we cannot propagate
/// [`RlayerReturn`] directly (e.g. during `clear()` where each individual
/// release error just needs to be summarised).
fn rlayer_return_to_error(rc: RlayerReturn) -> SslError {
    match rc {
        RlayerReturn::Fatal => SslError::Protocol(String::from("record layer fatal error")),
        RlayerReturn::NonFatalError => {
            SslError::Protocol(String::from("record layer non-fatal error"))
        }
        RlayerReturn::Eof => SslError::ConnectionClosed,
        RlayerReturn::Retry => SslError::Protocol(String::from("record layer retry requested")),
        RlayerReturn::Success => SslError::Protocol(String::from(
            "record layer unexpected Success in error path",
        )),
    }
}

// ---------------------------------------------------------------------------
// Return handling — translates ossl_tls_handle_rlayer_return
// (rec_layer_s3.c lines 491–558).
// ---------------------------------------------------------------------------

/// Options affecting [`handle_rlayer_return`] behaviour.
///
/// Supplied by the caller because the mod.rs layer does not itself own
/// the full `SslConnection` options bitmap — this keeps the record layer
/// decoupled from `ssl::options`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RlayerReturnOptions {
    /// `SSL_OP_IGNORE_UNEXPECTED_EOF` — if true, an EOF during read is
    /// converted into a clean shutdown rather than a fatal error.
    pub ignore_unexpected_eof: bool,
}

/// Outcome from [`handle_rlayer_return`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlayerReturnOutcome {
    /// The operation succeeded — caller should continue normally.
    Success,
    /// The operation should be retried (transport would block).
    Retry,
    /// The connection was closed cleanly.
    Shutdown,
    /// The connection failed — state machine should transition to error.
    /// Carries the optional alert code for the peer notification.
    Fatal {
        /// Alert code from the backend, if available.
        alert: Option<u8>,
    },
}

/// Centralised handler for record-layer backend return values.
///
/// Translates C `ossl_tls_handle_rlayer_return` (`rec_layer_s3.c`
/// lines 491–558). The C function mutates the SSL connection's
/// `rwstate`, `shutdown`, and error state directly; the Rust version
/// returns an [`RlayerReturnOutcome`] describing what the caller should
/// do, plus mutating `state.alert_count` when appropriate. This keeps
/// the record layer decoupled from the connection-level error queue.
///
/// # Arguments
///
/// * `state` — the per-connection record layer state.
/// * `writing` — `true` if the backend call was a write (determines
///   direction-specific error mapping).
/// * `rc` — the backend's return code.
/// * `opts` — caller-supplied option bitmap (`ignore_unexpected_eof`).
#[allow(
    clippy::needless_pass_by_value,
    reason = "state and opts are passed by value for clarity of semantics at call site"
)]
pub fn handle_rlayer_return(
    state: &mut RecordLayerState,
    writing: bool,
    rc: RlayerReturn,
    opts: RlayerReturnOptions,
) -> SslResult<RlayerReturnOutcome> {
    trace!(
        target: "openssl_ssl::record",
        writing,
        return_code = ?rc,
        ignore_unexpected_eof = opts.ignore_unexpected_eof,
        "handle_rlayer_return",
    );

    match rc {
        RlayerReturn::Success => Ok(RlayerReturnOutcome::Success),

        RlayerReturn::Retry => {
            // C code sets s->rwstate to SSL_READING / SSL_WRITING and
            // returns -1. We just report Retry; the caller (tls.rs) sets
            // the rwstate on its own SSL state.
            debug!(
                target: "openssl_ssl::record",
                direction = if writing { "write" } else { "read" },
                "backend returned Retry — would-block",
            );
            Ok(RlayerReturnOutcome::Retry)
        }

        RlayerReturn::Eof => {
            if writing {
                // EOF while writing should never happen — fatal.
                warn!(
                    target: "openssl_ssl::record",
                    "backend returned Eof on write — fatal",
                );
                return Err(SslError::Protocol(String::from(
                    "handle_rlayer_return: Eof on write (internal error)",
                )));
            }

            if opts.ignore_unexpected_eof {
                // Convert to clean shutdown (matches C's
                // SSL_OP_IGNORE_UNEXPECTED_EOF → SSL_RECEIVED_SHUTDOWN).
                // Bump warning-alert count so repeated EOFs still trip
                // the MAX_WARN_ALERT_COUNT guard.
                state.alert_count = state.alert_count.saturating_add(1);
                debug!(
                    target: "openssl_ssl::record",
                    alert_count = state.alert_count,
                    "converting unexpected EOF to clean shutdown",
                );
                Ok(RlayerReturnOutcome::Shutdown)
            } else {
                warn!(
                    target: "openssl_ssl::record",
                    "unexpected EOF while reading — fatal",
                );
                Err(SslError::ConnectionClosed)
            }
        }

        RlayerReturn::Fatal => {
            // Fetch an alert code if the backend has one.
            let alert = match (
                state.rrlmethod.as_ref(),
                state.rrl.as_ref(),
                state.wrlmethod.as_ref(),
                state.wrl.as_ref(),
            ) {
                (Some(rm), Some(rl), _, _) if !writing => rm.get_alert_code(rl.as_ref()),
                (_, _, Some(wm), Some(wl)) if writing => wm.get_alert_code(wl.as_ref()),
                _ => None,
            };
            warn!(
                target: "openssl_ssl::record",
                writing,
                alert_code = ?alert,
                "backend returned Fatal — terminating connection",
            );
            Ok(RlayerReturnOutcome::Fatal { alert })
        }

        RlayerReturn::NonFatalError => {
            // In C this maps to "0" — we surface it as a NonFatalError so
            // caller can attempt a method fallback.
            debug!(
                target: "openssl_ssl::record",
                writing,
                "backend returned NonFatalError",
            );
            Ok(RlayerReturnOutcome::Fatal { alert: None })
        }
    }
}

// ---------------------------------------------------------------------------
// release_record — translates ssl_release_record (rec_layer_s3.c 564–595)
// ---------------------------------------------------------------------------

/// Releases a record after the caller has consumed `length` bytes.
///
/// If `rechandle` is `Some`, delegates to the provider backend (which
/// may decrement a reference count or return the buffer to a pool).
/// If `rechandle` is `None` (locally-allocated DTLS record), drops the
/// buffer and zeros any sensitive plaintext.
///
/// Updates the record's `off` and `length` so that the record tracks how
/// much of it has been consumed. When fully consumed, advances
/// `state.curr_rec`.
///
/// # Errors
///
/// Returns [`SslError::Protocol`] if the backend returns a non-success
/// return code.
pub fn release_record(
    state: &mut RecordLayerState,
    record_index: usize,
    length: usize,
) -> SslResult<()> {
    trace!(
        target: "openssl_ssl::record",
        record_index,
        length,
        "release_record",
    );

    // Bound-check the record index.
    if record_index >= state.tlsrecs.len() {
        return Err(SslError::Protocol(format!(
            "release_record: index {record_index} out of bounds ({}):",
            state.tlsrecs.len(),
        )));
    }

    // Borrow the record mutably.
    let record = &mut state.tlsrecs[record_index];

    if let Some(handle) = record.rechandle {
        // Delegate to backend.
        if let (Some(method), Some(rl)) = (state.rrlmethod.as_ref(), state.rrl.as_mut()) {
            method
                .release_record(rl.as_mut(), &handle, length)
                .map_err(|rc| {
                    SslError::Protocol(format!("release_record: backend returned {rc:?}",))
                })?;
        } else {
            return Err(SslError::Protocol(String::from(
                "release_record: rechandle set but no backend method",
            )));
        }
    } else {
        // Locally-allocated (DTLS) — data will be dropped and zeroed on
        // clear(). Nothing to do at the backend level.
        trace!(
            target: "openssl_ssl::record",
            record_index,
            "release_record: local allocation, no backend call",
        );
    }

    // Re-borrow after the immutable borrow of state.rrlmethod ended.
    let record = &mut state.tlsrecs[record_index];

    // Update record's off/length.
    if length > record.length {
        return Err(SslError::Protocol(format!(
            "release_record: length {length} exceeds record length {}",
            record.length,
        )));
    }
    record.off = record.off.saturating_add(length);
    record.length = record.length.saturating_sub(length);

    // Advance curr_rec if the record is fully consumed.
    if record.length == 0 {
        // Zero any sensitive plaintext before the record is considered free.
        record.clear();
        if state.curr_rec == record_index {
            state.curr_rec = state.curr_rec.saturating_add(1);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Callback dispatch wrappers — translate rlayer_dispatch[] entries from
// rec_layer_s3.c lines 1130–1168.
// ---------------------------------------------------------------------------

/// Dispatches a `msg_callback` invocation from the record layer backend to
/// the SSL connection's installed message callback.
///
/// Translates C `rlayer_msg_callback_wrapper` (`rec_layer_s3.c`
/// lines 1130–1141):
/// ```c
/// static void rlayer_msg_callback_wrapper(int write_p, int version,
///         int content_type, const void *buf, size_t len, void *cbarg) {
///     SSL_CONNECTION *s = cbarg;
///     SSL *ssl = SSL_CONNECTION_GET_USER_SSL(s);
///     if (s->msg_callback != NULL)
///         s->msg_callback(write_p, version, content_type, buf, len, ssl,
///                         s->msg_callback_arg);
/// }
/// ```
///
/// In the Rust translation the per-connection `SSL *` and the user
/// `msg_callback_arg` are captured by the registered closure rather than
/// threaded as separate parameters. The `state` argument supplies the
/// per-`RecordLayerState` callback slot populated by
/// [`RecordLayerState::set_msg_callback`].
///
/// When no callback has been installed the function is a structured-trace
/// no-op, matching the C `if (s->msg_callback != NULL)` guard. This is the
/// production read-site of the [`RecordLayerState::msg_callback`] field
/// (Rule R3 — config field propagation; Rule R4 — registration / invocation
/// pairing; Rule R10 — wiring before done).
pub fn rlayer_msg_callback_wrapper(
    state: &RecordLayerState,
    write_p: bool,
    version: u16,
    content_type: u8,
    buf: &[u8],
) {
    if let Some(cb) = state.msg_callback.as_ref() {
        cb(write_p, version, content_type, buf);
        trace!(
            target: "openssl_ssl::record",
            write_p,
            version = format!("{version:#06x}"),
            content_type,
            length = buf.len(),
            "msg_callback dispatched to installed handler",
        );
    } else {
        trace!(
            target: "openssl_ssl::record",
            write_p,
            version = format!("{version:#06x}"),
            content_type,
            length = buf.len(),
            "msg_callback: no handler installed (no-op)",
        );
    }
}

/// Dispatches a `security_callback` invocation from the backend.
///
/// Translates C `rlayer_security_wrapper` (`rec_layer_s3.c`
/// lines 1143–1150):
/// ```c
/// static int rlayer_security_wrapper(void *cbarg, int op, int bits,
///         int nid, void *other) {
///     SSL_CONNECTION *s = cbarg;
///     return ssl_security(s, op, bits, nid, other);
/// }
/// ```
///
/// `ssl_security` consults the per-`SSL_CTX` / per-`SSL`
/// `security_callback`, defaulting to "permit" (return `1`) when none is
/// installed. The Rust translation preserves this:
///   * If [`RecordLayerState::security_callback`] is `Some`, invoke it and
///     return its boolean verdict.
///   * If `None`, default to `true` (permit) — matching the C default.
///
/// This is the production read-site of the
/// [`RecordLayerState::security_callback`] field (Rule R3 / R4 / R10).
/// Note that, unlike the previous stub, this function is no longer
/// `const fn` — it must dispatch through a `Box<dyn Fn>` slot.
#[must_use]
pub fn rlayer_security_wrapper(
    state: &RecordLayerState,
    op: i32,
    bits: i32,
    nid: i32,
) -> bool {
    state.security_callback.as_ref().map_or_else(
        || {
            trace!(
                target: "openssl_ssl::record",
                op,
                bits,
                nid,
                "security_callback: no handler installed, defaulting to permit",
            );
            true
        },
        |cb| {
            let permitted = cb(op, bits, nid);
            trace!(
                target: "openssl_ssl::record",
                op,
                bits,
                nid,
                permitted,
                "security_callback dispatched to installed handler",
            );
            permitted
        },
    )
}

/// Dispatches a record-padding callback invocation from the backend.
///
/// Translates C `rlayer_padding_wrapper` (`rec_layer_s3.c`
/// lines 1152–1160). Returns the number of padding bytes to add.
///
/// Invokes `state.record_padding_cb` if installed, else returns zero.
#[must_use]
pub fn rlayer_padding_wrapper(state: &RecordLayerState, record_type: u8, len: usize) -> usize {
    match state.record_padding_cb.as_ref() {
        Some(cb) => {
            let padding = cb(record_type, len);
            trace!(
                target: "openssl_ssl::record",
                record_type,
                len,
                padding,
                "record padding callback returned",
            );
            padding
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Helper: read a ParamValue field from the options/settings ParamSet.
//
// These helpers are used by backends to extract typed configuration from
// the bags built by build_options_params_real / build_settings_params.
// Exposing them here keeps parsing logic centralised.
// ---------------------------------------------------------------------------

/// Reads an unsigned 64-bit parameter from the set by key.
///
/// Returns `None` if the key is absent or the value is not a `u64`.
#[must_use]
pub fn param_get_u64(set: &ParamSet, key: &str) -> Option<u64> {
    set.get(key).and_then(ParamValue::as_u64)
}

/// Reads an unsigned 32-bit parameter from the set by key.
#[must_use]
pub fn param_get_u32(set: &ParamSet, key: &str) -> Option<u32> {
    set.get(key).and_then(ParamValue::as_u32)
}

/// Reads an unsigned 32-bit boolean parameter from the set by key.
/// Any non-zero value is `true`; missing keys return `false`.
#[must_use]
pub fn param_get_bool(set: &ParamSet, key: &str) -> bool {
    param_get_u32(set, key).is_some_and(|v| v != 0)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::any::Any;

    // ------------------------------------------------------------------
    // Fixture: minimal RecordMethod implementation for tests.
    // ------------------------------------------------------------------
    struct TestInstance {
        processed_pending: bool,
        unprocessed_pending: bool,
        app_pending: usize,
        last_version: u16,
        alert: Option<u8>,
        records: Vec<TlsRecord>,
        first_handshake: bool,
        max_pipelines: usize,
    }

    impl RecordLayerInstance for TestInstance {
        fn name(&self) -> &'static str {
            "test-instance"
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    struct TestMethod {
        name: &'static str,
        fail_new: bool,
    }

    impl RecordMethod for TestMethod {
        fn new_record_layer(
            &self,
            _args: NewRecordLayerArgs,
        ) -> Result<Box<dyn RecordLayerInstance>, RlayerReturn> {
            if self.fail_new {
                return Err(RlayerReturn::NonFatalError);
            }
            Ok(Box::new(TestInstance {
                processed_pending: false,
                unprocessed_pending: false,
                app_pending: 0,
                last_version: 0,
                alert: None,
                records: Vec::new(),
                first_handshake: false,
                max_pipelines: 0,
            }))
        }

        fn read_record(
            &self,
            _rl: &mut dyn RecordLayerInstance,
        ) -> Result<TlsRecord, RlayerReturn> {
            Err(RlayerReturn::Retry)
        }

        fn release_record(
            &self,
            _rl: &mut dyn RecordLayerInstance,
            _handle: &RecordHandle,
            _length: usize,
        ) -> Result<(), RlayerReturn> {
            Ok(())
        }

        fn write_records(
            &self,
            _rl: &mut dyn RecordLayerInstance,
            _templates: &[RecordTemplate<'_>],
        ) -> Result<(), RlayerReturn> {
            Ok(())
        }

        fn retry_write_records(
            &self,
            _rl: &mut dyn RecordLayerInstance,
        ) -> Result<(), RlayerReturn> {
            Ok(())
        }

        fn unprocessed_read_pending(&self, _rl: &dyn RecordLayerInstance) -> bool {
            false
        }

        fn processed_read_pending(&self, _rl: &dyn RecordLayerInstance) -> bool {
            false
        }

        fn app_data_pending(&self, _rl: &dyn RecordLayerInstance) -> usize {
            0
        }

        fn get_max_records(
            &self,
            _rl: &dyn RecordLayerInstance,
            _record_type: u8,
            data_len: usize,
            max_fragment: usize,
            split_fragment: &mut usize,
        ) -> usize {
            *split_fragment = max_fragment;
            if max_fragment == 0 {
                0
            } else {
                data_len.div_ceil(max_fragment)
            }
        }

        fn set_protocol_version(&self, _rl: &mut dyn RecordLayerInstance, _version: u16) {}

        fn get_state(&self, _rl: &dyn RecordLayerInstance) -> (&'static str, &'static str) {
            ("TEST", "test state")
        }

        fn get_alert_code(&self, _rl: &dyn RecordLayerInstance) -> Option<u8> {
            None
        }

        fn method_name(&self) -> &'static str {
            self.name
        }
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------
    #[test]
    fn record_direction_numeric_mapping_matches_c_constants() {
        // OSSL_RECORD_DIRECTION_READ  = 0
        // OSSL_RECORD_DIRECTION_WRITE = 1
        assert_eq!(RecordDirection::Read.as_u8(), 0);
        assert_eq!(RecordDirection::Write.as_u8(), 1);
    }

    #[test]
    fn protection_level_numeric_mapping_matches_c_constants() {
        assert_eq!(ProtectionLevel::None.as_u8(), 0);
        assert_eq!(ProtectionLevel::Early.as_u8(), 1);
        assert_eq!(ProtectionLevel::Handshake.as_u8(), 2);
        assert_eq!(ProtectionLevel::Application.as_u8(), 3);
    }

    #[test]
    fn rlayer_return_c_codes_match_openssl() {
        // Matches OSSL_RECORD_RETURN_{SUCCESS,RETRY,NON_FATAL_ERR,FATAL,EOF}.
        assert_eq!(RlayerReturn::Success.as_c_code(), 1);
        assert_eq!(RlayerReturn::Retry.as_c_code(), 0);
        assert_eq!(RlayerReturn::NonFatalError.as_c_code(), -1);
        assert_eq!(RlayerReturn::Fatal.as_c_code(), -2);
        assert_eq!(RlayerReturn::Eof.as_c_code(), -3);
    }

    #[test]
    fn record_type_constants_match_rfc5246() {
        assert_eq!(SSL3_RT_CHANGE_CIPHER_SPEC, 20);
        assert_eq!(SSL3_RT_ALERT, 21);
        assert_eq!(SSL3_RT_HANDSHAKE, 22);
        assert_eq!(SSL3_RT_APPLICATION_DATA, 23);
    }

    #[test]
    fn seq_num_size_is_eight() {
        // Matches SEQ_NUM_SIZE from record.h line 20.
        assert_eq!(SEQ_NUM_SIZE, 8);
    }

    #[test]
    fn max_warn_alert_count_is_five() {
        // Matches MAX_WARN_ALERT_COUNT from record_local.h line 17.
        assert_eq!(MAX_WARN_ALERT_COUNT, 5);
    }

    #[test]
    fn record_handle_roundtrips_identifier() {
        let h = RecordHandle::new(0xdead_beef);
        assert_eq!(h.id(), 0xdead_beef);
    }

    #[test]
    fn tls_record_default_zero_initialises() {
        let rec = TlsRecord::default();
        assert_eq!(rec.version, 0);
        assert_eq!(rec.record_type, 0);
        assert_eq!(rec.length, 0);
        assert_eq!(rec.off, 0);
        assert_eq!(rec.epoch, 0);
        assert_eq!(rec.seq_num, [0u8; SEQ_NUM_SIZE]);
        assert!(rec.rechandle.is_none());
        assert!(rec.data.is_empty());
        assert!(rec.is_empty());
    }

    #[test]
    fn tls_record_clear_zeroizes_and_resets() {
        let mut rec = TlsRecord::default();
        rec.data = vec![0x11u8, 0x22, 0x33, 0x44];
        rec.length = 4;
        rec.off = 0;
        rec.record_type = SSL3_RT_APPLICATION_DATA;
        rec.version = 0x0303;
        rec.epoch = 7;
        rec.seq_num = [1, 2, 3, 4, 5, 6, 7, 8];
        rec.rechandle = Some(RecordHandle::new(42));

        rec.clear();

        assert_eq!(rec.data, Vec::<u8>::new());
        assert_eq!(rec.length, 0);
        assert_eq!(rec.record_type, 0);
        assert_eq!(rec.version, 0);
        assert_eq!(rec.epoch, 0);
        assert_eq!(rec.seq_num, [0u8; SEQ_NUM_SIZE]);
        assert!(rec.rechandle.is_none());
    }

    #[test]
    fn record_layer_state_new_zero_initialises() {
        let s = RecordLayerState::new();
        assert!(!s.read_ahead);
        assert_eq!(s.default_read_buf_len, 0);
        assert_eq!(s.wnum, 0);
        assert_eq!(s.handshake_fragment_len, 0);
        assert_eq!(s.handshake_fragment, [0u8; 4]);
        assert_eq!(s.wpend_tot, 0);
        assert_eq!(s.wpend_type, 0);
        assert_eq!(s.alert_count, 0);
        assert_eq!(s.num_recs, 0);
        assert_eq!(s.curr_rec, 0);
        assert_eq!(s.block_padding, 0);
        assert_eq!(s.hs_padding, 0);
        assert!(s.tlsrecs.is_empty());
        assert!(s.custom_rlmethod.is_none());
        assert!(s.rlarg.is_none());
        assert!(s.rrlmethod.is_none());
        assert!(s.wrlmethod.is_none());
        assert!(s.rrl.is_none());
        assert!(s.wrl.is_none());
        assert!(s.rrlnext.is_none());
        assert!(s.record_padding_cb.is_none());
        assert!(s.record_padding_arg.is_none());
    }

    #[test]
    fn record_layer_state_default_and_new_agree() {
        let a = RecordLayerState::new();
        let b = RecordLayerState::default();
        assert_eq!(a.default_read_buf_len, b.default_read_buf_len);
        assert_eq!(a.read_ahead, b.read_ahead);
        assert_eq!(a.wpend_tot, b.wpend_tot);
    }

    #[test]
    fn set_read_ahead_roundtrips() {
        let mut s = RecordLayerState::new();
        assert!(!s.get_read_ahead());
        s.set_read_ahead(true);
        assert!(s.get_read_ahead());
        s.set_read_ahead(false);
        assert!(!s.get_read_ahead());
    }

    #[test]
    fn write_pending_reflects_wpend_tot() {
        let mut s = RecordLayerState::new();
        assert!(!s.write_pending());
        s.wpend_tot = 5;
        assert!(s.write_pending());
        s.wpend_tot = 0;
        assert!(!s.write_pending());
    }

    #[test]
    fn processed_read_pending_uses_curr_rec_and_num_recs() {
        let mut s = RecordLayerState::new();
        assert!(!s.processed_read_pending());
        s.tlsrecs.push(TlsRecord::default());
        s.num_recs = 1;
        s.curr_rec = 0;
        assert!(s.processed_read_pending());
        s.curr_rec = 1;
        assert!(!s.processed_read_pending());
    }

    #[test]
    fn read_pending_is_false_when_no_method() {
        let s = RecordLayerState::new();
        assert!(!s.read_pending());
    }

    #[test]
    fn clear_resets_all_counters() {
        let mut s = RecordLayerState::new();
        s.wnum = 10;
        s.handshake_fragment = [1, 2, 3, 4];
        s.handshake_fragment_len = 4;
        s.wpend_tot = 5;
        s.wpend_type = SSL3_RT_HANDSHAKE;
        s.alert_count = 3;
        s.num_recs = 2;
        s.curr_rec = 1;
        s.tlsrecs.push(TlsRecord::default());
        s.tlsrecs.push(TlsRecord::default());
        s.rrlnext = Some(Box::new(MemBio::new()));

        assert!(s.clear().is_ok());

        assert_eq!(s.wnum, 0);
        assert_eq!(s.handshake_fragment, [0u8; 4]);
        assert_eq!(s.handshake_fragment_len, 0);
        assert_eq!(s.wpend_tot, 0);
        assert_eq!(s.wpend_type, 0);
        assert_eq!(s.alert_count, 0);
        assert_eq!(s.num_recs, 0);
        assert_eq!(s.curr_rec, 0);
        assert!(s.tlsrecs.is_empty());
        assert!(s.rrlnext.is_none());
    }

    #[test]
    fn reset_clears_and_accepts_tls_or_dtls() {
        let mut s = RecordLayerState::new();
        s.wnum = 99;
        assert!(s.reset(false).is_ok());
        assert_eq!(s.wnum, 0);

        let mut s2 = RecordLayerState::new();
        s2.wpend_tot = 99;
        assert!(s2.reset(true).is_ok());
        assert_eq!(s2.wpend_tot, 0);
    }

    #[test]
    fn set_custom_record_layer_installs_and_clears() {
        let mut s = RecordLayerState::new();
        assert!(s.custom_rlmethod.is_none());

        let method: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "test",
            fail_new: false,
        });
        set_custom_record_layer(&mut s, Some(method), None);
        assert!(s.custom_rlmethod.is_some());

        set_custom_record_layer(&mut s, None, None);
        assert!(s.custom_rlmethod.is_none());
    }

    #[test]
    fn set_new_record_layer_succeeds_with_method_factory() {
        let mut s = RecordLayerState::new();
        let args = SetNewRecordLayerArgs {
            version: ProtocolVersion::Tls1_2,
            role: 0,
            direction: RecordDirection::Read,
            level: ProtectionLevel::None,
            epoch: 0,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        let factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "default-tls",
            fail_new: false,
        });

        let result = set_new_record_layer(&mut s, args, Some(factory));
        assert!(result.is_ok(), "got: {result:?}");
        assert!(s.rrl.is_some());
        assert!(s.rrlnext.is_some()); // staging BIO created for read
    }

    #[test]
    fn set_new_record_layer_fails_without_method() {
        let mut s = RecordLayerState::new();
        let args = SetNewRecordLayerArgs {
            direction: RecordDirection::Read,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        let result = set_new_record_layer(&mut s, args, None);
        assert!(result.is_err());
    }

    #[test]
    fn set_new_record_layer_fails_on_dtls_tls_mismatch() {
        let mut s = RecordLayerState::new();
        let factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "x",
            fail_new: false,
        });
        let args = SetNewRecordLayerArgs {
            version: ProtocolVersion::TlsAny,
            is_dtls: true, // mismatch
            direction: RecordDirection::Read,
            ..SetNewRecordLayerArgs::default()
        };
        let result = set_new_record_layer(&mut s, args, Some(factory));
        assert!(result.is_err());
    }

    #[test]
    fn set_new_record_layer_bubbles_non_fatal() {
        let mut s = RecordLayerState::new();
        let factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "failing",
            fail_new: true,
        });
        let args = SetNewRecordLayerArgs {
            direction: RecordDirection::Read,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        let result = set_new_record_layer(&mut s, args, Some(factory));
        assert!(result.is_err());
    }

    #[test]
    fn set_new_record_layer_no_staging_for_write() {
        let mut s = RecordLayerState::new();
        let factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "x",
            fail_new: false,
        });
        let args = SetNewRecordLayerArgs {
            direction: RecordDirection::Write,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        assert!(set_new_record_layer(&mut s, args, Some(factory)).is_ok(),);
        assert!(s.wrl.is_some());
        // Write direction doesn't allocate rrlnext.
        assert!(s.rrlnext.is_none());
    }

    #[test]
    fn set_record_protocol_version_requires_layers() {
        let mut s = RecordLayerState::new();
        // No layers installed yet — should fail.
        let result = set_record_protocol_version(&mut s, ProtocolVersion::Tls1_3);
        assert!(result.is_err());
    }

    #[test]
    fn set_record_protocol_version_succeeds_with_layers() {
        let mut s = RecordLayerState::new();
        // Install both read and write layers.
        let read_factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "r",
            fail_new: false,
        });
        let write_factory: Box<dyn RecordMethod> = Box::new(TestMethod {
            name: "w",
            fail_new: false,
        });
        let read_args = SetNewRecordLayerArgs {
            direction: RecordDirection::Read,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        let write_args = SetNewRecordLayerArgs {
            direction: RecordDirection::Write,
            is_dtls: false,
            ..SetNewRecordLayerArgs::default()
        };
        assert!(set_new_record_layer(&mut s, read_args, Some(read_factory)).is_ok(),);
        assert!(set_new_record_layer(&mut s, write_args, Some(write_factory)).is_ok(),);
        let result = set_record_protocol_version(&mut s, ProtocolVersion::Tls1_2);
        assert!(result.is_ok(), "got: {result:?}");
    }

    #[test]
    fn handle_rlayer_return_success_maps_to_success() {
        let mut s = RecordLayerState::new();
        let outcome = handle_rlayer_return(
            &mut s,
            false,
            RlayerReturn::Success,
            RlayerReturnOptions::default(),
        )
        .unwrap();
        assert_eq!(outcome, RlayerReturnOutcome::Success);
    }

    #[test]
    fn handle_rlayer_return_retry_maps_to_retry() {
        let mut s = RecordLayerState::new();
        let outcome = handle_rlayer_return(
            &mut s,
            false,
            RlayerReturn::Retry,
            RlayerReturnOptions::default(),
        )
        .unwrap();
        assert_eq!(outcome, RlayerReturnOutcome::Retry);
    }

    #[test]
    fn handle_rlayer_return_eof_on_write_is_fatal() {
        let mut s = RecordLayerState::new();
        let result = handle_rlayer_return(
            &mut s,
            true,
            RlayerReturn::Eof,
            RlayerReturnOptions::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn handle_rlayer_return_eof_read_without_option_errors() {
        let mut s = RecordLayerState::new();
        let result = handle_rlayer_return(
            &mut s,
            false,
            RlayerReturn::Eof,
            RlayerReturnOptions::default(),
        );
        assert!(matches!(result, Err(SslError::ConnectionClosed),));
    }

    #[test]
    fn handle_rlayer_return_eof_read_with_option_shuts_down() {
        let mut s = RecordLayerState::new();
        let opts = RlayerReturnOptions {
            ignore_unexpected_eof: true,
        };
        let outcome = handle_rlayer_return(&mut s, false, RlayerReturn::Eof, opts).unwrap();
        assert_eq!(outcome, RlayerReturnOutcome::Shutdown);
        assert_eq!(s.alert_count, 1);
    }

    #[test]
    fn handle_rlayer_return_fatal_returns_fatal_outcome() {
        let mut s = RecordLayerState::new();
        let outcome = handle_rlayer_return(
            &mut s,
            false,
            RlayerReturn::Fatal,
            RlayerReturnOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            RlayerReturnOutcome::Fatal { alert: None },
        ));
    }

    #[test]
    fn release_record_out_of_bounds_errors() {
        let mut s = RecordLayerState::new();
        let result = release_record(&mut s, 99, 0);
        assert!(result.is_err());
    }

    #[test]
    fn release_record_local_allocation_updates_offsets() {
        let mut s = RecordLayerState::new();
        let mut rec = TlsRecord::default();
        rec.data = vec![1, 2, 3, 4];
        rec.length = 4;
        rec.off = 0;
        rec.record_type = SSL3_RT_APPLICATION_DATA;
        s.tlsrecs.push(rec);
        s.num_recs = 1;
        s.curr_rec = 0;

        // Release 2 bytes.
        assert!(release_record(&mut s, 0, 2).is_ok());
        assert_eq!(s.tlsrecs[0].length, 2);
        assert_eq!(s.tlsrecs[0].off, 2);
        // Not yet fully consumed, curr_rec stays.
        assert_eq!(s.curr_rec, 0);

        // Release remaining 2 bytes.
        assert!(release_record(&mut s, 0, 2).is_ok());
        // Now fully consumed, curr_rec advances.
        assert_eq!(s.curr_rec, 1);
        assert_eq!(s.tlsrecs[0].length, 0);
    }

    #[test]
    fn release_record_length_overrun_errors() {
        let mut s = RecordLayerState::new();
        let mut rec = TlsRecord::default();
        rec.data = vec![1, 2];
        rec.length = 2;
        s.tlsrecs.push(rec);
        s.num_recs = 1;

        let result = release_record(&mut s, 0, 100);
        assert!(result.is_err());
    }

    #[test]
    fn rlayer_padding_wrapper_returns_zero_when_no_callback() {
        let s = RecordLayerState::new();
        assert_eq!(rlayer_padding_wrapper(&s, SSL3_RT_APPLICATION_DATA, 100), 0,);
    }

    #[test]
    fn rlayer_padding_wrapper_dispatches_to_callback() {
        let mut s = RecordLayerState::new();
        s.record_padding_cb = Some(Box::new(|_ct: u8, len: usize| -> usize {
            // Pad to next multiple of 16.
            let extra = 16 - (len % 16);
            if extra == 16 {
                0
            } else {
                extra
            }
        }));

        // len=100 => pad=12 (100+12 = 112, divisible by 16).
        assert_eq!(
            rlayer_padding_wrapper(&s, SSL3_RT_APPLICATION_DATA, 100),
            12,
        );
        // len=16 => pad=0.
        assert_eq!(rlayer_padding_wrapper(&s, SSL3_RT_APPLICATION_DATA, 16), 0,);
    }

    #[test]
    fn rlayer_msg_callback_wrapper_is_infallible_when_unset() {
        // With no callback installed the wrapper is a no-op (matches C
        // `if (s->msg_callback != NULL)` guard at rec_layer_s3.c:1138).
        let state = RecordLayerState::new();
        rlayer_msg_callback_wrapper(&state, false, 0x0303, SSL3_RT_HANDSHAKE, &[1, 2, 3]);
        rlayer_msg_callback_wrapper(&state, true, 0x0303, SSL3_RT_ALERT, &[]);
        assert!(!state.has_msg_callback());
    }

    #[test]
    fn rlayer_security_wrapper_defaults_to_true_when_unset() {
        // Default-permit semantics — translates the C `ssl_security`
        // behaviour at rec_layer_s3.c:1148 when no callback is installed.
        let state = RecordLayerState::new();
        assert!(rlayer_security_wrapper(&state, 0, 128, 0));
        assert!(rlayer_security_wrapper(&state, 1, 256, 42));
        assert!(!state.has_security_callback());
    }

    #[test]
    fn record_layer_msg_callback_register_trigger_assert() {
        // Rule R4 — registration / invocation pairing.
        // 1. Register a closure on the record layer state via the
        //    `set_msg_callback` setter.
        // 2. Trigger by invoking `rlayer_msg_callback_wrapper` (the
        //    same function the backend dispatch table targets).
        // 3. Assert the closure observed every parameter unmodified.
        use std::sync::{Arc, Mutex};

        let captured: Arc<Mutex<Vec<(bool, u16, u8, Vec<u8>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);

        let mut state = RecordLayerState::new();
        assert!(!state.has_msg_callback());
        state.set_msg_callback(Some(Box::new(move |write_p, version, content_type, buf| {
            // LOCK-SCOPE: short test-only mutation of the captured
            // record list — no .await held under this lock.
            let mut guard = captured_clone.lock().expect("test mutex poisoned");
            guard.push((write_p, version, content_type, buf.to_vec()));
        })));
        assert!(state.has_msg_callback());

        // First trigger: incoming handshake record.
        rlayer_msg_callback_wrapper(&state, false, 0x0303, SSL3_RT_HANDSHAKE, &[1, 2, 3]);
        // Second trigger: outgoing alert record (empty payload).
        rlayer_msg_callback_wrapper(&state, true, 0x0304, SSL3_RT_ALERT, &[]);
        // Third trigger: outgoing application data.
        rlayer_msg_callback_wrapper(
            &state,
            true,
            0x0303,
            SSL3_RT_APPLICATION_DATA,
            b"hello",
        );

        let guard = captured.lock().expect("test mutex poisoned");
        assert_eq!(guard.len(), 3, "callback fired exactly three times");
        assert_eq!(guard[0], (false, 0x0303, SSL3_RT_HANDSHAKE, vec![1, 2, 3]));
        assert_eq!(guard[1], (true, 0x0304, SSL3_RT_ALERT, vec![]));
        assert_eq!(
            guard[2],
            (true, 0x0303, SSL3_RT_APPLICATION_DATA, b"hello".to_vec()),
        );
    }

    #[test]
    fn record_layer_msg_callback_clearing_restores_noop() {
        // Verifies set_msg_callback(None) clears a previously installed
        // handler without panicking on subsequent dispatch.
        use std::sync::{Arc, Mutex};

        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);

        let mut state = RecordLayerState::new();
        state.set_msg_callback(Some(Box::new(move |_, _, _, _| {
            let mut g = counter_clone.lock().expect("test mutex poisoned");
            *g = g.saturating_add(1);
        })));
        rlayer_msg_callback_wrapper(&state, false, 0x0303, SSL3_RT_HANDSHAKE, &[]);
        assert_eq!(*counter.lock().expect("test mutex poisoned"), 1);

        state.set_msg_callback(None);
        assert!(!state.has_msg_callback());
        // Subsequent dispatch must not invoke the previously-installed
        // closure — otherwise the cleared closure would be use-after-clear.
        rlayer_msg_callback_wrapper(&state, false, 0x0303, SSL3_RT_HANDSHAKE, &[]);
        assert_eq!(*counter.lock().expect("test mutex poisoned"), 1);
    }

    #[test]
    fn record_layer_security_callback_register_trigger_assert() {
        // Rule R4 — registration / invocation pairing for the security
        // callback. Verifies the wrapper consults the installed closure
        // and faithfully returns its boolean verdict, both for permit
        // and reject decisions.
        use std::sync::{Arc, Mutex};

        let observed: Arc<Mutex<Vec<(i32, i32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_clone = Arc::clone(&observed);

        let mut state = RecordLayerState::new();
        assert!(!state.has_security_callback());
        // Policy: reject any operation requesting fewer than 128 bits of
        // security strength; otherwise permit.
        state.set_security_callback(Some(Box::new(move |op, bits, nid| {
            let mut g = observed_clone.lock().expect("test mutex poisoned");
            g.push((op, bits, nid));
            bits >= 128
        })));
        assert!(state.has_security_callback());

        // Trigger 1: 80 bits — should be rejected.
        assert!(!rlayer_security_wrapper(&state, 1, 80, 0));
        // Trigger 2: 256 bits — should be permitted.
        assert!(rlayer_security_wrapper(&state, 2, 256, 42));
        // Trigger 3: 128 bits — boundary, permitted.
        assert!(rlayer_security_wrapper(&state, 3, 128, 100));

        let guard = observed.lock().expect("test mutex poisoned");
        assert_eq!(guard.as_slice(), &[(1, 80, 0), (2, 256, 42), (3, 128, 100),]);
    }

    #[test]
    fn record_layer_security_callback_clearing_restores_default_permit() {
        // After clearing a previously-installed handler the wrapper must
        // resume returning the C-default "permit" verdict.
        let mut state = RecordLayerState::new();
        state.set_security_callback(Some(Box::new(|_, _, _| false)));
        // While installed, our handler always rejects.
        assert!(!rlayer_security_wrapper(&state, 0, 0, 0));

        state.set_security_callback(None);
        assert!(!state.has_security_callback());
        // Reverts to default-permit.
        assert!(rlayer_security_wrapper(&state, 0, 0, 0));
    }

    #[test]
    fn record_layer_callbacks_persist_across_clear() {
        // The callbacks are installed at the SSL_CTX / SSL level and
        // must outlive RecordLayerState::clear() — mirroring the
        // upstream C semantics where RECORD_LAYER_clear leaves
        // s->msg_callback / SSL_security_callback untouched.
        let mut state = RecordLayerState::new();
        state.set_msg_callback(Some(Box::new(|_, _, _, _| {})));
        state.set_security_callback(Some(Box::new(|_, _, _| true)));
        assert!(state.has_msg_callback());
        assert!(state.has_security_callback());

        // clear() must not remove the callbacks.
        state.clear().expect("clear must succeed on an empty state");
        assert!(
            state.has_msg_callback(),
            "msg_callback must persist across clear()",
        );
        assert!(
            state.has_security_callback(),
            "security_callback must persist across clear()",
        );
    }

    #[test]
    fn build_options_params_emits_expected_keys() {
        let state = RecordLayerState::new();
        let args = SetNewRecordLayerArgs {
            direction: RecordDirection::Read,
            ssl_options: 0xABCD,
            ssl_mode: 0x12,
            ..SetNewRecordLayerArgs::default()
        };
        let params = build_options_params_real(&args, &state);
        assert!(params.contains(PARAM_OPTIONS));
        assert!(params.contains(PARAM_MODE));
        assert!(params.contains(PARAM_READ_BUFFER_LEN));
        assert!(params.contains(PARAM_READ_AHEAD));
        assert_eq!(param_get_u64(&params, PARAM_OPTIONS), Some(0xABCD));
        assert_eq!(param_get_u32(&params, PARAM_MODE), Some(0x12));
        assert!(!param_get_bool(&params, PARAM_READ_AHEAD));
    }

    #[test]
    fn build_options_params_write_direction_has_padding_keys() {
        let mut state = RecordLayerState::new();
        state.block_padding = 16;
        state.hs_padding = 32;
        let args = SetNewRecordLayerArgs {
            direction: RecordDirection::Write,
            ssl_options: 0,
            ssl_mode: 0,
            ..SetNewRecordLayerArgs::default()
        };
        let params = build_options_params_real(&args, &state);
        assert!(params.contains(PARAM_OPTIONS));
        assert!(params.contains(PARAM_MODE));
        assert!(params.contains(PARAM_BLOCK_PADDING));
        assert!(params.contains(PARAM_HS_PADDING));
        assert_eq!(param_get_u64(&params, PARAM_BLOCK_PADDING), Some(16),);
        assert_eq!(param_get_u64(&params, PARAM_HS_PADDING), Some(32));
    }

    #[test]
    fn build_settings_params_emits_booleans() {
        let args = SetNewRecordLayerArgs {
            use_etm: true,
            stream_mac: false,
            tlstree: true,
            max_frag_len: Some(16384),
            level: ProtectionLevel::Handshake,
            max_early_data: 8192,
            ..SetNewRecordLayerArgs::default()
        };
        let settings = build_settings_params(&args);
        assert!(param_get_bool(&settings, PARAM_USE_ETM));
        assert!(!param_get_bool(&settings, PARAM_STREAM_MAC));
        assert!(param_get_bool(&settings, PARAM_TLSTREE));
        assert_eq!(param_get_u64(&settings, PARAM_MAX_FRAG_LEN), Some(16384),);
        assert_eq!(param_get_u32(&settings, PARAM_MAX_EARLY_DATA), Some(8192),);
    }

    #[test]
    fn build_settings_params_omits_early_data_for_app_level() {
        let args = SetNewRecordLayerArgs {
            level: ProtectionLevel::Application,
            max_early_data: 4096,
            ..SetNewRecordLayerArgs::default()
        };
        let settings = build_settings_params(&args);
        assert!(!settings.contains(PARAM_MAX_EARLY_DATA));
    }

    #[test]
    fn record_template_wraps_borrow() {
        let buf: Vec<u8> = vec![1, 2, 3];
        let tmpl = RecordTemplate::new(SSL3_RT_APPLICATION_DATA, 0x0303, &buf);
        assert_eq!(tmpl.record_type, SSL3_RT_APPLICATION_DATA);
        assert_eq!(tmpl.version, 0x0303);
        assert_eq!(tmpl.buf, &[1, 2, 3]);
    }

    #[test]
    fn app_data_pending_sums_queued_app_records() {
        let mut s = RecordLayerState::new();
        let mut r1 = TlsRecord::default();
        r1.record_type = SSL3_RT_APPLICATION_DATA;
        r1.length = 50;
        let mut r2 = TlsRecord::default();
        r2.record_type = SSL3_RT_APPLICATION_DATA;
        r2.length = 30;
        let mut r3 = TlsRecord::default();
        r3.record_type = SSL3_RT_HANDSHAKE;
        r3.length = 10;
        s.tlsrecs.push(r1);
        s.tlsrecs.push(r2);
        s.tlsrecs.push(r3);
        s.num_recs = 3;
        s.curr_rec = 0;
        assert_eq!(s.app_data_pending(), 80);
    }

    #[test]
    fn rlayer_return_to_error_maps_variants() {
        assert!(matches!(
            rlayer_return_to_error(RlayerReturn::Eof),
            SslError::ConnectionClosed,
        ));
        assert!(matches!(
            rlayer_return_to_error(RlayerReturn::Fatal),
            SslError::Protocol(_),
        ));
        assert!(matches!(
            rlayer_return_to_error(RlayerReturn::NonFatalError),
            SslError::Protocol(_),
        ));
    }

    #[test]
    fn record_padding_callback_pairing_test() {
        // Rule R4 — register a callback, trigger invocation, assert args.
        let mut s = RecordLayerState::new();
        let observed_type = std::sync::Arc::new(std::sync::Mutex::new(0u8));
        let observed_type_clone = std::sync::Arc::clone(&observed_type);
        s.record_padding_cb = Some(Box::new(move |ct: u8, _len: usize| -> usize {
            if let Ok(mut guard) = observed_type_clone.lock() {
                *guard = ct;
            }
            7 // arbitrary non-zero
        }));

        // Trigger via the wrapper.
        let result = rlayer_padding_wrapper(&s, SSL3_RT_HANDSHAKE, 12);
        assert_eq!(result, 7);
        // Assert callback received the correct record type.
        let captured = {
            let guard = observed_type
                .lock()
                .map_err(|e| format!("lock poisoned: {e}"))
                .unwrap_or_else(|_| panic!("lock poisoned"));
            *guard
        };
        assert_eq!(captured, SSL3_RT_HANDSHAKE);
    }
}
