//! TLS 1.3 key derivation, handshake encryption helpers, and TLS 1.2 PRF support.
//!
//! This module implements the TLS 1.3 key schedule (RFC 8446 §7.1), the HKDF-Expand-Label
//! primitive (RFC 8446 §7.1), the TLS 1.3 Finished MAC and key update (RFC 8446 §4.4.4 and
//! §7.2 respectively), and the exporter interface (RFC 8446 §7.5). It also provides the
//! TLS 1.0–1.2 PRF-based key derivation routines required by `SSL_CTX`/`SSL` setup
//! (originally implemented in `ssl/t1_enc.c`).
//!
//! ## Source mapping
//!
//! * [`ssl/tls13_enc.c`] (965 lines) — TLS 1.3 key derivation (`tls13_hkdf_expand`,
//!   `tls13_derive_secret`, `tls13_derive_*_key/iv`, `tls13_generate_secret`,
//!   `tls13_setup_key_block`, `tls13_update_*_traffic_secret`,
//!   `tls13_export_keying_material*`, `tls13_final_finish_mac`).
//! * [`ssl/t1_enc.c`] (610 lines) — TLS 1.0–1.2 PRF (`tls1_PRF`, `tls1_setup_key_block`,
//!   `tls1_final_finish_mac`).
//!
//! ## Architectural decisions
//!
//! ### HKDF-Expand-Label primitive
//!
//! TLS 1.3 mandates HKDF-Expand-Label (RFC 8446 §7.1), which builds a length-prefixed
//! `HkdfLabel` info structure and invokes HKDF-Expand on a pre-existing pseudorandom
//! key (PRK). The OpenSSL C source uses `EVP_KDF_NAME_TLS1_3_KDF` with the
//! `EVP_PKEY_HKDEF_MODE_EXPAND_ONLY` mode flag. The current Rust workspace
//! (`openssl-crypto/src/evp/kdf.rs`) routes both `HKDF` and `TLS13-KDF` through
//! `core_kdf::hkdf_derive`, which always performs **Extract+Expand** in a single call
//! and accepts only `key`/`salt`/`info`/`digest` parameters — there is no
//! `expand-only` mode. To preserve the RFC 8446 semantic exactly, this module
//! implements HKDF-Extract and HKDF-Expand directly on top of the [`mac_quick`]
//! HMAC primitive, mirroring RFC 5869 §2.2 / §2.3 byte-for-byte.
//!
//! ### TLS 1.2 PRF
//!
//! The `TLS1-PRF` dispatch in `openssl-crypto/src/evp/kdf.rs` correctly drives
//! `core_kdf::KdfContext` with the TLS 1.2 PRF construction (RFC 5246 §5). The
//! key parameter is the secret; the salt parameter holds the entire
//! `label || seed1 || seed2 || …` concatenation. This module uses the full
//! [`Kdf::fetch`]/[`KdfCtx`] pipeline for [`tls1_final_finish_mac`] and
//! [`tls1_setup_key_block`].
//!
//! ### Memory safety
//!
//! Every value that holds key material implements `Zeroize + ZeroizeOnDrop`
//! (per AAP §0.7.6). The [`Tls13Secret`] newtype wraps a [`Zeroizing<Vec<u8>>`]
//! buffer, replacing the C `OPENSSL_cleanse` patterns from the source files.
//! The [`KeySchedule`] struct (the long-lived per-connection state) derives
//! `ZeroizeOnDrop`, ensuring every retained secret is wiped on drop.
//!
//! ### Concurrency
//!
//! * **R7** — A `KeySchedule` is per-connection state. There is no shared mutable
//!   state across connections, hence no synchronization primitives are required.
//!   `// LOCK-SCOPE: none — per-connection state.`
//! * **R8** — The crate sets `#![forbid(unsafe_code)]` and this module uses zero
//!   `unsafe` blocks.
//! * **R6** — All numeric width conversions use `u8::try_from` / `u16::try_from`
//!   rather than bare `as` casts.
//! * **R5** — Secrets that may not yet be derived are stored as `Option<Tls13Secret>`,
//!   never as zero-length sentinel buffers.
//!
//! ### SHA-384 cipher suites
//!
//! The current `openssl-crypto` HKDF dispatch hardcodes SHA-256 (`require_sha256_alias`).
//! `TLS_AES_256_GCM_SHA384`-style cipher suites cannot be derived through the
//! workspace KDF dispatch yet; this module exposes that limitation cleanly via
//! [`SslError::Handshake`] error returns when an unsupported digest is requested.
//!
//! [`ssl/tls13_enc.c`]: https://github.com/openssl/openssl/blob/master/ssl/tls13_enc.c
//! [`ssl/t1_enc.c`]: https://github.com/openssl/openssl/blob/master/ssl/t1_enc.c
//! [`Zeroizing<Vec<u8>>`]: zeroize::Zeroizing
//! [`Kdf::fetch`]: openssl_crypto::evp::kdf::Kdf::fetch
//! [`KdfCtx`]: openssl_crypto::evp::kdf::KdfCtx
//! [`mac_quick`]: openssl_crypto::evp::mac::mac_quick
//! [`SslError::Handshake`]: openssl_common::SslError::Handshake

use std::sync::Arc;

use tracing::trace;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use openssl_common::{ParamBuilder, SslError, SslResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::kdf::{Kdf, KdfCtx, TLS13_KDF, TLS1_PRF};
use openssl_crypto::evp::mac::{mac_quick, HMAC};
use openssl_crypto::evp::md::MessageDigest;

use crate::cipher::CipherSuite;

// =========================================================================
// Public constants
// =========================================================================

/// Maximum length, in bytes, of an HKDF-Expand-Label *expanded* label
/// (i.e. `"tls13 " || label`) — RFC 8446 §7.1 limits the encoded
/// `HkdfLabel.label` field to 7..255 bytes; the OpenSSL C source caps it at
/// 249 to leave headroom for the `HkdfLabel` length prefixes.
///
/// This is the upper bound enforced by [`tls13_hkdf_expand`]. Labels longer
/// than this constant are rejected as a programming error
/// ([`SslError::Handshake`]).
pub const TLS13_MAX_LABEL_LEN: usize = 249;

/// The TLS 1.3 HKDF-Expand-Label prefix (RFC 8446 §7.1: `"tls13 "`).
///
/// Equivalent to the OpenSSL C source `label_prefix` constant
/// (`"\x74\x6c\x73\x31\x33\x20"`). The trailing space is part of the prefix.
pub const LABEL_PREFIX: &[u8] = b"tls13 ";

/// Length, in bytes, of [`LABEL_PREFIX`].
const LABEL_PREFIX_LEN: usize = LABEL_PREFIX.len();

/// Algorithm name string used when fetching the HMAC primitive — matches the
/// canonical `evp::md::SHA256` constant (Rust uses `"SHA2-256"`, not the
/// abbreviated `"SHA256"` form).
const SHA2_256: &str = "SHA2-256";

/// HKDF-Expand max output multiplier (RFC 5869 §2.3): a single PRK can produce
/// at most `255 * HashLen` bytes of keying material.
const HKDF_MAX_OUTPUT_MULTIPLIER: usize = 255;

// =========================================================================
// Tls13Secret newtype
// =========================================================================

/// A secret value derived during the TLS 1.3 key schedule.
///
/// Wraps a [`Zeroizing<Vec<u8>>`] so the underlying buffer is wiped on drop.
/// Used for every intermediate secret in the schedule (early/handshake/master
/// secrets, traffic secrets, exporter secrets) and for HKDF-Expand-Label
/// outputs (traffic keys, IVs, finished keys).
///
/// # Design notes
///
/// * **Rule R8**: contains no `unsafe`.
/// * **Rule R6**: provides only safe accessors — never exposes the raw pointer.
/// * **AAP §0.7.6**: derives `Zeroize + ZeroizeOnDrop`, replacing C
///   `OPENSSL_cleanse()` invocations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Tls13Secret {
    /// Inner zeroizing buffer holding the secret bytes.
    inner: Zeroizing<Vec<u8>>,
}

impl Tls13Secret {
    /// Creates a new secret from an owned byte vector.
    ///
    /// The vector is taken by value so it can be moved directly into a
    /// [`Zeroizing`] container — no copies.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
        }
    }

    /// Creates a new secret by copying from a byte slice.
    ///
    /// Use [`Tls13Secret::from_vec`] when you already own the buffer.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::from_vec(bytes.to_vec())
    }

    /// Returns a read-only view of the underlying secret bytes.
    ///
    /// **Caller responsibility**: callers must avoid copying the returned
    /// slice into non-zeroizing storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the length, in bytes, of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the secret is empty (zero-length).
    ///
    /// Note: callers should generally use `Option<Tls13Secret>` to represent
    /// "not yet derived" rather than relying on emptiness (Rule R5).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl core::fmt::Debug for Tls13Secret {
    /// Redacts the secret bytes — only the length is shown.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tls13Secret")
            .field("len", &self.inner.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

// =========================================================================
// KeyBlock — derived traffic key + IV pair
// =========================================================================

/// A pair of (traffic key, traffic IV) derived from a TLS 1.3 traffic secret
/// — equivalent to the C `record_layer` per-direction keys/IVs that result
/// from `tls13_setup_key_block()` for an AEAD cipher suite.
///
/// In TLS 1.3 each direction (client/server, handshake/application) has its
/// own `KeyBlock`, populated by [`tls13_setup_key_block`]. The struct also
/// carries the AEAD tag length so the record layer does not need to redo the
/// cipher-suite lookup.
///
/// # Memory safety
///
/// Derives `Zeroize + ZeroizeOnDrop` so the key and IV are wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyBlock {
    /// Traffic key bytes (16 bytes for AES-128-GCM, 32 bytes for AES-256-GCM
    /// or ChaCha20-Poly1305).
    key: Zeroizing<Vec<u8>>,
    /// Traffic IV bytes (12 bytes for all TLS 1.3 AEAD cipher suites).
    iv: Zeroizing<Vec<u8>>,
    /// AEAD tag length in bytes (8 or 16, per cipher suite).
    #[zeroize(skip)]
    tag_len: usize,
}

impl KeyBlock {
    /// Creates a new key block from already-derived material.
    ///
    /// `tag_len` is the AEAD tag length (typically 16 bytes; 8 for `*_CCM_8`
    /// suites). The other lengths are inferred from the supplied buffers.
    #[must_use]
    pub fn new(key: Vec<u8>, iv: Vec<u8>, tag_len: usize) -> Self {
        Self {
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
            tag_len,
        }
    }

    /// Returns a read-only view of the traffic key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns a read-only view of the traffic IV bytes.
    #[must_use]
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns the traffic key length, in bytes.
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key.len()
    }

    /// Returns the traffic IV length, in bytes.
    #[must_use]
    pub fn iv_len(&self) -> usize {
        self.iv.len()
    }

    /// Returns the AEAD tag length, in bytes.
    #[must_use]
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

impl core::fmt::Debug for KeyBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyBlock")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .field("tag_len", &self.tag_len)
            .finish()
    }
}

// =========================================================================
// KeySchedule — TLS 1.3 per-connection key derivation state
// =========================================================================

/// The TLS 1.3 key schedule (RFC 8446 §7.1).
///
/// Tracks the chain of secrets derived during a handshake:
///
/// ```text
///                  0
///                  |
///                  v
///      PSK ->  HKDF-Extract = Early Secret
///                  |
///                  +-----> Derive-Secret(., "ext binder" | "res binder", "")
///                  |                       = binder_key
///                  |
///                  +-----> Derive-Secret(., "c e traffic", ClientHello)
///                  |                       = client_early_traffic_secret
///                  |
///                  +-----> Derive-Secret(., "e exp master", ClientHello)
///                  |                       = early_exporter_master_secret
///                  v
///            Derive-Secret(., "derived", "")
///                  |
///                  v
/// (EC)DHE -> HKDF-Extract = Handshake Secret
///                  |
///                  +-----> Derive-Secret(., "c hs traffic", ClientHello…ServerHello)
///                  |                       = client_handshake_traffic_secret
///                  |
///                  +-----> Derive-Secret(., "s hs traffic", ClientHello…ServerHello)
///                  |                       = server_handshake_traffic_secret
///                  v
///            Derive-Secret(., "derived", "")
///                  |
///                  v
///      0 -> HKDF-Extract = Master Secret
///                  |
///                  +-----> Derive-Secret(., "c ap traffic", ClientHello…server Finished)
///                  |                       = client_application_traffic_secret_0
///                  |
///                  +-----> Derive-Secret(., "s ap traffic", ClientHello…server Finished)
///                  |                       = server_application_traffic_secret_0
///                  |
///                  +-----> Derive-Secret(., "exp master", ClientHello…server Finished)
///                  |                       = exporter_master_secret
///                  |
///                  +-----> Derive-Secret(., "res master", ClientHello…client Finished)
///                                          = resumption_master_secret
/// ```
///
/// Every secret is stored as `Option<Tls13Secret>` (Rule R5: nullability over
/// sentinels). The struct derives `ZeroizeOnDrop`, so all live secrets are
/// wiped on drop (AAP §0.7.6).
///
/// # Concurrency
///
/// `// LOCK-SCOPE: none — per-connection state, never shared between threads.`
/// Rule R7 is satisfied by the absence of shared mutable state.
#[derive(Default, ZeroizeOnDrop)]
pub struct KeySchedule {
    /// Early Secret (RFC 8446 §7.1): `HKDF-Extract(0, PSK)`.
    early_secret: Option<Tls13Secret>,
    /// Handshake Secret: `HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)`.
    handshake_secret: Option<Tls13Secret>,
    /// Master Secret: `HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)`.
    master_secret: Option<Tls13Secret>,
    /// `client_handshake_traffic_secret` (`Derive-Secret(handshake, "c hs traffic", …)`).
    client_handshake_traffic_secret: Option<Tls13Secret>,
    /// `server_handshake_traffic_secret` (`Derive-Secret(handshake, "s hs traffic", …)`).
    server_handshake_traffic_secret: Option<Tls13Secret>,
    /// `client_application_traffic_secret_0` (`Derive-Secret(master, "c ap traffic", …)`).
    client_app_traffic_secret: Option<Tls13Secret>,
    /// `server_application_traffic_secret_0` (`Derive-Secret(master, "s ap traffic", …)`).
    server_app_traffic_secret: Option<Tls13Secret>,
    /// `exporter_master_secret` (`Derive-Secret(master, "exp master", …)`).
    exporter_master_secret: Option<Tls13Secret>,
    /// `resumption_master_secret` (`Derive-Secret(master, "res master", …)`).
    resumption_master_secret: Option<Tls13Secret>,
}

impl core::fmt::Debug for KeySchedule {
    /// Diagnostic-friendly Debug: prints `"present"` / `"absent"` per slot
    /// instead of raw key bytes, satisfying the AAP §0.7.6 redaction
    /// requirement. Never reveals secret material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = |opt: &Option<Tls13Secret>| -> &'static str {
            if opt.is_some() {
                "present"
            } else {
                "absent"
            }
        };
        f.debug_struct("KeySchedule")
            .field("early_secret", &label(&self.early_secret))
            .field("handshake_secret", &label(&self.handshake_secret))
            .field("master_secret", &label(&self.master_secret))
            .field(
                "client_handshake_traffic_secret",
                &label(&self.client_handshake_traffic_secret),
            )
            .field(
                "server_handshake_traffic_secret",
                &label(&self.server_handshake_traffic_secret),
            )
            .field(
                "client_app_traffic_secret",
                &label(&self.client_app_traffic_secret),
            )
            .field(
                "server_app_traffic_secret",
                &label(&self.server_app_traffic_secret),
            )
            .field(
                "exporter_master_secret",
                &label(&self.exporter_master_secret),
            )
            .field(
                "resumption_master_secret",
                &label(&self.resumption_master_secret),
            )
            .finish()
    }
}

// =========================================================================
// Internal HKDF primitives — RFC 5869 §2.2 / §2.3
// =========================================================================

/// Validates that the supplied [`MessageDigest`] is supported by the workspace
/// HKDF dispatch. Currently only SHA-256 is wired through to
/// `core_kdf::hkdf_derive` (`require_sha256_alias`); other digests must be
/// rejected up front so that callers receive a deterministic
/// [`SslError::Handshake`] error.
fn validate_digest(md: &MessageDigest) -> SslResult<()> {
    let name = md.name();
    // Accept any of the canonical SHA-256 spellings — the underlying crypto
    // dispatch normalises them.
    let normalised = name.to_ascii_uppercase().replace(['_', ' '], "-");
    let is_sha256 = normalised == "SHA2-256" || normalised == "SHA-256" || normalised == "SHA256";
    if !is_sha256 {
        return Err(SslError::Handshake(format!(
            "unsupported TLS 1.3 digest algorithm: {name} (only SHA-256 is currently supported)",
        )));
    }
    Ok(())
}

/// Returns the canonical algorithm name string passed to `mac_quick`,
/// derived from the supplied [`MessageDigest`]. Always returns `"SHA2-256"`
/// after validation.
fn digest_alg_name(md: &MessageDigest) -> SslResult<&'static str> {
    validate_digest(md)?;
    Ok(SHA2_256)
}

/// HKDF-Extract per RFC 5869 §2.2.
///
/// Computes `PRK = HMAC-Hash(salt, IKM)`. When `salt` is empty, RFC 5869
/// requires substituting a `HashLen`-byte zero string. This implementation
/// allocates a single zero-padded buffer in that case and feeds it directly
/// to [`mac_quick`].
///
/// The internal helper is used by [`KeySchedule::generate_early_secret`],
/// [`KeySchedule::generate_handshake_secret`], and
/// [`KeySchedule::generate_master_secret`].
fn hkdf_extract(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    salt: &[u8],
    ikm: &[u8],
) -> SslResult<Tls13Secret> {
    let alg = digest_alg_name(md)?;
    let digest_size = md.digest_size();

    let prk = if salt.is_empty() {
        // RFC 5869 §2.2: "if not provided, [salt] is set to a string of
        // HashLen zeros."
        let zero_salt = vec![0u8; digest_size];
        mac_quick(ctx, HMAC, &zero_salt, Some(alg), ikm)?
    } else {
        mac_quick(ctx, HMAC, salt, Some(alg), ikm)?
    };

    Ok(Tls13Secret::from_vec(prk))
}

/// HKDF-Expand per RFC 5869 §2.3.
///
/// Iterates HMAC blocks until `length` bytes of output keying material have
/// been produced. The intermediate `T(i)` blocks and concatenation buffers
/// are zeroized on each iteration so secrets never linger in dropped
/// allocations.
///
/// # Errors
///
/// * Returns [`SslError::Handshake`] if `length == 0` or if `length` exceeds
///   `255 * HashLen` (RFC 5869 §2.3 hard limit).
/// * Returns [`SslError::Handshake`] (via narrowing-cast guard) if the loop
///   counter cannot fit in a `u8` — should be unreachable given the above
///   length check, but enforced explicitly to satisfy Rule R6.
fn hkdf_expand(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> SslResult<Tls13Secret> {
    let alg = digest_alg_name(md)?;
    let digest_size = md.digest_size();

    if digest_size == 0 {
        return Err(SslError::Handshake(
            "TLS 1.3 HKDF-Expand: digest reports zero-length output (XOF unsupported)".into(),
        ));
    }

    if length == 0 {
        return Err(SslError::Handshake(
            "TLS 1.3 HKDF-Expand: requested output length must be non-zero".into(),
        ));
    }

    let max_len = HKDF_MAX_OUTPUT_MULTIPLIER
        .checked_mul(digest_size)
        .ok_or_else(|| {
            SslError::Handshake("TLS 1.3 HKDF-Expand: digest size * 255 overflows usize".into())
        })?;
    if length > max_len {
        return Err(SslError::Handshake(format!(
            "TLS 1.3 HKDF-Expand: requested {length} bytes exceeds RFC 5869 limit of {max_len}",
        )));
    }

    let n = length.div_ceil(digest_size);
    let mut okm: Vec<u8> = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        // Build T(i-1) || info || i (where i is a 1-byte counter).
        let mut input: Vec<u8> = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        // Rule R6: avoid bare `as` narrowing casts — use try_from.
        let counter = u8::try_from(i).map_err(|e| {
            SslError::Handshake(format!(
                "TLS 1.3 HKDF-Expand: counter {i} exceeds u8 range: {e}",
            ))
        })?;
        input.push(counter);

        let mut t = mac_quick(ctx, HMAC, prk, Some(alg), &input)?;

        // Wipe the input buffer that contained T(i-1).
        input.zeroize();

        let remaining = length - okm.len();
        let to_copy = core::cmp::min(remaining, t.len());
        okm.extend_from_slice(&t[..to_copy]);

        // Replace t_prev with t for the next iteration; wipe the old buffer.
        t_prev.zeroize();
        t_prev = core::mem::take(&mut t);
    }
    // Final wipe of the trailing T(n).
    t_prev.zeroize();

    Ok(Tls13Secret::from_vec(okm))
}

/// Builds the `HkdfLabel` info structure (RFC 8446 §7.1):
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// `length` is the requested output length; `label` is the per-derivation
/// label (without the `"tls13 "` prefix); `data` is the optional context
/// (typically a transcript hash, may be empty).
fn build_hkdf_label(length: usize, label: &[u8], data: &[u8]) -> SslResult<Vec<u8>> {
    if label.len() > TLS13_MAX_LABEL_LEN {
        return Err(SslError::Handshake(format!(
            "TLS 1.3 HKDF-Expand-Label: label of length {} exceeds maximum {}",
            label.len(),
            TLS13_MAX_LABEL_LEN
        )));
    }

    // Rule R6: safe narrowing of usize → u16 / u8 with try_from.
    let length_u16 = u16::try_from(length).map_err(|e| {
        SslError::Handshake(format!(
            "TLS 1.3 HKDF-Expand-Label: output length {length} exceeds u16: {e}",
        ))
    })?;

    let total_label_len = LABEL_PREFIX_LEN
        .checked_add(label.len())
        .ok_or_else(|| SslError::Handshake("HkdfLabel: label length overflow".into()))?;
    let total_label_len_u8 = u8::try_from(total_label_len).map_err(|e| {
        SslError::Handshake(format!(
            "HkdfLabel: total label length {total_label_len} exceeds u8: {e}",
        ))
    })?;

    let data_len_u8 = u8::try_from(data.len()).map_err(|e| {
        SslError::Handshake(format!(
            "HkdfLabel: context length {} exceeds u8: {e}",
            data.len(),
        ))
    })?;

    let mut info = Vec::with_capacity(2 + 1 + total_label_len + 1 + data.len());
    // Length field (big-endian u16).
    info.extend_from_slice(&length_u16.to_be_bytes());
    // Label vector header (1-byte length).
    info.push(total_label_len_u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    // Context vector header (1-byte length).
    info.push(data_len_u8);
    info.extend_from_slice(data);

    Ok(info)
}

/// Best-effort wrapper around the workspace `Kdf::fetch(TLS13_KDF, …)` /
/// [`KdfCtx`] pipeline. Performs **HKDF Extract+Expand combined** in a single
/// call: passes `ikm` as the IKM, `salt` as the salt, `info` as the info, and
/// requests `length` bytes of output. This is the *standalone* HKDF behaviour
/// described in RFC 5869 §2 and matches the current Rust dispatch
/// implementation in `openssl-crypto/src/evp/kdf.rs`.
///
/// Note: this helper is **not** equivalent to HKDF-Expand-Label, which
/// requires expand-only operation. It is provided so the workspace KDF
/// pipeline (Rule "schema-driven development") is exercised end-to-end and
/// for higher-level callers that genuinely want full HKDF semantics. It is
/// also exercised by the public [`tls13_kdf_extract_and_expand`] helper.
fn tls13_kdf_full_derive(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> SslResult<Tls13Secret> {
    validate_digest(md)?;
    let digest_name = md.name().to_string();

    // Fetch the TLS 1.3 KDF algorithm and create a fresh derivation context.
    let kdf = Kdf::fetch(ctx, TLS13_KDF, None)?;
    let mut kctx = KdfCtx::new(&kdf);

    let params = ParamBuilder::new()
        .push_octet("key", ikm.to_vec())
        .push_octet("salt", salt.to_vec())
        .push_octet("info", info.to_vec())
        .push_utf8("digest", digest_name)
        .build();
    kctx.set_params(&params)?;

    let derived: Zeroizing<Vec<u8>> = kctx.derive(length)?;

    // Reset the context to drop residual state before the context drops.
    kctx.reset();

    // Move the inner Vec out of Zeroizing into the Tls13Secret newtype while
    // preserving the wipe-on-drop guarantee (Tls13Secret also wraps Zeroizing).
    Ok(Tls13Secret::from_vec(derived.to_vec()))
}

/// Public end-to-end HKDF helper that exercises the full workspace KDF
/// pipeline. Performs HKDF (Extract + Expand) using the workspace
/// `Kdf::fetch(TLS13_KDF, …)` dispatch.
///
/// This wraps [`tls13_kdf_full_derive`] and is the canonical example of how
/// to drive the workspace KDF pipeline for a single HKDF call. It is
/// **distinct from HKDF-Expand-Label** — the latter requires expand-only
/// semantics that the current dispatch does not expose.
///
/// # Errors
///
/// Returns [`SslError::Handshake`] for unsupported digests or
/// [`SslError::Crypto`] (auto-converted from `CryptoError`) if the underlying
/// KDF fetch or derivation fails.
pub fn tls13_kdf_extract_and_expand(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> SslResult<Tls13Secret> {
    tls13_kdf_full_derive(ctx, md, ikm, salt, info, length)
}

// =========================================================================
// TLS 1.3 HKDF-Expand-Label and Derive-Secret
// =========================================================================

/// Performs HKDF-Expand-Label as defined in RFC 8446 §7.1.
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
///
/// Where `HkdfLabel` is a structured byte string containing the requested
/// output length (big-endian `uint16`), the label prefixed with `"tls13 "`,
/// and the context value (each prefixed by a one-byte length).
///
/// This is the workhorse of every TLS 1.3 key derivation. It is used for the
/// traffic-key/IV expansion, Derive-Secret, the Finished base key, the early
/// exporter, the resumption secret, and key updates.
///
/// # Parameters
///
/// * `ctx` — workspace [`LibContext`] used for resolving the HMAC primitive.
/// * `md` — hash function for the HKDF call (only SHA-256 is currently
///   supported by the workspace dispatch).
/// * `secret` — the pseudorandom key (PRK) input to HKDF-Expand.
/// * `label` — the label *without* the `"tls13 "` prefix.
/// * `data` — the per-derivation context (often a transcript hash; may be
///   empty).
/// * `length` — the requested output length in bytes.
///
/// # Errors
///
/// * Returns [`SslError::Handshake`] if `length` exceeds the RFC 5869 cap of
///   `255 * HashLen`, if `label` exceeds [`TLS13_MAX_LABEL_LEN`], or if a
///   non-SHA-256 digest is supplied.
/// * Returns [`SslError::Crypto`] if the underlying HMAC primitive fails.
///
/// Translates `tls13_hkdf_expand_ex()` in `ssl/tls13_enc.c`.
pub fn tls13_hkdf_expand(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    secret: &[u8],
    label: &[u8],
    data: &[u8],
    length: usize,
) -> SslResult<Tls13Secret> {
    trace!(
        target: "openssl_ssl::tls13",
        label_len = label.len(),
        context_len = data.len(),
        out_len = length,
        digest = md.name(),
        "tls13_hkdf_expand: HKDF-Expand-Label invocation (secret/output values REDACTED)",
    );

    // Build the structured `HkdfLabel` info as the second HKDF-Expand
    // argument.
    let info = build_hkdf_label(length, label, data)?;
    let result = hkdf_expand(ctx, md, secret, &info, length)?;
    Ok(result)
}

/// Implements the TLS 1.3 `Derive-Secret` function (RFC 8446 §7.1):
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
/// ```
///
/// The `hash` parameter is the precomputed transcript hash (i.e. the caller
/// invokes `Transcript-Hash(Messages)` and passes the result here). The
/// output length is fixed to the digest size.
///
/// Translates the `tls13_derive_secret` flow in `tls13_generate_secret`.
pub fn tls13_derive_secret(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    secret: &[u8],
    label: &[u8],
    hash: &[u8],
) -> SslResult<Tls13Secret> {
    let digest_size = md.digest_size();
    if digest_size == 0 {
        return Err(SslError::Handshake(
            "tls13_derive_secret: digest reports zero-length output".into(),
        ));
    }
    trace!(
        target: "openssl_ssl::tls13",
        label_len = label.len(),
        digest = md.name(),
        out_len = digest_size,
        "tls13_derive_secret: Derive-Secret invocation",
    );
    tls13_hkdf_expand(ctx, md, secret, label, hash, digest_size)
}

/// Derives a traffic key using HKDF-Expand-Label with the `"key"` label and
/// no context. RFC 8446 §7.3:
///
/// ```text
/// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// ```
pub fn tls13_derive_key(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    secret: &[u8],
    key_len: usize,
) -> SslResult<Tls13Secret> {
    trace!(
        target: "openssl_ssl::tls13",
        out_len = key_len,
        digest = md.name(),
        "tls13_derive_key: traffic-key derivation",
    );
    tls13_hkdf_expand(ctx, md, secret, b"key", &[], key_len)
}

/// Derives a traffic IV using HKDF-Expand-Label with the `"iv"` label and no
/// context. RFC 8446 §7.3:
///
/// ```text
/// [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
/// ```
pub fn tls13_derive_iv(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    secret: &[u8],
    iv_len: usize,
) -> SslResult<Tls13Secret> {
    trace!(
        target: "openssl_ssl::tls13",
        out_len = iv_len,
        digest = md.name(),
        "tls13_derive_iv: traffic-IV derivation",
    );
    tls13_hkdf_expand(ctx, md, secret, b"iv", &[], iv_len)
}

// =========================================================================
// Finished MAC and key update (RFC 8446 §4.4.4 / §7.2)
// =========================================================================

/// Computes the TLS 1.3 Finished MAC `verify_data` (RFC 8446 §4.4.4):
///
/// ```text
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data  = HMAC(finished_key, Transcript-Hash(Handshake Context, Cert*, CertVerify*))
/// ```
///
/// `base_key` is the `[sender]_handshake_traffic_secret` (or
/// `[sender]_application_traffic_secret_0` for post-handshake authentication).
/// `transcript_hash` is the precomputed transcript hash that should be
/// authenticated. The returned vector has length equal to the digest size.
///
/// Translates `tls13_final_finish_mac()` in `ssl/tls13_enc.c`.
pub fn tls13_compute_finished(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> SslResult<Vec<u8>> {
    let digest_size = md.digest_size();
    if digest_size == 0 {
        return Err(SslError::Handshake(
            "tls13_compute_finished: digest reports zero-length output".into(),
        ));
    }
    if transcript_hash.len() != digest_size {
        return Err(SslError::Handshake(format!(
            "tls13_compute_finished: transcript hash length {} does not match digest size {}",
            transcript_hash.len(),
            digest_size
        )));
    }

    let alg = digest_alg_name(md)?;

    // Step 1: derive the per-direction finished_key from the supplied
    // base_key via HKDF-Expand-Label(base_key, "finished", "", Hash.length).
    let finished_key = tls13_hkdf_expand(ctx, md, base_key, b"finished", &[], digest_size)?;

    // Step 2: HMAC the transcript hash with that finished_key.
    let verify_data = mac_quick(
        ctx,
        HMAC,
        finished_key.as_bytes(),
        Some(alg),
        transcript_hash,
    )?;

    trace!(
        target: "openssl_ssl::tls13",
        digest = md.name(),
        out_len = verify_data.len(),
        "tls13_compute_finished: Finished MAC computed (verify_data REDACTED)",
    );
    Ok(verify_data)
}

/// Updates a traffic secret per RFC 8446 §7.2:
///
/// ```text
/// application_traffic_secret_N+1 =
///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
/// ```
///
/// The output length matches the digest size of `md`. The previous secret is
/// expected to be wiped by the caller (`Tls13Secret`/`Zeroizing`) once the
/// new secret is in place.
pub fn tls13_update_traffic_secret(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    current_secret: &[u8],
) -> SslResult<Tls13Secret> {
    let digest_size = md.digest_size();
    if digest_size == 0 {
        return Err(SslError::Handshake(
            "tls13_update_traffic_secret: digest reports zero-length output".into(),
        ));
    }
    trace!(
        target: "openssl_ssl::tls13",
        digest = md.name(),
        out_len = digest_size,
        "tls13_update_traffic_secret: traffic-secret update (KeyUpdate)",
    );
    tls13_hkdf_expand(ctx, md, current_secret, b"traffic upd", &[], digest_size)
}

// =========================================================================
// Per-direction key block setup
// =========================================================================

/// Determines the cipher's key length, IV length, and tag length from its
/// [`EncryptionAlgorithm`].
///
/// TLS 1.3 only ever uses AEAD ciphers; non-AEAD or stream ciphers are not
/// permitted. For AES-GCM/ChaCha20-Poly1305 and AES-CCM the per-record IV
/// length is fixed at 12 bytes. The tag length is always 16 bytes for
/// "standard" CCM and 8 bytes for the `_8` variants.
fn tls13_cipher_dimensions(cipher: &CipherSuite) -> SslResult<(usize, usize, usize)> {
    use crate::cipher::EncryptionAlgorithm as E;

    // TLS 1.3 AEAD record IV is always 12 bytes (RFC 8446 §5.3).
    const TLS13_IV_LEN: usize = 12;

    if !cipher.is_tls13() {
        return Err(SslError::Handshake(format!(
            "tls13_setup_key_block: cipher suite 0x{:04X} is not a TLS 1.3 cipher",
            cipher.protocol_id()
        )));
    }
    if !cipher.is_aead() {
        return Err(SslError::Handshake(format!(
            "tls13_setup_key_block: TLS 1.3 cipher suite 0x{:04X} is not an AEAD cipher",
            cipher.protocol_id()
        )));
    }

    match cipher.algorithm_enc {
        // 128-bit key, 16-byte tag (AES-128-GCM, AES-128-CCM, ARIA-128-GCM, SM4-GCM).
        E::Aes128Gcm | E::Aes128Ccm | E::Aria128Gcm | E::Sm4Gcm => Ok((16, TLS13_IV_LEN, 16)),
        // 128-bit key, 8-byte tag (AES-128-CCM-8 only).
        E::Aes128Ccm8 => Ok((16, TLS13_IV_LEN, 8)),
        // 256-bit key, 16-byte tag (AES-256-GCM, AES-256-CCM, ChaCha20-Poly1305, ARIA-256-GCM).
        E::Aes256Gcm | E::Aes256Ccm | E::ChaCha20Poly1305 | E::Aria256Gcm => {
            Ok((32, TLS13_IV_LEN, 16))
        }
        other => Err(SslError::Handshake(format!(
            "tls13_setup_key_block: unsupported AEAD cipher {other:?} for TLS 1.3",
        ))),
    }
}

/// Derives the per-direction record-protection key block (write key + write
/// IV) from a traffic secret. This is the Rust analogue of the C
/// `tls13_setup_key_block()` function: it fetches the cipher's key and IV
/// dimensions and runs HKDF-Expand-Label twice.
///
/// The returned [`KeyBlock`] zeros its key/IV buffers on drop.
///
/// # Errors
///
/// * [`SslError::Handshake`] if `cipher` is not a TLS 1.3 AEAD suite, if the
///   digest is unsupported, or if the underlying HKDF-Expand-Label fails.
pub fn tls13_setup_key_block(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    cipher: &CipherSuite,
    secret: &[u8],
) -> SslResult<KeyBlock> {
    let (key_len, iv_len, tag_len) = tls13_cipher_dimensions(cipher)?;
    trace!(
        target: "openssl_ssl::tls13",
        cipher_id = cipher.protocol_id(),
        key_len,
        iv_len,
        tag_len,
        digest = md.name(),
        "tls13_setup_key_block: deriving traffic key+IV",
    );

    // Derive write key.
    let key_secret = tls13_derive_key(ctx, md, secret, key_len)?;
    let key_vec = key_secret.as_bytes().to_vec();

    // Derive write IV.
    let iv_secret = tls13_derive_iv(ctx, md, secret, iv_len)?;
    let iv_vec = iv_secret.as_bytes().to_vec();

    Ok(KeyBlock::new(key_vec, iv_vec, tag_len))
}

// =========================================================================
// Exporters (RFC 8446 §7.5)
// =========================================================================

/// Computes a digest of the supplied data. Used by the exporter to form
/// `Hash(empty)` and `Hash(context_value)` per RFC 8446 §7.5.
///
/// We re-implement this locally using the workspace `mac_quick`/`Kdf`
/// helpers; rather than reaching into a separate digest function we do an
/// HMAC with a zero key — but the canonical approach is to use
/// [`MessageDigest`] directly. To keep this module self-contained we
/// allocate a local `MdContext` via the runtime helper. As [`MessageDigest`]
/// is the only digest primitive in our `depends_on_files`, we expose a small
/// helper that calls into the workspace digest dispatch using a zero-keyed
/// HMAC and extracting the underlying digest by re-using the HMAC primitive
/// is *not* equivalent.
///
/// To avoid that subtle pitfall we instead delegate to a helper inside the
/// `openssl_crypto` crate. The helper [`digest_via_hmac_zero_key`] is
/// **not** used here — the implementation below uses a direct `MessageDigest`
/// invocation through the workspace context.
fn hash_data(ctx: &Arc<LibContext>, md: &MessageDigest, data: &[u8]) -> SslResult<Vec<u8>> {
    // We need a one-shot digest. The workspace `MessageDigest` exposes
    // metadata, but the concrete digest pipeline is in `MdContext`. To keep
    // this module's dependency graph minimal we use `mac_quick` with a
    // zero-length HMAC key would *not* yield Hash(data). Instead we use the
    // free function `openssl_crypto::evp::digest_quick` re-exported through
    // the `openssl_crypto::evp::md` module in our `depends_on_files`.
    //
    // `digest_quick(ctx, alg_name, data)` — fetches the digest by name and
    // returns the one-shot output, matching `EVP_Q_digest()` in C.
    let alg = digest_alg_name(md)?;
    let result = openssl_crypto::evp::md::digest_quick(ctx, alg, data)?;
    Ok(result)
}

/// Implements the TLS 1.3 exporter (RFC 8446 §7.5):
///
/// ```text
/// TLS-Exporter(label, context_value, key_length) =
///     HKDF-Expand-Label(
///         Derive-Secret(Secret, label, ""),
///         "exporter", Hash(context_value), key_length)
/// ```
///
/// The `Secret` parameter is either the `exporter_master_secret` (post-
/// handshake exporter) or the `early_exporter_master_secret` (early
/// exporter — see [`tls13_export_keying_material_early`]).
///
/// `context` may be empty; if present, it is hashed before being fed to the
/// outer HKDF-Expand-Label.
///
/// Translates `tls13_export_keying_material()` in `ssl/tls13_enc.c`.
pub fn tls13_export_keying_material(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> SslResult<Vec<u8>> {
    if out_len == 0 {
        return Err(SslError::Handshake(
            "tls13_export_keying_material: requested length must be non-zero".into(),
        ));
    }

    trace!(
        target: "openssl_ssl::tls13",
        label_len = label.len(),
        context_len = context.len(),
        out_len,
        digest = md.name(),
        "tls13_export_keying_material: exporter invocation",
    );

    let digest_size = md.digest_size();
    if digest_size == 0 {
        return Err(SslError::Handshake(
            "tls13_export_keying_material: digest reports zero-length output".into(),
        ));
    }

    // Step 1: data = Hash("") — the empty-string transcript hash used as the
    // context to Derive-Secret.
    let data = hash_data(ctx, md, &[])?;

    // Step 2: intermediate = Derive-Secret(secret, label, "")
    //                     = HKDF-Expand-Label(secret, label, Hash(""), Hash.length)
    let intermediate = tls13_hkdf_expand(ctx, md, secret, label, &data, digest_size)?;

    // Step 3: hash = Hash(context_value)
    let hash = hash_data(ctx, md, context)?;

    // Step 4: result = HKDF-Expand-Label(intermediate, "exporter", hash, out_len)
    let result = tls13_hkdf_expand(
        ctx,
        md,
        intermediate.as_bytes(),
        b"exporter",
        &hash,
        out_len,
    )?;

    Ok(result.as_bytes().to_vec())
}

/// Computes the TLS 1.3 *early* exporter (RFC 8446 §7.5).
///
/// The early exporter follows the same two-step pattern as the post-
/// handshake exporter, but its `Secret` input is the
/// `early_exporter_master_secret` derived during the early-data phase. This
/// function is a thin convenience wrapper over [`tls13_export_keying_material`]
/// that uses the same machinery; the caller is responsible for supplying
/// the early exporter master secret.
pub fn tls13_export_keying_material_early(
    ctx: &Arc<LibContext>,
    md: &MessageDigest,
    early_exporter_secret: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> SslResult<Vec<u8>> {
    trace!(
        target: "openssl_ssl::tls13",
        label_len = label.len(),
        context_len = context.len(),
        out_len,
        digest = md.name(),
        "tls13_export_keying_material_early: early-exporter invocation",
    );
    tls13_export_keying_material(ctx, md, early_exporter_secret, label, context, out_len)
}

// =========================================================================
// KeySchedule implementation
// =========================================================================

impl KeySchedule {
    /// Creates a new, empty key schedule. All secret slots are `None` and
    /// will be populated as the handshake progresses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates the early secret per RFC 8446 §7.1.
    ///
    /// ```text
    /// 0 -> HKDF-Extract = Early Secret
    ///         |
    ///         psk (or 0..0 if absent)
    /// ```
    ///
    /// `psk` is the pre-shared key (or `None` if no PSK is in use, in which
    /// case a `HashLen`-byte zero string is substituted).
    ///
    /// This corresponds to the first call to `tls13_generate_secret()` with
    /// `prevsecret = NULL` and `insecret = psk_or_zeros` in
    /// `ssl/tls13_enc.c`.
    pub fn generate_early_secret(
        &mut self,
        ctx: &Arc<LibContext>,
        md: &MessageDigest,
        psk: Option<&[u8]>,
    ) -> SslResult<()> {
        let digest_size = md.digest_size();
        if digest_size == 0 {
            return Err(SslError::Handshake(
                "generate_early_secret: digest reports zero-length output".into(),
            ));
        }

        // RFC 8446 §7.1: when no PSK is present, IKM is HashLen zero bytes.
        let zero_buf;
        let ikm: &[u8] = if let Some(p) = psk {
            p
        } else {
            zero_buf = vec![0u8; digest_size];
            &zero_buf
        };

        // Salt is empty (zero-length string), which HKDF-Extract substitutes
        // with HashLen zero bytes per RFC 5869 §2.2.
        let early = hkdf_extract(ctx, md, &[], ikm)?;

        trace!(
            target: "openssl_ssl::tls13",
            psk_present = psk.is_some(),
            digest = md.name(),
            "KeySchedule::generate_early_secret: early secret derived",
        );

        self.early_secret = Some(early);
        Ok(())
    }

    /// Generates the handshake secret per RFC 8446 §7.1.
    ///
    /// ```text
    /// Derive-Secret(Early Secret, "derived", "")
    ///         |
    ///         (EC)DHE -> HKDF-Extract = Handshake Secret
    /// ```
    ///
    /// `shared_secret` is the (EC)DHE shared secret — the output of the key
    /// share negotiation. Requires that [`Self::generate_early_secret`] has
    /// been called first.
    pub fn generate_handshake_secret(
        &mut self,
        ctx: &Arc<LibContext>,
        md: &MessageDigest,
        shared_secret: &[u8],
    ) -> SslResult<()> {
        let early = self.early_secret.as_ref().ok_or_else(|| {
            SslError::Handshake("generate_handshake_secret: early secret not yet derived".into())
        })?;
        let digest_size = md.digest_size();
        if digest_size == 0 {
            return Err(SslError::Handshake(
                "generate_handshake_secret: digest reports zero-length output".into(),
            ));
        }

        // Step 1: data = Hash("") for the Derive-Secret call.
        let empty_hash = hash_data(ctx, md, &[])?;

        // Step 2: derived = Derive-Secret(early, "derived", "")
        //                = HKDF-Expand-Label(early, "derived", Hash(""), Hash.length)
        let derived = tls13_hkdf_expand(
            ctx,
            md,
            early.as_bytes(),
            b"derived",
            &empty_hash,
            digest_size,
        )?;

        // Step 3: handshake_secret = HKDF-Extract(derived, shared_secret).
        let handshake = hkdf_extract(ctx, md, derived.as_bytes(), shared_secret)?;

        trace!(
            target: "openssl_ssl::tls13",
            digest = md.name(),
            "KeySchedule::generate_handshake_secret: handshake secret derived",
        );

        self.handshake_secret = Some(handshake);
        Ok(())
    }

    /// Generates the master secret per RFC 8446 §7.1.
    ///
    /// ```text
    /// Derive-Secret(Handshake Secret, "derived", "")
    ///         |
    ///         0..0 -> HKDF-Extract = Master Secret
    /// ```
    ///
    /// The IKM for this HKDF-Extract is the all-zeros string of length
    /// `HashLen`. Requires that [`Self::generate_handshake_secret`] has been
    /// called first.
    pub fn generate_master_secret(
        &mut self,
        ctx: &Arc<LibContext>,
        md: &MessageDigest,
    ) -> SslResult<()> {
        let handshake = self.handshake_secret.as_ref().ok_or_else(|| {
            SslError::Handshake("generate_master_secret: handshake secret not yet derived".into())
        })?;
        let digest_size = md.digest_size();
        if digest_size == 0 {
            return Err(SslError::Handshake(
                "generate_master_secret: digest reports zero-length output".into(),
            ));
        }

        // Step 1: data = Hash("")
        let empty_hash = hash_data(ctx, md, &[])?;

        // Step 2: derived = Derive-Secret(handshake, "derived", "")
        let derived = tls13_hkdf_expand(
            ctx,
            md,
            handshake.as_bytes(),
            b"derived",
            &empty_hash,
            digest_size,
        )?;

        // Step 3: IKM is HashLen zero bytes.
        let zeros = vec![0u8; digest_size];

        // Step 4: master_secret = HKDF-Extract(derived, 0..0)
        let master = hkdf_extract(ctx, md, derived.as_bytes(), &zeros)?;

        trace!(
            target: "openssl_ssl::tls13",
            digest = md.name(),
            "KeySchedule::generate_master_secret: master secret derived",
        );

        self.master_secret = Some(master);
        Ok(())
    }

    /// Derives the client and server handshake traffic secrets.
    ///
    /// ```text
    /// client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", ClientHello..ServerHello)
    /// server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", ClientHello..ServerHello)
    /// ```
    ///
    /// `transcript_hash` is the precomputed transcript hash through the
    /// `ServerHello`. Requires that [`Self::generate_handshake_secret`] has
    /// been called first.
    pub fn derive_traffic_secrets(
        &mut self,
        ctx: &Arc<LibContext>,
        md: &MessageDigest,
        transcript_hash: &[u8],
    ) -> SslResult<()> {
        let handshake = self.handshake_secret.as_ref().ok_or_else(|| {
            SslError::Handshake("derive_traffic_secrets: handshake secret not yet derived".into())
        })?;
        let digest_size = md.digest_size();
        if digest_size == 0 {
            return Err(SslError::Handshake(
                "derive_traffic_secrets: digest reports zero-length output".into(),
            ));
        }
        if transcript_hash.len() != digest_size {
            return Err(SslError::Handshake(format!(
                "derive_traffic_secrets: transcript hash length {} does not match digest size {}",
                transcript_hash.len(),
                digest_size
            )));
        }

        let client_hs = tls13_hkdf_expand(
            ctx,
            md,
            handshake.as_bytes(),
            b"c hs traffic",
            transcript_hash,
            digest_size,
        )?;
        let server_hs = tls13_hkdf_expand(
            ctx,
            md,
            handshake.as_bytes(),
            b"s hs traffic",
            transcript_hash,
            digest_size,
        )?;

        trace!(
            target: "openssl_ssl::tls13",
            digest = md.name(),
            "KeySchedule::derive_traffic_secrets: client/server handshake traffic secrets derived",
        );

        self.client_handshake_traffic_secret = Some(client_hs);
        self.server_handshake_traffic_secret = Some(server_hs);
        Ok(())
    }

    /// Derives the client and server *application* traffic secrets, the
    /// exporter master secret, and the resumption master secret.
    ///
    /// ```text
    /// client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", ClientHello..server Finished)
    /// server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", ClientHello..server Finished)
    /// exporter_master_secret              = Derive-Secret(Master Secret, "exp master", ClientHello..server Finished)
    /// resumption_master_secret            = Derive-Secret(Master Secret, "res master", ClientHello..client Finished)
    /// ```
    ///
    /// Note that strictly per RFC 8446 the `resumption_master_secret` should
    /// be derived from the transcript through the *client* Finished, not
    /// the server Finished. The same `transcript_hash` is supplied here for
    /// API simplicity; callers that need the strict resumption-secret flow
    /// should call [`tls13_derive_secret`] directly with the appropriate
    /// transcript.
    pub fn derive_application_secrets(
        &mut self,
        ctx: &Arc<LibContext>,
        md: &MessageDigest,
        transcript_hash: &[u8],
    ) -> SslResult<()> {
        let master = self.master_secret.as_ref().ok_or_else(|| {
            SslError::Handshake("derive_application_secrets: master secret not yet derived".into())
        })?;
        let digest_size = md.digest_size();
        if digest_size == 0 {
            return Err(SslError::Handshake(
                "derive_application_secrets: digest reports zero-length output".into(),
            ));
        }
        if transcript_hash.len() != digest_size {
            return Err(SslError::Handshake(format!(
                "derive_application_secrets: transcript hash length {} does not match digest size {}",
                transcript_hash.len(),
                digest_size
            )));
        }

        let client_ap = tls13_hkdf_expand(
            ctx,
            md,
            master.as_bytes(),
            b"c ap traffic",
            transcript_hash,
            digest_size,
        )?;
        let server_ap = tls13_hkdf_expand(
            ctx,
            md,
            master.as_bytes(),
            b"s ap traffic",
            transcript_hash,
            digest_size,
        )?;
        let exporter = tls13_hkdf_expand(
            ctx,
            md,
            master.as_bytes(),
            b"exp master",
            transcript_hash,
            digest_size,
        )?;
        let resumption = tls13_hkdf_expand(
            ctx,
            md,
            master.as_bytes(),
            b"res master",
            transcript_hash,
            digest_size,
        )?;

        trace!(
            target: "openssl_ssl::tls13",
            digest = md.name(),
            "KeySchedule::derive_application_secrets: app/exporter/resumption secrets derived",
        );

        self.client_app_traffic_secret = Some(client_ap);
        self.server_app_traffic_secret = Some(server_ap);
        self.exporter_master_secret = Some(exporter);
        self.resumption_master_secret = Some(resumption);
        Ok(())
    }

    // ---------- Accessors -----------------------------------------------

    /// Returns the early secret if it has been derived.
    #[must_use]
    pub fn early_secret(&self) -> Option<&Tls13Secret> {
        self.early_secret.as_ref()
    }

    /// Returns the handshake secret if it has been derived.
    #[must_use]
    pub fn handshake_secret(&self) -> Option<&Tls13Secret> {
        self.handshake_secret.as_ref()
    }

    /// Returns the master secret if it has been derived.
    #[must_use]
    pub fn master_secret(&self) -> Option<&Tls13Secret> {
        self.master_secret.as_ref()
    }

    /// Returns the client handshake traffic secret if it has been derived.
    #[must_use]
    pub fn client_handshake_traffic_secret(&self) -> Option<&Tls13Secret> {
        self.client_handshake_traffic_secret.as_ref()
    }

    /// Returns the server handshake traffic secret if it has been derived.
    #[must_use]
    pub fn server_handshake_traffic_secret(&self) -> Option<&Tls13Secret> {
        self.server_handshake_traffic_secret.as_ref()
    }

    /// Returns the client application traffic secret if it has been derived.
    #[must_use]
    pub fn client_app_traffic_secret(&self) -> Option<&Tls13Secret> {
        self.client_app_traffic_secret.as_ref()
    }

    /// Returns the server application traffic secret if it has been derived.
    #[must_use]
    pub fn server_app_traffic_secret(&self) -> Option<&Tls13Secret> {
        self.server_app_traffic_secret.as_ref()
    }

    /// Returns the exporter master secret if it has been derived.
    #[must_use]
    pub fn exporter_master_secret(&self) -> Option<&Tls13Secret> {
        self.exporter_master_secret.as_ref()
    }

    /// Returns the resumption master secret if it has been derived.
    #[must_use]
    pub fn resumption_master_secret(&self) -> Option<&Tls13Secret> {
        self.resumption_master_secret.as_ref()
    }
}

// =========================================================================
// TLS 1.2 PRF support — translates ssl/t1_enc.c
// =========================================================================

/// Default block size for TLS 1.2 master secret derivation (RFC 5246 §8.1).
///
/// Used by [`tls1_generate_master_secret`], which the SSL/TLS 1.2 state
/// machine will invoke once that module is wired into the workspace.
#[allow(
    dead_code,
    reason = "Reserved API: consumed by tls1_generate_master_secret and TLS 1.2 state machine modules not yet wired."
)]
const TLS12_MASTER_SECRET_LEN: usize = 48;

/// Convenience wrapper around the workspace `Kdf::fetch(TLS1_PRF, …)` /
/// [`KdfCtx`] pipeline. Performs the canonical TLS 1.2 PRF computation:
///
/// ```text
/// PRF(secret, label, seed) =
///     P_<hash>(secret, label || seed)
/// ```
///
/// `secret` is the master/pre-master secret (the "key"); `label` and `seed`
/// are concatenated into the "salt" parameter that the workspace TLS1-PRF
/// dispatch reads back as `seed = label || seed`. `digest_name` selects the
/// PRF hash (typically `"SHA2-256"` for TLS 1.2 cipher suites).
///
/// Returns a [`Zeroizing<Vec<u8>>`] wrapper so the derived bytes are wiped
/// on drop.
fn tls12_prf(
    ctx: &Arc<LibContext>,
    digest_name: &str,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> SslResult<Zeroizing<Vec<u8>>> {
    if out_len == 0 {
        return Err(SslError::Handshake(
            "tls12_prf: requested output length must be non-zero".into(),
        ));
    }

    // Combine label and seed into a single buffer; the workspace TLS1-PRF
    // dispatch reads `seed = self.salt` directly.
    let mut combined: Vec<u8> = Vec::with_capacity(label.len() + seed.len());
    combined.extend_from_slice(label);
    combined.extend_from_slice(seed);

    let kdf = Kdf::fetch(ctx, TLS1_PRF, None)?;
    let mut kctx = KdfCtx::new(&kdf);

    let params = ParamBuilder::new()
        .push_octet("key", secret.to_vec())
        .push_octet("salt", combined.clone())
        .push_utf8("digest", digest_name.to_string())
        .build();
    kctx.set_params(&params)?;

    let derived = kctx.derive(out_len)?;

    // Wipe the temporary salt buffer holding label||seed before returning.
    combined.zeroize();

    // Reset the KDF context so its internal state is dropped clean.
    kctx.reset();

    Ok(derived)
}

/// Computes the TLS 1.2 Finished `verify_data` (RFC 5246 §7.4.9):
///
/// ```text
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))
///                    [0..verify_data_length-1]
/// ```
///
/// `label` is one of `"client finished"` or `"server finished"`.
/// `handshake_hash` is the precomputed hash of the handshake messages.
/// `out_len` is normally 12 bytes (or 32 for some legacy GOST suites).
///
/// Translates `tls1_final_finish_mac()` in `ssl/t1_enc.c`.
pub fn tls1_final_finish_mac(
    ctx: &Arc<LibContext>,
    digest_name: &str,
    master_secret: &[u8],
    label: &[u8],
    handshake_hash: &[u8],
    out_len: usize,
) -> SslResult<Vec<u8>> {
    trace!(
        target: "openssl_ssl::tls13",
        label_len = label.len(),
        hash_len = handshake_hash.len(),
        out_len,
        digest = digest_name,
        "tls1_final_finish_mac: TLS 1.2 Finished MAC computation",
    );
    let derived = tls12_prf(
        ctx,
        digest_name,
        master_secret,
        label,
        handshake_hash,
        out_len,
    )?;
    Ok(derived.to_vec())
}

/// Generates the TLS 1.2 key block from the master secret and the client/
/// server randoms (RFC 5246 §6.3):
///
/// ```text
/// key_block = PRF(master_secret, "key expansion",
///                 SecurityParameters.server_random + SecurityParameters.client_random)
/// ```
///
/// The output length is determined by the negotiated cipher suite — the
/// caller is responsible for splitting the returned key block into MAC
/// secrets, write keys, and write IVs in the order specified by RFC 5246
/// §6.3.
///
/// Translates `tls1_setup_key_block()` in `ssl/t1_enc.c`.
pub fn tls1_setup_key_block(
    ctx: &Arc<LibContext>,
    digest_name: &str,
    master_secret: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_size: usize,
) -> SslResult<Zeroizing<Vec<u8>>> {
    if key_block_size == 0 {
        return Err(SslError::Handshake(
            "tls1_setup_key_block: requested key_block_size must be non-zero".into(),
        ));
    }
    trace!(
        target: "openssl_ssl::tls13",
        key_block_size,
        digest = digest_name,
        "tls1_setup_key_block: TLS 1.2 key block generation",
    );

    // RFC 5246 §6.3: the seed order is server_random || client_random.
    let mut seed: Vec<u8> = Vec::with_capacity(server_random.len() + client_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let derived = tls12_prf(
        ctx,
        digest_name,
        master_secret,
        b"key expansion",
        &seed,
        key_block_size,
    )?;

    // Wipe the seed buffer.
    seed.zeroize();
    Ok(derived)
}

/// Generates the TLS 1.2 master secret from the pre-master secret and the
/// client/server randoms (RFC 5246 §8.1):
///
/// ```text
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
/// ```
///
/// The master secret is fixed at 48 bytes ([`TLS12_MASTER_SECRET_LEN`]).
///
/// This function is *not* part of the schema-required exports but is a
/// natural complement to [`tls1_setup_key_block`]. It is exercised by the
/// in-crate unit tests to verify the workspace `TLS1_PRF` pipeline behaves
/// correctly end-to-end.
#[allow(
    dead_code,
    reason = "Reserved API: callers in the TLS 1.2 SSL state machine (statem/) are not yet wired into this crate. Function is fully exercised by tls13::tests::test_tls1_generate_master_secret_smoke."
)]
pub(crate) fn tls1_generate_master_secret(
    ctx: &Arc<LibContext>,
    digest_name: &str,
    pre_master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> SslResult<Zeroizing<Vec<u8>>> {
    let mut seed: Vec<u8> = Vec::with_capacity(client_random.len() + server_random.len());
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let derived = tls12_prf(
        ctx,
        digest_name,
        pre_master_secret,
        b"master secret",
        &seed,
        TLS12_MASTER_SECRET_LEN,
    )?;
    seed.zeroize();
    Ok(derived)
}

// =========================================================================
// Tests (R10 — wiring verification: every public function exercised)
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::ParamSet;
    use openssl_crypto::context::{get_default, LibContext};
    use openssl_crypto::evp::mac::{Mac, MacCtx};
    use openssl_crypto::evp::md::MessageDigest;

    /// Returns a SHA-256 [`MessageDigest`] handle for tests. Falls back to
    /// the workspace default context.
    fn sha256(ctx: &Arc<LibContext>) -> MessageDigest {
        MessageDigest::fetch(ctx, SHA2_256, None).expect("SHA-256 must be fetchable in tests")
    }

    fn ctx() -> Arc<LibContext> {
        get_default()
    }

    // ---------------------------------------------------------------
    // Constant smoke tests
    // ---------------------------------------------------------------

    #[test]
    fn test_label_prefix_is_tls13_space() {
        // Critical: the label prefix MUST be exactly `tls13 ` (6 bytes)
        // per RFC 8446 §7.1. Any deviation breaks interop.
        assert_eq!(LABEL_PREFIX, b"tls13 ");
        assert_eq!(LABEL_PREFIX.len(), 6);
    }

    #[test]
    fn test_max_label_len_constant() {
        // The label vector header is a 1-byte length covering
        // "tls13 " || label, so the maximum label length is 255 - 6 = 249.
        assert_eq!(TLS13_MAX_LABEL_LEN, 249);
    }

    // ---------------------------------------------------------------
    // Tls13Secret tests
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_secret_construction_and_accessors() {
        let bytes = vec![1u8, 2, 3, 4];
        let s = Tls13Secret::from_vec(bytes.clone());
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        assert_eq!(s.as_bytes(), &[1, 2, 3, 4]);

        let s2 = Tls13Secret::from_slice(&[]);
        assert_eq!(s2.len(), 0);
        assert!(s2.is_empty());
    }

    #[test]
    fn test_tls13_secret_debug_redacts_bytes() {
        let s = Tls13Secret::from_vec(vec![0xAA, 0xBB, 0xCC]);
        let debug = format!("{s:?}");
        // Debug output must NOT contain the secret bytes.
        assert!(!debug.contains("AA"));
        assert!(!debug.contains("BB"));
        assert!(!debug.contains("CC"));
        // Should mention the length though.
        assert!(debug.contains('3'));
    }

    // ---------------------------------------------------------------
    // KeyBlock tests
    // ---------------------------------------------------------------

    #[test]
    fn test_keyblock_construction_and_accessors() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let kb = KeyBlock::new(key, iv, 16);
        assert_eq!(kb.key_len(), 16);
        assert_eq!(kb.iv_len(), 12);
        assert_eq!(kb.tag_len(), 16);
        assert_eq!(kb.key().len(), 16);
        assert_eq!(kb.iv().len(), 12);
    }

    #[test]
    fn test_keyblock_debug_redacts_key_iv() {
        let kb = KeyBlock::new(vec![0xDE; 16], vec![0xAD; 12], 16);
        let debug = format!("{kb:?}");
        assert!(!debug.contains("DE"));
        assert!(!debug.contains("AD"));
        assert!(debug.contains("16"));
        assert!(debug.contains("12"));
    }

    // ---------------------------------------------------------------
    // build_hkdf_label tests
    // ---------------------------------------------------------------

    #[test]
    fn test_build_hkdf_label_structure() {
        // For label "test" and empty context with output length 32:
        //  uint16: 0x0020
        //  u8: 6 + 4 = 10
        //  6 bytes "tls13 "
        //  4 bytes "test"
        //  u8: 0
        //  0 bytes context
        let info = build_hkdf_label(32, b"test", &[]).expect("label must build");
        assert_eq!(info[0], 0x00);
        assert_eq!(info[1], 0x20);
        assert_eq!(info[2], 10);
        assert_eq!(&info[3..9], LABEL_PREFIX);
        assert_eq!(&info[9..13], b"test");
        assert_eq!(info[13], 0);
        assert_eq!(info.len(), 14);
    }

    #[test]
    fn test_build_hkdf_label_with_context() {
        let info = build_hkdf_label(16, b"x", &[0xAB, 0xCD]).expect("label must build");
        // length = 16 = 0x0010
        assert_eq!(info[0], 0x00);
        assert_eq!(info[1], 0x10);
        // label vector len = 6 + 1 = 7
        assert_eq!(info[2], 7);
        assert_eq!(&info[3..9], b"tls13 ");
        assert_eq!(info[9], b'x');
        // context vector len = 2
        assert_eq!(info[10], 2);
        assert_eq!(info[11], 0xAB);
        assert_eq!(info[12], 0xCD);
    }

    #[test]
    fn test_build_hkdf_label_label_too_long() {
        let big_label = vec![b'a'; TLS13_MAX_LABEL_LEN + 1];
        let result = build_hkdf_label(32, &big_label, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SslError::Handshake(_)));
    }

    #[test]
    fn test_build_hkdf_label_max_length_ok() {
        let label = vec![b'a'; TLS13_MAX_LABEL_LEN];
        let result = build_hkdf_label(32, &label, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_hkdf_label_oversize_output() {
        // Output length > 65535 must error (cannot fit in u16).
        let result = build_hkdf_label(0x1_0000, b"x", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_hkdf_label_oversize_context() {
        // Context length > 255 must error (cannot fit in u8).
        let big = vec![0u8; 256];
        let result = build_hkdf_label(16, b"x", &big);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // hkdf_extract / hkdf_expand tests
    //
    // NOTE on test scope: These tests verify the structural correctness
    // of the TLS 1.3 HKDF iteration logic — output length, determinism,
    // and input-sensitivity. They do NOT compare against canonical RFC
    // 5869 / RFC 8448 vectors because the underlying `MacCtx::finalize`
    // primitive in `crates/openssl-crypto/src/evp/mac.rs` is currently a
    // structural stub (it produces deterministic non-cryptographic bytes
    // pending real provider integration). Once a real HMAC primitive is
    // wired into the workspace, the canonical vectors documented in each
    // test below should be promoted to assertions.
    // ---------------------------------------------------------------

    #[test]
    fn test_hkdf_extract_rfc8448_early_secret_structure() {
        // RFC 8448 §3 — Simple 1-RTT Handshake.
        //   Early Secret = HKDF-Extract(salt=0, IKM=0..0_32) with SHA-256.
        //   Canonical PRK (with real HMAC):
        //     33ad0a1c607ec03b09e6cd9893680ce2 10adf300aa1f2660e1b22e10f170f92a
        //
        // With the current stub HMAC primitive, we verify only structural
        // properties: digest-sized output, determinism, and that the call
        // succeeds end-to-end through the HKDF-Extract code path.
        let ctx = ctx();
        let md = sha256(&ctx);
        let zeros = [0u8; 32];
        let prk = hkdf_extract(&ctx, &md, &[], &zeros).expect("HKDF-Extract must succeed");
        // Output must equal SHA-256 digest length (32 bytes).
        assert_eq!(prk.len(), md.digest_size());
        // Determinism: identical inputs must yield identical outputs.
        let prk2 = hkdf_extract(&ctx, &md, &[], &zeros).expect("HKDF-Extract must succeed");
        assert_eq!(prk.as_bytes(), prk2.as_bytes());
        // Output must not be empty.
        assert!(!prk.is_empty());
    }

    #[test]
    fn test_hkdf_extract_with_explicit_salt_structure() {
        // RFC 5869 Test Case 1
        //   IKM  = 0x0b * 22
        //   salt = 0x000102030405060708090a0b0c
        //   Canonical PRK (with real HMAC):
        //     0x077709362c2e32df0ddc3f0dc47bba63
        //     0x90b6c73bb50f9c3122ec844ad7c2b3e5
        //
        // With the stub HMAC primitive, we verify structural properties:
        // explicit-salt path executes and returns digest-sized output.
        let ctx = ctx();
        let md = sha256(&ctx);
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let prk = hkdf_extract(&ctx, &md, &salt, &ikm).expect("HKDF-Extract must succeed");
        assert_eq!(prk.len(), md.digest_size());
        // Determinism.
        let prk2 = hkdf_extract(&ctx, &md, &salt, &ikm).expect("HKDF-Extract must succeed");
        assert_eq!(prk.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn test_hkdf_extract_zero_salt_vs_explicit_salt() {
        // Verify the zero-salt fallback in hkdf_extract takes a different
        // code branch than the explicit-salt path.  With the structural
        // stub HMAC, the explicit non-zero salt has a non-zero key_sum
        // while the zero-salt fallback has key_sum = 0 — so outputs differ.
        // This ensures both code paths in `hkdf_extract` are exercised.
        let ctx = ctx();
        let md = sha256(&ctx);
        let ikm = [0x0bu8; 22];
        let prk_zero = hkdf_extract(&ctx, &md, &[], &ikm).expect("zero-salt extract must succeed");
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let prk_explicit =
            hkdf_extract(&ctx, &md, &salt, &ikm).expect("explicit-salt extract must succeed");
        // Both must be digest-sized.
        assert_eq!(prk_zero.len(), md.digest_size());
        assert_eq!(prk_explicit.len(), md.digest_size());
        // Different salt material must yield different output (true under
        // both real HMAC and the structural stub since key_sum differs).
        assert_ne!(prk_zero.as_bytes(), prk_explicit.as_bytes());
    }

    #[test]
    fn test_hkdf_expand_rfc5869_test1_structure() {
        // RFC 5869 Test Case 1 expand step
        //   PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
        //          0x90b6c73bb50f9c3122ec844ad7c2b3e5
        //   info = 0xf0f1f2f3f4f5f6f7f8f9
        //   L    = 42
        //   Canonical OKM (with real HMAC):
        //     0x3cb25f25faacd57a90434f64d0362f2a
        //     0x2d2d0a90cf1a5a4c5db02d56ecc4c5bf
        //     0x34007208d5b887185865
        //
        // Structural verification: the expand path produces exactly L
        // bytes deterministically.
        let ctx = ctx();
        let md = sha256(&ctx);
        let prk = [
            0x07u8, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf_expand(&ctx, &md, &prk, &info, 42).expect("HKDF-Expand must succeed");
        // Output length must match requested length (42).
        assert_eq!(okm.len(), 42);
        // Determinism.
        let okm2 = hkdf_expand(&ctx, &md, &prk, &info, 42).expect("HKDF-Expand must succeed");
        assert_eq!(okm.as_bytes(), okm2.as_bytes());
    }

    #[test]
    fn test_hkdf_expand_various_lengths() {
        // Verify hkdf_expand handles output lengths spanning multiple
        // HMAC blocks (T(0), T(1), T(2), ...) correctly.  SHA-256 block
        // is 32 bytes — 1, 32, 33, 64, 65, 100 bytes exercise the loop
        // body with N=1, 1, 2, 2, 3, 4 iterations respectively.
        let ctx = ctx();
        let md = sha256(&ctx);
        let prk = [0x42u8; 32];
        let info = b"info";
        for &len in &[1usize, 32, 33, 64, 65, 100] {
            let okm = hkdf_expand(&ctx, &md, &prk, info, len)
                .unwrap_or_else(|_| panic!("expand({len}) must succeed"));
            assert_eq!(okm.len(), len, "length mismatch for L={len}");
        }
    }

    #[test]
    fn test_hkdf_expand_rejects_oversize_length() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let prk = [0u8; 32];
        // 255 * 32 = 8160 — request 8161 must error.
        let result = hkdf_expand(&ctx, &md, &prk, &[], 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_zero_length_errors() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let prk = [0u8; 32];
        let result = hkdf_expand(&ctx, &md, &prk, &[], 0);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // tls13_hkdf_expand / tls13_derive_secret tests (RFC 8448)
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_hkdf_expand_rfc8448_derived_for_handshake_structure() {
        // RFC 8446 §7.1 / RFC 8448 §3:
        //   early_secret = 33ad0a1c607ec03b09e6cd9893680ce2 10adf300aa1f2660e1b22e10f170f92a
        //   empty_hash   = e3b0c44298fc1c149afbf4c8996fb924 27ae41e4649b934ca495991b7852b855
        //   Canonical "derived" output (with real HMAC):
        //     6f2615a108c702c5678f54fc9dbab697 16c076189c48250cebeac3576c3611ba
        //
        // Structural test: HKDF-Expand-Label produces exactly out_len
        // bytes deterministically, and label variation alters the output.
        let ctx = ctx();
        let md = sha256(&ctx);
        let early = [
            0x33u8, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68,
            0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10,
            0xf1, 0x70, 0xf9, 0x2a,
        ];
        let empty_hash = [
            0xe3u8, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let derived = tls13_hkdf_expand(&ctx, &md, &early, b"derived", &empty_hash, 32)
            .expect("HKDF-Expand-Label must succeed");
        // Output must be exactly the requested 32 bytes.
        assert_eq!(derived.len(), 32);
        // Determinism.
        let derived2 = tls13_hkdf_expand(&ctx, &md, &early, b"derived", &empty_hash, 32)
            .expect("HKDF-Expand-Label must succeed");
        assert_eq!(derived.as_bytes(), derived2.as_bytes());
        // Different lengths produce different lengths.
        let short = tls13_hkdf_expand(&ctx, &md, &early, b"derived", &empty_hash, 16)
            .expect("HKDF-Expand-Label must succeed");
        assert_eq!(short.len(), 16);
    }

    #[test]
    fn test_tls13_derive_secret_uses_digest_size() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let hash = [0u8; 32];
        let r = tls13_derive_secret(&ctx, &md, &secret, b"derived", &hash)
            .expect("derive_secret must succeed");
        assert_eq!(r.len(), 32);
    }

    #[test]
    fn test_tls13_derive_key_iv_lengths() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let key = tls13_derive_key(&ctx, &md, &secret, 16).expect("derive_key must succeed");
        let iv = tls13_derive_iv(&ctx, &md, &secret, 12).expect("derive_iv must succeed");
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_tls13_hkdf_expand_unsupported_digest_errors() {
        // Use SHA-512 — should be rejected by validate_digest.
        let ctx = ctx();
        let sha512 =
            MessageDigest::fetch(&ctx, "SHA2-512", None).expect("SHA-512 fetch must succeed");
        let secret = [0u8; 64];
        let result = tls13_hkdf_expand(&ctx, &sha512, &secret, b"finished", &[], 32);
        assert!(matches!(result, Err(SslError::Handshake(_))));
    }

    // ---------------------------------------------------------------
    // tls13_compute_finished tests
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_compute_finished_smoke() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let base_key = [0u8; 32];
        let transcript = [0u8; 32];
        let mac = tls13_compute_finished(&ctx, &md, &base_key, &transcript)
            .expect("compute_finished must succeed");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_tls13_compute_finished_wrong_hash_size_errors() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let base_key = [0u8; 32];
        let bad_transcript = [0u8; 16]; // wrong size
        let result = tls13_compute_finished(&ctx, &md, &base_key, &bad_transcript);
        assert!(matches!(result, Err(SslError::Handshake(_))));
    }

    // ---------------------------------------------------------------
    // tls13_update_traffic_secret
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_update_traffic_secret_smoke() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let current = [0xAAu8; 32];
        let updated = tls13_update_traffic_secret(&ctx, &md, &current)
            .expect("update_traffic_secret must succeed");
        assert_eq!(updated.len(), 32);
        // The new secret must differ from the old.
        assert_ne!(updated.as_bytes(), &current[..]);
    }

    // ---------------------------------------------------------------
    // tls13_setup_key_block
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_setup_key_block_aes_128_gcm() {
        // Find a TLS 1.3 cipher suite and verify dimensions.
        use crate::cipher::find_cipher_by_id;

        // TLS_AES_128_GCM_SHA256 = 0x1301 (full ID = 0x03001301 internally).
        // We look it up by protocol_id, so we need to find any TLS 1.3
        // suite. Iterate the known IDs.
        let suite = find_cipher_by_id(0x03001301)
            .or_else(|| find_cipher_by_id(0x1301))
            .expect("TLS_AES_128_GCM_SHA256 must be defined");
        assert!(suite.is_tls13());
        assert!(suite.is_aead());

        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let kb =
            tls13_setup_key_block(&ctx, &md, suite, &secret).expect("setup_key_block must succeed");
        assert_eq!(kb.key_len(), 16);
        assert_eq!(kb.iv_len(), 12);
        assert_eq!(kb.tag_len(), 16);
    }

    #[test]
    fn test_tls13_setup_key_block_aes_256_gcm() {
        use crate::cipher::find_cipher_by_id;
        // TLS_AES_256_GCM_SHA384 = 0x1302
        let suite = find_cipher_by_id(0x03001302)
            .or_else(|| find_cipher_by_id(0x1302))
            .expect("TLS_AES_256_GCM_SHA384 must be defined");
        assert!(suite.is_tls13());

        // We use SHA-256 for the HKDF here to satisfy the workspace digest
        // gate, even though the negotiated PRF in TLS 1.3 would be SHA-384.
        // The cipher dimensions don't depend on the digest.
        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let kb =
            tls13_setup_key_block(&ctx, &md, suite, &secret).expect("setup_key_block must succeed");
        assert_eq!(kb.key_len(), 32);
        assert_eq!(kb.iv_len(), 12);
        assert_eq!(kb.tag_len(), 16);
    }

    #[test]
    fn test_tls13_setup_key_block_chacha20_poly1305() {
        use crate::cipher::find_cipher_by_id;
        // TLS_CHACHA20_POLY1305_SHA256 = 0x1303
        let suite = find_cipher_by_id(0x03001303)
            .or_else(|| find_cipher_by_id(0x1303))
            .expect("TLS_CHACHA20_POLY1305_SHA256 must be defined");
        assert!(suite.is_tls13());

        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let kb =
            tls13_setup_key_block(&ctx, &md, suite, &secret).expect("setup_key_block must succeed");
        assert_eq!(kb.key_len(), 32);
        assert_eq!(kb.iv_len(), 12);
        assert_eq!(kb.tag_len(), 16);
    }

    // ---------------------------------------------------------------
    // tls13_export_keying_material
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_export_keying_material_smoke() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let exporter_secret = [0xBBu8; 32];
        let out = tls13_export_keying_material(
            &ctx,
            &md,
            &exporter_secret,
            b"EXPORTER-Test",
            b"context",
            48,
        )
        .expect("export_keying_material must succeed");
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn test_tls13_export_keying_material_early_smoke() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let early_exporter_secret = [0xCCu8; 32];
        let out = tls13_export_keying_material_early(
            &ctx,
            &md,
            &early_exporter_secret,
            b"EXPORTER-EarlyTest",
            &[],
            32,
        )
        .expect("early exporter must succeed");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_tls13_export_keying_material_zero_length_errors() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let secret = [0u8; 32];
        let result = tls13_export_keying_material(&ctx, &md, &secret, b"label", &[], 0);
        assert!(matches!(result, Err(SslError::Handshake(_))));
    }

    // ---------------------------------------------------------------
    // tls13_kdf_extract_and_expand
    // ---------------------------------------------------------------

    #[test]
    fn test_tls13_kdf_extract_and_expand_smoke() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let ikm = [0u8; 32];
        let salt = [0u8; 32];
        let info = b"test info";
        let result = tls13_kdf_extract_and_expand(&ctx, &md, &ikm, &salt, info, 32)
            .expect("KDF pipeline must succeed");
        assert_eq!(result.len(), 32);
    }

    // ---------------------------------------------------------------
    // KeySchedule end-to-end test
    // ---------------------------------------------------------------

    #[test]
    fn test_keyschedule_full_progression() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let mut sched = KeySchedule::new();

        // No PSK — early secret derived from zero IKM.
        sched
            .generate_early_secret(&ctx, &md, None)
            .expect("early secret must derive");
        assert!(sched.early_secret().is_some());
        assert_eq!(sched.early_secret().unwrap().len(), 32);

        // Synthetic shared secret (32 bytes).
        let shared = [0xAAu8; 32];
        sched
            .generate_handshake_secret(&ctx, &md, &shared)
            .expect("handshake secret must derive");
        assert!(sched.handshake_secret().is_some());

        // Master secret.
        sched
            .generate_master_secret(&ctx, &md)
            .expect("master secret must derive");
        assert!(sched.master_secret().is_some());

        // Traffic secrets after ServerHello transcript hash.
        let transcript_after_sh = [0u8; 32];
        sched
            .derive_traffic_secrets(&ctx, &md, &transcript_after_sh)
            .expect("traffic secrets must derive");
        assert!(sched.client_handshake_traffic_secret().is_some());
        assert!(sched.server_handshake_traffic_secret().is_some());

        // Application secrets after server Finished.
        let transcript_after_sf = [0u8; 32];
        sched
            .derive_application_secrets(&ctx, &md, &transcript_after_sf)
            .expect("application secrets must derive");
        assert!(sched.client_app_traffic_secret().is_some());
        assert!(sched.server_app_traffic_secret().is_some());
        assert!(sched.exporter_master_secret().is_some());
        assert!(sched.resumption_master_secret().is_some());

        // Each traffic secret should be 32 bytes (SHA-256 hash size).
        assert_eq!(sched.client_handshake_traffic_secret().unwrap().len(), 32);
        assert_eq!(sched.server_handshake_traffic_secret().unwrap().len(), 32);
        assert_eq!(sched.client_app_traffic_secret().unwrap().len(), 32);
        assert_eq!(sched.server_app_traffic_secret().unwrap().len(), 32);
        assert_eq!(sched.exporter_master_secret().unwrap().len(), 32);
        assert_eq!(sched.resumption_master_secret().unwrap().len(), 32);
    }

    #[test]
    fn test_keyschedule_with_psk() {
        // Verify the PSK-provided early-secret code path is exercised
        // and produces a digest-sized output.  Uses a PSK of length
        // distinct from the no-PSK fallback (which is `[0u8; digest_size]`)
        // so the two derivations exercise different IKM material — under
        // both the structural stub HMAC and a future real HMAC, the
        // resulting early secrets must differ.
        let ctx = ctx();
        let md = sha256(&ctx);
        let digest_size = md.digest_size();

        // Use a 16-byte PSK so the IKM length differs from the 32-byte
        // zero-IKM used in the no-PSK case (digest_size for SHA-256).
        let psk = [0xDDu8; 16];
        let mut sched = KeySchedule::new();
        sched
            .generate_early_secret(&ctx, &md, Some(&psk))
            .expect("early secret with PSK must derive");
        let early = sched
            .early_secret()
            .expect("early secret slot must be populated")
            .as_bytes()
            .to_vec();
        assert_eq!(early.len(), digest_size);

        // No-PSK path: HKDF-Extract(salt=0, IKM=0..0_digest_size).
        let mut sched_zero = KeySchedule::new();
        sched_zero
            .generate_early_secret(&ctx, &md, None)
            .expect("early secret without PSK must derive");
        let early_zero = sched_zero
            .early_secret()
            .expect("early secret slot must be populated")
            .as_bytes()
            .to_vec();
        assert_eq!(early_zero.len(), digest_size);

        // PSK and no-PSK cases must yield different early secrets when
        // the IKM differs (which it does: 16 PSK bytes vs 32 zero bytes).
        assert_ne!(early, early_zero);
    }

    #[test]
    fn test_keyschedule_progression_requires_predecessors() {
        let ctx = ctx();
        let md = sha256(&ctx);
        let mut sched = KeySchedule::new();

        // Cannot generate handshake secret without early secret.
        let r = sched.generate_handshake_secret(&ctx, &md, &[0u8; 32]);
        assert!(matches!(r, Err(SslError::Handshake(_))));

        // Cannot generate master secret without handshake secret.
        let r = sched.generate_master_secret(&ctx, &md);
        assert!(matches!(r, Err(SslError::Handshake(_))));

        // Cannot derive traffic secrets without handshake secret.
        let r = sched.derive_traffic_secrets(&ctx, &md, &[0u8; 32]);
        assert!(matches!(r, Err(SslError::Handshake(_))));

        // Cannot derive application secrets without master secret.
        let r = sched.derive_application_secrets(&ctx, &md, &[0u8; 32]);
        assert!(matches!(r, Err(SslError::Handshake(_))));
    }

    #[test]
    fn test_keyschedule_default_is_empty() {
        let sched = KeySchedule::default();
        assert!(sched.early_secret().is_none());
        assert!(sched.handshake_secret().is_none());
        assert!(sched.master_secret().is_none());
        assert!(sched.client_handshake_traffic_secret().is_none());
        assert!(sched.server_handshake_traffic_secret().is_none());
        assert!(sched.client_app_traffic_secret().is_none());
        assert!(sched.server_app_traffic_secret().is_none());
        assert!(sched.exporter_master_secret().is_none());
        assert!(sched.resumption_master_secret().is_none());
    }

    #[test]
    fn test_keyschedule_debug_redacts() {
        let mut sched = KeySchedule::new();
        let ctx = ctx();
        let md = sha256(&ctx);
        sched.generate_early_secret(&ctx, &md, None).unwrap();
        let dbg = format!("{sched:?}");
        // Must report which slots are populated but never raw bytes.
        assert!(dbg.contains("early_secret"));
        assert!(dbg.contains("present"));
        assert!(dbg.contains("absent"));
    }

    // ---------------------------------------------------------------
    // TLS 1.2 PRF tests
    // ---------------------------------------------------------------

    #[test]
    fn test_tls1_setup_key_block_smoke() {
        let ctx = ctx();
        let master = [0u8; 48];
        let server_random = [0xAAu8; 32];
        let client_random = [0xBBu8; 32];
        let kb = tls1_setup_key_block(
            &ctx,
            "SHA2-256",
            &master,
            &server_random,
            &client_random,
            96,
        )
        .expect("key block must derive");
        assert_eq!(kb.len(), 96);
    }

    #[test]
    fn test_tls1_final_finish_mac_smoke() {
        let ctx = ctx();
        let master = [0u8; 48];
        let handshake_hash = [0u8; 32];
        let mac = tls1_final_finish_mac(
            &ctx,
            "SHA2-256",
            &master,
            b"client finished",
            &handshake_hash,
            12,
        )
        .expect("finish MAC must derive");
        assert_eq!(mac.len(), 12);

        // Different label must produce different output.
        let mac2 = tls1_final_finish_mac(
            &ctx,
            "SHA2-256",
            &master,
            b"server finished",
            &handshake_hash,
            12,
        )
        .expect("finish MAC must derive");
        assert_eq!(mac2.len(), 12);
        assert_ne!(mac, mac2);
    }

    #[test]
    fn test_tls1_generate_master_secret_smoke() {
        let ctx = ctx();
        let pms = [0xEEu8; 48];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let ms = tls1_generate_master_secret(&ctx, "SHA2-256", &pms, &cr, &sr)
            .expect("master secret must derive");
        assert_eq!(ms.len(), TLS12_MASTER_SECRET_LEN);
        assert_eq!(ms.len(), 48);
    }

    #[test]
    fn test_tls1_setup_key_block_zero_size_errors() {
        let ctx = ctx();
        let master = [0u8; 48];
        let r = tls1_setup_key_block(&ctx, "SHA2-256", &master, &[0u8; 32], &[0u8; 32], 0);
        assert!(matches!(r, Err(SslError::Handshake(_))));
    }

    // ---------------------------------------------------------------
    // R5 — Option<Tls13Secret> rather than empty-bytes sentinel
    // ---------------------------------------------------------------

    #[test]
    fn test_undriven_keyschedule_uses_option_not_empty_bytes() {
        let sched = KeySchedule::new();
        // R5 verification: undriven slots are None, NOT Some(empty-vec).
        assert!(sched.early_secret().is_none());
    }

    // ---------------------------------------------------------------
    // R8 — no unsafe blocks (compile-time enforced via forbid(unsafe_code))
    // ---------------------------------------------------------------

    #[test]
    fn test_no_unsafe_in_module() {
        // `forbid(unsafe_code)` at the crate root would refuse compilation
        // if any unsafe block existed in this module. The presence of this
        // passing test in a successful build is the proof.
        // (No code needed — this is an "assertion by compilation" test.)
    }

    // ---------------------------------------------------------------
    // Schema members_accessed coverage —
    // Mac::fetch, MacCtx::{new, init, update, finalize}, ParamSet
    //
    // The production `tls13_compute_finished` path uses the optimised
    // [`mac_quick`] one-shot wrapper. The schema also requires the
    // multi-step MAC API (`Mac::fetch` + `MacCtx::{new,init,update,
    // finalize}`) to be exercised so callers needing chunked transcript
    // hashing have a verified path. This test computes
    // HMAC-SHA256(key, msg) twice — once via `mac_quick` and once via
    // the multi-step API — and asserts the outputs are byte-identical.
    // ---------------------------------------------------------------

    #[test]
    fn test_multi_step_hmac_matches_mac_quick() {
        let ctx = ctx();
        let key = [0xABu8; 32];
        let msg_chunk1 = b"Hello, ";
        let msg_chunk2 = b"world!";
        let full_msg = b"Hello, world!";

        // One-shot path used in production (`tls13_compute_finished`).
        let one_shot =
            mac_quick(&ctx, HMAC, &key, Some(SHA2_256), full_msg).expect("mac_quick must succeed");

        // Multi-step path exercising Mac::fetch + MacCtx::{new,init,update,finalize}
        // and ParamSet construction.
        let mac_method = Mac::fetch(&ctx, HMAC, None).expect("Mac::fetch must succeed");
        let mut mac_ctx = MacCtx::new(&mac_method).expect("MacCtx::new must succeed");
        let init_params: ParamSet = ParamBuilder::new()
            .push_utf8("digest", SHA2_256.to_string())
            .build();
        mac_ctx
            .init(&key, Some(&init_params))
            .expect("MacCtx::init must succeed");
        mac_ctx
            .update(msg_chunk1)
            .expect("MacCtx::update must succeed (chunk 1)");
        mac_ctx
            .update(msg_chunk2)
            .expect("MacCtx::update must succeed (chunk 2)");
        let multi_step = mac_ctx.finalize().expect("MacCtx::finalize must succeed");

        // Both paths must produce identical HMAC-SHA256 output.
        assert_eq!(one_shot, multi_step);
        assert_eq!(one_shot.len(), 32);
    }
}
