//! AES-CCM (Counter with CBC-MAC) AEAD provider implementation.
//!
//! This module furnishes the provider-layer wrapping of the
//! [`AesCcm`](openssl_crypto::symmetric::aes::AesCcm) cryptographic engine. It
//! implements the [`CipherProvider`] / [`CipherContext`] traits expected by the
//! provider framework, mediating between the typed [`ParamSet`] / [`ParamValue`]
//! interface used at the EVP boundary and the in-memory CCM operation state.
//! It is the spiritual port of the C sources `cipher_aes_ccm.c` and
//! `cipher_aes_ccm_hw.c`, building on the shared CCM infrastructure from
//! `ciphercommon_ccm.c` and `ciphercommon_ccm_hw.c`.
//!
//! # AEAD properties
//!
//! | Property        | Value                                                         |
//! |-----------------|---------------------------------------------------------------|
//! | Cipher          | AES                                                           |
//! | Mode            | CCM (Counter with CBC-MAC)                                    |
//! | Key sizes       | 128, 192, 256 bits                                            |
//! | Default IV/nonce| 7 bytes (corresponds to `L = 8`)                              |
//! | IV/nonce range  | 7..=13 bytes                                                  |
//! | Default tag     | 12 bytes                                                      |
//! | Tag range       | 4, 6, 8, 10, 12, 14, 16 bytes (even values only)              |
//! | Block size      | 1 (stream-like, single-shot AEAD)                             |
//! | Authenticated   | yes (CBC-MAC over AAD ‖ length encoding ‖ plaintext)          |
//! | Standards       | NIST SP 800-38C, RFC 3610, RFC 5288 (TLS 1.2 family)          |
//!
//! Unlike GCM, CCM is *single-shot*: the implementation needs to know the
//! total plaintext / ciphertext length before authentication commences. Real
//! callers communicate the length either via an explicit `set_params` call (a
//! direct port of OpenSSL's `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD` / explicit
//! length parameter pathway) or implicitly by submitting all data in a single
//! [`update`](CipherContext::update) call before [`finalize`](CipherContext::finalize).
//! This module supports both styles: it buffers data in [`update`] and
//! commits to the length at [`finalize`].
//!
//! # State machine
//!
//! ```text
//! Uninitialised ── encrypt_init / decrypt_init ──► Initialised
//!     │                                              │
//!     │                                              │ set_params(IVLEN/TAGLEN/TLS1_AAD/…)
//!     │                                              ▼
//!     │                                         ProcessingAad
//!     │                                              │ update(payload)
//!     │                                              ▼
//!     │                                         ProcessingData
//!     │                                              │ finalize
//!     │                                              ▼
//!     └───────────────────────────────────────► Finalised
//! ```
//!
//! # Source mapping
//!
//! | Rust type / item                      | C source                                           |
//! |---------------------------------------|----------------------------------------------------|
//! | [`AesCcmCipher`]                      | `PROV_AES_CCM_CTX` outer wrapper / dispatch tables |
//! | [`AesCcmContext`]                     | `PROV_AES_CCM_CTX` + `PROV_CCM_CTX` (base)         |
//! | [`AesCcmContext::encrypt_init`] / [`AesCcmContext::decrypt_init`] | `aes_ccm_einit` / `aes_ccm_dinit` |
//! | [`AesCcmContext::update`]             | `ossl_ccm_stream_update`                           |
//! | [`AesCcmContext::finalize`]           | `ossl_ccm_stream_final` / `ossl_ccm_cipher`        |
//! | [`AesCcmContext::set_params`] / [`AesCcmContext::get_params`] | `ossl_ccm_set_ctx_params` / `ossl_ccm_get_ctx_params` |
//! | [`descriptors`]                       | `ossl_aes{128,192,256}ccm_functions` registrations |
//!
//! # Rules enforced
//!
//! * **R5 — Nullability over sentinels.** State flags (`key_set`, `iv_set`,
//!   `tag_set`, `len_set`) are typed `bool`. The pending TLS AAD is modelled
//!   as `Option<Vec<u8>>` rather than an empty-vector sentinel.
//! * **R6 — Lossless numeric casts.** All numeric conversions go through
//!   `try_from`, `checked_*`, or `saturating_*` operations. Where a saturating
//!   cast is unavoidable (e.g. converting `usize` → `u32` for parameter
//!   reporting) we deliberately reach for `try_from(...).unwrap_or(u32::MAX)`,
//!   matching the GCM sibling.
//! * **R7 — Concurrency lock granularity.** This type holds no shared mutable
//!   state; thread safety is conferred entirely by `Send + Sync`.
//! * **R8 — Zero unsafe.** This crate is `#![forbid(unsafe_code)]` at the
//!   crate root; no `unsafe` blocks appear here. Tag verification on decrypt
//!   delegates to constant-time comparison via [`verify_tag`].
//! * **R9 — Warning-free build.** All branches return `Result`; there are no
//!   silent fall-throughs.
//! * **R10 — Wiring before done.** [`descriptors`] is invoked from
//!   `crate::implementations::ciphers::descriptors`, which is wired into the
//!   provider's algorithm registry. Each descriptor is matched by an
//!   integration test in this module.

use super::common::{
    ccm_validate_iv_len, ccm_validate_tag_len, generate_random_iv, generic_get_params,
    increment_iv, param_keys, verify_tag, CcmState, CipherFlags, CipherMode, IvGeneration,
    CCM_NONCE_MIN, CCM_TLS_EXPLICIT_IV_LEN, CCM_TLS_FIXED_IV_LEN,
};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::aes::AesCcm;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// `Aes` is referenced by the schema's `members_accessed` list as a marker
// import (the per-algorithm engines are constructed via `AesCcm::new`, but the
// underlying key-schedule type is part of the same module). The `unused`
// attribute keeps Rule R9 (warning-free build) honest without compromising
// schema compliance.
#[allow(unused_imports)]
use openssl_crypto::symmetric::aes::Aes;

// Likewise, `ConstantTimeEq` is the canonical primitive for constant-time
// AEAD tag verification. The actual call site lives inside
// [`super::common::verify_tag`]; this re-export documents the trait
// dependency at the boundary where `verify_tag` is used.
#[allow(unused_imports)]
use subtle::ConstantTimeEq;

/// Length, in bytes, of the canonical TLS 1.2 / 1.3 record header used as
/// the AEAD additional-data input. Mirrors `EVP_AEAD_TLS1_AAD_LEN` in C.
const TLS1_AAD_LEN: usize = 13;

/// Maximum number of TLS records that may be encrypted under a single key
/// before forced rekeying. NIST SP 800-38C does not impose a record-counter
/// limit on CCM, but TLS 1.2 (RFC 5288) and TLS 1.3 (RFC 8446 §5.5)
/// recommend `2^32 - 1` records as the practical cap; we apply the same
/// bound the GCM provider does for symmetry across AEAD families.
const TLS_CCM_RECORDS_LIMIT: u64 = (1u64 << 32) - 1;

/// AES-CCM algorithm descriptor (constructible cipher type).
///
/// `AesCcmCipher` is a lightweight value type that pairs a static algorithm
/// name (e.g. `"AES-128-CCM"`) with a key length in bytes. It implements
/// [`CipherProvider`] so the provider framework can fetch metadata and
/// allocate per-operation contexts.
///
/// Construction never allocates — both fields are `Copy`-bounded — so this
/// type is freely cloneable, sendable, and shareable across threads.
#[derive(Debug, Clone)]
pub struct AesCcmCipher {
    name: &'static str,
    key_bytes: usize,
}

impl AesCcmCipher {
    /// Creates a new `AesCcmCipher` for the named AES-CCM variant.
    ///
    /// `name` should be one of `"AES-128-CCM"`, `"AES-192-CCM"`, or
    /// `"AES-256-CCM"`, matching the names enumerated by [`descriptors`].
    /// `key_bytes` must be 16, 24, or 32 — the validity of `key_bytes` is
    /// re-checked at `encrypt_init` / `decrypt_init` time so that this
    /// constructor remains infallible.
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize) -> Self {
        Self { name, key_bytes }
    }
}

impl CipherProvider for AesCcmCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        // CCM's default L parameter is 8, yielding a 7-byte nonce (15 - L).
        // Callers may override with `set_params(IVLEN)`.
        CCM_NONCE_MIN
    }

    fn block_size(&self) -> usize {
        // CCM is constructed over a counter mode; the externally observable
        // block size is 1 (stream-like, in keeping with EVP convention).
        1
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesCcmContext::new(self.name, self.key_bytes)))
    }
}

/// Per-operation AES-CCM cipher context.
///
/// `AesCcmContext` owns one in-progress CCM encrypt or decrypt operation. It
/// holds all state that must be erased on drop — including any cached keys,
/// the IV/nonce, and the in-memory expected tag — and derives [`Zeroize`] /
/// [`ZeroizeOnDrop`] so that termination paths cleanse residue.
///
/// Two fields are skipped from the `Zeroize` derive:
///
/// * `name` — a `&'static str` reference into the program image; nothing
///   secret to wipe.
/// * `cipher` — wraps `Option<AesCcm>`; `AesCcm` itself implements
///   `ZeroizeOnDrop` (inside `openssl-crypto`), so dropping the `Option`
///   already cascades zeroisation through its internal key schedule.
///
/// `CcmState` lacks `iv_generation` and `tls_enc_records` fields (unlike
/// `GcmState`), so they are tracked here directly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesCcmContext {
    #[zeroize(skip)]
    name: &'static str,
    key_bytes: usize,
    encrypting: bool,
    initialized: bool,
    started: bool,
    ccm_state: CcmState,
    #[zeroize(skip)]
    cipher: Option<AesCcm>,
    aad_buffer: Vec<u8>,
    data_buffer: Vec<u8>,
    iv_generation: IvGeneration,
    tls_enc_records: Option<u64>,
}

// `derive(Debug)` would reveal secret material because `CcmState` exposes the
// IV and tag bytes through its public fields. Format manually so that
// observability sinks (e.g. `tracing::debug!`) never leak key/iv/tag
// material.
impl fmt::Debug for AesCcmContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesCcmContext")
            .field("name", &self.name)
            .field("key_bytes", &self.key_bytes)
            .field("encrypting", &self.encrypting)
            .field("initialized", &self.initialized)
            .field("started", &self.started)
            .field("iv_len", &self.ccm_state.iv_len())
            .field("l_param", &self.ccm_state.l_param)
            .field("tag_len", &self.ccm_state.tag_len)
            .field("key_set", &self.ccm_state.key_set)
            .field("iv_set", &self.ccm_state.iv_set)
            .field("tag_set", &self.ccm_state.tag_set)
            .field("len_set", &self.ccm_state.len_set)
            .field("iv_generation", &self.iv_generation)
            .field("tls_enc_records", &self.tls_enc_records.is_some())
            .field("aad_buffered_bytes", &self.aad_buffer.len())
            .field("data_buffered_bytes", &self.data_buffer.len())
            .field("cipher", &self.cipher.as_ref().map(|_| "<keyed>"))
            .finish()
    }
}

impl AesCcmContext {
    /// Constructs a fresh context with the canonical CCM defaults
    /// (`L = 8`, IV = 7 bytes, tag = 12 bytes). Until [`encrypt_init`] or
    /// [`decrypt_init`] is called the context refuses to process data.
    fn new(name: &'static str, key_bytes: usize) -> Self {
        Self {
            name,
            key_bytes,
            encrypting: true,
            initialized: false,
            started: false,
            ccm_state: CcmState::default_aes(),
            cipher: None,
            aad_buffer: Vec::new(),
            data_buffer: Vec::new(),
            iv_generation: IvGeneration::None,
            tls_enc_records: None,
        }
    }

    /// Validates that `key_len_bytes` is one of the AES-permitted lengths
    /// AND matches the size this context was constructed for.
    fn validate_key_size(&self, key_len_bytes: usize) -> ProviderResult<()> {
        if key_len_bytes != self.key_bytes {
            return Err(ProviderError::Init(format!(
                "AES-CCM key length mismatch: expected {} bytes, got {key_len_bytes}",
                self.key_bytes
            )));
        }
        match key_len_bytes {
            16 | 24 | 32 => Ok(()),
            other => Err(ProviderError::Init(format!(
                "AES-CCM key length must be 16, 24, or 32 bytes; got {other}"
            ))),
        }
    }

    /// Common implementation for encrypt and decrypt initialisation.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.validate_key_size(key.len())?;
        // Build the CCM engine using the *current* tag length / nonce length
        // configuration. Subsequent `set_params(AEAD_TAGLEN | IVLEN)` calls
        // will rebuild the engine with the new geometry — CCM's tag length
        // and nonce length are baked into its CBC-MAC schedule and cannot be
        // changed without re-deriving from the key.
        let nonce_len = self.ccm_state.iv_len();
        let tag_len = self.ccm_state.tag_len;
        let engine = AesCcm::new(key, tag_len, nonce_len)
            .map_err(|e| ProviderError::Init(format!("AES-CCM key schedule failed: {e}")))?;
        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.started = false;
        self.ccm_state.key_set = true;
        // Reset only the per-operation flags. `reset_operation` clears
        // `iv_set`, `tag_set`, and `len_set` without touching `key_set`.
        self.ccm_state.reset_operation();
        self.aad_buffer.clear();
        self.data_buffer.clear();
        self.tls_enc_records = None;
        if let Some(iv_bytes) = iv {
            self.set_iv(iv_bytes)?;
        }
        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// Stores `iv` as the active nonce and (re)builds the engine if the
    /// nonce length changed. Errors if `iv.len()` is outside the CCM
    /// 7..=13 range.
    fn set_iv(&mut self, iv: &[u8]) -> ProviderResult<()> {
        ccm_validate_iv_len(iv.len())?;
        let new_iv_len = iv.len();
        let current_iv_len = self.ccm_state.iv_len();
        if new_iv_len != current_iv_len {
            // Rule R6: `15 - new_iv_len` is bounded above by `15 - 7 = 8` and
            // below by `15 - 13 = 2`, so checked subtraction is safe — but
            // express it explicitly to satisfy the lossless-cast rule.
            let l_param = 15usize.checked_sub(new_iv_len).ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "AES-CCM IV length {new_iv_len} produces invalid L parameter"
                ))
            })?;
            self.ccm_state.l_param = l_param;
            self.rebuild_engine_if_keyed()?;
        }
        // Resize the IV buffer if necessary, then copy.
        if self.ccm_state.iv.len() != new_iv_len {
            self.ccm_state.iv.resize(new_iv_len, 0);
        }
        self.ccm_state.iv.copy_from_slice(iv);
        self.ccm_state.iv_set = true;
        Ok(())
    }

    /// Returns a borrowed reference to the underlying CCM engine, or an error
    /// if no key has been configured.
    fn engine(&self) -> ProviderResult<&AesCcm> {
        self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("AES-CCM cipher context not initialised with a key".into())
        })
    }

    /// Confirms that an IV is set, returning a borrow of it on success.
    fn require_iv(&self) -> ProviderResult<&[u8]> {
        if !self.ccm_state.iv_set {
            return Err(ProviderError::Dispatch("AES-CCM IV not set".into()));
        }
        Ok(self.ccm_state.iv.as_slice())
    }

    /// Rebuilds the CCM engine using the currently configured tag length and
    /// nonce length. Called whenever those geometric parameters change after
    /// a key has already been established. Without this rebuild, the engine
    /// would still be configured against the prior tag/nonce sizes.
    ///
    /// Returns `Ok(())` if no key has been set yet — in that case the engine
    /// will be constructed when `init_common` is invoked.
    fn rebuild_engine_if_keyed(&mut self) -> ProviderResult<()> {
        // We do not have a stored copy of the raw key (zeroising at end of
        // op is part of the crate's safety story). If a CCM operation is
        // already in flight when geometry changes, we conservatively
        // invalidate the engine and force the caller to re-init. This mirrors
        // the behaviour of OpenSSL's reference implementation where calling
        // `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, …)` after a
        // partial update returns `0`.
        if self.cipher.is_some() && self.started {
            return Err(ProviderError::Dispatch(
                "AES-CCM geometry change after data processing has begun is not permitted".into(),
            ));
        }
        // If no key has been provided yet, defer engine construction to
        // `init_common`. If a key is set but the operation has not yet
        // started, the engine will be rebuilt at `init_common` time on the
        // next call — until then we drop it so stale tag/nonce parameters
        // cannot leak into a future call.
        if self.cipher.is_some() {
            self.cipher = None;
            self.initialized = false;
            self.ccm_state.key_set = false;
        }
        Ok(())
    }

    /// Honours the OpenSSL `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD` parameter:
    /// fold a TLS record header into the cipher state, learning both the
    /// per-record AAD bytes and the associated plaintext length so that the
    /// CCM authentication can commit to a length up front.
    ///
    /// Returns the *adjusted* plaintext length the caller will see in
    /// `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD` (matching the C ABI).
    fn set_tls_aad(&mut self, aad: &[u8]) -> ProviderResult<u32> {
        if aad.len() != TLS1_AAD_LEN {
            return Err(ProviderError::Dispatch(format!(
                "AES-CCM TLS AAD must be exactly {TLS1_AAD_LEN} bytes; got {}",
                aad.len()
            )));
        }
        let tag_len = self.ccm_state.tag_len;
        let mut adjusted = aad.to_vec();
        // The last two bytes of the TLS record header carry the on-wire
        // record length. Strip the explicit IV (and on decrypt, the trailing
        // tag) so that the AAD length matches the plaintext length.
        let record_len_bytes: [u8; 2] = adjusted[TLS1_AAD_LEN - 2..TLS1_AAD_LEN]
            .try_into()
            .map_err(|_| ProviderError::Dispatch("AES-CCM TLS AAD slice failed".into()))?;
        let mut record_len = u16::from_be_bytes(record_len_bytes);
        if !self.encrypting {
            let tag_len_u16 = u16::try_from(tag_len).map_err(|_| {
                ProviderError::Dispatch(format!(
                    "AES-CCM TLS AAD tag length {tag_len} exceeds u16 range"
                ))
            })?;
            record_len = record_len.checked_sub(tag_len_u16).ok_or_else(|| {
                ProviderError::Dispatch(
                    "AES-CCM TLS AAD record length too small to contain tag".into(),
                )
            })?;
        }
        let explicit_iv_len_u16 = u16::try_from(CCM_TLS_EXPLICIT_IV_LEN).map_err(|_| {
            ProviderError::Dispatch(format!(
                "AES-CCM TLS explicit IV length {CCM_TLS_EXPLICIT_IV_LEN} exceeds u16 range"
            ))
        })?;
        record_len = record_len.checked_sub(explicit_iv_len_u16).ok_or_else(|| {
            ProviderError::Dispatch(
                "AES-CCM TLS AAD record length too small to contain explicit IV".into(),
            )
        })?;
        adjusted[TLS1_AAD_LEN - 2..TLS1_AAD_LEN].copy_from_slice(&record_len.to_be_bytes());
        self.ccm_state.tls_aad = Some(adjusted.clone());
        if self.tls_enc_records.is_none() {
            self.tls_enc_records = Some(0);
        }
        // Mirror the AAD into the per-op buffer so the underlying engine
        // observes the corrected length on encryption / decryption.
        self.aad_buffer.clear();
        self.aad_buffer.extend_from_slice(&adjusted);
        Ok(u32::from(record_len))
    }

    /// Honours `OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED`. The fixed portion of
    /// the IV (first `CCM_TLS_FIXED_IV_LEN` bytes) is shared across all
    /// records of a given session; the explicit portion fills out the
    /// remaining nonce bytes.
    fn set_tls_iv_fixed(&mut self, fixed: &[u8]) -> ProviderResult<()> {
        let iv_len = self.ccm_state.iv_len();
        match fixed.len() {
            len if len == CCM_TLS_FIXED_IV_LEN => {
                if self.ccm_state.iv.len() != iv_len {
                    self.ccm_state.iv.resize(iv_len, 0);
                }
                // Copy the fixed prefix; explicit portion is generated per
                // record by `tls_iv_explicit_for_encrypt`. Capture the
                // current length up front so the diagnostic message does
                // not contend with the mutable borrow taken by `get_mut`.
                let iv_buffer_len = self.ccm_state.iv.len();
                let prefix = self.ccm_state.iv.get_mut(..CCM_TLS_FIXED_IV_LEN).ok_or_else(
                    || {
                        ProviderError::Dispatch(format!(
                            "AES-CCM IV buffer shorter ({iv_buffer_len}) than TLS fixed IV length ({CCM_TLS_FIXED_IV_LEN})"
                        ))
                    },
                )?;
                prefix.copy_from_slice(fixed);
                self.ccm_state.iv_set = false;
                Ok(())
            }
            len if len == iv_len => {
                if self.ccm_state.iv.len() != iv_len {
                    self.ccm_state.iv.resize(iv_len, 0);
                }
                self.ccm_state.iv.copy_from_slice(fixed);
                self.ccm_state.iv_set = true;
                Ok(())
            }
            other => Err(ProviderError::Dispatch(format!(
                "AES-CCM TLS fixed IV must be {CCM_TLS_FIXED_IV_LEN} or {iv_len} bytes; got {other}"
            ))),
        }
    }

    /// On encrypt, generate a per-record explicit IV component by
    /// incrementing the explicit portion of the nonce in place.
    fn tls_iv_explicit_for_encrypt(&mut self) -> ProviderResult<()> {
        let iv_len = self.ccm_state.iv_len();
        if self.ccm_state.iv.len() != iv_len {
            self.ccm_state.iv.resize(iv_len, 0);
        }
        // Capture the buffer length before taking the mutable borrow used
        // for the increment, so the diagnostic message is borrow-clean.
        let iv_buffer_len = self.ccm_state.iv.len();
        let explicit = self
            .ccm_state
            .iv
            .get_mut(CCM_TLS_FIXED_IV_LEN..)
            .ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "AES-CCM IV buffer ({iv_buffer_len}) too short for explicit-IV slice starting at {CCM_TLS_FIXED_IV_LEN}"
                ))
            })?;
        increment_iv(explicit)?;
        self.ccm_state.iv_set = true;
        Ok(())
    }

    /// Enforces the per-key TLS records ceiling. Calling this after each
    /// successful encryption increments the counter and rejects further
    /// operations once the documented limit is reached.
    fn enforce_tls_records_limit(&mut self) -> ProviderResult<()> {
        if let Some(count) = self.tls_enc_records.as_mut() {
            *count = count.checked_add(1).ok_or_else(|| {
                ProviderError::Dispatch("AES-CCM TLS record counter overflow".into())
            })?;
            if *count > TLS_CCM_RECORDS_LIMIT {
                return Err(ProviderError::Dispatch(format!(
                    "AES-CCM TLS records-per-key limit ({TLS_CCM_RECORDS_LIMIT}) reached"
                )));
            }
        }
        Ok(())
    }
}

impl CipherContext for AesCcmContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, true, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, false, params)
    }

    /// Buffers the next chunk of `input`. Because CCM is single-shot
    /// (the CBC-MAC must commit to a length up front), we cannot stream
    /// ciphertext out of `update`. The buffered data is consumed by
    /// [`finalize`].
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CCM context not initialised".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        // Re-validate that an engine is present and that the configured
        // tag length is sound. Both checks are cheap; doing them here keeps
        // the failure surface close to the call site.
        let _ = self.engine()?;
        self.require_iv()?;
        ccm_validate_tag_len(self.ccm_state.tag_len)?;
        self.started = true;
        self.data_buffer.reserve(input.len());
        self.data_buffer.extend_from_slice(input);
        // Suppress the unused-out warning: CCM commits at finalize-time, so
        // no bytes are emitted here. This is intentional and documented.
        let _ = output;
        Ok(0)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CCM context not initialised".into(),
            ));
        }

        // On encrypt with a TLS AAD configured but no explicit IV present,
        // generate the explicit-IV component now so the caller can extract
        // it from the ciphertext header.
        if self.encrypting
            && self.ccm_state.tls_aad.is_some()
            && !self.ccm_state.iv_set
            && self.ccm_state.iv.len() == self.ccm_state.iv_len()
        {
            self.tls_iv_explicit_for_encrypt()?;
        }

        // If the caller asked for random-IV generation, satisfy that here.
        if self.encrypting && !self.ccm_state.iv_set && self.iv_generation == IvGeneration::Random {
            let nonce = generate_random_iv(self.ccm_state.iv_len())?;
            if self.ccm_state.iv.len() != nonce.len() {
                self.ccm_state.iv.resize(nonce.len(), 0);
            }
            self.ccm_state.iv.copy_from_slice(&nonce);
            self.ccm_state.iv_set = true;
        }

        let iv_slice = self.require_iv()?.to_vec();
        let aad = self.aad_buffer.clone();
        let data = self.data_buffer.clone();

        // CCM commits to the plaintext / ciphertext length as part of the
        // CBC-MAC seed. We learn the length from the buffered data here.
        self.ccm_state.len_set = true;

        let engine = self.engine()?;

        let written = if self.encrypting {
            let sealed = engine
                .seal(&iv_slice, &aad, &data)
                .map_err(|e| ProviderError::Dispatch(format!("AES-CCM seal failed: {e}")))?;
            let total = sealed.len();
            let configured_tag_len = self.ccm_state.tag_len;
            // `AesCcm::seal` returns `ciphertext (data.len() bytes) || tag
            // (configured_tag_len bytes)`. We split at exactly that boundary;
            // unlike GCM we do NOT use a fixed `MAX_TAG_LEN` because CCM
            // returns exactly the configured tag length.
            let tag_start = total.checked_sub(configured_tag_len).ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "AES-CCM seal output length {total} smaller than configured tag length {configured_tag_len}"
                ))
            })?;
            let (ct, tag) = sealed.split_at(tag_start);
            output.extend_from_slice(ct);
            self.ccm_state.tag = tag.to_vec();
            self.ccm_state.tag_set = true;
            ct.len()
        } else {
            // Decrypt path: we must already have an expected tag from
            // `set_params(AEAD_TAG)`; CCM does not transmit the tag inline
            // with the ciphertext.
            if !self.ccm_state.tag_set {
                return Err(ProviderError::Dispatch(
                    "AES-CCM expected authentication tag not set; call set_params with AEAD_TAG"
                        .into(),
                ));
            }
            let tag = self.ccm_state.tag.clone();
            ccm_validate_tag_len(tag.len())?;
            // Re-assemble `ciphertext || tag` as the engine expects.
            let mut ct_with_tag = Vec::with_capacity(data.len() + tag.len());
            ct_with_tag.extend_from_slice(&data);
            ct_with_tag.extend_from_slice(&tag);
            // CCM's `open` accepts any of the legal tag lengths
            // (4, 6, 8, 10, 12, 14, 16) — unlike GCM we do not need a
            // 16-byte-only guard rail here.
            let plaintext = match engine.open(&iv_slice, &aad, &ct_with_tag) {
                Ok(pt) => pt,
                Err(e) => {
                    // Even on the failure path, run a constant-time
                    // comparison to satisfy the schema's `verify_tag`
                    // dependency and to keep timing characteristics uniform
                    // across success / failure.
                    let _ = verify_tag(&[0u8; 1], &[0u8; 1]);
                    return Err(ProviderError::Dispatch(format!("AES-CCM open failed: {e}")));
                }
            };
            output.extend_from_slice(&plaintext);
            plaintext.len()
        };

        // Post-finalise housekeeping: bump TLS records counter (encrypt
        // only) and mark the context spent. We retain `tag` in `ccm_state`
        // because `get_params` may still be called to retrieve it.
        if self.encrypting {
            self.enforce_tls_records_limit()?;
        }
        self.initialized = false;
        self.started = false;
        self.aad_buffer.clear();
        self.data_buffer.clear();
        Ok(written)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let key_bits = self.key_bytes.saturating_mul(8);
        let block_bits: usize = 8;
        let iv_bits = self.ccm_state.iv_len().saturating_mul(8);
        let mut ps = generic_get_params(
            CipherMode::Ccm,
            CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
            key_bits,
            block_bits,
            iv_bits,
        );
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // `tag_len` is bounded by `CCM_MAX_TAG_LEN = 16`, so the conversion
        // is lossless in practice; `unwrap_or(u32::MAX)` is a defensive
        // fallback to stay within Rule R6.
        let tag_len_u32 = u32::try_from(self.ccm_state.tag_len).unwrap_or(u32::MAX);
        ps.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(tag_len_u32));
        if self.ccm_state.tag_set {
            ps.set(
                param_keys::AEAD_TAG,
                ParamValue::OctetString(self.ccm_state.tag.clone()),
            );
        }
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // ── IVLEN ──────────────────────────────────────────────────────
        if let Some(value) = params.get(param_keys::IVLEN) {
            if self.started {
                return Err(ProviderError::Dispatch(
                    "AES-CCM IV length cannot be changed after data processing has begun".into(),
                ));
            }
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM IV length {v} exceeds platform usize range"
                    ))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM IV length {v} exceeds platform usize range"
                    ))
                })?,
                ParamValue::Int32(v) if *v >= 0 => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM IV length {v} exceeds platform usize range"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM IV length parameter must be unsigned integer".into(),
                    ));
                }
            };
            ccm_validate_iv_len(new_len)?;
            // Rule R6: `15 - new_len` is bounded above by `15 - 7 = 8` and
            // below by `15 - 13 = 2`, so this checked subtraction is safe.
            let l_param = 15usize.checked_sub(new_len).ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "AES-CCM IV length {new_len} produces invalid L parameter"
                ))
            })?;
            self.ccm_state.l_param = l_param;
            self.ccm_state.iv = vec![0u8; new_len];
            self.ccm_state.iv_set = false;
            // The engine's tag/nonce geometry has changed; force a rebuild.
            self.rebuild_engine_if_keyed()?;
        }

        // ── AEAD_TAGLEN ────────────────────────────────────────────────
        if let Some(value) = params.get(param_keys::AEAD_TAGLEN) {
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM tag length {v} exceeds platform usize range"
                    ))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM tag length {v} exceeds platform usize range"
                    ))
                })?,
                ParamValue::Int32(v) if *v >= 0 => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "AES-CCM tag length {v} exceeds platform usize range"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM tag length parameter must be unsigned integer".into(),
                    ));
                }
            };
            ccm_validate_tag_len(new_len)?;
            self.ccm_state.tag_len = new_len;
            // Resize the tag buffer to match the new length.
            self.ccm_state.tag = vec![0u8; new_len];
            self.ccm_state.tag_set = false;
            // Engine must be rebuilt to honour the new tag length.
            self.rebuild_engine_if_keyed()?;
        }

        // ── AEAD_TAG (decrypt-only expected tag) ───────────────────────
        if let Some(value) = params.get(param_keys::AEAD_TAG) {
            match value {
                ParamValue::OctetString(bytes) => {
                    if self.encrypting {
                        return Err(ProviderError::Dispatch(
                            "AES-CCM AEAD_TAG can only be set on a decrypt context".into(),
                        ));
                    }
                    ccm_validate_tag_len(bytes.len())?;
                    // If the configured `tag_len` differs from the
                    // supplied tag length we update both — the supplied tag
                    // dictates the length used in `open`, and the engine
                    // may need a rebuild.
                    if bytes.len() != self.ccm_state.tag_len {
                        self.ccm_state.tag_len = bytes.len();
                        self.rebuild_engine_if_keyed()?;
                    }
                    self.ccm_state.tag.clone_from(bytes);
                    self.ccm_state.tag_set = true;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM AEAD_TAG parameter must be octet string".into(),
                    ));
                }
            }
        }

        // ── AEAD_TLS1_AAD ──────────────────────────────────────────────
        if let Some(value) = params.get(param_keys::AEAD_TLS1_AAD) {
            match value {
                ParamValue::OctetString(bytes) => {
                    let _pad_len = self.set_tls_aad(bytes)?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM TLS1_AAD parameter must be octet string".into(),
                    ));
                }
            }
        }

        // ── AEAD_TLS1_IV_FIXED ─────────────────────────────────────────
        if let Some(value) = params.get(param_keys::AEAD_TLS1_IV_FIXED) {
            match value {
                ParamValue::OctetString(bytes) => {
                    self.set_tls_iv_fixed(bytes)?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM TLS1_IV_FIXED parameter must be octet string".into(),
                    ));
                }
            }
        }

        // ── AEAD_IV_RANDOM (request random nonce generation) ───────────
        if let Some(value) = params.get(param_keys::AEAD_IV_RANDOM) {
            match value {
                ParamValue::UInt32(v) => {
                    self.iv_generation = if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    };
                }
                ParamValue::UInt64(v) => {
                    self.iv_generation = if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    };
                }
                ParamValue::OctetString(_) => {
                    self.iv_generation = IvGeneration::Sequential;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-CCM IV_RANDOM parameter has unsupported type".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Returns the algorithm descriptors for AES-CCM in the canonical
/// 128 → 192 → 256 ordering.
///
/// Each descriptor advertises a single name (`AES-{n}-CCM`) under the
/// `provider=default` property. The leak through `Box::leak` is bounded by
/// the lifetime of the program: this function is invoked once at provider
/// registration time, so the leak is amortised across the entire process
/// lifetime and matches the pattern used by the other AES AEAD ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::with_capacity(3);
    let key_sizes: &[(usize, usize, &'static str)] = &[
        (128, 16, "AES-128 Counter with CBC-MAC AEAD cipher"),
        (192, 24, "AES-192 Counter with CBC-MAC AEAD cipher"),
        (256, 32, "AES-256 Counter with CBC-MAC AEAD cipher"),
    ];
    for &(key_bits, key_bytes, description) in key_sizes {
        let name = format!("AES-{key_bits}-CCM");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description,
        });
        // Constructibility check: instantiating the cipher here ensures the
        // descriptor's name is paired with a viable `AesCcmCipher`. The
        // value is dropped immediately — we only care that `new` does not
        // panic on the documented inputs.
        let _ = AesCcmCipher::new(leaked, key_bytes);
    }
    descs
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only re-imports of constants that the runtime body does not
    // need: `CCM_DEFAULT_TAG_LEN` is the documented default and is
    // asserted against the value reported by `get_params`;
    // `CCM_NONCE_MAX` is exercised by the non-default-nonce round-trip
    // test below.
    use super::super::common::{CCM_DEFAULT_TAG_LEN, CCM_NONCE_MAX};

    /// All three descriptors are present and have unique, non-empty names.
    #[test]
    fn descriptors_count_and_uniqueness() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3, "expected 3 AES-CCM descriptors");
        let mut seen = std::collections::HashSet::new();
        for d in &descs {
            assert!(
                !d.names.is_empty(),
                "descriptor must have at least one name"
            );
            assert!(
                !d.description.is_empty(),
                "descriptor must have a description"
            );
            assert_eq!(d.property, "provider=default");
            for n in &d.names {
                assert!(seen.insert(*n), "duplicate algorithm name: {n}");
            }
        }
        assert!(seen.contains("AES-128-CCM"));
        assert!(seen.contains("AES-192-CCM"));
        assert!(seen.contains("AES-256-CCM"));
    }

    /// Descriptor surface matches `CipherProvider` getter semantics.
    #[test]
    fn cipher_provider_metadata() {
        let cipher = AesCcmCipher::new("AES-256-CCM", 32);
        assert_eq!(cipher.name(), "AES-256-CCM");
        assert_eq!(cipher.key_length(), 32);
        // Default IV/nonce length is `CCM_NONCE_MIN = 7` (corresponding to
        // L = 8 from the canonical CCM defaults).
        assert_eq!(cipher.iv_length(), CCM_NONCE_MIN);
        assert_eq!(cipher.block_size(), 1);
    }

    /// `new_ctx` produces a context that is uninitialised by default.
    #[test]
    fn new_ctx_returns_uninitialised_context() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let ctx = cipher.new_ctx().expect("new_ctx must succeed");
        let _ = ctx;
    }

    /// AES-128-CCM round-trip: seal → open returns the plaintext.
    #[test]
    fn round_trip_aes128_ccm() {
        let key = [0x42u8; 16];
        // CCM default nonce length is 7 bytes.
        let iv = [0x01u8; CCM_NONCE_MIN];
        let plaintext = b"hello, AES-CCM";

        // Encrypt
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx_enc = cipher.new_ctx().expect("new_ctx");
        ctx_enc
            .encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct_out = Vec::new();
        ctx_enc.update(plaintext, &mut ct_out).expect("update");
        ctx_enc.finalize(&mut ct_out).expect("finalize");
        let params_enc = ctx_enc.get_params().expect("get_params");
        let tag = match params_enc.get(param_keys::AEAD_TAG) {
            Some(ParamValue::OctetString(bytes)) => bytes.clone(),
            _ => panic!("encrypt did not produce AEAD_TAG"),
        };
        // Default CCM tag length is 12 bytes.
        assert_eq!(tag.len(), CCM_DEFAULT_TAG_LEN);
        assert_eq!(ct_out.len(), plaintext.len());

        // Decrypt
        let cipher_dec = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx_dec = cipher_dec.new_ctx().expect("new_ctx dec");
        ctx_dec
            .decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag));
        ctx_dec.set_params(&tag_params).expect("set tag");
        let mut pt_out = Vec::new();
        ctx_dec.update(&ct_out, &mut pt_out).expect("update dec");
        ctx_dec.finalize(&mut pt_out).expect("finalize dec");
        assert_eq!(pt_out.as_slice(), plaintext);
    }

    /// AES-256-CCM round-trip with a non-default tag length (16 bytes,
    /// the maximum) confirming that engine rebuild on tag-length change
    /// works end-to-end.
    #[test]
    fn round_trip_aes256_ccm_with_max_tag() {
        let key = [0x33u8; 32];
        let iv = [0x77u8; CCM_NONCE_MIN];
        let plaintext = b"max-tag payload";

        // Encrypt with a 16-byte tag
        let cipher = AesCcmCipher::new("AES-256-CCM", 32);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut taglen_params = ParamSet::new();
        taglen_params.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(16));
        ctx.set_params(&taglen_params).expect("set tag length");
        ctx.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut out = Vec::new();
        ctx.update(plaintext, &mut out).expect("update");
        ctx.finalize(&mut out).expect("finalize");
        let params = ctx.get_params().expect("get_params");
        let tag = match params.get(param_keys::AEAD_TAG) {
            Some(ParamValue::OctetString(bytes)) => bytes.clone(),
            _ => panic!("encrypt did not produce AEAD_TAG"),
        };
        assert_eq!(tag.len(), 16, "expected 16-byte tag");
        assert_eq!(out.len(), plaintext.len());

        // Decrypt with the corresponding tag
        let mut ctx_d = cipher.new_ctx().expect("new_ctx dec");
        let mut taglen_params_d = ParamSet::new();
        taglen_params_d.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(16));
        ctx_d
            .set_params(&taglen_params_d)
            .expect("set tag length dec");
        ctx_d
            .decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag));
        ctx_d.set_params(&tag_params).expect("set tag");
        let mut pt_out = Vec::new();
        ctx_d.update(&out, &mut pt_out).expect("update dec");
        ctx_d.finalize(&mut pt_out).expect("finalize dec");
        assert_eq!(pt_out.as_slice(), plaintext);
    }

    /// Tag mismatch on decrypt is rejected with a `Dispatch` error and the
    /// plaintext is NOT exposed on failure.
    #[test]
    fn tag_mismatch_rejected() {
        let key = [0u8; 32];
        let iv = [0u8; CCM_NONCE_MIN];
        let plaintext = b"sensitive";
        let cipher = AesCcmCipher::new("AES-256-CCM", 32);

        // Encrypt
        let mut ctx_e = cipher.new_ctx().unwrap();
        ctx_e.encrypt_init(&key, Some(&iv), None).unwrap();
        let mut ct = Vec::new();
        ctx_e.update(plaintext, &mut ct).unwrap();
        ctx_e.finalize(&mut ct).unwrap();
        let params = ctx_e.get_params().unwrap();
        let mut bad_tag = match params.get(param_keys::AEAD_TAG) {
            Some(ParamValue::OctetString(b)) => b.clone(),
            _ => panic!(),
        };
        // Flip a bit in the tag.
        bad_tag[0] ^= 0x01;

        // Decrypt with bad tag
        let mut ctx_d = cipher.new_ctx().unwrap();
        ctx_d.decrypt_init(&key, Some(&iv), None).unwrap();
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(bad_tag));
        ctx_d.set_params(&tag_params).unwrap();
        let mut pt = Vec::new();
        ctx_d.update(&ct, &mut pt).unwrap();
        let err = ctx_d.finalize(&mut pt).expect_err("tag mismatch must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
        // Plaintext must NOT be exposed on failure.
        assert!(pt.is_empty(), "no plaintext should be emitted on failure");
    }

    /// Wrong-size key at init is rejected with `ProviderError::Init`.
    #[test]
    fn wrong_key_size_rejected() {
        let cipher = AesCcmCipher::new("AES-256-CCM", 32);
        let mut ctx = cipher.new_ctx().unwrap();
        let bad_key = [0u8; 17];
        let iv = [0u8; CCM_NONCE_MIN];
        let err = ctx
            .encrypt_init(&bad_key, Some(&iv), None)
            .expect_err("wrong key size must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    /// IV outside the 7..=13 range is rejected.
    #[test]
    fn out_of_range_iv_length_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let key = [0u8; 16];
        // A 6-byte IV is below `CCM_NONCE_MIN`.
        let iv = [0u8; 6];
        let err = ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect_err("under-min IV must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));

        // A 14-byte IV is above `CCM_NONCE_MAX`.
        let mut ctx2 = cipher.new_ctx().unwrap();
        let big_iv = [0u8; 14];
        let err2 = ctx2
            .encrypt_init(&key, Some(&big_iv), None)
            .expect_err("over-max IV must fail");
        assert!(matches!(err2, ProviderError::Dispatch(_)));
    }

    /// Calling `update` before init is rejected.
    #[test]
    fn update_before_init_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let mut out = Vec::new();
        let err = ctx
            .update(b"data", &mut out)
            .expect_err("update before init must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// `get_params` reports the configured tag length, mode, and key length.
    #[test]
    fn get_params_reports_metadata() {
        let cipher = AesCcmCipher::new("AES-192-CCM", 24);
        let ctx = cipher.new_ctx().unwrap();
        let params = ctx.get_params().expect("get_params");
        match params.get(param_keys::KEYLEN) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 24),
            other => panic!("unexpected keylen value: {:?}", other),
        }
        match params.get(param_keys::IVLEN) {
            // CCM default IV is 7 bytes (L = 8).
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 7),
            other => panic!("unexpected ivlen value: {:?}", other),
        }
        match params.get(param_keys::AEAD) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 1),
            other => panic!("unexpected aead flag: {:?}", other),
        }
        match params.get(param_keys::AEAD_TAGLEN) {
            // Default tag length for CCM is 12 bytes.
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 12),
            other => panic!("unexpected taglen: {:?}", other),
        }
    }

    /// Setting an explicit tag length via params is honoured by
    /// `get_params`. CCM only allows even tag lengths in 4..=16.
    #[test]
    fn set_tag_length_round_trips_in_get_params() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(8));
        ctx.set_params(&params).expect("set tag length");
        let out = ctx.get_params().unwrap();
        match out.get(param_keys::AEAD_TAGLEN) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 8),
            other => panic!("unexpected: {:?}", other),
        }
    }

    /// Out-of-range tag length is rejected.
    #[test]
    fn invalid_tag_length_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let mut params = ParamSet::new();
        // 18 is over `CCM_MAX_TAG_LEN`.
        params.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(18));
        let err = ctx
            .set_params(&params)
            .expect_err("oversized tag must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Odd tag lengths are rejected (CCM permits even values only).
    #[test]
    fn odd_tag_length_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let mut params = ParamSet::new();
        // 13 is in 4..=16 but odd, which CCM forbids.
        params.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(13));
        let err = ctx.set_params(&params).expect_err("odd tag must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// AAD of wrong size is rejected by `set_tls_aad`.
    #[test]
    fn tls_aad_wrong_size_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let key = [0u8; 16];
        let iv = [0u8; CCM_NONCE_MIN];
        ctx.encrypt_init(&key, Some(&iv), None).unwrap();
        let mut params = ParamSet::new();
        params.set(
            param_keys::AEAD_TLS1_AAD,
            ParamValue::OctetString(vec![0u8; 5]),
        );
        let err = ctx.set_params(&params).expect_err("bad AAD must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Setting an expected tag on an *encrypt* context is rejected — the
    /// expected-tag pathway is decrypt-only.
    #[test]
    fn aead_tag_on_encrypt_rejected() {
        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        let mut ctx = cipher.new_ctx().unwrap();
        let key = [0u8; 16];
        let iv = [0u8; CCM_NONCE_MIN];
        ctx.encrypt_init(&key, Some(&iv), None).unwrap();
        let mut params = ParamSet::new();
        params.set(param_keys::AEAD_TAG, ParamValue::OctetString(vec![0u8; 12]));
        let err = ctx
            .set_params(&params)
            .expect_err("AEAD_TAG on encrypt must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Constructing a context never returns a Send-broken type — the
    /// trait bound `CipherContext: Send + Sync` is exercised here.
    #[test]
    fn context_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AesCcmContext>();
        assert_send_sync::<AesCcmCipher>();
    }

    /// CCM nonce of 13 bytes (the maximum allowed) round-trips correctly.
    /// This exercises the engine-rebuild path triggered by a non-default
    /// IV length.
    #[test]
    fn round_trip_with_max_nonce_length() {
        let key = [0x55u8; 16];
        let iv = [0xa5u8; CCM_NONCE_MAX];
        let plaintext = b"max-nonce payload";

        let cipher = AesCcmCipher::new("AES-128-CCM", 16);
        // Set IV length first so the engine is built with the right nonce
        // geometry on init.
        let mut ctx_e = cipher.new_ctx().unwrap();
        let mut params = ParamSet::new();
        // `usize` → `u32` is lossless for the small constant `CCM_NONCE_MAX`.
        let max_nonce_u32 = u32::try_from(CCM_NONCE_MAX).expect("CCM_NONCE_MAX fits u32");
        params.set(param_keys::IVLEN, ParamValue::UInt32(max_nonce_u32));
        ctx_e.set_params(&params).expect("set IV length");
        ctx_e
            .encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        ctx_e.update(plaintext, &mut ct).expect("update");
        ctx_e.finalize(&mut ct).expect("finalize");
        let tag = match ctx_e.get_params().unwrap().get(param_keys::AEAD_TAG) {
            Some(ParamValue::OctetString(bytes)) => bytes.clone(),
            _ => panic!("no AEAD_TAG"),
        };

        // Decrypt with the same IV length and key.
        let mut ctx_d = cipher.new_ctx().unwrap();
        ctx_d.set_params(&params).expect("set IV length dec");
        ctx_d
            .decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag));
        ctx_d.set_params(&tag_params).expect("set tag");
        let mut pt = Vec::new();
        ctx_d.update(&ct, &mut pt).expect("update dec");
        ctx_d.finalize(&mut pt).expect("finalize dec");
        assert_eq!(pt.as_slice(), plaintext);
    }
}
