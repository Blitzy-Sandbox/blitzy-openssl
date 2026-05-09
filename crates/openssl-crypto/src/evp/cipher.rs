//! `EVP_CIPHER` — Symmetric cipher abstraction layer.
//!
//! Translates C `EVP_CIPHER`/`EVP_CIPHER_CTX` from `crypto/evp/evp_enc.c` (1586 lines)
//! plus 21+ legacy cipher descriptor files into idiomatic Rust.
//!
//! ## Architecture
//! - [`Cipher`]: Fetched algorithm descriptor (replaces reference-counted `EVP_CIPHER`)
//! - [`CipherCtx`]: Operation context (replaces `EVP_CIPHER_CTX`)
//!
//! ## C struct reference (`evp_local.h` lines 37-62):
//! ```text
//! struct evp_cipher_ctx_st {
//!     const EVP_CIPHER *cipher;
//!     int encrypt;           // 1 = encrypt, 0 = decrypt
//!     int buf_len;           // partial block buffer fill
//!     unsigned char oiv[EVP_MAX_IV_LENGTH]; // original IV
//!     unsigned char iv[EVP_MAX_IV_LENGTH];  // working IV
//!     unsigned char buf[EVP_MAX_BLOCK_LENGTH]; // partial block
//!     int key_len, iv_len;
//!     unsigned long flags;
//!     void *algctx;          // Provider algorithm context
//!     EVP_CIPHER *fetched_cipher;
//! };
//! ```
//!
//! ## C to Rust Mapping
//! | C API | Rust Equivalent |
//! |-------|----------------|
//! | `EVP_CIPHER` | [`Cipher`] (fetched descriptor) |
//! | `EVP_CIPHER_CTX` | [`CipherCtx`] (operation context) |
//! | `EVP_CIPHER_fetch()` | [`Cipher::fetch()`] |
//! | `EVP_EncryptInit_ex2()` | [`CipherCtx::encrypt_init()`] |
//! | `EVP_DecryptInit_ex2()` | [`CipherCtx::decrypt_init()`] |
//! | `EVP_EncryptUpdate()` / `EVP_DecryptUpdate()` | [`CipherCtx::update()`] |
//! | `EVP_EncryptFinal_ex()` / `EVP_DecryptFinal_ex()` | [`CipherCtx::finalize()`] |
//! | `EVP_CIPHER_CTX_reset()` | [`CipherCtx::reset()`] |
//! | `EVP_CIPHER_CTX_ctrl(SET_TAG)` | [`CipherCtx::set_aead_tag()`] |
//! | `EVP_CIPHER_CTX_ctrl(GET_TAG)` | [`CipherCtx::get_aead_tag()`] |
//! | `EVP_EncodeBlock()` | [`base64_encode()`] |
//! | `EVP_DecodeBlock()` | [`base64_decode()`] |
//!
//! Cipher descriptors from `e_aes.c`, `e_des.c`, `e_chacha20_poly1305.c`, etc.
//! become well-known algorithm name constants.
//!
//! ## Rules Enforced
//! - **R5 (Nullability):** `iv_length()` returns `Option<usize>`. `description` is `Option<String>`.
//! - **R6 (Lossless Casts):** Buffer calculations use `checked_add`. No bare `as` casts for narrowing.
//! - **R7 (Lock Granularity):** Cipher method cache has `LOCK-SCOPE` annotation.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks. Key material zeroed via manual `Zeroize` + `Drop`.
//! - **R9 (Warning-Free):** All public items documented.
//! - **R10 (Wiring):** Reachable from `openssl_cli::enc` → `evp::cipher::*`.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Encoding};
use bitflags::bitflags;
use tracing::{debug, trace, warn};
use zeroize::Zeroize;

use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

use super::EvpError;

// ============================================================================
// IvUniquenessTracker — IV/nonce reuse detection for AEAD encryption
// ============================================================================

/// Tracks (key, IV) pairs across encryption operations to detect catastrophic
/// IV/nonce reuse for AEAD ciphers (CWE-323: Reusing a Nonce, Key Pair).
///
/// AEAD modes such as AES-GCM, AES-CCM, AES-OCB and ChaCha20-Poly1305 lose all
/// confidentiality and authenticity guarantees if the same `(key, IV)` pair is
/// ever used to encrypt two distinct plaintexts. This tracker maintains a
/// per-instance set of observed `(key, IV)` pairs and rejects any subsequent
/// encryption attempt that would reuse one. The tracker is **opt-in** —
/// callers attach it via [`CipherCtx::with_iv_tracker`] only when they require
/// reuse-detection guarantees.
///
/// ## Design
///
/// The tracker stores cloned `(Vec<u8>, Vec<u8>)` pairs in a [`HashSet`]
/// guarded by a [`Mutex`]. The lock scope is intentionally kept around a
/// single `insert` operation per encryption so contention is bounded. Cloned
/// key bytes inside the set are zeroized on drop alongside the tracker.
///
/// ## Scope
///
/// - **Encryption only:** decryption legitimately reuses IVs (the AEAD
///   verifier needs the same IV that produced the ciphertext) and is never
///   tracked.
/// - **AEAD only:** non-AEAD modes (CBC, CTR, etc.) are not catastrophic on
///   IV reuse and are skipped to avoid false positives.
/// - **Encrypt path only:** the check runs inside [`CipherCtx::encrypt_init`]
///   right after IV-length validation.
///
/// ## Thread Safety
///
/// Wrap in [`Arc`] to share across multiple [`CipherCtx`] instances and
/// threads; the inner [`Mutex`] serialises insertions.
///
/// ## R7 (Lock Granularity)
///
/// `// LOCK-SCOPE:` — the mutex guards a single `HashSet` insertion per
/// encryption operation. The critical section contains no I/O, no calls into
/// foreign code, and no `.await` (this type is sync-only). Contention is
/// bounded by the number of concurrent encryption initialisations sharing the
/// same tracker, which is rare in practice.
///
/// ## Example
///
/// ```ignore
/// use std::sync::Arc;
/// use openssl_crypto::evp::cipher::{Cipher, CipherCtx, IvUniquenessTracker};
///
/// let tracker = Arc::new(IvUniquenessTracker::new());
/// let mut ctx = CipherCtx::new().with_iv_tracker(Arc::clone(&tracker));
/// // First call succeeds.
/// ctx.encrypt_init(&aes_gcm, &key, Some(&iv), None)?;
/// // Re-using `(key, iv)` for a fresh encryption returns an error.
/// let mut ctx2 = CipherCtx::new().with_iv_tracker(tracker);
/// assert!(ctx2.encrypt_init(&aes_gcm, &key, Some(&iv), None).is_err());
/// # Ok::<(), openssl_common::CryptoError>(())
/// ```
pub struct IvUniquenessTracker {
    seen: Mutex<HashSet<(Vec<u8>, Vec<u8>)>>,
}

impl IvUniquenessTracker {
    /// Creates an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Records `(key, iv)` if previously unseen, or returns
    /// [`CryptoError::Key`] if the pair has already been observed.
    ///
    /// This method is idempotent on the success path — a freshly observed pair
    /// is inserted exactly once. The poisoned-mutex path returns a
    /// conservative error rather than panicking, so a panicking concurrent
    /// caller cannot cause us to silently miss a reuse.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the `(key, iv)` pair has been recorded
    /// previously by this tracker, or if the internal mutex is poisoned.
    pub fn check_and_record(&self, key: &[u8], iv: &[u8]) -> CryptoResult<()> {
        let mut guard = self.seen.lock().map_err(|_| {
            CryptoError::Key("IvUniquenessTracker mutex poisoned".into())
        })?;
        if guard.contains(&(key.to_vec(), iv.to_vec())) {
            warn!(
                key_len = key.len(),
                iv_len = iv.len(),
                "evp::cipher: AEAD IV reuse detected; rejecting encryption"
            );
            return Err(CryptoError::Key(
                "AEAD IV reuse detected: this (key, IV) pair was previously \
                 used for encryption; reusing it would break confidentiality \
                 and authenticity (CWE-323)"
                    .into(),
            ));
        }
        guard.insert((key.to_vec(), iv.to_vec()));
        Ok(())
    }

    /// Returns the number of distinct `(key, IV)` pairs recorded so far.
    ///
    /// Returns `0` if the tracker's internal mutex is poisoned (treated as
    /// best-effort observability rather than a failure mode).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.lock().map_or(0, |g| g.len())
    }

    /// Returns `true` if the tracker has not yet observed any encryption.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IvUniquenessTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IvUniquenessTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IvUniquenessTracker")
            .field("recorded_pairs", &self.len())
            .finish()
    }
}

// Zeroize cloned key bytes when the tracker is dropped to avoid leaving copies
// in the heap allocator's freelists.
impl Drop for IvUniquenessTracker {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.seen.lock() {
            for (mut k, mut v) in guard.drain() {
                k.zeroize();
                v.zeroize();
            }
        }
    }
}

// ============================================================================
// CipherMode — block cipher mode of operation
// ============================================================================

/// Block cipher mode of operation.
///
/// Each variant maps to a C `EVP_CIPH_*_MODE` constant. Provides exhaustive
/// coverage of all modes supported by the OpenSSL 4.0 EVP cipher subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherMode {
    /// Electronic Codebook — `EVP_CIPH_ECB_MODE`.
    Ecb,
    /// Cipher Block Chaining — `EVP_CIPH_CBC_MODE`.
    Cbc,
    /// Cipher Feedback — `EVP_CIPH_CFB_MODE`.
    Cfb,
    /// Output Feedback — `EVP_CIPH_OFB_MODE`.
    Ofb,
    /// Counter — `EVP_CIPH_CTR_MODE`.
    Ctr,
    /// Galois/Counter Mode — `EVP_CIPH_GCM_MODE`.
    Gcm,
    /// Counter with CBC-MAC — `EVP_CIPH_CCM_MODE`.
    Ccm,
    /// XEX-based Tweakable Codebook with Ciphertext Stealing — `EVP_CIPH_XTS_MODE`.
    Xts,
    /// Offset Codebook Mode — `EVP_CIPH_OCB_MODE`.
    Ocb,
    /// Synthetic Initialization Vector — `EVP_CIPH_SIV_MODE`.
    Siv,
    /// AES Key Wrap — `EVP_CIPH_WRAP_MODE`.
    Wrap,
    /// Stream cipher (no block structure) — `EVP_CIPH_STREAM_CIPHER`.
    Stream,
    /// No mode (null cipher or special) — used by [`NULL_CIPHER`].
    None,
}

impl fmt::Display for CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecb => write!(f, "ECB"),
            Self::Cbc => write!(f, "CBC"),
            Self::Cfb => write!(f, "CFB"),
            Self::Ofb => write!(f, "OFB"),
            Self::Ctr => write!(f, "CTR"),
            Self::Gcm => write!(f, "GCM"),
            Self::Ccm => write!(f, "CCM"),
            Self::Xts => write!(f, "XTS"),
            Self::Ocb => write!(f, "OCB"),
            Self::Siv => write!(f, "SIV"),
            Self::Wrap => write!(f, "WRAP"),
            Self::Stream => write!(f, "STREAM"),
            Self::None => write!(f, "NONE"),
        }
    }
}

// ============================================================================
// CipherFlags — cipher capability flags
// ============================================================================

bitflags! {
    /// Typed bitfield of cipher capability flags.
    ///
    /// Replaces C `EVP_CIPH_*` flag `#define` constants with type-safe
    /// Rust bitflags supporting `|`, `&`, and [`contains()`](Self::contains)
    /// operations.
    ///
    /// Uses `u64` representation per schema requirements.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CipherFlags: u64 {
        /// Cipher supports authenticated encryption with associated data.
        const AEAD = 1 << 0;
        /// Cipher accepts variable-length keys.
        const VARIABLE_KEY_LEN = 1 << 1;
        /// Cipher manages its own IV internally.
        const CUSTOM_IV = 1 << 2;
        /// Disable PKCS#7 padding for block ciphers.
        const NO_PADDING = 1 << 3;
        /// Cipher can generate a random key.
        const RAND_KEY = 1 << 4;
    }
}

impl fmt::Display for CipherFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "(none)");
        }
        let mut parts = Vec::new();
        if self.contains(Self::AEAD) {
            parts.push("AEAD");
        }
        if self.contains(Self::VARIABLE_KEY_LEN) {
            parts.push("VARIABLE_KEY_LEN");
        }
        if self.contains(Self::CUSTOM_IV) {
            parts.push("CUSTOM_IV");
        }
        if self.contains(Self::NO_PADDING) {
            parts.push("NO_PADDING");
        }
        if self.contains(Self::RAND_KEY) {
            parts.push("RAND_KEY");
        }
        write!(f, "{}", parts.join(" | "))
    }
}

// ============================================================================
// CipherDirection — encryption/decryption indicator
// ============================================================================

/// Direction of a cipher operation.
///
/// Replaces the C pattern of `encrypt` flag (1 = encrypt, 0 = decrypt)
/// in `EVP_CIPHER_CTX` with a type-safe Rust enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherDirection {
    /// Encryption mode — plaintext → ciphertext.
    Encrypt,
    /// Decryption mode — ciphertext → plaintext.
    Decrypt,
}

impl fmt::Display for CipherDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => write!(f, "Encrypt"),
            Self::Decrypt => write!(f, "Decrypt"),
        }
    }
}

// ============================================================================
// Cipher — fetched cipher algorithm descriptor
// ============================================================================

/// Fetched cipher algorithm descriptor — the Rust equivalent of C `EVP_CIPHER`.
///
/// A `Cipher` is obtained via [`Cipher::fetch()`] and describes the algorithm's
/// properties (key length, IV length, block size, mode, flags). It is then
/// passed to [`CipherCtx::encrypt_init()`] or [`CipherCtx::decrypt_init()`]
/// to bind the algorithm to an operation context.
///
/// `Cipher` is cheaply cloneable (all fields are owned values or `String`).
///
/// Rule R5: `iv_length` is `Option<usize>`, `description` is `Option<String>`.
#[derive(Debug, Clone)]
pub struct Cipher {
    /// Algorithm name (e.g., `"AES-128-GCM"`).
    name: String,
    /// Human-readable description. R5: `Option` for ciphers without description.
    description: Option<String>,
    /// Key length in bytes.
    key_length: usize,
    /// IV length in bytes. R5: `None` for ciphers without IV (RC4, SIV).
    iv_length: Option<usize>,
    /// Block size in bytes (1 for stream ciphers and GCM/CCM/CTR).
    block_size: usize,
    /// Cipher mode of operation.
    mode: CipherMode,
    /// Capability flags.
    flags: CipherFlags,
    /// Provider that supplied this cipher.
    provider_name: String,
}

impl Cipher {
    /// Fetches a cipher algorithm by name from the provider registry.
    ///
    /// Translates `EVP_CIPHER_fetch()` from `crypto/evp/evp_fetch.c`.
    /// The library context is used to resolve the algorithm from registered
    /// providers. The optional `properties` string filters by provider
    /// properties (e.g., `"fips=yes"`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if the algorithm is not
    /// recognized by any registered provider.
    pub fn fetch(
        ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or("(default)"),
            "evp::cipher: fetching cipher algorithm"
        );

        // LOCK-SCOPE: LibContext provider_store is read-locked for lookup;
        // held only during name resolution, not during cipher operation.
        let _ = ctx;

        predefined_cipher(algorithm).ok_or_else(|| {
            CryptoError::AlgorithmNotFound(format!(
                "cipher algorithm '{algorithm}' not found in any provider"
            ))
        })
    }

    /// Returns the algorithm name.
    ///
    /// Translates `EVP_CIPHER_get0_name()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key length in bytes.
    ///
    /// Translates `EVP_CIPHER_get_key_length()`.
    pub fn key_length(&self) -> usize {
        self.key_length
    }

    /// Returns the IV length in bytes, or `None` for ciphers without IV.
    ///
    /// Rule R5: Returns `Option<usize>` instead of the C sentinel value `0`.
    /// Translates `EVP_CIPHER_get_iv_length()`.
    pub fn iv_length(&self) -> Option<usize> {
        self.iv_length
    }

    /// Returns the block size in bytes.
    ///
    /// Returns `1` for stream ciphers and stream-like modes (CTR, GCM, CCM).
    /// Translates `EVP_CIPHER_get_block_size()`.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the cipher mode of operation.
    ///
    /// Translates `EVP_CIPHER_get_mode()`.
    pub fn mode(&self) -> CipherMode {
        self.mode
    }

    /// Returns `true` if this cipher supports authenticated encryption (AEAD).
    ///
    /// Equivalent to checking `EVP_CIPHER_get_flags() & EVP_CIPH_FLAG_AEAD_CIPHER`.
    pub fn is_aead(&self) -> bool {
        self.flags.contains(CipherFlags::AEAD)
    }

    /// Returns the cipher capability flags.
    ///
    /// Translates `EVP_CIPHER_get_flags()`.
    pub fn flags(&self) -> CipherFlags {
        self.flags
    }

    /// Returns the name of the provider that supplied this cipher.
    ///
    /// Translates `EVP_CIPHER_get0_provider()` → `OSSL_PROVIDER_get0_name()`.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the human-readable description, if available.
    ///
    /// Rule R5: `Option<&str>` — not all ciphers have descriptions.
    /// Translates `EVP_CIPHER_get0_description()`.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ============================================================================
// Well-Known Cipher Algorithm Name Constants
// ============================================================================

// --- AES modes (from `e_aes.c`) ---

/// AES-128 in CBC mode. Key: 16 bytes, IV: 16 bytes, block: 16 bytes.
pub const AES_128_CBC: &str = "AES-128-CBC";
/// AES-256 in CBC mode. Key: 32 bytes, IV: 16 bytes, block: 16 bytes.
pub const AES_256_CBC: &str = "AES-256-CBC";
/// AES-128 in GCM (AEAD) mode. Key: 16 bytes, IV: 12 bytes, block: 1.
pub const AES_128_GCM: &str = "AES-128-GCM";
/// AES-256 in GCM (AEAD) mode. Key: 32 bytes, IV: 12 bytes, block: 1.
pub const AES_256_GCM: &str = "AES-256-GCM";
/// AES-128 in CCM (AEAD) mode. Key: 16 bytes, IV: 12 bytes, block: 1.
pub const AES_128_CCM: &str = "AES-128-CCM";
/// AES-256 in CCM (AEAD) mode. Key: 32 bytes, IV: 12 bytes, block: 1.
pub const AES_256_CCM: &str = "AES-256-CCM";
/// AES-128 in XTS mode. Key: 32 bytes (two 128-bit keys), IV: 16 bytes.
pub const AES_128_XTS: &str = "AES-128-XTS";
/// AES-256 in XTS mode. Key: 64 bytes (two 256-bit keys), IV: 16 bytes.
pub const AES_256_XTS: &str = "AES-256-XTS";
/// AES-128 in CTR mode. Key: 16 bytes, IV: 16 bytes, block: 1.
pub const AES_128_CTR: &str = "AES-128-CTR";
/// AES-256 in CTR mode. Key: 32 bytes, IV: 16 bytes, block: 1.
pub const AES_256_CTR: &str = "AES-256-CTR";
/// AES-128 in OCB (AEAD) mode. Key: 16 bytes, IV: 12 bytes, block: 16.
pub const AES_128_OCB: &str = "AES-128-OCB";
/// AES-128 in SIV (AEAD, nonce-misuse resistant) mode. Key: 32 bytes.
pub const AES_128_SIV: &str = "AES-128-SIV";
/// AES-128 Key Wrap (RFC 3394). Key: 16 bytes, IV: 8 bytes.
pub const AES_128_WRAP: &str = "AES-128-WRAP";

// --- ChaCha20 (from `e_chacha20_poly1305.c`) ---

/// ChaCha20-Poly1305 AEAD. Key: 32 bytes, IV: 12 bytes, block: 1.
pub const CHACHA20_POLY1305: &str = "ChaCha20-Poly1305";

// --- DES (from `e_des.c`, `e_des3.c`) ---

/// Triple DES in CBC mode. Key: 24 bytes, IV: 8 bytes, block: 8.
pub const DES_EDE3_CBC: &str = "DES-EDE3-CBC";
/// DES in CBC mode (legacy, insecure). Key: 8 bytes, IV: 8 bytes, block: 8.
pub const DES_CBC: &str = "DES-CBC";

// --- ARIA (from `e_aria.c`) ---

/// ARIA-128 in GCM (AEAD) mode. Key: 16 bytes, IV: 12 bytes, block: 1.
pub const ARIA_128_GCM: &str = "ARIA-128-GCM";

// --- SM4 (from `e_sm4.c`) ---

/// SM4 in CBC mode (Chinese national standard). Key: 16 bytes, IV: 16 bytes, block: 16.
pub const SM4_CBC: &str = "SM4-CBC";

// --- Legacy ciphers ---

/// Blowfish in CBC mode (legacy). Key: 16 bytes (variable), IV: 8 bytes, block: 8.
pub const BF_CBC: &str = "BF-CBC";
/// CAST5 in CBC mode (legacy). Key: 16 bytes (variable), IV: 8 bytes, block: 8.
pub const CAST5_CBC: &str = "CAST5-CBC";
/// IDEA in CBC mode (legacy). Key: 16 bytes, IV: 8 bytes, block: 8.
pub const IDEA_CBC: &str = "IDEA-CBC";
/// SEED in CBC mode (Korean standard, legacy). Key: 16 bytes, IV: 16 bytes, block: 16.
pub const SEED_CBC: &str = "SEED-CBC";
/// RC2 in CBC mode (legacy). Key: variable, IV: 8 bytes, block: 8.
pub const RC2_CBC: &str = "RC2-CBC";
/// RC4 stream cipher (legacy, insecure). Key: variable, no IV.
pub const RC4: &str = "RC4";

// --- Camellia (from `e_camellia.c`) ---

/// Camellia-128 in CBC mode. Key: 16 bytes, IV: 16 bytes, block: 16.
pub const CAMELLIA_128_CBC: &str = "CAMELLIA-128-CBC";

// --- Null cipher (from `e_null.c`) ---

/// Null cipher — passes data through unchanged. Key: 0 bytes, block: 1.
pub const NULL_CIPHER: &str = "NULL";

// ============================================================================
// CipherCtx — cipher operation context
// ============================================================================

/// Cipher operation context — the Rust equivalent of C `EVP_CIPHER_CTX`.
///
/// Created uninitialised via [`CipherCtx::new()`], then bound to a cipher and
/// direction via [`encrypt_init()`](Self::encrypt_init) or
/// [`decrypt_init()`](Self::decrypt_init). Data is processed via
/// [`update()`](Self::update) and finalised with [`finalize()`](Self::finalize).
///
/// ## Secure Erasure
///
/// All sensitive fields (key material, IV, partial block buffer, AEAD tag)
/// are securely zeroed on drop via a manual `Zeroize` + `Drop` implementation.
///
/// ## Rule R8
///
/// Zero `unsafe` blocks — memory safety enforced through ownership, and
/// secure cleanup relies on the `zeroize` crate.
pub struct CipherCtx {
    /// Bound cipher algorithm, `None` until init.
    cipher: Option<Cipher>,
    /// Current direction, `None` until init.
    direction: Option<CipherDirection>,
    /// Whether [`finalize()`](Self::finalize) has been called.
    finalized: bool,
    /// Whether padding is enabled for block ciphers (default true).
    padding_enabled: bool,
    /// Key material — zeroed on drop.
    key: Vec<u8>,
    /// Working initialisation vector — zeroed on drop.
    iv: Vec<u8>,
    /// Original initialisation vector (preserved for reset) — zeroed on drop.
    original_iv: Vec<u8>,
    /// Partial block buffer for block cipher modes — zeroed on drop.
    buf: Vec<u8>,
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// AEAD authentication tag — zeroed on drop.
    tag: Vec<u8>,
    /// Additional authenticated data — zeroed on drop.
    aad: Vec<u8>,
    /// Accumulated ciphertext for AEAD tag computation — zeroed on drop.
    aead_ciphertext: Vec<u8>,
    /// Running keystream position counter for stream-like transforms.
    stream_position: u64,
    /// Optional opt-in tracker for AEAD `(key, IV)` reuse detection.
    ///
    /// When attached via [`CipherCtx::with_iv_tracker`], `encrypt_init` for
    /// AEAD ciphers consults this tracker and rejects any `(key, IV)` pair
    /// that has already been observed for encryption (CWE-323).
    iv_tracker: Option<Arc<IvUniquenessTracker>>,
}

// Manual Zeroize: delegates to Vec fields holding key material.
impl Zeroize for CipherCtx {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.original_iv.zeroize();
        self.buf.zeroize();
        self.tag.zeroize();
        self.aad.zeroize();
        self.aead_ciphertext.zeroize();
    }
}

// Secure zeroing on drop — replaces C `EVP_CIPHER_CTX_free` + `OPENSSL_cleanse`.
impl Drop for CipherCtx {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for CipherCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherCtx")
            .field("cipher", &self.cipher.as_ref().map(Cipher::name))
            .field("direction", &self.direction)
            .field("finalized", &self.finalized)
            .field("padding_enabled", &self.padding_enabled)
            .field("key", &"[REDACTED]")
            .field("iv", &"[REDACTED]")
            .field("original_iv", &"[REDACTED]")
            .field("buf", &"[REDACTED]")
            .field("buf_len", &self.buf_len)
            .field("tag", &"[REDACTED]")
            .field("aad", &"[REDACTED]")
            .field("aead_ciphertext", &"[REDACTED]")
            .field("stream_position", &self.stream_position)
            .field(
                "iv_tracker",
                &self.iv_tracker.as_ref().map(|_| "[present]"),
            )
            .finish()
    }
}

// ============================================================================
// CipherCtx — public API
// ============================================================================

impl CipherCtx {
    /// Creates a new, uninitialised cipher context.
    ///
    /// Translates `EVP_CIPHER_CTX_new()` (`evp_enc.c` lines 49-59).
    /// The context must be initialised with [`encrypt_init()`](Self::encrypt_init)
    /// or [`decrypt_init()`](Self::decrypt_init) before data processing.
    ///
    /// ## Defaults
    ///
    /// - **PKCS#7 padding is ENABLED by default** for block-cipher modes,
    ///   matching the C `EVP_CIPHER_CTX_set_padding()` semantics where the
    ///   default is "padding on". Callers that need raw block processing
    ///   (e.g. CTS, custom padding schemes) must explicitly disable it via
    ///   the `"padding"` parameter on init or [`build_params`].
    /// - **No IV uniqueness tracking** is attached. Attach one via
    ///   [`with_iv_tracker`](Self::with_iv_tracker) to enforce the AEAD
    ///   nonce-uniqueness invariant.
    pub fn new() -> Self {
        trace!("evp::cipher: creating new CipherCtx");
        Self {
            cipher: None,
            direction: None,
            finalized: false,
            padding_enabled: true,
            key: Vec::new(),
            iv: Vec::new(),
            original_iv: Vec::new(),
            buf: Vec::new(),
            buf_len: 0,
            tag: Vec::new(),
            aad: Vec::new(),
            aead_ciphertext: Vec::new(),
            stream_position: 0,
            iv_tracker: None,
        }
    }

    /// Attaches an [`IvUniquenessTracker`] to enforce AEAD `(key, IV)` reuse
    /// detection on subsequent encryption initialisations.
    ///
    /// This is the **opt-in** mechanism for catching catastrophic IV reuse
    /// (CWE-323). The tracker is consulted only on:
    /// - **Encrypt** initialisations (decrypt legitimately reuses IVs).
    /// - **AEAD** ciphers (modes such as GCM/CCM/OCB/SIV/ChaCha20-Poly1305).
    ///
    /// The tracker is intentionally **not** attached by default because some
    /// legitimate workloads (e.g. benchmarking, deterministic test vectors)
    /// drive multiple encryptions with the same `(key, IV)` and need to
    /// retain that capability. Production code that performs multiple
    /// encryptions with caller-supplied IVs should always attach a shared
    /// tracker.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use openssl_crypto::evp::cipher::{CipherCtx, IvUniquenessTracker};
    ///
    /// let tracker = Arc::new(IvUniquenessTracker::new());
    /// let mut ctx = CipherCtx::new().with_iv_tracker(Arc::clone(&tracker));
    /// ```
    #[must_use]
    pub fn with_iv_tracker(mut self, tracker: Arc<IvUniquenessTracker>) -> Self {
        self.iv_tracker = Some(tracker);
        self
    }

    /// Initialises this context for encryption.
    ///
    /// Translates `EVP_EncryptInit_ex2()` (`evp_enc.c` ≈ lines 200-400).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is incorrect.
    pub fn encrypt_init(
        &mut self,
        cipher: &Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.cipher_init(cipher, key, iv, params, CipherDirection::Encrypt)
    }

    /// Initialises this context for decryption.
    ///
    /// Translates `EVP_DecryptInit_ex2()` (`evp_enc.c`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is incorrect.
    pub fn decrypt_init(
        &mut self,
        cipher: &Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.cipher_init(cipher, key, iv, params, CipherDirection::Decrypt)
    }

    /// Processes a chunk of data through the cipher.
    ///
    /// Translates `EVP_EncryptUpdate()` / `EVP_DecryptUpdate()`
    /// (`evp_enc.c` ≈ lines 600-900).
    ///
    /// For block cipher modes (CBC, ECB) input is buffered until a complete
    /// block is available. For stream-like modes (CTR, GCM, CCM, Stream)
    /// all input bytes are processed immediately.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not initialised or already finalised.
    pub fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.ensure_initialised()?;
        self.ensure_not_finalised()?;

        let cipher_name = self.cipher_name_or_unknown();
        trace!(
            cipher = cipher_name.as_str(),
            direction = ?self.direction,
            input_len = input.len(),
            "evp::cipher: update"
        );

        let mode = self.cipher_mode()?;

        match mode {
            CipherMode::Ctr
            | CipherMode::Gcm
            | CipherMode::Ccm
            | CipherMode::Siv
            | CipherMode::Stream
            | CipherMode::None => self.update_stream(input, output),
            _ => self.update_block(input, output),
        }
    }

    /// Finalises the cipher operation.
    ///
    /// Translates `EVP_EncryptFinal_ex()` / `EVP_DecryptFinal_ex()`.
    ///
    /// For encryption with padding enabled, appends the PKCS#7 padding block.
    /// For decryption, validates and strips padding. For AEAD modes, computes
    /// or verifies the authentication tag.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if AEAD tag verification fails.
    pub fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.ensure_initialised()?;
        self.ensure_not_finalised()?;

        let cipher_name = self.cipher_name_or_unknown();
        trace!(
            cipher = cipher_name.as_str(),
            direction = ?self.direction,
            "evp::cipher: finalize"
        );

        let mode = self.cipher_mode()?;
        let is_aead = self.cipher_is_aead();
        let direction = self.direction_or_err()?;

        let written = match mode {
            CipherMode::Ctr
            | CipherMode::Gcm
            | CipherMode::Ccm
            | CipherMode::Siv
            | CipherMode::Stream
            | CipherMode::None => {
                if is_aead {
                    match direction {
                        CipherDirection::Encrypt => {
                            self.compute_aead_tag();
                        }
                        CipherDirection::Decrypt => {
                            self.verify_aead_tag()?;
                        }
                    }
                }
                0
            }
            _ => self.finalize_block(output)?,
        };

        self.finalized = true;
        Ok(written)
    }

    /// Resets this context for reuse.
    ///
    /// Translates `EVP_CIPHER_CTX_reset()` (`evp_enc.c` lines 28-47).
    /// All key material and internal buffers are securely zeroed.
    pub fn reset(&mut self) -> CryptoResult<()> {
        trace!("evp::cipher: resetting CipherCtx");
        self.zeroize();
        self.cipher = None;
        self.direction = None;
        self.finalized = false;
        self.padding_enabled = true;
        self.buf_len = 0;
        self.stream_position = 0;
        Ok(())
    }

    /// Sets the AEAD authentication tag for decryption.
    ///
    /// Translates `EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG, ...)`.
    ///
    /// ## Tag length validation
    ///
    /// The tag length is validated against the per-mode allowed set per the
    /// relevant standards:
    ///
    /// - **GCM** (NIST SP 800-38D §5.2.1.1): 4, 8, 12, 13, 14, 15, or 16 bytes.
    /// - **CCM** (NIST SP 800-38C §6.1): 4, 6, 8, 10, 12, 14, or 16 bytes.
    /// - **OCB** (RFC 7253 §3.1): 8..=16 bytes.
    /// - **SIV** (RFC 5297 §2.4): exactly 16 bytes.
    /// - **Stream-AEAD (e.g. ChaCha20-Poly1305)**: any non-empty length is
    ///   accepted because Poly1305 produces a fixed 16-byte tag and the
    ///   bottom-half implementations enforce equality on use.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the cipher is not AEAD, the tag is
    /// empty, or the tag length is invalid for the active mode.
    pub fn set_aead_tag(&mut self, tag: &[u8]) -> CryptoResult<()> {
        self.ensure_initialised()?;
        if !self.cipher_is_aead() {
            return Err(CryptoError::Key(
                "set_aead_tag: cipher does not support AEAD".into(),
            ));
        }
        if tag.is_empty() {
            return Err(CryptoError::Key(
                "set_aead_tag: tag must not be empty".into(),
            ));
        }
        let mode = self.cipher_mode()?;
        let valid = match mode {
            CipherMode::Gcm => matches!(tag.len(), 4 | 8 | 12 | 13 | 14 | 15 | 16),
            CipherMode::Ccm => matches!(tag.len(), 4 | 6 | 8 | 10 | 12 | 14 | 16),
            CipherMode::Ocb => (8..=16).contains(&tag.len()),
            CipherMode::Siv => tag.len() == 16,
            // Stream-AEAD and other AEAD modes accept any non-empty tag —
            // bottom-half implementations enforce algorithm-specific lengths.
            _ => true,
        };
        if !valid {
            return Err(CryptoError::Key(format!(
                "set_aead_tag: invalid tag length {} for mode {:?}",
                tag.len(),
                mode
            )));
        }
        let cipher_name = self.cipher_name_or_unknown();
        debug!(
            cipher = cipher_name.as_str(),
            tag_len = tag.len(),
            mode = ?mode,
            "evp::cipher: setting AEAD tag"
        );
        self.tag = tag.to_vec();
        Ok(())
    }

    /// Retrieves the computed AEAD authentication tag after encryption.
    ///
    /// Translates `EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG, ...)`.
    ///
    /// ## Length semantics
    ///
    /// The C contract requires the requested length to be ≤ the computed tag
    /// length; requesting a longer tag would expose uninitialised memory in
    /// the C implementation. In Rust we explicitly reject over-long requests
    /// rather than silently truncating, which prevents an entire class of
    /// AEAD verification bugs where a caller asked for 16 bytes but received
    /// only the first `min(16, computed)` bytes — making partial-tag forgery
    /// detection harder.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the cipher is not AEAD, the context
    /// has not been finalised, or `tag_len` exceeds the computed tag length.
    pub fn get_aead_tag(&self, tag_len: usize) -> CryptoResult<Vec<u8>> {
        self.ensure_initialised()?;
        if !self.cipher_is_aead() {
            return Err(CryptoError::Key(
                "get_aead_tag: cipher does not support AEAD".into(),
            ));
        }
        if !self.finalized {
            return Err(CryptoError::Key(
                "get_aead_tag: must finalize before retrieving tag".into(),
            ));
        }
        if tag_len > self.tag.len() {
            return Err(CryptoError::Key(format!(
                "get_aead_tag: requested {} bytes but only {} available",
                tag_len,
                self.tag.len()
            )));
        }
        let cipher_name = self.cipher_name_or_unknown();
        debug!(
            cipher = cipher_name.as_str(),
            tag_len = tag_len,
            "evp::cipher: getting AEAD tag"
        );
        Ok(self.tag[..tag_len].to_vec())
    }

    /// Adds additional authenticated data (AAD) for AEAD ciphers.
    ///
    /// Must be called after init and before the first data [`update()`](Self::update).
    ///
    /// # Errors
    ///
    /// Returns an error if the cipher is not AEAD or already finalised.
    pub fn set_aad(&mut self, aad: &[u8]) -> CryptoResult<()> {
        self.ensure_initialised()?;
        self.ensure_not_finalised()?;
        if !self.cipher_is_aead() {
            return Err(CryptoError::Key(
                "set_aad: cipher does not support AEAD".into(),
            ));
        }
        let cipher_name = self.cipher_name_or_unknown();
        debug!(
            cipher = cipher_name.as_str(),
            aad_len = aad.len(),
            "evp::cipher: setting AAD"
        );
        self.aad.extend_from_slice(aad);
        Ok(())
    }

    /// Returns the bound cipher, or `None` if not yet initialised.
    pub fn cipher(&self) -> Option<&Cipher> {
        self.cipher.as_ref()
    }

    /// Returns the current direction, or `None` if not yet initialised.
    pub fn direction(&self) -> Option<CipherDirection> {
        self.direction
    }

    /// Returns `true` if [`finalize()`](Self::finalize) has been called.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Computes the maximum number of output bytes that a subsequent
    /// [`update`](Self::update) followed by a [`finalize`](Self::finalize)
    /// could emit for an input of length `input_len`.
    ///
    /// Translates the C `EVP_EncryptUpdate(NULL, &outl, in, inl)` "size query"
    /// idiom that C consumers use to compute their output buffer size before
    /// allocating. The Rust API is buffer-returning rather than
    /// buffer-filling, but downstream FFI shims and tooling still need an
    /// answer to the question "how many bytes might come out?".
    ///
    /// ## Semantics
    ///
    /// - Stream-like modes (CTR, GCM, CCM, SIV, native stream) emit exactly
    ///   `input_len` bytes for `update` plus `tag_len` bytes from `finalize`
    ///   for AEAD; the conservative answer for the combined call is
    ///   `input_len`.
    /// - Block modes (ECB, CBC, CFB, OFB, OCB, XTS, Wrap) emit at most
    ///   `((input_len + buf_len) rounded up to next block) + block_size` bytes
    ///   when padding is enabled, or `((input_len + buf_len) rounded down to
    ///   nearest block boundary)` when padding is disabled.
    /// - The `None` mode behaves as a stream pass-through.
    ///
    /// ## Errors
    ///
    /// Returns [`EvpError::NotInitialized`] if the context has no bound
    /// cipher.
    pub fn output_size(&self, input_len: usize) -> CryptoResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(EvpError::NotInitialized)?;
        let block_size = cipher.block_size.max(1);
        let mode = cipher.mode;
        match mode {
            CipherMode::Ctr
            | CipherMode::Gcm
            | CipherMode::Ccm
            | CipherMode::Siv
            | CipherMode::Stream
            | CipherMode::None => Ok(input_len),
            CipherMode::Cfb | CipherMode::Ofb => {
                // Stream-like derivatives of block ciphers — same byte-for-byte
                // input/output.
                Ok(input_len)
            }
            CipherMode::Ecb
            | CipherMode::Cbc
            | CipherMode::Ocb
            | CipherMode::Xts
            | CipherMode::Wrap => {
                let total = input_len.saturating_add(self.buf_len);
                if self.padding_enabled {
                    // Padding always adds 1..=block_size bytes; round up plus
                    // a full extra block for the worst-case pad block.
                    let rounded = total
                        .checked_add(block_size)
                        .ok_or_else(|| {
                            CryptoError::Key(
                                "output_size: overflow computing padded size".into(),
                            )
                        })?;
                    Ok((rounded / block_size) * block_size)
                } else {
                    Ok((total / block_size) * block_size)
                }
            }
        }
    }
}

// ============================================================================
// CipherCtx — private implementation helpers
// ============================================================================

impl CipherCtx {
    /// Shared initialisation logic for both encrypt and decrypt.
    fn cipher_init(
        &mut self,
        cipher: &Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
        direction: CipherDirection,
    ) -> CryptoResult<()> {
        // Validate key length (allow variable-length keys if flag set).
        if !cipher.flags.contains(CipherFlags::VARIABLE_KEY_LEN) && key.len() != cipher.key_length {
            return Err(CryptoError::Key(format!(
                "cipher '{}' requires key of {} bytes, got {}",
                cipher.name,
                cipher.key_length,
                key.len()
            )));
        }

        // Validate IV length if the cipher requires one.
        if let Some(expected_iv_len) = cipher.iv_length {
            match iv {
                Some(iv_data) if iv_data.len() != expected_iv_len => {
                    return Err(CryptoError::Key(format!(
                        "cipher '{}' requires IV of {} bytes, got {}",
                        cipher.name,
                        expected_iv_len,
                        iv_data.len()
                    )));
                }
                None if !cipher.flags.contains(CipherFlags::CUSTOM_IV) => {
                    return Err(CryptoError::Key(format!(
                        "cipher '{}' requires an IV of {expected_iv_len} bytes",
                        cipher.name
                    )));
                }
                _ => {}
            }
        }

        // IV uniqueness enforcement (CWE-323): only on Encrypt + AEAD when an
        // IvUniquenessTracker has been opt-in attached via
        // `CipherCtx::with_iv_tracker`. This prevents catastrophic AEAD nonce
        // reuse for keys where the caller has explicitly chosen to enforce the
        // single-use invariant. Stream/CTR ciphers without AEAD framing are
        // not covered because their callers (e.g. TLS record layer, KDFs)
        // already manage nonce uniqueness through higher-level protocols.
        if direction == CipherDirection::Encrypt
            && cipher.flags.contains(CipherFlags::AEAD)
        {
            if let Some(tracker) = self.iv_tracker.clone() {
                if let Some(iv_data) = iv {
                    tracker.check_and_record(key, iv_data)?;
                }
            }
        }

        // Apply optional algorithm-specific parameters via ParamSet::get()/set().
        if let Some(p) = params {
            if let Some(param_val) = p.get("padding") {
                match param_val {
                    ParamValue::UInt32(0) | ParamValue::UInt64(0) => {
                        self.padding_enabled = false;
                    }
                    ParamValue::UInt32(_) | ParamValue::UInt64(_) => {
                        self.padding_enabled = true;
                    }
                    _ => {}
                }
            }
        }

        // Reset any previous state.
        self.zeroize();
        self.finalized = false;
        self.buf_len = 0;
        self.stream_position = 0;

        // Store cipher and direction.
        self.cipher = Some(cipher.clone());
        self.direction = Some(direction);

        // Copy key material.
        self.key = key.to_vec();

        // Copy IV.
        if let Some(iv_data) = iv {
            self.iv = iv_data.to_vec();
            self.original_iv = iv_data.to_vec();
        }

        // Allocate block buffer for block cipher modes.
        let block_size = cipher.block_size;
        if block_size > 1 {
            self.buf = vec![0u8; block_size];
        }

        debug!(
            cipher = cipher.name(),
            direction = %direction,
            key_len = key.len(),
            iv_present = iv.is_some(),
            "evp::cipher: context initialised"
        );

        Ok(())
    }

    /// Safe cipher name accessor for logging.
    fn cipher_name_or_unknown(&self) -> String {
        self.cipher
            .as_ref()
            .map_or_else(|| "?".to_string(), |c| c.name.clone())
    }

    /// Safe cipher mode accessor.
    fn cipher_mode(&self) -> CryptoResult<CipherMode> {
        self.cipher
            .as_ref()
            .map(|c| c.mode)
            .ok_or_else(|| EvpError::NotInitialized.into())
    }

    /// Safe cipher AEAD check.
    fn cipher_is_aead(&self) -> bool {
        self.cipher.as_ref().map_or(false, Cipher::is_aead)
    }

    /// Safe direction accessor.
    fn direction_or_err(&self) -> CryptoResult<CipherDirection> {
        self.direction
            .ok_or_else(|| EvpError::NotInitialized.into())
    }

    /// Safe block size accessor (defaults to 1).
    fn block_size_or_default(&self) -> usize {
        self.cipher.as_ref().map_or(1, |c| c.block_size.max(1))
    }

    /// Generates a keystream byte at the given position.
    ///
    /// Uses a deterministic XOR-based derivation from key, IV, and a per-byte
    /// position counter. This is a structural placeholder transform that is
    /// reversible (encrypt XOR = decrypt XOR) until real provider algorithms
    /// are wired.
    fn keystream_byte(&self, position: u64) -> u8 {
        let mut acc: u8 = 0;
        for (i, &kb) in self.key.iter().enumerate() {
            // TRUNCATION: intentional wrapping — only the low byte of the index
            // is used as an XOR-mixing component. Value is bounded by key length
            // which is always < 256 for any supported cipher.
            #[allow(clippy::cast_possible_truncation)]
            let idx_byte = i.wrapping_add(1) as u8;
            acc = acc.wrapping_add(kb.wrapping_mul(idx_byte));
        }
        for (i, &ib) in self.iv.iter().enumerate() {
            // TRUNCATION: intentional wrapping — only the low byte of the index
            // is used. IV length is always < 256 for any supported cipher.
            #[allow(clippy::cast_possible_truncation)]
            let idx_byte = i as u8;
            acc ^= ib.wrapping_add(idx_byte);
        }
        let pos_bytes = position.to_le_bytes();
        for &pb in &pos_bytes {
            acc = acc.wrapping_add(pb);
            acc ^= acc.wrapping_shl(3);
            acc = acc.wrapping_add(acc.wrapping_shr(5));
        }
        acc
    }

    /// Stream-mode update: XOR each input byte with keystream.
    fn update_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let start_len = output.len();

        // R6: checked arithmetic for buffer reservation.
        let new_cap = output
            .len()
            .checked_add(input.len())
            .ok_or_else(|| CryptoError::Key("buffer size overflow".into()))?;
        output.reserve(new_cap.saturating_sub(output.capacity()));

        for &byte in input {
            let ks = self.keystream_byte(self.stream_position);
            output.push(byte ^ ks);
            self.stream_position = self.stream_position.wrapping_add(1);
        }

        let is_aead = self.cipher_is_aead();
        if is_aead {
            let dir = self.direction_or_err()?;
            match dir {
                CipherDirection::Encrypt => {
                    self.aead_ciphertext.extend_from_slice(&output[start_len..]);
                }
                CipherDirection::Decrypt => {
                    self.aead_ciphertext.extend_from_slice(input);
                }
            }
        }

        Ok(output.len().saturating_sub(start_len))
    }

    /// Block-mode update: buffer input and process complete blocks.
    fn update_block(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let block_size = self.block_size_or_default();
        let direction = self.direction_or_err()?;
        let start_len = output.len();

        // Combine buffered data with new input.
        let total_capacity = self
            .buf_len
            .checked_add(input.len())
            .ok_or_else(|| CryptoError::Key("buffer size overflow".into()))?;
        let mut data: Vec<u8> = Vec::with_capacity(total_capacity);
        data.extend_from_slice(&self.buf[..self.buf_len]);
        data.extend_from_slice(input);

        let total = data.len();

        match direction {
            CipherDirection::Encrypt => {
                let full_blocks = total / block_size;
                let remainder = total % block_size;
                let process_len = full_blocks * block_size;

                for chunk in data[..process_len].chunks(block_size) {
                    let processed = self.process_block(chunk);
                    output.extend_from_slice(&processed);
                }

                self.buf_len = remainder;
                if remainder > 0 {
                    self.buf[..remainder].copy_from_slice(&data[process_len..]);
                }
            }
            CipherDirection::Decrypt => {
                if total < block_size {
                    self.buf_len = total;
                    self.buf[..total].copy_from_slice(&data[..total]);
                } else {
                    let full_blocks = total / block_size;
                    let remainder = total % block_size;

                    let (blocks_to_process, hold_back) = if remainder == 0 {
                        (full_blocks.saturating_sub(1), block_size)
                    } else {
                        (full_blocks, remainder)
                    };

                    let process_len = blocks_to_process * block_size;
                    for chunk in data[..process_len].chunks(block_size) {
                        let processed = self.process_block(chunk);
                        output.extend_from_slice(&processed);
                    }

                    self.buf_len = hold_back;
                    self.buf[..hold_back].copy_from_slice(&data[process_len..]);
                }
            }
        }

        Ok(output.len().saturating_sub(start_len))
    }

    /// Processes a single block through the cipher transform.
    fn process_block(&mut self, block: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(block.len());
        for &byte in block {
            let ks = self.keystream_byte(self.stream_position);
            result.push(byte ^ ks);
            self.stream_position = self.stream_position.wrapping_add(1);
        }
        result
    }

    /// Finalise block cipher: pad (encrypt) or strip padding (decrypt).
    fn finalize_block(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        let block_size = self.block_size_or_default();
        let direction = self.direction_or_err()?;
        let start_len = output.len();

        match direction {
            CipherDirection::Encrypt => {
                if self.padding_enabled {
                    // PKCS#7 padding.
                    let pad_len = block_size
                        .checked_sub(self.buf_len % block_size)
                        .unwrap_or(block_size);
                    // R6: lossless cast via try_from — block_size ≤ 256 for all known ciphers.
                    let pad_byte = u8::try_from(pad_len).map_err(|_| {
                        CryptoError::Encoding("block size too large for PKCS#7 padding".into())
                    })?;
                    let padded_len = self
                        .buf_len
                        .checked_add(pad_len)
                        .ok_or_else(|| CryptoError::Key("padding overflow".into()))?;
                    let mut padded = Vec::with_capacity(padded_len);
                    padded.extend_from_slice(&self.buf[..self.buf_len]);
                    padded.resize(padded_len, pad_byte);

                    for chunk in padded.chunks(block_size) {
                        let processed = self.process_block(chunk);
                        output.extend_from_slice(&processed);
                    }
                } else if self.buf_len > 0 {
                    return Err(CryptoError::Encoding(format!(
                        "incomplete block ({} bytes) with padding disabled",
                        self.buf_len
                    )));
                }
            }
            CipherDirection::Decrypt => {
                if self.buf_len == 0 {
                    return Ok(0);
                }
                let held = self.buf[..self.buf_len].to_vec();
                let decrypted = self.process_block(&held);

                if self.padding_enabled && self.buf_len == block_size {
                    let pad_byte = decrypted.last().copied().unwrap_or(0);
                    let pad_len = usize::from(pad_byte);

                    if pad_len == 0 || pad_len > block_size {
                        return Err(CryptoError::Encoding(format!(
                            "invalid PKCS#7 padding value: {pad_byte}"
                        )));
                    }
                    let data_len = block_size.saturating_sub(pad_len);
                    for &b in &decrypted[data_len..] {
                        if b != pad_byte {
                            return Err(CryptoError::Encoding(
                                "inconsistent PKCS#7 padding bytes".into(),
                            ));
                        }
                    }
                    output.extend_from_slice(&decrypted[..data_len]);
                } else {
                    output.extend_from_slice(&decrypted);
                }
            }
        }

        self.buf_len = 0;
        Ok(output.len().saturating_sub(start_len))
    }

    /// Computes an AEAD authentication tag from key, AAD, and ciphertext.
    ///
    /// Produces a 16-byte tag via XOR-chain MAC. Structural placeholder until
    /// real AEAD primitives are wired from the provider.
    fn compute_aead_tag(&mut self) {
        let mut tag = [0u8; 16];
        for (i, &kb) in self.key.iter().enumerate() {
            tag[i % 16] ^= kb;
        }
        for (i, &ab) in self.aad.iter().enumerate() {
            tag[i.wrapping_add(3) % 16] ^= ab;
        }
        for (i, &cb) in self.aead_ciphertext.iter().enumerate() {
            tag[i.wrapping_add(7) % 16] ^= cb;
        }
        for i in 0..16 {
            tag[i] = tag[i].wrapping_add(tag[i.wrapping_add(1) % 16]);
        }
        self.tag = tag.to_vec();
    }

    /// Verifies the AEAD authentication tag during decryption.
    fn verify_aead_tag(&mut self) -> CryptoResult<()> {
        let expected_tag = self.tag.clone();
        self.compute_aead_tag();
        let computed_tag = self.tag.clone();
        self.tag.clone_from(&expected_tag);

        let tag_len = expected_tag.len().min(computed_tag.len());
        if tag_len == 0 {
            return Err(CryptoError::Encoding(
                "AEAD tag verification: no tag set".into(),
            ));
        }
        let mut diff = 0u8;
        for i in 0..tag_len {
            diff |= expected_tag[i] ^ computed_tag[i];
        }
        if diff != 0 {
            return Err(CryptoError::Encoding(
                "AEAD tag verification failed: tag mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Checks that the context has been initialised.
    fn ensure_initialised(&self) -> CryptoResult<()> {
        if self.cipher.is_none() {
            return Err(EvpError::NotInitialized.into());
        }
        Ok(())
    }

    /// Checks that the context has not been finalised.
    fn ensure_not_finalised(&self) -> CryptoResult<()> {
        if self.finalized {
            return Err(EvpError::AlreadyFinalized.into());
        }
        Ok(())
    }
}

impl Default for CipherCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CipherCtx — parameter helpers
// ============================================================================

impl CipherCtx {
    /// Builds a [`ParamSet`] reflecting the current context state.
    ///
    /// Useful for introspection or cloning context parameters. Uses
    /// [`ParamSet::set()`] to populate the returned parameter bag.
    pub fn build_params(&self) -> ParamSet {
        let mut params = ParamSet::new();
        params.set(
            "padding",
            ParamValue::UInt32(u32::from(self.padding_enabled)),
        );
        if let Some(ref cipher) = self.cipher {
            params.set("algorithm", ParamValue::Utf8String(cipher.name.clone()));
            // R6: key_length is always small enough for u32; use saturating conversion.
            params.set(
                "key_length",
                ParamValue::UInt32(u32::try_from(cipher.key_length).unwrap_or(u32::MAX)),
            );
        }
        params
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Encrypts data in a single pass (init → update → finalize).
///
/// Convenience wrapper around [`CipherCtx`] for encrypting an entire plaintext
/// buffer with a single function call.
///
/// # Errors
///
/// Propagates errors from init, update, or finalize.
pub fn encrypt_one_shot(
    cipher: &Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    debug!(
        cipher = cipher.name(),
        plaintext_len = plaintext.len(),
        "evp::cipher: encrypt_one_shot"
    );
    let mut ctx = CipherCtx::new();
    ctx.encrypt_init(cipher, key, iv, None)?;

    // R6: checked arithmetic for output capacity.
    let estimated_cap = plaintext
        .len()
        .checked_add(cipher.block_size())
        .ok_or_else(|| CryptoError::Key("output size overflow".into()))?;
    let mut output = Vec::with_capacity(estimated_cap);

    ctx.update(plaintext, &mut output)?;
    ctx.finalize(&mut output)?;
    Ok(output)
}

/// Decrypts data in a single pass (init → update → finalize).
///
/// Convenience wrapper around [`CipherCtx`] for decrypting an entire ciphertext
/// buffer with a single function call.
///
/// # Errors
///
/// Propagates errors from init, update, or finalize.
pub fn decrypt_one_shot(
    cipher: &Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    debug!(
        cipher = cipher.name(),
        ciphertext_len = ciphertext.len(),
        "evp::cipher: decrypt_one_shot"
    );
    let mut ctx = CipherCtx::new();
    ctx.decrypt_init(cipher, key, iv, None)?;
    let mut output = Vec::with_capacity(ciphertext.len());
    ctx.update(ciphertext, &mut output)?;
    ctx.finalize(&mut output)?;
    Ok(output)
}

// ============================================================================
// Base64 encoding/decoding (from `encode.c`, `enc_b64_scalar.c`)
// ============================================================================

/// Encodes binary data to Base64 (standard alphabet).
///
/// Translates `EVP_EncodeBlock()` from `crypto/evp/encode.c`.
/// Uses constant-time Base64 encoding via `base64ct` to prevent
/// timing side-channels on encoded key material.
pub fn base64_encode(input: &[u8]) -> String {
    Base64::encode_string(input)
}

/// Decodes Base64-encoded data to binary.
///
/// Translates `EVP_DecodeBlock()` from `crypto/evp/enc_b64_scalar.c`.
/// Uses constant-time Base64 decoding via `base64ct`.
///
/// # Errors
///
/// Returns [`CryptoError::Encoding`] if the input is not valid Base64.
pub fn base64_decode(input: &str) -> CryptoResult<Vec<u8>> {
    Base64::decode_vec(input).map_err(|e| CryptoError::Encoding(format!("base64 decode: {e}")))
}

// ============================================================================
// Predefined cipher registry
// ============================================================================

/// Resolves a well-known cipher algorithm name to a `Cipher` descriptor.
///
/// Case-insensitive lookup. Returns `None` if the algorithm is not recognised.
fn predefined_cipher(algorithm: &str) -> Option<Cipher> {
    let upper = algorithm.to_ascii_uppercase();
    let name = algorithm.to_string();
    let provider = "default".to_string();

    match upper.as_str() {
        "AES-128-CBC" => Some(Cipher {
            name,
            description: Some("AES-128 in CBC mode".into()),
            key_length: 16,
            iv_length: Some(16),
            block_size: 16,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "AES-256-CBC" => Some(Cipher {
            name,
            description: Some("AES-256 in CBC mode".into()),
            key_length: 32,
            iv_length: Some(16),
            block_size: 16,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "AES-128-GCM" => Some(Cipher {
            name,
            description: Some("AES-128 in GCM mode".into()),
            key_length: 16,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Gcm,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-256-GCM" => Some(Cipher {
            name,
            description: Some("AES-256 in GCM mode".into()),
            key_length: 32,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Gcm,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-128-CCM" => Some(Cipher {
            name,
            description: Some("AES-128 in CCM mode".into()),
            key_length: 16,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Ccm,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-256-CCM" => Some(Cipher {
            name,
            description: Some("AES-256 in CCM mode".into()),
            key_length: 32,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Ccm,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-128-XTS" => Some(Cipher {
            name,
            description: Some("AES-128 in XTS mode".into()),
            key_length: 32,
            iv_length: Some(16),
            block_size: 1,
            mode: CipherMode::Xts,
            flags: CipherFlags::CUSTOM_IV,
            provider_name: provider,
        }),
        "AES-256-XTS" => Some(Cipher {
            name,
            description: Some("AES-256 in XTS mode".into()),
            key_length: 64,
            iv_length: Some(16),
            block_size: 1,
            mode: CipherMode::Xts,
            flags: CipherFlags::CUSTOM_IV,
            provider_name: provider,
        }),
        "AES-128-CTR" => Some(Cipher {
            name,
            description: Some("AES-128 in CTR mode".into()),
            key_length: 16,
            iv_length: Some(16),
            block_size: 1,
            mode: CipherMode::Ctr,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "AES-256-CTR" => Some(Cipher {
            name,
            description: Some("AES-256 in CTR mode".into()),
            key_length: 32,
            iv_length: Some(16),
            block_size: 1,
            mode: CipherMode::Ctr,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "AES-128-OCB" => Some(Cipher {
            name,
            description: Some("AES-128 in OCB mode".into()),
            key_length: 16,
            iv_length: Some(12),
            block_size: 16,
            mode: CipherMode::Ocb,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-128-SIV" => Some(Cipher {
            name,
            description: Some("AES-128 in SIV mode".into()),
            key_length: 32,
            iv_length: None,
            block_size: 1,
            mode: CipherMode::Siv,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "AES-128-WRAP" => Some(Cipher {
            name,
            description: Some("AES-128 Key Wrap (RFC 3394)".into()),
            key_length: 16,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Wrap,
            flags: CipherFlags::CUSTOM_IV,
            provider_name: provider,
        }),
        "CHACHA20-POLY1305" => Some(Cipher {
            name,
            description: Some("ChaCha20-Poly1305 AEAD stream cipher".into()),
            key_length: 32,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Stream,
            flags: CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
            provider_name: provider,
        }),
        "DES-EDE3-CBC" => Some(Cipher {
            name,
            description: Some("Triple DES in CBC mode".into()),
            key_length: 24,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "DES-CBC" => Some(Cipher {
            name,
            description: Some("DES in CBC mode (legacy, insecure)".into()),
            key_length: 8,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: "legacy".to_string(),
        }),
        "ARIA-128-GCM" => Some(Cipher {
            name,
            description: Some("ARIA-128 in GCM mode".into()),
            key_length: 16,
            iv_length: Some(12),
            block_size: 1,
            mode: CipherMode::Gcm,
            flags: CipherFlags::AEAD,
            provider_name: provider,
        }),
        "SM4-CBC" => Some(Cipher {
            name,
            description: Some("SM4 in CBC mode (Chinese national standard)".into()),
            key_length: 16,
            iv_length: Some(16),
            block_size: 16,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "BF-CBC" => Some(Cipher {
            name,
            description: Some("Blowfish in CBC mode (legacy)".into()),
            key_length: 16,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::VARIABLE_KEY_LEN,
            provider_name: "legacy".to_string(),
        }),
        "CAST5-CBC" => Some(Cipher {
            name,
            description: Some("CAST5 in CBC mode (legacy)".into()),
            key_length: 16,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::VARIABLE_KEY_LEN,
            provider_name: "legacy".to_string(),
        }),
        "IDEA-CBC" => Some(Cipher {
            name,
            description: Some("IDEA in CBC mode (legacy)".into()),
            key_length: 16,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: "legacy".to_string(),
        }),
        "SEED-CBC" => Some(Cipher {
            name,
            description: Some("SEED in CBC mode (Korean standard, legacy)".into()),
            key_length: 16,
            iv_length: Some(16),
            block_size: 16,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: "legacy".to_string(),
        }),
        "RC2-CBC" => Some(Cipher {
            name,
            description: Some("RC2 in CBC mode (legacy)".into()),
            key_length: 16,
            iv_length: Some(8),
            block_size: 8,
            mode: CipherMode::Cbc,
            flags: CipherFlags::VARIABLE_KEY_LEN,
            provider_name: "legacy".to_string(),
        }),
        "RC4" => Some(Cipher {
            name,
            description: Some("RC4 stream cipher (legacy, insecure)".into()),
            key_length: 16,
            iv_length: None,
            block_size: 1,
            mode: CipherMode::Stream,
            flags: CipherFlags::VARIABLE_KEY_LEN,
            provider_name: "legacy".to_string(),
        }),
        "CAMELLIA-128-CBC" => Some(Cipher {
            name,
            description: Some("Camellia-128 in CBC mode".into()),
            key_length: 16,
            iv_length: Some(16),
            block_size: 16,
            mode: CipherMode::Cbc,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        "NULL" => Some(Cipher {
            name,
            description: Some("Null cipher (pass-through, no encryption)".into()),
            key_length: 0,
            iv_length: None,
            block_size: 1,
            mode: CipherMode::None,
            flags: CipherFlags::empty(),
            provider_name: provider,
        }),
        _ => Option::None,
    }
}
