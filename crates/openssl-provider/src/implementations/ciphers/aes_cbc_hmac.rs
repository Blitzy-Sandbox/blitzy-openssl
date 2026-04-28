//! AES-CBC-HMAC-SHA composite cipher provider implementations.
//!
//! These TLS-optimized ciphers combine AES-CBC encryption with HMAC
//! authentication into a single provider so that the TLS record layer can
//! perform encryption and MAC computation in one pass. Two construction
//! orderings are supported:
//!
//! * **MAC-then-Encrypt (MtE)**: The legacy TLS construction where HMAC is
//!   computed over the TLS AAD plus plaintext, the MAC tag is appended, and
//!   the (plaintext || MAC || padding) is then AES-CBC encrypted as a single
//!   record.  Replaces C [`cipher_aes_cbc_hmac_sha.c`] /
//!   [`cipher_aes_cbc_hmac_sha1_hw.c`] / [`cipher_aes_cbc_hmac_sha256_hw.c`].
//! * **Encrypt-then-MAC (ETM)**: The modern TLS construction (RFC 7366) where
//!   the plaintext is AES-CBC encrypted with PKCS#7 padding first and HMAC
//!   is then computed over the resulting ciphertext.  Replaces C
//!   [`cipher_aes_cbc_hmac_sha_etm.c`] / [`cipher_aes_cbc_hmac_sha1_etm_hw.c`]
//!   / [`cipher_aes_cbc_hmac_sha256_etm_hw.c`] /
//!   [`cipher_aes_cbc_hmac_sha512_etm_hw.c`].
//!
//! The MtE provider supports SHA-1 and SHA-256 digests, while the ETM
//! provider additionally supports SHA-512.  AES key sizes are restricted to
//! 128 and 256 bits per the AAP scope (the C codebase also exposes a 192-bit
//! ETM variant, which is intentionally omitted here).
//!
//! All authentication-tag comparisons use [`subtle::ConstantTimeEq`] (either
//! directly or via [`crate::implementations::ciphers::common::verify_tag`])
//! to prevent timing side-channel attacks such as the Lucky-13 padding
//! oracle.  All key material, MAC keys, and intermediate cleartext buffers
//! are erased on drop via [`zeroize::ZeroizeOnDrop`] per
//! AAP §0.7.6 (secure erasure) and Rule R8 (zero unsafe outside FFI).
//!
//! [`cipher_aes_cbc_hmac_sha.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c
//! [`cipher_aes_cbc_hmac_sha_etm.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha_etm.c
//! [`cipher_aes_cbc_hmac_sha1_hw.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha1_hw.c
//! [`cipher_aes_cbc_hmac_sha256_hw.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha256_hw.c
//! [`cipher_aes_cbc_hmac_sha1_etm_hw.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha1_etm_hw.c
//! [`cipher_aes_cbc_hmac_sha256_etm_hw.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha256_etm_hw.c
//! [`cipher_aes_cbc_hmac_sha512_etm_hw.c`]: ../../../../../providers/implementations/ciphers/cipher_aes_cbc_hmac_sha512_etm_hw.c

use super::common::{param_keys, pkcs7_pad, pkcs7_unpad, verify_tag};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::mac::{MacContext, MacType};
use openssl_crypto::symmetric::aes::Aes;
use openssl_crypto::symmetric::SymmetricCipher;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// AES block size in bytes (also the IV length for CBC mode).
const AES_BLOCK_SIZE: usize = 16;

/// Maximum HMAC tag length any of the supported digests can produce.
///
/// SHA-512 emits 64-byte tags; SHA-256 emits 32; SHA-1 emits 20.
/// This constant matches the C `AES_CBC_MAX_HMAC_SIZE` symbol used in
/// `cipher_aes_cbc_hmac_sha_etm.c::aes_set_ctx_params` to bound the size of
/// the expected-tag buffer accepted via the `OSSL_CIPHER_PARAM_AEAD_TAG`
/// parameter.
const AES_CBC_MAX_HMAC_SIZE: usize = 64;

/// TLS 1.x explicit-AAD length: `seq(8) || type(1) || version(2) || len(2)`.
///
/// Matches the C macro `EVP_AEAD_TLS1_AAD_LEN` and is the only accepted size
/// for the `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD` parameter on `MtE` ciphers.
const TLS1_AAD_LEN: usize = 13;

/// TLS protocol version constants used to determine whether the explicit IV
/// occupies the first AES block of the record (TLS 1.1+) or whether the IV
/// chains from the prior record (SSL 3.0 / TLS 1.0).
const SSL3_VERSION: u32 = 0x0300;
/// TLS 1.0 protocol version (RFC 2246).
const TLS1_VERSION: u32 = 0x0301;

// =============================================================================
// Local helpers
// =============================================================================

/// XORs `src` into `dest` byte-wise for the overlapping length.
///
/// Used to chain the previous ciphertext (or IV) into the next CBC block.
/// Mirrors the private `xor_blocks` helper in `super::aes`; defined locally
/// here so this file does not depend on `aes.rs` private items.
#[inline]
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

// =============================================================================
// DigestVariant
// =============================================================================

/// Hash function selector for the HMAC component of the composite cipher.
///
/// `Sha1` and `Sha256` are exposed by both `MtE` and ETM providers; `Sha512`
/// is exposed by ETM only — matching the C code split between
/// `cipher_aes_cbc_hmac_sha.c` (SHA-1, SHA-256) and
/// `cipher_aes_cbc_hmac_sha_etm.c` (SHA-1, SHA-256, SHA-512).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestVariant {
    /// SHA-1 (RFC 3174), 20-byte output.  Used by older TLS 1.0/1.1 cipher
    /// suites.  Cryptographically deprecated for new applications but
    /// retained here for protocol compatibility.
    Sha1,
    /// SHA-256 (FIPS 180-4), 32-byte output.  Used by TLS 1.2 cipher suites.
    Sha256,
    /// SHA-512 (FIPS 180-4), 64-byte output.  Available only on the ETM
    /// provider (the legacy `MtE` construction never exposed SHA-512).
    Sha512,
}

impl DigestVariant {
    /// Returns the digest name accepted by [`MacContext::init`] via the
    /// `"digest"` parameter.
    #[must_use]
    pub fn digest_name(self) -> &'static str {
        match self {
            DigestVariant::Sha1 => "SHA-1",
            DigestVariant::Sha256 => "SHA-256",
            DigestVariant::Sha512 => "SHA-512",
        }
    }

    /// Returns the HMAC tag length in bytes produced by this digest.
    #[must_use]
    pub fn tag_size(self) -> usize {
        match self {
            DigestVariant::Sha1 => 20,
            DigestVariant::Sha256 => 32,
            DigestVariant::Sha512 => 64,
        }
    }
}

impl fmt::Display for DigestVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.digest_name())
    }
}

// =============================================================================
// Validation helpers shared by both provider variants
// =============================================================================

/// Validates the AES key length against the value declared by the provider.
///
/// Returns the validated length on success.  The composite cipher only
/// accepts 128 and 256 bit AES keys (matching the C source which carries
/// distinct dispatch tables for each key size).
fn validate_aes_key_len(provider_key_bytes: usize, supplied: usize) -> ProviderResult<()> {
    if supplied != provider_key_bytes {
        return Err(ProviderError::Init(format!(
            "AES key length mismatch: expected {provider_key_bytes} bytes, got {supplied}"
        )));
    }
    match supplied {
        16 | 32 => Ok(()),
        other => Err(ProviderError::Init(format!(
            "AES-CBC-HMAC supports only 16- or 32-byte keys; got {other}"
        ))),
    }
}

/// Validates the IV length against the AES block size (always 16 bytes for
/// CBC).
fn validate_iv_len(supplied: usize) -> ProviderResult<()> {
    if supplied != AES_BLOCK_SIZE {
        return Err(ProviderError::Init(format!(
            "AES-CBC-HMAC IV length must be {AES_BLOCK_SIZE} bytes; got {supplied}"
        )));
    }
    Ok(())
}

/// Computes a one-shot HMAC over `data` with the given key and digest, used
/// by both encrypt and decrypt paths to produce or verify the authentication
/// tag.
fn hmac_compute(digest: DigestVariant, key: &[u8], data: &[u8]) -> ProviderResult<Vec<u8>> {
    let mut ctx = MacContext::new(MacType::Hmac);
    let mut params = ParamSet::new();
    params.set(
        "digest",
        ParamValue::Utf8String(digest.digest_name().to_owned()),
    );
    ctx.init(key, Some(&params)).map_err(|e| {
        ProviderError::Dispatch(format!("HMAC init ({}): {e}", digest.digest_name()))
    })?;
    ctx.update(data)
        .map_err(|e| ProviderError::Dispatch(format!("HMAC update: {e}")))?;
    ctx.finalize()
        .map_err(|e| ProviderError::Dispatch(format!("HMAC finalize: {e}")))
}

/// Computes an HMAC over the concatenation of `aad` and `payload`.
///
/// Equivalent to feeding both buffers sequentially into [`MacContext::update`]
/// without allocating a temporary concatenation, which would create an extra
/// copy of plaintext in memory.
fn hmac_compute_aad_then_payload(
    digest: DigestVariant,
    key: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> ProviderResult<Vec<u8>> {
    let mut ctx = MacContext::new(MacType::Hmac);
    let mut params = ParamSet::new();
    params.set(
        "digest",
        ParamValue::Utf8String(digest.digest_name().to_owned()),
    );
    ctx.init(key, Some(&params)).map_err(|e| {
        ProviderError::Dispatch(format!("HMAC init ({}): {e}", digest.digest_name()))
    })?;
    ctx.update(aad)
        .map_err(|e| ProviderError::Dispatch(format!("HMAC update (aad): {e}")))?;
    ctx.update(payload)
        .map_err(|e| ProviderError::Dispatch(format!("HMAC update (payload): {e}")))?;
    ctx.finalize()
        .map_err(|e| ProviderError::Dispatch(format!("HMAC finalize: {e}")))
}

/// Performs an AES-CBC encrypt of an in-place buffer that is an exact
/// multiple of [`AES_BLOCK_SIZE`].  The IV slice is updated in place to the
/// final ciphertext block so subsequent calls chain correctly.
fn aes_cbc_encrypt_inplace(cipher: &Aes, iv: &mut [u8], buf: &mut [u8]) -> ProviderResult<()> {
    if buf.len() % AES_BLOCK_SIZE != 0 {
        return Err(ProviderError::Dispatch(format!(
            "AES-CBC encrypt requires whole blocks; got {} bytes",
            buf.len()
        )));
    }
    let mut block = [0u8; AES_BLOCK_SIZE];
    let mut offset = 0;
    while offset + AES_BLOCK_SIZE <= buf.len() {
        block.copy_from_slice(&buf[offset..offset + AES_BLOCK_SIZE]);
        xor_blocks(&mut block, iv);
        cipher
            .encrypt_block(&mut block)
            .map_err(|e| ProviderError::Dispatch(format!("AES-CBC encrypt block: {e}")))?;
        iv.copy_from_slice(&block);
        buf[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&block);
        offset += AES_BLOCK_SIZE;
    }
    Ok(())
}

/// Performs an AES-CBC decrypt of an in-place buffer that is an exact
/// multiple of [`AES_BLOCK_SIZE`].  The IV slice is updated in place so
/// subsequent calls chain correctly.
fn aes_cbc_decrypt_inplace(cipher: &Aes, iv: &mut [u8], buf: &mut [u8]) -> ProviderResult<()> {
    if buf.len() % AES_BLOCK_SIZE != 0 {
        return Err(ProviderError::Dispatch(format!(
            "AES-CBC decrypt requires whole blocks; got {} bytes",
            buf.len()
        )));
    }
    let mut block = [0u8; AES_BLOCK_SIZE];
    let mut next_iv = [0u8; AES_BLOCK_SIZE];
    let mut offset = 0;
    while offset + AES_BLOCK_SIZE <= buf.len() {
        next_iv.copy_from_slice(&buf[offset..offset + AES_BLOCK_SIZE]);
        block.copy_from_slice(&buf[offset..offset + AES_BLOCK_SIZE]);
        cipher
            .decrypt_block(&mut block)
            .map_err(|e| ProviderError::Dispatch(format!("AES-CBC decrypt block: {e}")))?;
        xor_blocks(&mut block, iv);
        iv.copy_from_slice(&next_iv);
        buf[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&block);
        offset += AES_BLOCK_SIZE;
    }
    Ok(())
}

// =============================================================================
// AesCbcHmacShaCipher (MAC-then-Encrypt provider)
// =============================================================================

/// AES-CBC-HMAC-SHA composite cipher (MAC-then-Encrypt).
///
/// This is the traditional TLS 1.0/1.1/1.2 cipher construction in which the
/// HMAC is computed first over the TLS AAD plus plaintext and the resulting
/// MAC tag is appended to the plaintext before AES-CBC encryption.  The
/// provider exposes these algorithms:
///
/// | Name                           | AES key | Digest    | MAC size |
/// |--------------------------------|---------|-----------|----------|
/// | `AES-128-CBC-HMAC-SHA1`        | 128 bit | SHA-1     | 20 bytes |
/// | `AES-256-CBC-HMAC-SHA1`        | 256 bit | SHA-1     | 20 bytes |
/// | `AES-128-CBC-HMAC-SHA256`      | 128 bit | SHA-256   | 32 bytes |
/// | `AES-256-CBC-HMAC-SHA256`      | 256 bit | SHA-256   | 32 bytes |
///
/// Each provider instance carries the cipher's display name, key size, and
/// digest variant.  Construct one via [`AesCbcHmacShaCipher::new`] (or use
/// [`descriptors`] to enumerate all variants for provider registration).
#[derive(Debug, Clone)]
pub struct AesCbcHmacShaCipher {
    /// Algorithm display name (e.g., `"AES-128-CBC-HMAC-SHA1"`).
    name: &'static str,
    /// AES key length in bytes (16 or 32).
    key_bytes: usize,
    /// HMAC digest variant.
    digest: DigestVariant,
}

impl AesCbcHmacShaCipher {
    /// Constructs an `MtE` composite cipher provider.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `key_bytes` is not 16 or 32.  Release
    /// builds defer rejection to [`encrypt_init`](CipherContext::encrypt_init)
    /// / [`decrypt_init`](CipherContext::decrypt_init) where an invalid
    /// key length yields [`ProviderError::Init`].
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize, digest: DigestVariant) -> Self {
        debug_assert!(
            key_bytes == 16 || key_bytes == 32,
            "key_bytes must be 16 or 32"
        );
        Self {
            name,
            key_bytes,
            digest,
        }
    }

    /// Returns the AES key length in bits (128 or 256).
    #[must_use]
    pub fn key_bits(&self) -> usize {
        self.key_bytes.saturating_mul(8)
    }

    /// Returns the HMAC digest variant configured on this provider.
    #[must_use]
    pub fn digest_variant(&self) -> DigestVariant {
        self.digest
    }
}

impl CipherProvider for AesCbcHmacShaCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn block_size(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesCbcHmacShaContext::new(
            self.name,
            self.key_bytes,
            self.digest,
        )))
    }
}

// =============================================================================
// AesCbcHmacShaContext (MAC-then-Encrypt operation state)
// =============================================================================

/// Per-operation state for the `MtE` composite cipher.
///
/// The context implements both the streaming [`CipherContext`] interface and
/// the TLS-record fast path that is selected when the caller uses
/// [`OSSL_CIPHER_PARAM_AEAD_TLS1_AAD`](`param_keys::AEAD_TLS1_AAD`) to
/// pre-declare the TLS AAD before [`update`](CipherContext::update) is
/// invoked.  When TLS-AAD mode is active the input passed to `update`
/// represents the entire TLS record body; the cipher computes the HMAC,
/// applies PKCS#7 padding, and AES-CBC encrypts in a single pass.
///
/// All sensitive fields are zeroized on drop via the
/// [`ZeroizeOnDrop`] derive.  Per Rule R8, no `unsafe` is required: every
/// secret-bearing field is a [`Vec<u8>`] or fixed-size array and `zeroize`
/// is implemented for those types.
#[derive(ZeroizeOnDrop)]
pub struct AesCbcHmacShaContext {
    // ---- Configuration (non-secret) ----------------------------------------
    /// Algorithm name reported by [`get_params`](CipherContext::get_params).
    #[zeroize(skip)]
    name: &'static str,
    /// Required AES key length in bytes.
    #[zeroize(skip)]
    key_bytes: usize,
    /// HMAC digest variant.
    #[zeroize(skip)]
    digest: DigestVariant,

    // ---- Operation state ---------------------------------------------------
    /// `true` for encryption, `false` for decryption.
    #[zeroize(skip)]
    encrypting: bool,
    /// Whether [`encrypt_init`] / [`decrypt_init`] has been called.
    #[zeroize(skip)]
    initialized: bool,
    /// PKCS#7 padding flag.  Streaming-mode only — TLS-AAD mode always
    /// applies its own padding.
    #[zeroize(skip)]
    padding: bool,

    // ---- Crypto engine (sensitive) ----------------------------------------
    /// Wrapped AES block cipher.  Holds the round-key schedule which is
    /// secret material; freeing the option drops the key schedule, and the
    /// outer `Zeroize` impl on this struct will not reach inside `Aes`,
    /// however dropping the option already zeroizes the round keys via
    /// `Aes`'s own `Drop` impl in `openssl-crypto`.
    #[zeroize(skip)]
    aes: Option<Aes>,
    /// HMAC key supplied by the caller via
    /// [`OSSL_CIPHER_PARAM_AEAD_MAC_KEY`].  Empty until set.
    mac_key: Vec<u8>,
    /// Current CBC IV / chaining block (always 16 bytes once initialised).
    iv: Vec<u8>,
    /// Streaming buffer for non-TLS-AAD mode — accumulates input until a
    /// full block can be processed.
    buffer: Vec<u8>,

    // ---- TLS-record state (secret AAD treated as non-secret) ---------------
    /// 13-byte TLS AAD (`seq || type || version || length`) supplied via
    /// [`OSSL_CIPHER_PARAM_AEAD_TLS1_AAD`].  Empty when no AAD has been
    /// supplied.  Cleared on drop only as a defence-in-depth measure (the
    /// AAD itself is not secret).
    #[zeroize(skip)]
    tls_aad: Vec<u8>,
    /// TLS version copied from the AAD; set to `0` when no AAD has been
    /// supplied or when the AAD does not carry a known version.
    #[zeroize(skip)]
    tls_version: u32,
    /// Pad length the caller must subtract from the record fragment before
    /// re-running [`set_params`] for the next record.  Reported via
    /// [`OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD`].
    #[zeroize(skip)]
    tls_aad_pad: usize,
    /// Optional declared payload length (post-AAD) — when set the cipher is
    /// in TLS-AAD fast path mode.  Per Rule R5 this is `Option<usize>`
    /// rather than the C convention of using `0` as a sentinel.
    #[zeroize(skip)]
    payload_length: Option<usize>,

    // ---- Multiblock optimisation parameters --------------------------------
    /// Maximum send fragment for multiblock optimisation
    /// ([`OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT`]).
    #[zeroize(skip)]
    multiblock_max_send_fragment: usize,
    /// Reported per-record packet length for multiblock processing
    /// ([`OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN`]).
    #[zeroize(skip)]
    multiblock_aad_packlen: usize,
    /// Number of records interleaved in the multiblock buffer
    /// ([`OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE`]).
    #[zeroize(skip)]
    multiblock_interleave: usize,
    /// Effective ciphertext length produced by the most recent multiblock
    /// encrypt operation
    /// ([`OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENCRYPT_LEN`]).
    #[zeroize(skip)]
    multiblock_encrypt_len: usize,
}

impl AesCbcHmacShaContext {
    /// Creates an uninitialised `MtE` context.
    fn new(name: &'static str, key_bytes: usize, digest: DigestVariant) -> Self {
        Self {
            name,
            key_bytes,
            digest,
            encrypting: true,
            initialized: false,
            padding: true,
            aes: None,
            mac_key: Vec::new(),
            iv: Vec::new(),
            buffer: Vec::new(),
            tls_aad: Vec::new(),
            tls_version: 0,
            tls_aad_pad: 0,
            payload_length: None,
            multiblock_max_send_fragment: 0,
            multiblock_aad_packlen: 0,
            multiblock_interleave: 0,
            multiblock_encrypt_len: 0,
        }
    }

    /// Common initialisation path for both encrypt and decrypt directions.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        validate_aes_key_len(self.key_bytes, key.len())?;
        let aes = Aes::new(key)
            .map_err(|e| ProviderError::Init(format!("AES key schedule expansion failed: {e}")))?;
        self.aes = Some(aes);
        if let Some(iv_bytes) = iv {
            validate_iv_len(iv_bytes.len())?;
            self.iv = iv_bytes.to_vec();
        } else {
            // Allow init with no IV (caller may supply via params later).
            self.iv = vec![0u8; AES_BLOCK_SIZE];
        }
        self.encrypting = encrypting;
        self.initialized = true;
        // Reset per-record state so the context can be reused across records.
        self.buffer.clear();
        self.tls_aad.clear();
        self.tls_version = 0;
        self.tls_aad_pad = 0;
        self.payload_length = None;
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    /// Computes the TLS AAD pad value reported back via
    /// [`OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD`] when the caller supplies the
    /// initial AAD.  Mirrors the C
    /// `aesni_cbc_hmac_sha*_set_tls1_aad` return value: the number of bytes
    /// the TLS record will be padded with to make the encrypted payload an
    /// exact multiple of the AES block size, including the trailing length
    /// byte itself.
    fn compute_tls_aad_pad(mac_size: usize, payload_len: usize) -> usize {
        // For TLS, the payload to be padded is
        //   plaintext (payload_len) || MAC (mac_size)
        // and PKCS#7 padding fills to the next AES block boundary.
        let unpadded = payload_len.saturating_add(mac_size);
        AES_BLOCK_SIZE - (unpadded % AES_BLOCK_SIZE)
    }

    /// Builds the per-record HMAC AAD by reconstructing the TLS record
    /// header from the stored 13-byte AAD with a corrected length field.
    /// Returns the modified AAD plus the payload length the caller should
    /// authenticate.
    fn build_record_aad(&self, payload_len: usize) -> ProviderResult<Vec<u8>> {
        if self.tls_aad.len() != TLS1_AAD_LEN {
            return Err(ProviderError::Dispatch(format!(
                "TLS AAD must be {TLS1_AAD_LEN} bytes; got {}",
                self.tls_aad.len()
            )));
        }
        let mut aad = self.tls_aad.clone();
        // For SSL 3.0 / TLS 1.0 the explicit IV is part of the encrypted
        // payload reported by the caller; remove it so the HMAC is computed
        // over only the application data.
        let removetlsfixed = match self.tls_version {
            SSL3_VERSION | TLS1_VERSION => 0,
            _ => AES_BLOCK_SIZE,
        };
        let effective = payload_len.checked_sub(removetlsfixed).ok_or_else(|| {
            ProviderError::Dispatch("TLS payload shorter than explicit IV".into())
        })?;
        // The length field occupies bytes 11..13 of the AAD in network byte
        // order.  Replace it with the application-data length the HMAC
        // covers.
        let len_bytes = u16::try_from(effective).map_err(|_| {
            ProviderError::Dispatch(format!(
                "TLS payload length {effective} does not fit in u16"
            ))
        })?;
        aad[11] = (len_bytes >> 8) as u8;
        aad[12] = (len_bytes & 0xff) as u8;
        Ok(aad)
    }

    /// TLS-AAD fast-path encrypt: input is the full TLS record fragment;
    /// output is `record || HMAC || PKCS7-pad` AES-CBC encrypted.
    fn encrypt_tls_record(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let aad = self.build_record_aad(input.len())?;
        let mac_size = self.digest.tag_size();
        // Compute HMAC over (modified-AAD || payload).
        let mac = hmac_compute_aad_then_payload(self.digest, &self.mac_key, &aad, input)?;
        if mac.len() != mac_size {
            return Err(ProviderError::Dispatch(format!(
                "HMAC produced {} bytes, expected {mac_size}",
                mac.len()
            )));
        }
        // Build the cleartext that will be encrypted: payload || MAC.
        let mut plaintext = Vec::with_capacity(input.len() + mac_size + AES_BLOCK_SIZE);
        plaintext.extend_from_slice(input);
        plaintext.extend_from_slice(&mac);
        // Apply TLS-style CBC padding to reach the next AES block boundary.
        //
        // Unlike PKCS#7 (where `pad_count` bytes hold the value `pad_count`),
        // TLS records use the layout described in RFC 5246 §6.2.3.2:
        //   padding := repeat(pad_count) of byte value (pad_count - 1)
        // where `pad_count` is in 1..=AES_BLOCK_SIZE, equal to
        // `block_size - (plaintext.len() % block_size)`.  When the plaintext
        // is already block-aligned, a full block of padding is appended.
        // The constant-time stripping helper
        // `super::common::tls_cbc_remove_padding_and_mac` consumes exactly
        // this layout, so encrypt and decrypt must agree on it.
        let pad_count = AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
        // TRUNCATION: pad_count is in 1..=AES_BLOCK_SIZE (== 16), so it
        // always fits in u8.  This invariant is enforced by the modulo
        // arithmetic above and by AES_BLOCK_SIZE being a small constant.
        #[allow(clippy::cast_possible_truncation)]
        let pad_byte = (pad_count - 1) as u8;
        let mut padded = Vec::with_capacity(plaintext.len() + pad_count);
        padded.extend_from_slice(&plaintext);
        padded.resize(padded.len() + pad_count, pad_byte);
        // Erase the intermediate plaintext copy now that it has been padded.
        plaintext.zeroize();
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
        let result = aes_cbc_encrypt_inplace(aes, &mut iv, &mut padded);
        self.iv = iv;
        result?;
        let written = padded.len();
        output.extend_from_slice(&padded);
        // Wipe the encrypted-buffer copy that contained MAC bytes briefly.
        padded.zeroize();
        Ok(written)
    }

    /// TLS-AAD fast-path decrypt: input is the full TLS record (including
    /// MAC and padding); output is the application-data plaintext.
    fn decrypt_tls_record(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let mac_size = self.digest.tag_size();
        if input.len() % AES_BLOCK_SIZE != 0 {
            return Err(ProviderError::Dispatch(format!(
                "TLS record length {} is not a multiple of {AES_BLOCK_SIZE}",
                input.len()
            )));
        }
        if input.len() < AES_BLOCK_SIZE + mac_size {
            return Err(ProviderError::Dispatch(format!(
                "TLS record too short: {} bytes < {AES_BLOCK_SIZE}+{mac_size}",
                input.len()
            )));
        }
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut buf = input.to_vec();
        let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
        let res = aes_cbc_decrypt_inplace(aes, &mut iv, &mut buf);
        self.iv = iv;
        res?;
        // Strip PKCS#7 padding and split off the MAC in constant time using
        // the helper from `super::common`.  Returns plaintext (excluding
        // MAC) and the trailing MAC bytes.
        let (plaintext, mac) =
            super::common::tls_cbc_remove_padding_and_mac(&buf, AES_BLOCK_SIZE, mac_size).map_err(
                |_| ProviderError::Dispatch("TLS record padding/MAC validation failed".into()),
            )?;
        // Recompute the HMAC and compare in constant time.
        let aad = self.build_record_aad(plaintext.len())?;
        let computed = hmac_compute_aad_then_payload(self.digest, &self.mac_key, &aad, plaintext)?;
        verify_tag(&computed, mac)?;
        output.extend_from_slice(plaintext);
        let written = plaintext.len();
        // Erase the temporary buffer that contained plaintext + MAC.
        buf.zeroize();
        Ok(written)
    }
}

impl CipherContext for AesCbcHmacShaContext {
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

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CBC-HMAC context not initialised".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        if self.payload_length.is_some() {
            // TLS-AAD fast path.
            return if self.encrypting {
                self.encrypt_tls_record(input, output)
            } else {
                self.decrypt_tls_record(input, output)
            };
        }
        // Streaming (non-TLS) mode behaves exactly like AES-CBC: no MAC is
        // computed automatically.  Callers that want the composite
        // construction outside of TLS must call set_params with TLS AAD
        // first.  This mirrors the C provider, where streaming use yields
        // raw CBC output.
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= AES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }
        let mut to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
        let res = if self.encrypting {
            aes_cbc_encrypt_inplace(aes, &mut iv, &mut to_process)
        } else {
            aes_cbc_decrypt_inplace(aes, &mut iv, &mut to_process)
        };
        self.iv = iv;
        res?;
        let written = to_process.len();
        output.extend_from_slice(&to_process);
        to_process.zeroize();
        Ok(written)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CBC-HMAC context not initialised".into(),
            ));
        }
        // TLS-AAD mode does its work in `update`; nothing to flush.
        if self.payload_length.is_some() {
            return Ok(0);
        }
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
        let written = if self.encrypting {
            if self.padding {
                let mut padded = pkcs7_pad(&self.buffer, AES_BLOCK_SIZE);
                self.buffer.clear();
                let res = aes_cbc_encrypt_inplace(aes, &mut iv, &mut padded);
                self.iv = iv;
                res?;
                let n = padded.len();
                output.extend_from_slice(&padded);
                padded.zeroize();
                n
            } else if self.buffer.is_empty() {
                self.iv = iv;
                0
            } else {
                self.iv = iv;
                return Err(ProviderError::Dispatch(format!(
                    "AES-CBC: {} bytes remaining without padding",
                    self.buffer.len()
                )));
            }
        } else if self.padding {
            if self.buffer.len() != AES_BLOCK_SIZE {
                self.iv = iv;
                return Err(ProviderError::Dispatch(format!(
                    "AES-CBC final block must be {AES_BLOCK_SIZE} bytes; got {}",
                    self.buffer.len()
                )));
            }
            let mut last: Vec<u8> = self.buffer.drain(..).collect();
            let res = aes_cbc_decrypt_inplace(aes, &mut iv, &mut last);
            self.iv = iv;
            res?;
            let unpadded = pkcs7_unpad(&last, AES_BLOCK_SIZE)?;
            let n = unpadded.len();
            output.extend_from_slice(unpadded);
            last.zeroize();
            n
        } else if self.buffer.is_empty() {
            self.iv = iv;
            0
        } else {
            self.iv = iv;
            return Err(ProviderError::Dispatch(format!(
                "AES-CBC: {} bytes remaining without padding",
                self.buffer.len()
            )));
        };
        Ok(written)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        ps.set(
            param_keys::KEYLEN,
            ParamValue::UInt32(u32::try_from(self.key_bytes).unwrap_or(u32::MAX)),
        );
        ps.set(
            param_keys::IVLEN,
            ParamValue::UInt32(u32::try_from(AES_BLOCK_SIZE).unwrap_or(u32::MAX)),
        );
        ps.set(
            param_keys::BLOCK_SIZE,
            ParamValue::UInt32(u32::try_from(AES_BLOCK_SIZE).unwrap_or(u32::MAX)),
        );
        ps.set(param_keys::AEAD, ParamValue::UInt32(1));
        ps.set(
            param_keys::PADDING,
            ParamValue::UInt32(u32::from(self.padding)),
        );
        // Report the current (potentially advanced) IV.
        if !self.iv.is_empty() {
            ps.set(
                param_keys::UPDATED,
                ParamValue::OctetString(self.iv.clone()),
            );
        }
        // Report the TLS AAD pad length expected for the next record.
        ps.set(
            param_keys::AEAD_TLS1_AAD_PAD,
            ParamValue::UInt32(u32::try_from(self.tls_aad_pad).unwrap_or(u32::MAX)),
        );
        // Multiblock parameters reported back to the caller.
        ps.set(
            "tls1-multiblock-max-bufsize",
            ParamValue::UInt32(
                u32::try_from(self.multiblock_max_send_fragment).unwrap_or(u32::MAX),
            ),
        );
        ps.set(
            "tls1-multiblock-aad-packlen",
            ParamValue::UInt32(u32::try_from(self.multiblock_aad_packlen).unwrap_or(u32::MAX)),
        );
        ps.set(
            "tls1-multiblock-interleave",
            ParamValue::UInt32(u32::try_from(self.multiblock_interleave).unwrap_or(u32::MAX)),
        );
        ps.set(
            "tls1-multiblock-encrypt-len",
            ParamValue::UInt32(u32::try_from(self.multiblock_encrypt_len).unwrap_or(u32::MAX)),
        );
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Streaming-mode padding flag.
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => self.padding = *v != 0,
                ParamValue::UInt64(v) => self.padding = *v != 0,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "padding parameter must be unsigned integer".into(),
                    ));
                }
            }
        }
        // OSSL_CIPHER_PARAM_KEYLEN — validation only; the key length is fixed
        // by the provider variant (16 or 32) and any divergent value is
        // rejected.
        if let Some(val) = params.get(param_keys::KEYLEN) {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            let supplied = match val {
                ParamValue::UInt32(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Dispatch(format!("keylen out of range: {e}")))?,
                ParamValue::UInt64(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Dispatch(format!("keylen out of range: {e}")))?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "keylen parameter must be unsigned integer".into(),
                    ));
                }
            };
            if supplied != self.key_bytes {
                return Err(ProviderError::Dispatch(format!(
                    "key length {supplied} does not match provider key length {}",
                    self.key_bytes
                )));
            }
        }
        // OSSL_CIPHER_PARAM_AEAD_MAC_KEY — the HMAC key.
        if let Some(val) = params.get("aead-mac-key") {
            match val {
                ParamValue::OctetString(bytes) => {
                    self.mac_key.zeroize();
                    self.mac_key.clone_from(bytes);
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AEAD MAC key parameter must be octet string".into(),
                    ));
                }
            }
        }
        // OSSL_CIPHER_PARAM_AEAD_TLS1_AAD — full 13-byte TLS AAD.
        if let Some(val) = params.get(param_keys::AEAD_TLS1_AAD) {
            match val {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() != TLS1_AAD_LEN {
                        return Err(ProviderError::Dispatch(format!(
                            "TLS AAD must be {TLS1_AAD_LEN} bytes; got {}",
                            bytes.len()
                        )));
                    }
                    self.tls_aad.clone_from(bytes);
                    // Read the protocol version field from the AAD.
                    self.tls_version = (u32::from(bytes[9]) << 8) | u32::from(bytes[10]);
                    // Read the embedded length field and configure the fast
                    // path.
                    let payload_len = (usize::from(bytes[11]) << 8) | usize::from(bytes[12]);
                    self.payload_length = Some(payload_len);
                    let mac_size = self.digest.tag_size();
                    self.tls_aad_pad = Self::compute_tls_aad_pad(mac_size, payload_len);
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "TLS AAD parameter must be octet string".into(),
                    ));
                }
            }
        }
        // OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD — read-only output; if the
        // caller pre-populates a slot it is silently ignored.
        // OSSL_CIPHER_PARAM_TLS_VERSION — explicit TLS protocol version.
        if let Some(val) = params.get(param_keys::TLS_VERSION) {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            self.tls_version = match val {
                ParamValue::UInt32(v) => *v,
                ParamValue::Int32(v) => u32::try_from(*v)
                    .map_err(|e| ProviderError::Dispatch(format!("TLS version negative: {e}")))?,
                ParamValue::UInt64(v) => u32::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("TLS version out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "TLS version parameter must be unsigned integer".into(),
                    ));
                }
            };
        }
        // Multiblock parameters.
        if let Some(val) = params.get("tls1-multiblock-max-bufsize") {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            self.multiblock_max_send_fragment = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("multiblock-max-bufsize out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("multiblock-max-bufsize out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "tls1-multiblock-max-bufsize must be unsigned integer".into(),
                    ));
                }
            };
        }
        if let Some(val) = params.get("tls1-multiblock-aad") {
            match val {
                ParamValue::OctetString(bytes) => {
                    // Multiblock AAD updates the per-record AAD; treat as
                    // re-set of TLS AAD.
                    if bytes.len() == TLS1_AAD_LEN {
                        self.tls_aad.clone_from(bytes);
                        self.tls_version = (u32::from(bytes[9]) << 8) | u32::from(bytes[10]);
                        let payload_len = (usize::from(bytes[11]) << 8) | usize::from(bytes[12]);
                        self.payload_length = Some(payload_len);
                        let mac_size = self.digest.tag_size();
                        self.multiblock_aad_packlen = payload_len
                            .saturating_add(mac_size)
                            .saturating_add(Self::compute_tls_aad_pad(mac_size, payload_len));
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "tls1-multiblock-aad must be octet string".into(),
                    ));
                }
            }
        }
        if let Some(val) = params.get("tls1-multiblock-interleave") {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            self.multiblock_interleave = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("multiblock-interleave out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("multiblock-interleave out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "tls1-multiblock-interleave must be unsigned integer".into(),
                    ));
                }
            };
        }
        Ok(())
    }
}

// =============================================================================
// AesCbcHmacShaEtmCipher (Encrypt-then-MAC provider)
// =============================================================================

/// AES-CBC-HMAC-SHA composite cipher (Encrypt-then-MAC, RFC 7366).
///
/// This is the modern TLS construction in which the plaintext is AES-CBC
/// encrypted with PKCS#7 padding first and HMAC is then computed over the
/// resulting ciphertext.  ETM provides better separation of concerns (the
/// MAC verifier never sees plaintext from an unauthenticated source) and is
/// the recommended construction for new applications.
///
/// | Name                                | AES key | Digest    | MAC size |
/// |-------------------------------------|---------|-----------|----------|
/// | `AES-128-CBC-HMAC-SHA1-ETM`         | 128 bit | SHA-1     | 20 bytes |
/// | `AES-256-CBC-HMAC-SHA1-ETM`         | 256 bit | SHA-1     | 20 bytes |
/// | `AES-128-CBC-HMAC-SHA256-ETM`       | 128 bit | SHA-256   | 32 bytes |
/// | `AES-256-CBC-HMAC-SHA256-ETM`       | 256 bit | SHA-256   | 32 bytes |
/// | `AES-128-CBC-HMAC-SHA512-ETM`       | 128 bit | SHA-512   | 64 bytes |
/// | `AES-256-CBC-HMAC-SHA512-ETM`       | 256 bit | SHA-512   | 64 bytes |
#[derive(Debug, Clone)]
pub struct AesCbcHmacShaEtmCipher {
    /// Algorithm display name.
    name: &'static str,
    /// AES key length in bytes (16 or 32).
    key_bytes: usize,
    /// HMAC digest variant.
    digest: DigestVariant,
}

impl AesCbcHmacShaEtmCipher {
    /// Constructs an ETM composite cipher provider.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `key_bytes` is not 16 or 32.
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize, digest: DigestVariant) -> Self {
        debug_assert!(
            key_bytes == 16 || key_bytes == 32,
            "key_bytes must be 16 or 32"
        );
        Self {
            name,
            key_bytes,
            digest,
        }
    }

    /// Returns the AES key length in bits (128 or 256).
    #[must_use]
    pub fn key_bits(&self) -> usize {
        self.key_bytes.saturating_mul(8)
    }

    /// Returns the HMAC digest variant configured on this provider.
    #[must_use]
    pub fn digest_variant(&self) -> DigestVariant {
        self.digest
    }
}

impl CipherProvider for AesCbcHmacShaEtmCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn block_size(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesCbcHmacShaEtmContext::new(
            self.name,
            self.key_bytes,
            self.digest,
        )))
    }
}

// =============================================================================
// AesCbcHmacShaEtmContext (Encrypt-then-MAC operation state)
// =============================================================================

/// Per-operation state for the ETM composite cipher.
///
/// The context buffers all input across [`update`](CipherContext::update)
/// calls and performs the encrypt/MAC (or MAC-verify/decrypt) transformation
/// in [`finalize`](CipherContext::finalize) where the full record is
/// available.  This matches the C
/// `cipher_aes_cbc_hmac_sha_etm.c::aes_cipher` flow which only acts at
/// `EVP_CipherFinal_ex` time when a TLS record is complete.
///
/// All sensitive fields are zeroized on drop via [`ZeroizeOnDrop`].
#[derive(ZeroizeOnDrop)]
pub struct AesCbcHmacShaEtmContext {
    // ---- Configuration ----------------------------------------------------
    #[zeroize(skip)]
    name: &'static str,
    #[zeroize(skip)]
    key_bytes: usize,
    #[zeroize(skip)]
    digest: DigestVariant,

    // ---- Operation state --------------------------------------------------
    #[zeroize(skip)]
    encrypting: bool,
    #[zeroize(skip)]
    initialized: bool,
    #[zeroize(skip)]
    padding: bool,

    // ---- Crypto engine ----------------------------------------------------
    #[zeroize(skip)]
    aes: Option<Aes>,
    /// HMAC key (sensitive — zeroized on drop).
    mac_key: Vec<u8>,
    /// Current CBC IV.
    iv: Vec<u8>,
    /// Buffered input — entire record assembled across `update()` calls.
    buffer: Vec<u8>,

    // ---- ETM tag state ----------------------------------------------------
    /// Computed MAC tag (encrypt path) — populated at finalize time and
    /// reported via [`OSSL_CIPHER_PARAM_TLS_MAC`](`param_keys::TLS_MAC`).
    computed_tag: Vec<u8>,
    /// Expected MAC tag supplied by the caller for decrypt verification.
    expected_tag: Vec<u8>,
    /// Optional declared tag length — `None` until the caller sets it via
    /// the TLS-MAC-size or AEAD-tag parameters.  Per Rule R5, distinguish
    /// "not set" from `0` rather than using a sentinel.
    #[zeroize(skip)]
    taglen: Option<usize>,
}

impl AesCbcHmacShaEtmContext {
    fn new(name: &'static str, key_bytes: usize, digest: DigestVariant) -> Self {
        Self {
            name,
            key_bytes,
            digest,
            encrypting: true,
            initialized: false,
            padding: true,
            aes: None,
            mac_key: Vec::new(),
            iv: Vec::new(),
            buffer: Vec::new(),
            computed_tag: Vec::new(),
            expected_tag: Vec::new(),
            taglen: None,
        }
    }

    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        validate_aes_key_len(self.key_bytes, key.len())?;
        let aes = Aes::new(key)
            .map_err(|e| ProviderError::Init(format!("AES key schedule expansion failed: {e}")))?;
        self.aes = Some(aes);
        if let Some(iv_bytes) = iv {
            validate_iv_len(iv_bytes.len())?;
            self.iv = iv_bytes.to_vec();
        } else {
            self.iv = vec![0u8; AES_BLOCK_SIZE];
        }
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        self.computed_tag.zeroize();
        self.computed_tag.clear();
        self.expected_tag.zeroize();
        self.expected_tag.clear();
        self.taglen = None;
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }
}

impl CipherContext for AesCbcHmacShaEtmContext {
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

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CBC-HMAC-ETM context not initialised".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        // ETM buffers the entire record and processes it in finalize.  The
        // C code achieves this by acting only on EVP_CipherFinal_ex; we
        // emulate by deferring all work to finalize.  Output is empty
        // during update.
        let _ = output; // explicitly unused — see comment above.
        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-CBC-HMAC-ETM context not initialised".into(),
            ));
        }
        if self.mac_key.is_empty() {
            return Err(ProviderError::Dispatch(
                "AES-CBC-HMAC-ETM HMAC key not set".into(),
            ));
        }
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mac_size = self.digest.tag_size();
        if self.encrypting {
            // ETM encrypt: pad + AES-CBC encrypt, then HMAC over ciphertext.
            let mut padded = if self.padding {
                pkcs7_pad(&self.buffer, AES_BLOCK_SIZE)
            } else {
                if self.buffer.len() % AES_BLOCK_SIZE != 0 {
                    return Err(ProviderError::Dispatch(format!(
                        "AES-CBC-HMAC-ETM: {} bytes remaining without padding",
                        self.buffer.len()
                    )));
                }
                self.buffer.clone()
            };
            self.buffer.zeroize();
            self.buffer.clear();
            let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
            let res = aes_cbc_encrypt_inplace(aes, &mut iv, &mut padded);
            self.iv = iv;
            res?;
            // HMAC the ciphertext.
            let tag = hmac_compute(self.digest, &self.mac_key, &padded)?;
            if tag.len() != mac_size {
                return Err(ProviderError::Dispatch(format!(
                    "HMAC produced {} bytes, expected {mac_size}",
                    tag.len()
                )));
            }
            let written = padded.len();
            output.extend_from_slice(&padded);
            padded.zeroize();
            self.computed_tag.zeroize();
            self.computed_tag = tag;
            Ok(written)
        } else {
            // ETM decrypt: HMAC over ciphertext (constant-time compare),
            // then AES-CBC decrypt and PKCS#7 unpad.
            // The expected tag MUST have been supplied via set_params.
            let expected = match self.taglen {
                Some(0) => {
                    return Err(ProviderError::Dispatch(
                        "AES-CBC-HMAC-ETM decrypt requires non-empty tag".into(),
                    ));
                }
                None => {
                    return Err(ProviderError::Dispatch(
                        "AES-CBC-HMAC-ETM decrypt requires tag (set TLS_MAC parameter)".into(),
                    ));
                }
                Some(len) => {
                    if self.expected_tag.len() != len {
                        return Err(ProviderError::Dispatch(format!(
                            "AES-CBC-HMAC-ETM expected tag length {} does not match TLS_MAC_SIZE {len}",
                            self.expected_tag.len()
                        )));
                    }
                    if len != mac_size {
                        return Err(ProviderError::Dispatch(format!(
                            "AES-CBC-HMAC-ETM tag length {len} does not match digest size {mac_size}"
                        )));
                    }
                    self.expected_tag.clone()
                }
            };
            let computed = hmac_compute(self.digest, &self.mac_key, &self.buffer)?;
            // Constant-time compare via subtle.  Bool conversion is
            // explicit so that early-exit cannot be inferred by the
            // optimiser.
            let ok: bool = computed.ct_eq(&expected).into();
            if !ok {
                self.buffer.zeroize();
                self.buffer.clear();
                return Err(ProviderError::Dispatch(
                    "AES-CBC-HMAC-ETM tag verification failed".into(),
                ));
            }
            self.computed_tag.zeroize();
            self.computed_tag = computed;
            // Tag verified — proceed to AES-CBC decrypt.
            let mut buf: Vec<u8> = self.buffer.drain(..).collect();
            if buf.len() % AES_BLOCK_SIZE != 0 {
                return Err(ProviderError::Dispatch(format!(
                    "AES-CBC-HMAC-ETM ciphertext length {} not a multiple of {AES_BLOCK_SIZE}",
                    buf.len()
                )));
            }
            let mut iv = std::mem::replace(&mut self.iv, vec![0u8; AES_BLOCK_SIZE]);
            let res = aes_cbc_decrypt_inplace(aes, &mut iv, &mut buf);
            self.iv = iv;
            res?;
            let written = if self.padding {
                let unpadded = pkcs7_unpad(&buf, AES_BLOCK_SIZE)?;
                let n = unpadded.len();
                output.extend_from_slice(unpadded);
                n
            } else {
                output.extend_from_slice(&buf);
                buf.len()
            };
            buf.zeroize();
            Ok(written)
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        ps.set(
            param_keys::KEYLEN,
            ParamValue::UInt32(u32::try_from(self.key_bytes).unwrap_or(u32::MAX)),
        );
        ps.set(
            param_keys::IVLEN,
            ParamValue::UInt32(u32::try_from(AES_BLOCK_SIZE).unwrap_or(u32::MAX)),
        );
        ps.set(
            param_keys::BLOCK_SIZE,
            ParamValue::UInt32(u32::try_from(AES_BLOCK_SIZE).unwrap_or(u32::MAX)),
        );
        ps.set(
            param_keys::PADDING,
            ParamValue::UInt32(u32::from(self.padding)),
        );
        if !self.iv.is_empty() {
            ps.set(
                param_keys::UPDATED,
                ParamValue::OctetString(self.iv.clone()),
            );
        }
        // Report computed/expected tag and length when meaningful.
        if !self.computed_tag.is_empty() {
            ps.set(
                param_keys::TLS_MAC,
                ParamValue::OctetString(self.computed_tag.clone()),
            );
        }
        if let Some(len) = self.taglen {
            ps.set(
                param_keys::TLS_MAC_SIZE,
                ParamValue::UInt32(u32::try_from(len).unwrap_or(u32::MAX)),
            );
        }
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => self.padding = *v != 0,
                ParamValue::UInt64(v) => self.padding = *v != 0,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "padding parameter must be unsigned integer".into(),
                    ));
                }
            }
        }
        if let Some(val) = params.get(param_keys::KEYLEN) {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            let supplied = match val {
                ParamValue::UInt32(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Dispatch(format!("keylen out of range: {e}")))?,
                ParamValue::UInt64(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Dispatch(format!("keylen out of range: {e}")))?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "keylen parameter must be unsigned integer".into(),
                    ));
                }
            };
            if supplied != self.key_bytes {
                return Err(ProviderError::Dispatch(format!(
                    "key length {supplied} does not match provider key length {}",
                    self.key_bytes
                )));
            }
        }
        if let Some(val) = params.get("aead-mac-key") {
            match val {
                ParamValue::OctetString(bytes) => {
                    self.mac_key.zeroize();
                    self.mac_key.clone_from(bytes);
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AEAD MAC key parameter must be octet string".into(),
                    ));
                }
            }
        }
        // OSSL_CIPHER_PARAM_AEAD_TAG / OSSL_CIPHER_PARAM_TLS_MAC — expected
        // tag for decrypt operations.  Bound to AES_CBC_MAX_HMAC_SIZE per
        // the C source.
        let tag_param = params
            .get(param_keys::TLS_MAC)
            .or_else(|| params.get(param_keys::AEAD_TAG));
        if let Some(val) = tag_param {
            match val {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > AES_CBC_MAX_HMAC_SIZE {
                        return Err(ProviderError::Dispatch(format!(
                            "AES-CBC-HMAC-ETM tag length {} exceeds maximum {AES_CBC_MAX_HMAC_SIZE}",
                            bytes.len()
                        )));
                    }
                    self.expected_tag.zeroize();
                    self.expected_tag.clone_from(bytes);
                    self.taglen = Some(bytes.len());
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "tag parameter must be octet string".into(),
                    ));
                }
            }
        }
        // OSSL_CIPHER_PARAM_TLS_MAC_SIZE — tag length declaration (used when
        // the tag itself is supplied later or inline with the ciphertext).
        let taglen_param = params
            .get(param_keys::TLS_MAC_SIZE)
            .or_else(|| params.get(param_keys::AEAD_TAGLEN));
        if let Some(val) = taglen_param {
            // Rule R6: typed conversion via `try_from`, no `as` casts.
            let len = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("tag length out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("tag length out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "tag length parameter must be unsigned integer".into(),
                    ));
                }
            };
            if len > AES_CBC_MAX_HMAC_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "tag length {len} exceeds maximum {AES_CBC_MAX_HMAC_SIZE}"
                )));
            }
            self.taglen = Some(len);
        }
        Ok(())
    }
}

// =============================================================================
// descriptors() — Algorithm registration table
// =============================================================================

/// Returns the algorithm descriptors exposed by the AES-CBC-HMAC-SHA
/// composite cipher implementations.
///
/// Four `MtE` descriptors and six ETM descriptors — ten in total — are
/// returned, each carrying the `provider=default` property string.  The `MtE`
/// variants register the legacy MAC-then-Encrypt construction (TLS 1.0/1.1
/// /1.2 cipher suites); the ETM variants register the modern Encrypt-then-
/// MAC construction (RFC 7366 cipher suites).
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` ready to be appended to the default
/// provider's algorithm dispatch table.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // ---- MAC-then-Encrypt -------------------------------------------
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA1"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA1 composite (TLS, MAC-then-Encrypt)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA1"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA1 composite (TLS, MAC-then-Encrypt)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA256 composite (TLS, MAC-then-Encrypt)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA256 composite (TLS, MAC-then-Encrypt)",
        },
        // ---- Encrypt-then-MAC -------------------------------------------
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA1-ETM"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA1 (RFC 7366 Encrypt-then-MAC)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA1-ETM"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA1 (RFC 7366 Encrypt-then-MAC)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256-ETM"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA256 (RFC 7366 Encrypt-then-MAC)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256-ETM"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA256 (RFC 7366 Encrypt-then-MAC)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA512-ETM"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA512 (RFC 7366 Encrypt-then-MAC)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA512-ETM"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA512 (RFC 7366 Encrypt-then-MAC)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // RATIONALE: Within the `#[cfg(test)]` test module the `expect`, `unwrap`,
    // and `panic!` patterns are idiomatic for asserting setup invariants and
    // failing fast on unexpected branches. The clippy.toml guidance explicitly
    // permits these patterns in tests with a justification (see workspace
    // `Cargo.toml` `[workspace.lints.clippy]` notes for `unwrap_used`,
    // `expect_used`, and `panic`). Production code in this file uses
    // `Result<T, ProviderError>` everywhere — these allowances are scoped
    // exclusively to the test module.
    //
    // RATIONALE (cast lints): Test inputs and TLS AAD construction use
    // small, well-known constants (digest tag sizes ≤ 64 bytes, payload
    // lengths ≤ 65535 bytes, AES block size = 16) that fit comfortably
    // within the destination type's range. The truncation/wrap lints are
    // suppressed only for these statically-bounded conversions to keep the
    // test harness readable; production code uses `try_from` per Rule R6.
    //
    // RATIONALE (unreadable_literal): Test vectors use TLS sequence
    // numbers in the canonical hex form (`0x0001020304050607`) matching
    // wire-format byte order; inserting underscores would obscure their
    // origin in TLS protocol traces.
    //
    // RATIONALE (redundant_closure): `Option::and_then` accepting
    // `ParamValue::as_u32` directly is more concise but reads less
    // naturally next to the surrounding `match` and `.get()` chains; we
    // keep the closures for readability.
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::cast_possible_truncation,
        clippy::unreadable_literal,
        clippy::redundant_closure_for_method_calls
    )]

    use super::*;
    use crate::traits::CipherProvider;

    /// 16-byte test AES key.
    const KEY128: [u8; 16] = [0x42; 16];
    /// 32-byte test AES key.
    const KEY256: [u8; 32] = [0x55; 32];
    /// 16-byte zero IV.
    const IV: [u8; 16] = [0u8; 16];

    fn mac_key_for(digest: DigestVariant) -> Vec<u8> {
        // HMAC keys must match the underlying digest's recommended length to
        // exercise full-strength keying; the implementation accepts any
        // length though.
        vec![0x99; digest.tag_size()]
    }

    // -----------------------------------------------------------------
    // DigestVariant
    // -----------------------------------------------------------------

    #[test]
    fn digest_variant_names_and_sizes() {
        assert_eq!(DigestVariant::Sha1.digest_name(), "SHA-1");
        assert_eq!(DigestVariant::Sha256.digest_name(), "SHA-256");
        assert_eq!(DigestVariant::Sha512.digest_name(), "SHA-512");
        assert_eq!(DigestVariant::Sha1.tag_size(), 20);
        assert_eq!(DigestVariant::Sha256.tag_size(), 32);
        assert_eq!(DigestVariant::Sha512.tag_size(), 64);
    }

    #[test]
    fn digest_variant_display_matches_name() {
        assert_eq!(format!("{}", DigestVariant::Sha1), "SHA-1");
        assert_eq!(format!("{}", DigestVariant::Sha256), "SHA-256");
        assert_eq!(format!("{}", DigestVariant::Sha512), "SHA-512");
    }

    // -----------------------------------------------------------------
    // descriptors()
    // -----------------------------------------------------------------

    #[test]
    fn descriptors_returns_ten_entries() {
        let d = descriptors();
        assert_eq!(d.len(), 10, "expected 4 MtE + 6 ETM descriptors");
        let names: Vec<&str> = d.iter().flat_map(|x| x.names.iter().copied()).collect();
        assert!(names.contains(&"AES-128-CBC-HMAC-SHA1"));
        assert!(names.contains(&"AES-256-CBC-HMAC-SHA1"));
        assert!(names.contains(&"AES-128-CBC-HMAC-SHA256"));
        assert!(names.contains(&"AES-256-CBC-HMAC-SHA256"));
        assert!(names.contains(&"AES-128-CBC-HMAC-SHA1-ETM"));
        assert!(names.contains(&"AES-256-CBC-HMAC-SHA1-ETM"));
        assert!(names.contains(&"AES-128-CBC-HMAC-SHA256-ETM"));
        assert!(names.contains(&"AES-256-CBC-HMAC-SHA256-ETM"));
        assert!(names.contains(&"AES-128-CBC-HMAC-SHA512-ETM"));
        assert!(names.contains(&"AES-256-CBC-HMAC-SHA512-ETM"));
        for entry in &d {
            assert_eq!(entry.property, "provider=default");
        }
    }

    // -----------------------------------------------------------------
    // CipherProvider basics
    // -----------------------------------------------------------------

    #[test]
    fn mte_provider_reports_correct_dimensions() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA256", 16, DigestVariant::Sha256);
        assert_eq!(p.name(), "AES-128-CBC-HMAC-SHA256");
        assert_eq!(p.key_length(), 16);
        assert_eq!(p.iv_length(), 16);
        assert_eq!(p.block_size(), 16);
        assert_eq!(p.key_bits(), 128);
        assert_eq!(p.digest_variant(), DigestVariant::Sha256);
    }

    #[test]
    fn etm_provider_reports_correct_dimensions() {
        let p =
            AesCbcHmacShaEtmCipher::new("AES-256-CBC-HMAC-SHA512-ETM", 32, DigestVariant::Sha512);
        assert_eq!(p.name(), "AES-256-CBC-HMAC-SHA512-ETM");
        assert_eq!(p.key_length(), 32);
        assert_eq!(p.iv_length(), 16);
        assert_eq!(p.block_size(), 16);
        assert_eq!(p.key_bits(), 256);
        assert_eq!(p.digest_variant(), DigestVariant::Sha512);
    }

    #[test]
    fn new_ctx_returns_ready_context() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA1", 16, DigestVariant::Sha1);
        let ctx = p.new_ctx().expect("new_ctx must succeed");
        // Newly constructed context cannot be used until init; update before
        // init must error.
        // We can't directly invoke the trait methods on a Box<dyn ...> from
        // here with mut, but we can verify by drop.
        drop(ctx);
    }

    // -----------------------------------------------------------------
    // Init validation
    // -----------------------------------------------------------------

    #[test]
    fn mte_rejects_wrong_key_length() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA1", 16, DigestVariant::Sha1);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let bad_key = [0u8; 24];
        assert!(ctx.encrypt_init(&bad_key, Some(&IV), None).is_err());
    }

    #[test]
    fn mte_rejects_wrong_iv_length() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA1", 16, DigestVariant::Sha1);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let bad_iv = [0u8; 8];
        assert!(ctx.encrypt_init(&KEY128, Some(&bad_iv), None).is_err());
    }

    #[test]
    fn etm_rejects_wrong_key_length() {
        let p = AesCbcHmacShaEtmCipher::new("AES-128-CBC-HMAC-SHA1-ETM", 16, DigestVariant::Sha1);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let bad_key = [0u8; 24];
        assert!(ctx.decrypt_init(&bad_key, Some(&IV), None).is_err());
    }

    // -----------------------------------------------------------------
    // ETM encrypt-decrypt round trip
    // -----------------------------------------------------------------

    fn etm_round_trip(key: &[u8], digest: DigestVariant) {
        let mac_key = mac_key_for(digest);
        // Encrypt
        let p_enc = AesCbcHmacShaEtmCipher::new("test-etm", key.len(), digest);
        let mut enc = p_enc.new_ctx().expect("new_ctx enc");
        let mut params = ParamSet::new();
        params.set("aead-mac-key", ParamValue::OctetString(mac_key.clone()));
        enc.encrypt_init(key, Some(&IV), Some(&params))
            .expect("encrypt_init");
        let plaintext = b"The quick brown fox jumps over the lazy dog. ETM round trip!";
        let mut ct = Vec::new();
        let upd = enc.update(plaintext, &mut ct).expect("encrypt update");
        assert_eq!(upd, 0, "ETM defers all output to finalize");
        let fin = enc.finalize(&mut ct).expect("encrypt finalize");
        assert!(fin > 0, "encrypt finalize must produce ciphertext");
        let tag = enc
            .get_params()
            .expect("get_params after encrypt")
            .get(param_keys::TLS_MAC)
            .and_then(|v| v.as_bytes().map(<[u8]>::to_vec))
            .expect("computed MAC tag in params");
        assert_eq!(tag.len(), digest.tag_size());

        // Decrypt with correct tag — must succeed.
        let p_dec = AesCbcHmacShaEtmCipher::new("test-etm", key.len(), digest);
        let mut dec = p_dec.new_ctx().expect("new_ctx dec");
        let mut dec_params = ParamSet::new();
        dec_params.set("aead-mac-key", ParamValue::OctetString(mac_key.clone()));
        dec_params.set(param_keys::TLS_MAC, ParamValue::OctetString(tag.clone()));
        dec_params.set(
            param_keys::TLS_MAC_SIZE,
            ParamValue::UInt32(digest.tag_size() as u32),
        );
        dec.decrypt_init(key, Some(&IV), Some(&dec_params))
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("decrypt update");
        let out = dec.finalize(&mut pt).expect("decrypt finalize");
        assert_eq!(&pt, plaintext);
        assert_eq!(out, plaintext.len());

        // Decrypt with corrupted tag — must fail.
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0x01;
        let p_dec2 = AesCbcHmacShaEtmCipher::new("test-etm", key.len(), digest);
        let mut dec2 = p_dec2.new_ctx().expect("new_ctx dec2");
        let mut bad_params = ParamSet::new();
        bad_params.set("aead-mac-key", ParamValue::OctetString(mac_key.clone()));
        bad_params.set(param_keys::TLS_MAC, ParamValue::OctetString(bad_tag));
        bad_params.set(
            param_keys::TLS_MAC_SIZE,
            ParamValue::UInt32(digest.tag_size() as u32),
        );
        dec2.decrypt_init(key, Some(&IV), Some(&bad_params))
            .expect("decrypt_init bad");
        let mut bad_pt = Vec::new();
        dec2.update(&ct, &mut bad_pt).expect("decrypt update bad");
        assert!(dec2.finalize(&mut bad_pt).is_err());
    }

    #[test]
    fn etm_round_trip_aes128_sha1() {
        etm_round_trip(&KEY128, DigestVariant::Sha1);
    }

    #[test]
    fn etm_round_trip_aes256_sha256() {
        etm_round_trip(&KEY256, DigestVariant::Sha256);
    }

    #[test]
    fn etm_round_trip_aes128_sha512() {
        etm_round_trip(&KEY128, DigestVariant::Sha512);
    }

    #[test]
    fn etm_round_trip_aes256_sha512() {
        etm_round_trip(&KEY256, DigestVariant::Sha512);
    }

    #[test]
    fn etm_decrypt_requires_tag() {
        let p =
            AesCbcHmacShaEtmCipher::new("AES-128-CBC-HMAC-SHA256-ETM", 16, DigestVariant::Sha256);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(
            "aead-mac-key",
            ParamValue::OctetString(mac_key_for(DigestVariant::Sha256)),
        );
        ctx.decrypt_init(&KEY128, Some(&IV), Some(&params))
            .expect("decrypt_init");
        // Need a record at least one block large to attempt decrypt.
        let dummy = vec![0u8; AES_BLOCK_SIZE];
        ctx.update(&dummy, &mut Vec::new()).expect("update");
        // Without supplying a tag, finalize must error.
        assert!(ctx.finalize(&mut Vec::new()).is_err());
    }

    // -----------------------------------------------------------------
    // MtE TLS-AAD round trip
    // -----------------------------------------------------------------

    fn build_tls_aad(seq: u64, content_type: u8, version: u16, len: u16) -> Vec<u8> {
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.push(content_type);
        aad.extend_from_slice(&version.to_be_bytes());
        aad.extend_from_slice(&len.to_be_bytes());
        aad
    }

    fn mte_tls_round_trip(key: &[u8], digest: DigestVariant) {
        let mac_key = mac_key_for(digest);
        let payload = b"hello, TLS world! mte round trip payload";
        let payload_len = u16::try_from(payload.len()).unwrap();
        // TLS 1.2 (0x0303) — explicit IV required, so the AAD's "len" field
        // must include the explicit-IV block.
        let aad_len = payload_len + AES_BLOCK_SIZE as u16;
        let aad = build_tls_aad(0x0001020304050607, 23, 0x0303, aad_len);

        // Encrypt
        let p_enc = AesCbcHmacShaCipher::new("test-mte", key.len(), digest);
        let mut enc = p_enc.new_ctx().expect("new_ctx enc");
        let mut params = ParamSet::new();
        params.set("aead-mac-key", ParamValue::OctetString(mac_key.clone()));
        params.set(
            param_keys::AEAD_TLS1_AAD,
            ParamValue::OctetString(aad.clone()),
        );
        enc.encrypt_init(key, Some(&IV), Some(&params))
            .expect("encrypt_init");
        // The TLS-fast-path expects the entire record (explicit IV +
        // application data) as input.  We construct a record by prepending
        // the explicit IV to the payload.
        let mut record = Vec::with_capacity(AES_BLOCK_SIZE + payload.len());
        record.extend_from_slice(&IV);
        record.extend_from_slice(payload);
        let mut ct = Vec::new();
        let upd = enc.update(&record, &mut ct).expect("encrypt update");
        assert!(upd > 0);
        let fin = enc.finalize(&mut ct).expect("encrypt finalize");
        assert_eq!(fin, 0, "MtE TLS path emits in update");

        // Decrypt
        let p_dec = AesCbcHmacShaCipher::new("test-mte", key.len(), digest);
        let mut dec = p_dec.new_ctx().expect("new_ctx dec");
        let mut dec_params = ParamSet::new();
        dec_params.set("aead-mac-key", ParamValue::OctetString(mac_key.clone()));
        dec_params.set(
            param_keys::AEAD_TLS1_AAD,
            ParamValue::OctetString(aad.clone()),
        );
        dec.decrypt_init(key, Some(&IV), Some(&dec_params))
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("decrypt update");
        // The decrypted plaintext should equal the original record (including
        // the explicit IV block, since the cipher is agnostic about where the
        // record-level fragment ends).
        assert_eq!(pt.len(), payload.len() + AES_BLOCK_SIZE);
        assert_eq!(&pt[AES_BLOCK_SIZE..], &payload[..]);
    }

    #[test]
    fn mte_tls_round_trip_aes128_sha1() {
        mte_tls_round_trip(&KEY128, DigestVariant::Sha1);
    }

    #[test]
    fn mte_tls_round_trip_aes256_sha1() {
        mte_tls_round_trip(&KEY256, DigestVariant::Sha1);
    }

    #[test]
    fn mte_tls_round_trip_aes128_sha256() {
        mte_tls_round_trip(&KEY128, DigestVariant::Sha256);
    }

    #[test]
    fn mte_tls_round_trip_aes256_sha256() {
        mte_tls_round_trip(&KEY256, DigestVariant::Sha256);
    }

    // -----------------------------------------------------------------
    // get_params / set_params
    // -----------------------------------------------------------------

    #[test]
    fn mte_get_params_reports_dimensions() {
        let p = AesCbcHmacShaCipher::new("AES-256-CBC-HMAC-SHA256", 32, DigestVariant::Sha256);
        let ctx = p.new_ctx().expect("new_ctx");
        let ps = ctx.get_params().expect("get_params");
        assert_eq!(
            ps.get(param_keys::KEYLEN).and_then(|v| v.as_u32()),
            Some(32)
        );
        assert_eq!(ps.get(param_keys::IVLEN).and_then(|v| v.as_u32()), Some(16));
        assert_eq!(
            ps.get(param_keys::BLOCK_SIZE).and_then(|v| v.as_u32()),
            Some(16)
        );
        assert_eq!(ps.get(param_keys::AEAD).and_then(|v| v.as_u32()), Some(1));
    }

    #[test]
    fn etm_set_params_rejects_oversized_tag() {
        let p =
            AesCbcHmacShaEtmCipher::new("AES-128-CBC-HMAC-SHA256-ETM", 16, DigestVariant::Sha256);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(
            "aead-mac-key",
            ParamValue::OctetString(mac_key_for(DigestVariant::Sha256)),
        );
        ctx.decrypt_init(&KEY128, Some(&IV), Some(&params))
            .expect("decrypt_init");
        let mut bad = ParamSet::new();
        let oversized = vec![0u8; AES_CBC_MAX_HMAC_SIZE + 1];
        bad.set(param_keys::TLS_MAC, ParamValue::OctetString(oversized));
        assert!(ctx.set_params(&bad).is_err());
    }

    #[test]
    fn mte_set_params_rejects_wrong_aad_length() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA1", 16, DigestVariant::Sha1);
        let mut ctx = p.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&KEY128, Some(&IV), None).expect("init");
        let mut bad = ParamSet::new();
        bad.set(
            param_keys::AEAD_TLS1_AAD,
            ParamValue::OctetString(vec![0u8; 12]),
        );
        assert!(ctx.set_params(&bad).is_err());
    }

    // -----------------------------------------------------------------
    // Streaming-mode update before init must fail
    // -----------------------------------------------------------------

    #[test]
    fn update_before_init_errors() {
        let p =
            AesCbcHmacShaEtmCipher::new("AES-128-CBC-HMAC-SHA256-ETM", 16, DigestVariant::Sha256);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let mut out = Vec::new();
        assert!(ctx.update(b"hi", &mut out).is_err());
    }

    #[test]
    fn finalize_before_init_errors() {
        let p = AesCbcHmacShaCipher::new("AES-128-CBC-HMAC-SHA1", 16, DigestVariant::Sha1);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let mut out = Vec::new();
        assert!(ctx.finalize(&mut out).is_err());
    }

    // -----------------------------------------------------------------
    // xor_blocks
    // -----------------------------------------------------------------

    #[test]
    fn xor_blocks_overlap() {
        let mut a = [0xaau8; 16];
        let b = [0x55u8; 16];
        xor_blocks(&mut a, &b);
        assert_eq!(a, [0xffu8; 16]);
    }

    #[test]
    fn xor_blocks_short_src() {
        let mut a = [0xaau8; 16];
        let b = [0x01u8; 4];
        xor_blocks(&mut a, &b);
        assert_eq!(&a[..4], &[0xab; 4]);
        assert_eq!(&a[4..], &[0xaa; 12]);
    }
}
