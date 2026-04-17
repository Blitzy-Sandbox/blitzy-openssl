//! Symmetric cipher module for the openssl-crypto crate.
//!
//! Provides the core cipher traits, block modes, and implementations for:
//! - **AES** (128/192/256-bit, all modes including GCM, CCM, XTS, OCB, SIV, Key Wrap)
//! - **ChaCha20-Poly1305** (256-bit key, AEAD stream cipher)
//! - **DES / 3DES** (legacy block ciphers)
//! - **Legacy ciphers** (Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, Camellia, ARIA, SM4)
//!
//! ## Architecture
//!
//! The module follows OpenSSL's layered design:
//! 1. **Block primitives** — each cipher struct provides `encrypt_block`/`decrypt_block`
//! 2. **Mode engines** — generic CBC/CTR/CFB/OFB wrappers compose with any block cipher
//! 3. **AEAD constructions** — GCM/CCM/OCB/SIV/ChaCha20-Poly1305 provide authenticated encryption
//!
//! This replaces the C `block128_f` callback pattern from `crypto/modes/*.c` with
//! Rust's trait-based dispatch via [`SymmetricCipher`].
//!
//! ## Source Mapping
//!
//! | Rust Trait/Type    | C Source                     | Purpose                  |
//! |--------------------|------------------------------|--------------------------|
//! | [`SymmetricCipher`]| `block128_f` in `modes.h`    | Block cipher trait       |
//! | [`AeadCipher`]     | GCM/CCM/OCB/SIV modes       | Authenticated encryption |
//! | [`StreamCipher`]   | RC4, `ChaCha20`              | Stream cipher trait      |
//! | [`cbc_encrypt`]    | `crypto/modes/cbc128.c`      | CBC mode engine          |
//! | [`ctr_encrypt`]    | `crypto/modes/ctr128.c`      | CTR mode engine          |
//! | [`cfb_encrypt`]    | `crypto/modes/cfb128.c`      | CFB mode engine          |
//! | [`ofb_encrypt`]    | `crypto/modes/ofb128.c`      | OFB mode engine          |
//! | [`ecb_encrypt`]    | N/A (trivial wrapper)        | ECB mode engine          |
//! | [`pkcs7_pad`]      | `EVP_CIPHER_CTX` padding     | PKCS#7 padding           |
//! | [`pkcs7_unpad`]    | `EVP_CIPHER_CTX` padding     | PKCS#7 unpadding         |
//!
//! ## Rules Enforced
//!
//! - **R5 (Nullability):** All fallible operations return `CryptoResult<T>`.
//! - **R6 (Lossless Casts):** Block size uses typed [`BlockSize`] enum; counter
//!   increments use wrapping arithmetic; no bare `as` narrowing.
//! - **R7 (Lock Granularity):** N/A — mode engines are stateless.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All public items documented.
//! - **R10 (Wiring):** All submodules declared and re-exported.

use openssl_common::{CryptoError, CryptoResult};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// =============================================================================
// Submodule Declarations
// =============================================================================

/// AES block cipher with all modes (GCM, CCM, XTS, OCB, SIV, Key Wrap, CBC,
/// CTR, CFB, OFB, ECB, CTS).
#[cfg(feature = "aes")]
pub mod aes;

/// ChaCha20 stream cipher and ChaCha20-Poly1305 AEAD.
#[cfg(feature = "chacha")]
pub mod chacha20;

/// DES and Triple-DES (3DES-EDE) block ciphers.
#[cfg(feature = "des")]
pub mod des;

/// Legacy ciphers: Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, Camellia,
/// ARIA, SM4.
#[cfg(feature = "legacy")]
pub mod legacy;

// =============================================================================
// Re-exports — Convenience Imports for Downstream Users
// =============================================================================

#[cfg(feature = "aes")]
pub use aes::{Aes, AesCcm, AesGcm, AesKeySize, AesXts};

#[cfg(feature = "chacha")]
pub use chacha20::{ChaCha20, ChaCha20Poly1305};

#[cfg(feature = "des")]
pub use des::{Des, TripleDes};

#[cfg(feature = "legacy")]
pub use legacy::{Aria, Blowfish, Camellia, Cast5, Idea, Rc2, Rc4, Rc5, Seed, Sm4};

// =============================================================================
// CipherDirection — Encrypt / Decrypt Selector
// =============================================================================

/// Direction of a symmetric cipher operation.
///
/// Replaces the C `int enc` parameter (1 = encrypt, 0 = decrypt) used
/// throughout `crypto/modes/*.c` and `crypto/evp/evp_enc.c` with a type-safe
/// Rust enum per **Rule R5** (no integer sentinels).
///
/// # Examples
///
/// ```ignore
/// use openssl_crypto::symmetric::CipherDirection;
///
/// let dir = CipherDirection::Encrypt;
/// assert_ne!(dir, CipherDirection::Decrypt);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherDirection {
    /// Encryption direction.
    Encrypt,
    /// Decryption direction.
    Decrypt,
}

// =============================================================================
// CipherMode — Block Cipher Modes of Operation
// =============================================================================

/// Block cipher mode of operation for the symmetric cipher module.
///
/// Enumerates all modes supported by the generic mode engine functions and
/// the AES, DES, and legacy cipher implementations. This is the module-local
/// mode enum used within the `symmetric` subsystem; the EVP-level
/// [`openssl_common::CipherMode`] serves the provider/EVP abstraction layer.
///
/// # Variants
///
/// Each variant maps directly to an OpenSSL `EVP_CIPH_*_MODE` constant and
/// a corresponding `crypto/modes/*.c` implementation file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherMode {
    /// Electronic Codebook — **INSECURE**: identical plaintext blocks produce
    /// identical ciphertext blocks, leaking patterns. Provided for legacy
    /// compatibility only.
    Ecb,
    /// Cipher Block Chaining — the standard confidentiality mode. Each
    /// plaintext block is XOR-ed with the previous ciphertext block before
    /// encryption. Translates `crypto/modes/cbc128.c`.
    Cbc,
    /// Counter mode — turns a block cipher into a stream cipher by encrypting
    /// successive counter values. Same operation for encrypt and decrypt.
    /// Translates `crypto/modes/ctr128.c`.
    Ctr,
    /// Cipher Feedback (128-bit) mode — self-synchronising stream mode.
    /// Translates `crypto/modes/cfb128.c`.
    Cfb,
    /// Output Feedback mode — generates a keystream independent of plaintext.
    /// Same operation for encrypt and decrypt. Translates
    /// `crypto/modes/ofb128.c`.
    Ofb,
    /// Galois/Counter Mode — AEAD providing confidentiality and authenticity
    /// via CTR encryption + GHASH authentication. Translates
    /// `crypto/modes/gcm128.c`.
    Gcm,
    /// Counter with CBC-MAC — AEAD with variable nonce/tag lengths.
    /// Translates `crypto/modes/ccm128.c`.
    Ccm,
    /// XEX-based Tweaked-codebook mode with ciphertext Stealing — designed
    /// for disk/storage encryption. Translates `crypto/modes/xts128.c`.
    Xts,
    /// Offset Codebook Mode — AEAD with single-pass encrypt-and-authenticate.
    /// Translates `crypto/modes/ocb128.c`.
    Ocb,
    /// Synthetic Initialization Vector — nonce-misuse-resistant AEAD using
    /// S2V (CMAC-based) + CTR encryption. Translates `crypto/modes/siv128.c`.
    Siv,
    /// Key Wrap per RFC 3394 — wraps cryptographic keys for transport.
    /// Translates `crypto/modes/wrap128.c`.
    Wrap,
    /// Key Wrap with Padding per RFC 5649 — extends Key Wrap to arbitrary
    /// payload lengths. Translates `crypto/modes/wrap128.c`.
    WrapPad,
    /// Ciphertext Stealing — variant of CBC that avoids padding by stealing
    /// bits from the penultimate ciphertext block. Translates
    /// `crypto/modes/cts128.c`.
    Cts,
}

// =============================================================================
// BlockSize — Block Size Type Enum
// =============================================================================

/// Block size in bytes for a block cipher.
///
/// The two standard block sizes in symmetric cryptography:
/// - 64-bit (8 bytes): DES, Blowfish, CAST5, IDEA, RC2, RC5
/// - 128-bit (16 bytes): AES, Camellia, ARIA, SEED, SM4
///
/// Used as the return type of [`SymmetricCipher::block_size()`] to enforce
/// type safety per **Rule R6** (no bare integer comparison).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockSize {
    /// 64-bit block (8 bytes) — DES, Blowfish, CAST5, IDEA, RC2, RC5.
    Block64 = 8,
    /// 128-bit block (16 bytes) — AES, Camellia, ARIA, SEED, SM4.
    Block128 = 16,
}

impl BlockSize {
    /// Returns the block size as a byte count.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use openssl_crypto::symmetric::BlockSize;
    ///
    /// assert_eq!(BlockSize::Block64.bytes(), 8);
    /// assert_eq!(BlockSize::Block128.bytes(), 16);
    /// ```
    #[inline]
    pub fn bytes(self) -> usize {
        self as usize
    }
}

// =============================================================================
// CipherAlgorithm — Algorithm Identifier Enum
// =============================================================================

/// Enumeration of all supported symmetric cipher algorithms.
///
/// Used as the return type of the `algorithm()` method on [`SymmetricCipher`],
/// [`AeadCipher`], and [`StreamCipher`] traits to provide runtime algorithm
/// identification without string matching.
///
/// Variant names follow the convention `<Algorithm><KeySizeBits>` for ciphers
/// with multiple key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherAlgorithm {
    /// AES with 128-bit key (10 rounds).
    Aes128,
    /// AES with 192-bit key (12 rounds).
    Aes192,
    /// AES with 256-bit key (14 rounds).
    Aes256,
    /// `ChaCha20` stream cipher (256-bit key, 96-bit nonce).
    ChaCha20,
    /// ChaCha20-Poly1305 AEAD (256-bit key, 96-bit nonce, 128-bit tag).
    ChaCha20Poly1305,
    /// Single DES (56-bit effective key) — **BROKEN**, legacy only.
    Des,
    /// Triple-DES EDE (112/168-bit effective key).
    TripleDes,
    /// Blowfish (up to 448-bit key, 64-bit block).
    Blowfish,
    /// CAST-128 / CAST5 (40–128-bit key, 64-bit block).
    Cast5,
    /// IDEA (128-bit key, 64-bit block).
    Idea,
    /// SEED (128-bit key, 128-bit block).
    Seed,
    /// RC2 (8–1024-bit key, 64-bit block).
    Rc2,
    /// RC4 stream cipher (40–2048-bit key).
    Rc4,
    /// RC5-32/12/16 (variable rounds, 64-bit block).
    Rc5,
    /// Camellia with 128-bit key.
    Camellia128,
    /// Camellia with 192-bit key.
    Camellia192,
    /// Camellia with 256-bit key.
    Camellia256,
    /// ARIA with 128-bit key.
    Aria128,
    /// ARIA with 192-bit key.
    Aria192,
    /// ARIA with 256-bit key.
    Aria256,
    /// SM4 (128-bit key, 128-bit block) — Chinese national standard.
    Sm4,
}

// =============================================================================
// SymmetricCipher Trait — Replaces C `block128_f` Callback
// =============================================================================

/// Core trait for block cipher implementations.
///
/// Replaces the C `block128_f` function pointer callback from
/// `crypto/modes.h`:
/// ```c
/// typedef void (*block128_f)(const unsigned char in[16],
///                            unsigned char out[16],
///                            const void *key);
/// ```
///
/// Implementors provide single-block encrypt/decrypt operations. Generic mode
/// engine functions ([`cbc_encrypt`], [`ctr_encrypt`], [`cfb_encrypt`],
/// [`ofb_encrypt`], [`ecb_encrypt`]) compose with this trait to build full
/// cipher operations on arbitrary-length data.
///
/// # Contract
///
/// - `encrypt_block` and `decrypt_block` operate **in-place** on a mutable
///   byte slice whose length **must** equal [`block_size()`](Self::block_size).
/// - Implementations must not panic on valid input.
/// - Implementations must be **deterministic** (no internal randomness).
///
/// # Implementors
///
/// - `aes::Aes` (AES-128/192/256)
/// - `des::Des`, `des::TripleDes` (DES, 3DES-EDE)
/// - `legacy::Blowfish`, `legacy::Cast5`, `legacy::Idea`, etc.
pub trait SymmetricCipher: Send + Sync {
    /// Returns the block size of this cipher.
    ///
    /// - 64-bit ciphers (DES, Blowfish, CAST5, IDEA, RC2, RC5) return
    ///   [`BlockSize::Block64`].
    /// - 128-bit ciphers (AES, Camellia, ARIA, SEED, SM4) return
    ///   [`BlockSize::Block128`].
    fn block_size(&self) -> BlockSize;

    /// Encrypt a single block **in-place**.
    ///
    /// # Arguments
    ///
    /// * `block` — mutable byte slice whose length equals
    ///   `self.block_size().bytes()`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the slice length does not match the block
    /// size, or if an internal cipher error occurs.
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()>;

    /// Decrypt a single block **in-place**.
    ///
    /// # Arguments
    ///
    /// * `block` — mutable byte slice whose length equals
    ///   `self.block_size().bytes()`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the slice length does not match the block
    /// size, or if an internal cipher error occurs.
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()>;

    /// Returns the algorithm identifier for this cipher instance.
    fn algorithm(&self) -> CipherAlgorithm;
}

// =============================================================================
// AeadCipher Trait — Authenticated Encryption with Associated Data
// =============================================================================

/// Trait for Authenticated Encryption with Associated Data (AEAD) ciphers.
///
/// Provides [`seal`](Self::seal) (encrypt + authenticate) and
/// [`open`](Self::open) (verify + decrypt) operations. Covers:
/// - AES-GCM (`crypto/modes/gcm128.c`)
/// - AES-CCM (`crypto/modes/ccm128.c`)
/// - AES-OCB (`crypto/modes/ocb128.c`)
/// - AES-SIV (`crypto/modes/siv128.c`)
/// - ChaCha20-Poly1305
///
/// # Security
///
/// - `open()` **never** returns plaintext when authentication fails.
/// - Nonce reuse **destroys** confidentiality for CTR-based AEADs (GCM,
///   ChaCha20-Poly1305). Use a fresh nonce for every encryption.
/// - SIV is nonce-misuse-resistant: repeated nonces only leak equality of
///   plaintexts, not key material.
pub trait AeadCipher: Send + Sync {
    /// Encrypt plaintext and produce ciphertext with an appended
    /// authentication tag.
    ///
    /// Returns `ciphertext || tag` as a single `Vec<u8>`.
    ///
    /// # Arguments
    ///
    /// * `nonce` — unique nonce, length must equal [`nonce_length()`](Self::nonce_length).
    /// * `aad` — additional authenticated data (may be empty).
    /// * `plaintext` — data to encrypt.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on nonce length mismatch, key issues, or
    /// internal cipher failure.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Verify authentication tag, then decrypt ciphertext.
    ///
    /// Returns plaintext on success. On authentication failure, returns
    /// `CryptoError::Verification` and **never** exposes decrypted data.
    ///
    /// # Arguments
    ///
    /// * `nonce` — the nonce used during [`seal`](Self::seal).
    /// * `aad` — the same additional authenticated data used during seal.
    /// * `ciphertext_with_tag` — `ciphertext || tag` (output from `seal`).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Verification` if the tag does not match, or
    /// other [`CryptoError`] variants on parameter/internal errors.
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Expected nonce length in bytes (e.g., 12 for GCM, 12 for
    /// ChaCha20-Poly1305, 7–13 for CCM).
    fn nonce_length(&self) -> usize;

    /// Authentication tag length in bytes (e.g., 16 for GCM, 16 for
    /// ChaCha20-Poly1305, 4–16 for CCM).
    fn tag_length(&self) -> usize;

    /// Returns the algorithm identifier for this AEAD cipher instance.
    fn algorithm(&self) -> CipherAlgorithm;
}

// =============================================================================
// StreamCipher Trait — RC4, ChaCha20
// =============================================================================

/// Trait for stream ciphers (no block structure).
///
/// Stream ciphers produce a keystream that is XOR-ed with data; encrypt and
/// decrypt are the **same** operation.
///
/// # Implementors
///
/// - `chacha20::ChaCha20` (256-bit key, 96-bit nonce)
/// - `legacy::Rc4` (variable key length)
///
/// # Note
///
/// `process` takes `&mut self` because stream ciphers maintain internal
/// keystream state (position/counter).
pub trait StreamCipher: Send + Sync {
    /// Process data by XOR-ing with the keystream.
    ///
    /// The same function is used for both encryption and decryption.
    /// Each call advances the internal keystream state.
    ///
    /// # Arguments
    ///
    /// * `data` — input bytes to XOR with the keystream.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` of the same length as `data`.
    fn process(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Returns the algorithm identifier for this stream cipher instance.
    fn algorithm(&self) -> CipherAlgorithm;
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// XOR two byte slices element-wise: `a[i] ^= b[i]`.
///
/// The shorter slice determines the number of bytes XOR-ed. This follows
/// the pattern used throughout `crypto/modes/*.c` for IV/feedback XOR.
#[inline]
fn xor_blocks(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

/// Increment a big-endian counter in-place with carry propagation.
///
/// Translates `ctr128_inc` from `crypto/modes/ctr128.c`:
/// ```c
/// static void ctr128_inc(unsigned char *counter)
/// {
///     u32 n = 16, c = 1;
///     do {
///         --n;
///         c += counter[n];
///         counter[n] = (u8)c;
///         c >>= 8;
///     } while (n);
/// }
/// ```
///
/// Wraps around to zero on overflow — the C implementation does the same.
#[inline]
fn increment_counter(counter: &mut [u8]) {
    let mut carry: u16 = 1;
    for byte in counter.iter_mut().rev() {
        let sum = u16::from(*byte).wrapping_add(carry);
        // Low 8 bits of the sum stored back into counter byte.
        // Using bitwise AND instead of `as u8` to satisfy R6 lossless casts.
        *byte = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
}

/// Validate that a byte slice has the expected length, returning a
/// descriptive error on mismatch.
#[inline]
fn validate_length(name: &str, actual: usize, expected: usize) -> CryptoResult<()> {
    if actual != expected {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "{name} length mismatch: expected {expected}, got {actual}"
            )),
        ));
    }
    Ok(())
}

// =============================================================================
// CBC Mode Engine — from crypto/modes/cbc128.c
// =============================================================================

/// Generic CBC (Cipher Block Chaining) mode encryption/decryption.
///
/// Translates `CRYPTO_cbc128_encrypt` and `CRYPTO_cbc128_decrypt` from
/// `crypto/modes/cbc128.c`.
///
/// ## Encryption
///
/// 1. PKCS#7-pad the plaintext to a multiple of the block size.
/// 2. XOR each plaintext block with the previous ciphertext block (or IV for
///    the first block).
/// 3. Encrypt the XOR-ed block.
///
/// ## Decryption
///
/// 1. Verify the ciphertext length is a non-zero multiple of the block size.
/// 2. Decrypt each block.
/// 3. XOR with the previous ciphertext block (or IV for the first block).
/// 4. Remove and validate PKCS#7 padding.
///
/// ## Arguments
///
/// * `cipher` — block cipher implementing [`SymmetricCipher`].
/// * `data` — plaintext (encrypt) or ciphertext (decrypt).
/// * `iv` — initialization vector; length must equal the block size.
/// * `direction` — [`CipherDirection::Encrypt`] or [`CipherDirection::Decrypt`].
///
/// ## Errors
///
/// - IV length mismatch.
/// - Data length not a multiple of block size (decrypt only).
/// - Invalid PKCS#7 padding (decrypt only).
///
/// ## Security Note
///
/// CBC mode is **vulnerable to padding oracle attacks** if the caller
/// reveals whether unpadding succeeded or failed and the attacker can submit
/// chosen ciphertexts. Use AEAD modes (GCM, CCM) when possible.
pub fn cbc_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    let bs = cipher.block_size().bytes();
    validate_length("IV", iv.len(), bs)?;

    match direction {
        CipherDirection::Encrypt => cbc_encrypt_impl(cipher, data, iv, bs),
        CipherDirection::Decrypt => cbc_decrypt_impl(cipher, data, iv, bs),
    }
}

/// CBC encryption: pad → XOR with IV → encrypt block.
fn cbc_encrypt_impl<C: SymmetricCipher>(
    cipher: &C,
    plaintext: &[u8],
    iv: &[u8],
    bs: usize,
) -> CryptoResult<Vec<u8>> {
    let padded = pkcs7_pad(plaintext, bs);
    let num_blocks = padded.len() / bs;

    let mut output = Vec::with_capacity(padded.len());
    // Working buffer for the current block — max 16 bytes.
    let mut block_buf = [0u8; 16];
    // Previous ciphertext block (initially the IV) — max 16 bytes.
    let mut prev = [0u8; 16];
    prev[..bs].copy_from_slice(iv);

    for i in 0..num_blocks {
        let start = i * bs;
        let end = start + bs;
        block_buf[..bs].copy_from_slice(&padded[start..end]);

        // XOR plaintext block with previous ciphertext (or IV)
        xor_blocks(&mut block_buf[..bs], &prev[..bs]);

        // Encrypt the XOR-ed block in-place
        cipher.encrypt_block(&mut block_buf[..bs])?;

        // Store ciphertext block as the new "previous" for chaining
        prev[..bs].copy_from_slice(&block_buf[..bs]);

        output.extend_from_slice(&block_buf[..bs]);
    }

    // Securely zero intermediate buffers per AAP §0.7.6
    block_buf.zeroize();
    prev.zeroize();

    Ok(output)
}

/// CBC decryption: decrypt block → XOR with previous ciphertext → unpad.
fn cbc_decrypt_impl<C: SymmetricCipher>(
    cipher: &C,
    ciphertext: &[u8],
    iv: &[u8],
    bs: usize,
) -> CryptoResult<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % bs != 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "CBC decrypt: ciphertext length {} is not a positive multiple of block size {bs}",
                ciphertext.len()
            )),
        ));
    }

    let num_blocks = ciphertext.len() / bs;
    let mut output = Vec::with_capacity(ciphertext.len());
    let mut block_buf = [0u8; 16];
    let mut prev = [0u8; 16];
    prev[..bs].copy_from_slice(iv);

    for i in 0..num_blocks {
        let start = i * bs;
        let end = start + bs;
        block_buf[..bs].copy_from_slice(&ciphertext[start..end]);

        // Save current ciphertext block before decryption (needed for XOR)
        let mut saved_ct = [0u8; 16];
        saved_ct[..bs].copy_from_slice(&ciphertext[start..end]);

        // Decrypt the block in-place
        cipher.decrypt_block(&mut block_buf[..bs])?;

        // XOR with previous ciphertext block (or IV)
        xor_blocks(&mut block_buf[..bs], &prev[..bs]);

        // This block's ciphertext becomes "previous" for next iteration
        prev[..bs].copy_from_slice(&saved_ct[..bs]);
        saved_ct.zeroize();

        output.extend_from_slice(&block_buf[..bs]);
    }

    // Securely zero intermediate buffers
    block_buf.zeroize();
    prev.zeroize();

    // Remove PKCS#7 padding (constant-time validation)
    pkcs7_unpad(&output, bs)
}

// =============================================================================
// CTR Mode Engine — from crypto/modes/ctr128.c
// =============================================================================

/// Generic CTR (Counter) mode encryption/decryption.
///
/// Translates `CRYPTO_ctr128_encrypt` from `crypto/modes/ctr128.c`.
///
/// CTR mode turns a block cipher into a stream cipher by encrypting
/// successive counter values and XOR-ing the keystream with data. The same
/// function is used for both encryption and decryption.
///
/// ## Arguments
///
/// * `cipher` — block cipher implementing [`SymmetricCipher`].
/// * `data` — plaintext or ciphertext.
/// * `nonce` — initial counter block; length must equal the block size.
///
/// ## Errors
///
/// - Nonce length mismatch.
///
/// ## Security Note
///
/// **Never reuse the same nonce with the same key.** Nonce reuse produces
/// the same keystream, allowing XOR recovery of plaintext.
pub fn ctr_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    nonce: &[u8],
) -> CryptoResult<Vec<u8>> {
    let bs = cipher.block_size().bytes();
    validate_length("CTR nonce", nonce.len(), bs)?;

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(data.len());
    // Counter block — mutable copy of the nonce.
    let mut counter = [0u8; 16];
    counter[..bs].copy_from_slice(nonce);

    // Keystream block buffer.
    let mut keystream = [0u8; 16];

    let full_blocks = data.len() / bs;
    let remainder = data.len() % bs;

    // Process full blocks
    for i in 0..full_blocks {
        let start = i * bs;
        let end = start + bs;

        // Encrypt the counter to produce keystream
        keystream[..bs].copy_from_slice(&counter[..bs]);
        cipher.encrypt_block(&mut keystream[..bs])?;

        // XOR keystream with data
        let mut out_block = [0u8; 16];
        out_block[..bs].copy_from_slice(&data[start..end]);
        xor_blocks(&mut out_block[..bs], &keystream[..bs]);
        output.extend_from_slice(&out_block[..bs]);

        // Increment the counter (big-endian with carry)
        increment_counter(&mut counter[..bs]);
    }

    // Process partial last block (if any)
    if remainder > 0 {
        let start = full_blocks * bs;

        keystream[..bs].copy_from_slice(&counter[..bs]);
        cipher.encrypt_block(&mut keystream[..bs])?;

        // XOR only the remaining bytes with the keystream
        let mut partial = data[start..].to_vec();
        xor_blocks(&mut partial, &keystream[..remainder]);
        output.extend_from_slice(&partial);

        partial.zeroize();
    }

    // Securely zero intermediate buffers
    counter.zeroize();
    keystream.zeroize();

    Ok(output)
}

// =============================================================================
// CFB Mode Engine — from crypto/modes/cfb128.c
// =============================================================================

/// Generic CFB128 (Cipher Feedback, 128-bit) mode.
///
/// Translates `CRYPTO_cfb128_encrypt` from `crypto/modes/cfb128.c`.
///
/// In CFB mode the block cipher is used **only in encryption direction**
/// (even for decryption), making it a self-synchronising stream mode. The
/// feedback register is updated differently for encrypt vs. decrypt:
///
/// - **Encrypt:** `E(IV) XOR plaintext = ciphertext`; feed **ciphertext**
///   into IV.
/// - **Decrypt:** `E(IV) XOR ciphertext = plaintext`; feed **ciphertext**
///   (input) into IV **before** XOR.
///
/// ## Arguments
///
/// * `cipher` — block cipher implementing [`SymmetricCipher`].
/// * `data` — plaintext (encrypt) or ciphertext (decrypt).
/// * `iv` — initialization vector; length must equal the block size.
/// * `direction` — [`CipherDirection::Encrypt`] or [`CipherDirection::Decrypt`].
///
/// ## Errors
///
/// - IV length mismatch.
pub fn cfb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    let bs = cipher.block_size().bytes();
    validate_length("CFB IV", iv.len(), bs)?;

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(data.len());
    // Feedback register — mutable copy of the IV.
    let mut feedback = [0u8; 16];
    feedback[..bs].copy_from_slice(iv);

    let full_blocks = data.len() / bs;
    let remainder = data.len() % bs;

    // Process full blocks
    for i in 0..full_blocks {
        let start = i * bs;
        let end = start + bs;

        // Encrypt the feedback register
        let mut encrypted_fb = [0u8; 16];
        encrypted_fb[..bs].copy_from_slice(&feedback[..bs]);
        cipher.encrypt_block(&mut encrypted_fb[..bs])?;

        match direction {
            CipherDirection::Encrypt => {
                // XOR encrypted feedback with plaintext to produce ciphertext
                let mut out_block = [0u8; 16];
                out_block[..bs].copy_from_slice(&data[start..end]);
                xor_blocks(&mut out_block[..bs], &encrypted_fb[..bs]);
                // Feed ciphertext back into feedback register
                feedback[..bs].copy_from_slice(&out_block[..bs]);
                output.extend_from_slice(&out_block[..bs]);
            }
            CipherDirection::Decrypt => {
                // Feed input ciphertext into feedback register BEFORE XOR
                feedback[..bs].copy_from_slice(&data[start..end]);
                // XOR encrypted feedback with ciphertext to produce plaintext
                let mut out_block = [0u8; 16];
                out_block[..bs].copy_from_slice(&data[start..end]);
                xor_blocks(&mut out_block[..bs], &encrypted_fb[..bs]);
                output.extend_from_slice(&out_block[..bs]);
            }
        }

        encrypted_fb.zeroize();
    }

    // Process partial last block (if any)
    if remainder > 0 {
        let start = full_blocks * bs;

        let mut encrypted_fb = [0u8; 16];
        encrypted_fb[..bs].copy_from_slice(&feedback[..bs]);
        cipher.encrypt_block(&mut encrypted_fb[..bs])?;

        match direction {
            CipherDirection::Encrypt => {
                let mut partial = data[start..].to_vec();
                xor_blocks(&mut partial, &encrypted_fb[..remainder]);
                // Note: feedback not updated for partial tail — no further
                // blocks follow.
                output.extend_from_slice(&partial);
                partial.zeroize();
            }
            CipherDirection::Decrypt => {
                let mut partial = data[start..].to_vec();
                xor_blocks(&mut partial, &encrypted_fb[..remainder]);
                output.extend_from_slice(&partial);
                partial.zeroize();
            }
        }

        encrypted_fb.zeroize();
    }

    // Securely zero the feedback register
    feedback.zeroize();

    Ok(output)
}

// =============================================================================
// OFB Mode Engine — from crypto/modes/ofb128.c
// =============================================================================

/// Generic OFB128 (Output Feedback) mode encryption/decryption.
///
/// Translates `CRYPTO_ofb128_encrypt` from `crypto/modes/ofb128.c`.
///
/// In OFB mode, the keystream is generated independently of the plaintext
/// by repeatedly encrypting the IV/feedback register:
///
/// ```text
/// keystream[0] = E(IV)
/// keystream[i] = E(keystream[i-1])
/// output[i]    = data[i] XOR keystream[i]
/// ```
///
/// The same operation is used for both encryption and decryption.
///
/// ## Arguments
///
/// * `cipher` — block cipher implementing [`SymmetricCipher`].
/// * `data` — plaintext or ciphertext.
/// * `iv` — initialization vector; length must equal the block size.
///
/// ## Errors
///
/// - IV length mismatch.
pub fn ofb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
) -> CryptoResult<Vec<u8>> {
    let bs = cipher.block_size().bytes();
    validate_length("OFB IV", iv.len(), bs)?;

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(data.len());
    // Feedback register — mutable copy of the IV.
    let mut feedback = [0u8; 16];
    feedback[..bs].copy_from_slice(iv);

    let full_blocks = data.len() / bs;
    let remainder = data.len() % bs;

    // Process full blocks
    for i in 0..full_blocks {
        let start = i * bs;
        let end = start + bs;

        // Generate keystream by encrypting the feedback register in-place.
        // The updated feedback becomes the input for the next iteration.
        cipher.encrypt_block(&mut feedback[..bs])?;

        // XOR keystream with data
        let mut out_block = [0u8; 16];
        out_block[..bs].copy_from_slice(&data[start..end]);
        xor_blocks(&mut out_block[..bs], &feedback[..bs]);
        output.extend_from_slice(&out_block[..bs]);
    }

    // Process partial last block (if any)
    if remainder > 0 {
        let start = full_blocks * bs;

        cipher.encrypt_block(&mut feedback[..bs])?;

        let mut partial = data[start..].to_vec();
        xor_blocks(&mut partial, &feedback[..remainder]);
        output.extend_from_slice(&partial);
        partial.zeroize();
    }

    // Securely zero the feedback register
    feedback.zeroize();

    Ok(output)
}

// =============================================================================
// ECB Mode Engine — Trivial Single-Block Wrapper
// =============================================================================

/// Generic ECB (Electronic Codebook) mode encryption/decryption.
///
/// **⚠ INSECURE:** ECB mode processes each block independently — identical
/// plaintext blocks produce identical ciphertext blocks, leaking patterns.
/// This mode is provided **only for legacy compatibility and testing**.
/// Use CBC, CTR, or an AEAD mode for any real application.
///
/// PKCS#7 padding is applied on encryption and removed on decryption.
///
/// ## Arguments
///
/// * `cipher` — block cipher implementing [`SymmetricCipher`].
/// * `data` — plaintext (encrypt) or ciphertext (decrypt).
/// * `direction` — [`CipherDirection::Encrypt`] or [`CipherDirection::Decrypt`].
///
/// ## Errors
///
/// - Data length not a multiple of block size (decrypt only, before unpadding).
/// - Invalid PKCS#7 padding (decrypt only).
pub fn ecb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    let bs = cipher.block_size().bytes();

    match direction {
        CipherDirection::Encrypt => {
            let padded = pkcs7_pad(data, bs);
            let num_blocks = padded.len() / bs;
            let mut output = Vec::with_capacity(padded.len());
            let mut block_buf = [0u8; 16];

            for i in 0..num_blocks {
                let start = i * bs;
                let end = start + bs;
                block_buf[..bs].copy_from_slice(&padded[start..end]);
                cipher.encrypt_block(&mut block_buf[..bs])?;
                output.extend_from_slice(&block_buf[..bs]);
            }

            block_buf.zeroize();
            Ok(output)
        }
        CipherDirection::Decrypt => {
            if data.is_empty() || data.len() % bs != 0 {
                return Err(CryptoError::Common(
                    openssl_common::CommonError::InvalidArgument(format!(
                        "ECB decrypt: data length {} is not a positive multiple of block size {bs}",
                        data.len()
                    )),
                ));
            }

            let num_blocks = data.len() / bs;
            let mut output = Vec::with_capacity(data.len());
            let mut block_buf = [0u8; 16];

            for i in 0..num_blocks {
                let start = i * bs;
                let end = start + bs;
                block_buf[..bs].copy_from_slice(&data[start..end]);
                cipher.decrypt_block(&mut block_buf[..bs])?;
                output.extend_from_slice(&block_buf[..bs]);
            }

            block_buf.zeroize();
            pkcs7_unpad(&output, bs)
        }
    }
}

// =============================================================================
// PKCS#7 Padding — Constant-Time Validation
// =============================================================================

/// Add PKCS#7 padding to `data` for a given `block_size`.
///
/// PKCS#7 (RFC 5652 §6.3) appends N bytes of value N, where N is the number
/// of padding bytes needed to reach the next block boundary. If the data is
/// already block-aligned, a full block of padding is added (N == `block_size`).
///
/// ## Arguments
///
/// * `data` — input plaintext.
/// * `block_size` — cipher block size in bytes (8 or 16).
///
/// ## Returns
///
/// A new `Vec<u8>` containing `data` followed by PKCS#7 padding.
///
/// ## Panics
///
/// Panics if `block_size` is zero or greater than 255 (PKCS#7 limit).
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    debug_assert!(
        block_size > 0 && block_size <= 255,
        "PKCS#7 block_size must be 1..=255"
    );

    let remainder = data.len() % block_size;
    let pad_len = block_size - remainder;
    // pad_len is guaranteed 1..=block_size, fitting in a u8 since block_size <= 255.
    // SAFETY: pad_len is always 1..=block_size, and block_size is 8 or 16, so this
    // value always fits in a u8. Using saturating conversion for additional safety.
    let pad_byte: u8 = u8::try_from(pad_len).unwrap_or(u8::MAX);

    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.resize(data.len() + pad_len, pad_byte);
    padded
}

/// Remove and validate PKCS#7 padding in **constant time**.
///
/// Uses [`subtle::ConstantTimeEq`] to compare every padding byte against the
/// expected value, preventing padding oracle timing attacks as specified in
/// AAP §0.7.6.
///
/// ## Arguments
///
/// * `data` — PKCS#7-padded data whose length must be a non-zero multiple of
///   `block_size`.
/// * `block_size` — cipher block size in bytes (8 or 16).
///
/// ## Returns
///
/// The unpadded data on success.
///
/// ## Errors
///
/// Returns [`CryptoError::Verification`] if:
/// - `data` is empty or not a multiple of `block_size`.
/// - The last byte is zero or greater than `block_size`.
/// - Any padding byte does not match the expected value (constant-time check).
pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> CryptoResult<Vec<u8>> {
    if data.is_empty() || data.len() % block_size != 0 {
        return Err(CryptoError::Verification(
            "PKCS#7 unpad: data length is not a positive multiple of block size".into(),
        ));
    }

    // Read the last byte to determine padding length.
    let pad_byte = data[data.len() - 1];
    let pad_len = usize::from(pad_byte);

    // The padding length must be in 1..=block_size.
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(CryptoError::Verification(
            "PKCS#7 unpad: invalid padding byte value".into(),
        ));
    }

    // Constant-time validation: build expected padding and compare.
    let pad_start = data.len() - pad_len;
    let padding_region = &data[pad_start..];
    let expected: Vec<u8> = vec![pad_byte; pad_len];

    // Constant-time comparison via subtle::ConstantTimeEq — prevents the
    // caller from inferring which byte mismatched based on timing.
    let is_valid: bool = bool::from(padding_region.ct_eq(&expected));

    if is_valid {
        Ok(data[..pad_start].to_vec())
    } else {
        Err(CryptoError::Verification(
            "PKCS#7 unpad: padding validation failed".into(),
        ))
    }
}

// =============================================================================
// Display Implementations
// =============================================================================

impl core::fmt::Display for CipherDirection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encrypt => f.write_str("Encrypt"),
            Self::Decrypt => f.write_str("Decrypt"),
        }
    }
}

impl core::fmt::Display for CipherMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
            Self::Ctr => "CTR",
            Self::Cfb => "CFB",
            Self::Ofb => "OFB",
            Self::Gcm => "GCM",
            Self::Ccm => "CCM",
            Self::Xts => "XTS",
            Self::Ocb => "OCB",
            Self::Siv => "SIV",
            Self::Wrap => "Wrap",
            Self::WrapPad => "WrapPad",
            Self::Cts => "CTS",
        };
        f.write_str(name)
    }
}

impl core::fmt::Display for BlockSize {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Block64 => f.write_str("64-bit (8 bytes)"),
            Self::Block128 => f.write_str("128-bit (16 bytes)"),
        }
    }
}

impl core::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::ChaCha20 => "ChaCha20",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Des => "DES",
            Self::TripleDes => "3DES",
            Self::Blowfish => "Blowfish",
            Self::Cast5 => "CAST5",
            Self::Idea => "IDEA",
            Self::Seed => "SEED",
            Self::Rc2 => "RC2",
            Self::Rc4 => "RC4",
            Self::Rc5 => "RC5",
            Self::Camellia128 => "Camellia-128",
            Self::Camellia192 => "Camellia-192",
            Self::Camellia256 => "Camellia-256",
            Self::Aria128 => "ARIA-128",
            Self::Aria192 => "ARIA-192",
            Self::Aria256 => "ARIA-256",
            Self::Sm4 => "SM4",
        };
        f.write_str(name)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Mock Block Cipher for Testing Mode Engines
    // =========================================================================

    /// A trivial XOR-based "cipher" for testing mode engines.
    /// Encrypt: XOR each byte with 0xAA.
    /// Decrypt: XOR each byte with 0xAA (same operation — involutory).
    struct MockCipher128;

    impl SymmetricCipher for MockCipher128 {
        fn block_size(&self) -> BlockSize {
            BlockSize::Block128
        }

        fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
            if block.len() != 16 {
                return Err(CryptoError::Common(
                    openssl_common::CommonError::InvalidArgument(
                        "MockCipher128 requires 16-byte block".into(),
                    ),
                ));
            }
            for b in block.iter_mut() {
                *b ^= 0xAA;
            }
            Ok(())
        }

        fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
            // XOR cipher is its own inverse
            self.encrypt_block(block)
        }

        fn algorithm(&self) -> CipherAlgorithm {
            CipherAlgorithm::Aes128
        }
    }

    /// Mock 64-bit block cipher for testing with DES-like block sizes.
    struct MockCipher64;

    impl SymmetricCipher for MockCipher64 {
        fn block_size(&self) -> BlockSize {
            BlockSize::Block64
        }

        fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
            if block.len() != 8 {
                return Err(CryptoError::Common(
                    openssl_common::CommonError::InvalidArgument(
                        "MockCipher64 requires 8-byte block".into(),
                    ),
                ));
            }
            for b in block.iter_mut() {
                *b ^= 0x55;
            }
            Ok(())
        }

        fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
            self.encrypt_block(block)
        }

        fn algorithm(&self) -> CipherAlgorithm {
            CipherAlgorithm::Des
        }
    }

    // =========================================================================
    // Enum Tests
    // =========================================================================

    #[test]
    fn test_block_size_bytes() {
        assert_eq!(BlockSize::Block64.bytes(), 8);
        assert_eq!(BlockSize::Block128.bytes(), 16);
    }

    #[test]
    fn test_cipher_direction_display() {
        assert_eq!(CipherDirection::Encrypt.to_string(), "Encrypt");
        assert_eq!(CipherDirection::Decrypt.to_string(), "Decrypt");
    }

    #[test]
    fn test_cipher_mode_display() {
        assert_eq!(CipherMode::Gcm.to_string(), "GCM");
        assert_eq!(CipherMode::Cbc.to_string(), "CBC");
        assert_eq!(CipherMode::Cts.to_string(), "CTS");
    }

    #[test]
    fn test_cipher_algorithm_display() {
        assert_eq!(CipherAlgorithm::Aes256.to_string(), "AES-256");
        assert_eq!(
            CipherAlgorithm::ChaCha20Poly1305.to_string(),
            "ChaCha20-Poly1305"
        );
        assert_eq!(CipherAlgorithm::Sm4.to_string(), "SM4");
    }

    #[test]
    fn test_block_size_display() {
        assert_eq!(BlockSize::Block64.to_string(), "64-bit (8 bytes)");
        assert_eq!(BlockSize::Block128.to_string(), "128-bit (16 bytes)");
    }

    // =========================================================================
    // PKCS#7 Padding Tests
    // =========================================================================

    #[test]
    fn test_pkcs7_pad_block_aligned() {
        // 16 bytes input → gets full block of padding (16 bytes of 0x10)
        let data = [0u8; 16];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 16));
    }

    #[test]
    fn test_pkcs7_pad_partial_block() {
        let data = b"hello"; // 5 bytes → need 11 bytes of padding for bs=16
        let padded = pkcs7_pad(data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..5], b"hello");
        assert!(padded[5..].iter().all(|&b| b == 11));
    }

    #[test]
    fn test_pkcs7_pad_empty() {
        let padded = pkcs7_pad(&[], 8);
        assert_eq!(padded.len(), 8);
        assert!(padded.iter().all(|&b| b == 8));
    }

    #[test]
    fn test_pkcs7_roundtrip() {
        let data = b"test data 1234";
        let padded = pkcs7_pad(data, 16);
        let unpadded = pkcs7_unpad(&padded, 16).expect("valid padding");
        assert_eq!(&unpadded, data);
    }

    #[test]
    fn test_pkcs7_unpad_invalid_zero_pad() {
        // Last byte is 0 → invalid
        let mut data = [0u8; 16];
        data[15] = 0;
        assert!(pkcs7_unpad(&data, 16).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_invalid_too_large() {
        // Last byte is 17 → larger than block size
        let mut data = [0u8; 16];
        data[15] = 17;
        assert!(pkcs7_unpad(&data, 16).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_invalid_mismatch() {
        // Last byte says 4 padding bytes, but they don't all match
        let mut data = [0u8; 16];
        data[12] = 4;
        data[13] = 4;
        data[14] = 3; // mismatch!
        data[15] = 4;
        assert!(pkcs7_unpad(&data, 16).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_empty_data() {
        assert!(pkcs7_unpad(&[], 16).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_non_multiple() {
        assert!(pkcs7_unpad(&[0u8; 15], 16).is_err());
    }

    // =========================================================================
    // CBC Mode Tests
    // =========================================================================

    #[test]
    fn test_cbc_roundtrip_128() {
        let cipher = MockCipher128;
        let iv = [0u8; 16];
        let plaintext = b"hello world test"; // exactly 16 bytes

        let ct =
            cbc_encrypt(&cipher, plaintext, &iv, CipherDirection::Encrypt).expect("CBC encrypt");
        assert_ne!(&ct[..], plaintext); // ciphertext differs from plaintext

        let pt = cbc_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt).expect("CBC decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_cbc_roundtrip_partial_block() {
        let cipher = MockCipher128;
        let iv = [0x42u8; 16];
        let plaintext = b"short"; // 5 bytes — needs padding

        let ct =
            cbc_encrypt(&cipher, plaintext, &iv, CipherDirection::Encrypt).expect("CBC encrypt");
        assert_eq!(ct.len(), 16); // padded to one block

        let pt = cbc_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt).expect("CBC decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_cbc_roundtrip_multi_block() {
        let cipher = MockCipher128;
        let iv = [0x11u8; 16];
        let plaintext = b"this is a longer plaintext that spans multiple blocks!!";

        let ct =
            cbc_encrypt(&cipher, plaintext, &iv, CipherDirection::Encrypt).expect("CBC encrypt");
        let pt = cbc_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt).expect("CBC decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_cbc_iv_length_mismatch() {
        let cipher = MockCipher128;
        let bad_iv = [0u8; 8]; // 8 bytes for 128-bit cipher
        assert!(cbc_encrypt(&cipher, b"data", &bad_iv, CipherDirection::Encrypt).is_err());
    }

    #[test]
    fn test_cbc_decrypt_invalid_length() {
        let cipher = MockCipher128;
        let iv = [0u8; 16];
        let bad_ct = [0u8; 15]; // not a multiple of 16
        assert!(cbc_encrypt(&cipher, &bad_ct, &iv, CipherDirection::Decrypt).is_err());
    }

    #[test]
    fn test_cbc_64bit_roundtrip() {
        let cipher = MockCipher64;
        let iv = [0xFFu8; 8];
        let plaintext = b"testing 64-bit block cipher CBC mode roundtrip";

        let ct =
            cbc_encrypt(&cipher, plaintext, &iv, CipherDirection::Encrypt).expect("CBC-64 encrypt");
        let pt = cbc_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt).expect("CBC-64 decrypt");
        assert_eq!(&pt, plaintext);
    }

    // =========================================================================
    // CTR Mode Tests
    // =========================================================================

    #[test]
    fn test_ctr_roundtrip_128() {
        let cipher = MockCipher128;
        let nonce = [0u8; 16];
        let plaintext = b"counter mode test data 12345";

        let ct = ctr_encrypt(&cipher, plaintext, &nonce).expect("CTR encrypt");
        assert_eq!(ct.len(), plaintext.len());

        // Decrypt: same operation with same nonce
        let pt = ctr_encrypt(&cipher, &ct, &nonce).expect("CTR decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_ctr_empty_data() {
        let cipher = MockCipher128;
        let nonce = [0u8; 16];
        let result = ctr_encrypt(&cipher, &[], &nonce).expect("CTR empty");
        assert!(result.is_empty());
    }

    #[test]
    fn test_ctr_nonce_length_mismatch() {
        let cipher = MockCipher128;
        let bad_nonce = [0u8; 12]; // 12 bytes for 128-bit cipher
        assert!(ctr_encrypt(&cipher, b"data", &bad_nonce).is_err());
    }

    #[test]
    fn test_ctr_partial_last_block() {
        let cipher = MockCipher128;
        let nonce = [0u8; 16];
        // Use a known odd length — 7 bytes, definitely partial for 128-bit
        let pt = &[0xABu8; 7];

        let ct = ctr_encrypt(&cipher, pt, &nonce).expect("CTR partial");
        assert_eq!(ct.len(), 7);

        let recovered = ctr_encrypt(&cipher, &ct, &nonce).expect("CTR partial decrypt");
        assert_eq!(&recovered, pt);
    }

    // =========================================================================
    // CFB Mode Tests
    // =========================================================================

    #[test]
    fn test_cfb_roundtrip_128() {
        let cipher = MockCipher128;
        let iv = [0x33u8; 16];
        let plaintext = b"CFB mode roundtrip testing data";

        let ct =
            cfb_encrypt(&cipher, plaintext, &iv, CipherDirection::Encrypt).expect("CFB encrypt");
        assert_eq!(ct.len(), plaintext.len());

        let pt = cfb_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt).expect("CFB decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_cfb_empty_data() {
        let cipher = MockCipher128;
        let iv = [0u8; 16];
        let result = cfb_encrypt(&cipher, &[], &iv, CipherDirection::Encrypt).expect("CFB empty");
        assert!(result.is_empty());
    }

    #[test]
    fn test_cfb_iv_length_mismatch() {
        let cipher = MockCipher128;
        let bad_iv = [0u8; 10];
        assert!(cfb_encrypt(&cipher, b"data", &bad_iv, CipherDirection::Encrypt).is_err());
    }

    // =========================================================================
    // OFB Mode Tests
    // =========================================================================

    #[test]
    fn test_ofb_roundtrip_128() {
        let cipher = MockCipher128;
        let iv = [0x77u8; 16];
        let plaintext = b"OFB mode is the same for encrypt and decrypt!";

        let ct = ofb_encrypt(&cipher, plaintext, &iv).expect("OFB encrypt");
        assert_eq!(ct.len(), plaintext.len());

        let pt = ofb_encrypt(&cipher, &ct, &iv).expect("OFB decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_ofb_empty_data() {
        let cipher = MockCipher128;
        let iv = [0u8; 16];
        let result = ofb_encrypt(&cipher, &[], &iv).expect("OFB empty");
        assert!(result.is_empty());
    }

    // =========================================================================
    // ECB Mode Tests
    // =========================================================================

    #[test]
    fn test_ecb_roundtrip_128() {
        let cipher = MockCipher128;
        let plaintext = b"ECB roundtrip test data for 128";

        let ct = ecb_encrypt(&cipher, plaintext, CipherDirection::Encrypt).expect("ECB encrypt");
        assert!(ct.len() % 16 == 0); // padded to block multiple

        let pt = ecb_encrypt(&cipher, &ct, CipherDirection::Decrypt).expect("ECB decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_ecb_roundtrip_64() {
        let cipher = MockCipher64;
        let plaintext = b"ECB 64-bit test";

        let ct = ecb_encrypt(&cipher, plaintext, CipherDirection::Encrypt).expect("ECB-64 encrypt");
        assert!(ct.len() % 8 == 0);

        let pt = ecb_encrypt(&cipher, &ct, CipherDirection::Decrypt).expect("ECB-64 decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_ecb_decrypt_invalid_length() {
        let cipher = MockCipher128;
        let bad_ct = [0u8; 15]; // not a multiple of 16
        assert!(ecb_encrypt(&cipher, &bad_ct, CipherDirection::Decrypt).is_err());
    }

    // =========================================================================
    // Internal Helper Tests
    // =========================================================================

    #[test]
    fn test_xor_blocks() {
        let mut a = [0xFF, 0x00, 0xAA, 0x55];
        let b = [0xFF, 0xFF, 0x55, 0xAA];
        xor_blocks(&mut a, &b);
        assert_eq!(a, [0x00, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_increment_counter_basic() {
        let mut counter = [0x00, 0x00, 0x00, 0x01];
        increment_counter(&mut counter);
        assert_eq!(counter, [0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_increment_counter_carry() {
        let mut counter = [0x00, 0x00, 0x00, 0xFF];
        increment_counter(&mut counter);
        assert_eq!(counter, [0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_increment_counter_full_carry() {
        let mut counter = [0xFF, 0xFF, 0xFF, 0xFF];
        increment_counter(&mut counter);
        assert_eq!(counter, [0x00, 0x00, 0x00, 0x00]); // wraps around
    }

    #[test]
    fn test_validate_length_ok() {
        assert!(validate_length("test", 16, 16).is_ok());
    }

    #[test]
    fn test_validate_length_mismatch() {
        assert!(validate_length("IV", 12, 16).is_err());
    }
}
