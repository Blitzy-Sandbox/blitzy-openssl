//! `ChaCha20` stream cipher and `ChaCha20-Poly1305` AEAD implementation.
//!
//! Provides the `ChaCha20` stream cipher (RFC 8439, formerly RFC 7539) and
//! the `ChaCha20-Poly1305` AEAD construction for authenticated encryption.
//!
//! `ChaCha20` is a 256-bit key, 96-bit nonce stream cipher operating on
//! 64-byte blocks internally. It was designed by Daniel J. Bernstein and
//! is the standard alternative to AES for TLS 1.3.
//!
//! # Source Mapping
//!
//! | Rust item | C source | Key details |
//! |-----------|----------|-------------|
//! | [`ChaCha20`] | `crypto/chacha/chacha_enc.c` | `ChaCha20_ctr32`, `chacha20_core`, QUARTERROUND |
//! | [`ChaCha20Poly1305`] | Provider AEAD layer | RFC 8439 §2.8 construction |
//! | `quarter_round` (private) | `QUARTERROUND` macro, `chacha_enc.c` §57 | 16/12/8/7 rotations |
//! | `chacha20_block` (private) | `chacha20_core`, `chacha_enc.c` §65 | 20 rounds, feed-forward |
//!
//! # Design Notes
//!
//! - `ChaCha20` is a stream cipher, not a block cipher — it does NOT implement
//!   `SymmetricCipher`. Instead it provides a
//!   streaming XOR API via the `StreamCipher` trait.
//! - The Poly1305 MAC component is imported from the [`crate::mac`] module
//!   via `mac_compute` (`mac::compute`).
//! - Key material is zeroed on drop via [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop).
//! - Tag comparison in [`ChaCha20Poly1305::open`] uses
//!   [`ConstantTimeEq`] to prevent timing
//!   side-channel attacks (AAP §0.7.6).
//! - ZERO `unsafe` blocks — pure Rust implementation (Rule R8).
//!
//! # Specifications
//!
//! - [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
//! - D. J. Bernstein, [ChaCha, a variant of Salsa20](https://cr.yp.to/chacha/chacha-20080128.pdf)

use openssl_common::{CommonError, CryptoError, CryptoResult};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{AeadCipher, CipherAlgorithm, StreamCipher};
use crate::mac::{compute as mac_compute, MacType};

// =============================================================================
// Public Constants
// =============================================================================

/// `ChaCha20` internal block size — 16 × 4 bytes = 64 bytes (512 bits).
///
/// This is the size of one keystream block generated per
/// `chacha20_block` invocation.
pub const CHACHA_BLOCK_SIZE: usize = 64;

/// `ChaCha20` key size — 256 bits = 32 bytes.
pub const CHACHA_KEY_SIZE: usize = 32;

/// `ChaCha20` nonce size per RFC 8439 — 96 bits = 12 bytes.
///
/// Combined with the 32-bit block counter, this gives a total of 128 bits
/// of state per encrypted block.
pub const CHACHA_NONCE_SIZE: usize = 12;

/// Legacy `ChaCha20` nonce size per original Bernstein design — 64 bits = 8 bytes.
///
/// Provided for compatibility with pre-RFC 8439 specifications. This
/// implementation uses the RFC 8439 (`CHACHA_NONCE_SIZE = 12`) variant.
pub const CHACHA_NONCE_SIZE_LEGACY: usize = 8;

/// `ChaCha20-Poly1305` authentication tag size — 128 bits = 16 bytes.
const CHACHA_POLY1305_TAG_SIZE: usize = 16;

/// `ChaCha20-Poly1305` Poly1305 one-time key size — 32 bytes.
///
/// Derived from the first 32 bytes of `ChaCha20(key, nonce, counter=0)`
/// per RFC 8439 §2.6.
const POLY1305_KEY_SIZE: usize = 32;

// =============================================================================
// Sigma Constants — "expand 32-byte k"
// =============================================================================

/// `ChaCha20` initial state constants — `"expand 32-byte k"` in little-endian.
///
/// These are the first four 32-bit words of the `ChaCha20` initial state
/// (words 0–3). They are derived from the ASCII bytes of the string
/// `"expand 32-byte k"`:
///
/// | Index | ASCII    | `u32` (LE) |
/// |-------|----------|------------|
/// | 0     | `expa`   | `0x61707865` |
/// | 1     | `nd 3`   | `0x3320646e` |
/// | 2     | `2-by`   | `0x79622d32` |
/// | 3     | `te k`   | `0x6b206574` |
///
/// Translates the sigma initialisation from
/// `ChaCha20_ctr32` in `crypto/chacha/chacha_enc.c`.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

// =============================================================================
// Internal Helpers — Core ChaCha20 Primitives
// =============================================================================

/// Initialises the 16-word `ChaCha20` state from key, nonce, and block counter.
///
/// The layout follows RFC 8439 §2.3:
///
/// ```text
///  0  1  2  3      ← sigma ("expand 32-byte k")
///  4  5  6  7      ← key[0..16]
///  8  9 10 11      ← key[16..32]
/// 12               ← block counter
/// 13 14 15         ← nonce
/// ```
///
/// All multi-byte values are loaded as little-endian.
#[inline]
fn init_state(
    key: &[u8; CHACHA_KEY_SIZE],
    nonce: &[u8; CHACHA_NONCE_SIZE],
    counter: u32,
) -> [u32; 16] {
    [
        // Words 0..4 — sigma constant.
        SIGMA[0],
        SIGMA[1],
        SIGMA[2],
        SIGMA[3],
        // Words 4..12 — 256-bit key as 8 little-endian u32s.
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        // Word 12 — 32-bit block counter.
        counter,
        // Words 13..16 — 96-bit nonce as 3 little-endian u32s.
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ]
}

/// `ChaCha20` quarter round — the fundamental mixing operation.
///
/// Implements the `QUARTERROUND(a, b, c, d)` macro from
/// `crypto/chacha/chacha_enc.c` line 57 and RFC 8439 §2.1:
///
/// ```text
/// a += b; d ^= a; d <<<= 16;
/// c += d; b ^= c; b <<<= 12;
/// a += b; d ^= a; d <<<= 8;
/// c += d; b ^= c; b <<<= 7;
/// ```
///
/// All additions are modulo 2^32 (wrapping). All shifts are left rotations.
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Generates one 64-byte `ChaCha20` keystream block from the input state.
///
/// Translates `chacha20_core` from `crypto/chacha/chacha_enc.c` line 65.
///
/// The algorithm runs 20 rounds (10 double-rounds) of the quarter-round
/// function alternating between **column rounds** and **diagonal rounds**,
/// then adds the working state back into the original state (feed-forward)
/// and serialises to little-endian bytes.
///
/// This function does **not** modify the input state; the caller must
/// advance the block counter (`state[12]`) between successive calls.
fn chacha20_block(input: &[u32; 16]) -> [u8; CHACHA_BLOCK_SIZE] {
    // Working copy of the state; rounds mutate this.
    let mut x = *input;

    // 20 rounds = 10 double-rounds (column + diagonal).
    for _ in 0..10 {
        // Column rounds — operate on state columns.
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        // Diagonal rounds — operate on state diagonals.
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    // Feed-forward — add working state back into original state.
    // Rule R6: explicit wrapping_add (matches C unsigned addition modulo 2^32).
    for i in 0..16 {
        x[i] = x[i].wrapping_add(input[i]);
    }

    // Serialise 16 × u32 to 64 little-endian bytes.
    let mut output = [0u8; CHACHA_BLOCK_SIZE];
    for (i, word) in x.iter().enumerate() {
        let bytes = word.to_le_bytes();
        output[i * 4] = bytes[0];
        output[i * 4 + 1] = bytes[1];
        output[i * 4 + 2] = bytes[2];
        output[i * 4 + 3] = bytes[3];
    }

    // Zeroize the working buffer — it contains keystream material derived
    // from the key. Part of this is directly used as the Poly1305 one-time
    // key in AEAD mode, so clearing it here adds defence in depth.
    x.zeroize();

    output
}

/// Stateless `ChaCha20` XOR encryption / decryption.
///
/// Produces `input.len()` bytes of keystream starting at `counter` and
/// XORs them with `input`. Because the operation is symmetric, this
/// function is used for both `seal` (encryption) and `open` (decryption)
/// by [`ChaCha20Poly1305`].
///
/// The internal state is zeroized before returning — it contained the key
/// material that would otherwise persist on the stack.
fn chacha20_process_raw(
    key: &[u8; CHACHA_KEY_SIZE],
    nonce: &[u8; CHACHA_NONCE_SIZE],
    counter: u32,
    input: &[u8],
) -> Vec<u8> {
    let mut state = init_state(key, nonce, counter);
    let mut output = vec![0u8; input.len()];

    // Process full 64-byte blocks.
    let mut offset = 0;
    while offset < input.len() {
        let block = chacha20_block(&state);
        let remaining = input.len() - offset;
        let todo = if remaining < CHACHA_BLOCK_SIZE {
            remaining
        } else {
            CHACHA_BLOCK_SIZE
        };

        for i in 0..todo {
            output[offset + i] = input[offset + i] ^ block[i];
        }

        offset += todo;
        // Advance block counter (32-bit wrapping per C `input[12]++`).
        // Rule R6: explicit wrapping_add.
        state[12] = state[12].wrapping_add(1);
    }

    // Zeroize the state — it contains the key.
    state.zeroize();
    output
}

/// Builds the Poly1305 MAC input for `ChaCha20-Poly1305` AEAD per RFC 8439 §2.8.
///
/// The MAC input is constructed as:
///
/// ```text
/// mac_data = pad16(aad)
///         || pad16(ciphertext)
///         || le64(len(aad))
///         || le64(len(ciphertext))
/// ```
///
/// where `pad16(x)` is `x` followed by enough zero bytes to round the total
/// length up to a multiple of 16, and `le64(n)` is the 64-bit little-endian
/// encoding of `n`.
///
/// # Errors
///
/// Returns [`CryptoError::Common`](CryptoError::Common) wrapping
/// [`CommonError::ArithmeticOverflow`] if either length does not fit in a
/// `u64` (impossible on practical 64-bit platforms but checked per Rule R6).
fn build_poly1305_mac_input(aad: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // Rule R6: lossless cast via try_from, not `as`.
    let aad_len_u64 = u64::try_from(aad.len()).map_err(|_| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ChaCha20-Poly1305 AAD length exceeds u64::MAX",
        })
    })?;
    let ct_len_u64 = u64::try_from(ciphertext.len()).map_err(|_| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ChaCha20-Poly1305 ciphertext length exceeds u64::MAX",
        })
    })?;

    // Zero-padding to align each segment to a 16-byte boundary.
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;

    let capacity = aad.len() + aad_pad + ciphertext.len() + ct_pad + 16;
    let mut mac_input = Vec::with_capacity(capacity);

    mac_input.extend_from_slice(aad);
    mac_input.resize(mac_input.len() + aad_pad, 0u8);

    mac_input.extend_from_slice(ciphertext);
    mac_input.resize(mac_input.len() + ct_pad, 0u8);

    mac_input.extend_from_slice(&aad_len_u64.to_le_bytes());
    mac_input.extend_from_slice(&ct_len_u64.to_le_bytes());

    Ok(mac_input)
}

// =============================================================================
// ChaCha20 — 256-bit Stream Cipher
// =============================================================================

/// `ChaCha20` stream cipher (256-bit key, 96-bit nonce, 32-bit counter).
///
/// Translates `ChaCha20_ctr32` from `crypto/chacha/chacha_enc.c`.
///
/// The same [`process`](ChaCha20::process) operation is used for both
/// encryption and decryption (XOR is symmetric). Each instance maintains
/// an internal 512-bit state advancing its block counter as data is
/// processed, so `process` must be called in-order across the keystream.
///
/// # Security
///
/// Key material is zeroized on drop via [`ZeroizeOnDrop`]. For AEAD
/// operation with authentication, use [`ChaCha20Poly1305`] instead.
///
/// A `(key, nonce)` pair MUST NEVER be reused across independent messages —
/// the counter is per-block within one message, but a fresh random nonce
/// must be chosen per message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20 {
    /// 16 × u32 `ChaCha20` state (sigma | key | counter | nonce).
    ///
    /// Contains the full key material — zeroed on drop.
    state: [u32; 16],
}

impl ChaCha20 {
    /// Creates a new `ChaCha20` stream cipher with a fresh block counter of 0.
    ///
    /// # Arguments
    ///
    /// * `key`   — 32-byte (256-bit) secret key.
    /// * `nonce` — 12-byte (96-bit) nonce per RFC 8439.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key` is not exactly 32 bytes.
    /// Returns [`CryptoError::Common`] wrapping
    /// [`CommonError::InvalidArgument`] if `nonce` is not exactly 12 bytes.
    pub fn new(key: &[u8], nonce: &[u8]) -> CryptoResult<Self> {
        if key.len() != CHACHA_KEY_SIZE {
            return Err(CryptoError::Key(format!(
                "ChaCha20 requires exactly {CHACHA_KEY_SIZE}-byte key, got {}",
                key.len()
            )));
        }
        if nonce.len() != CHACHA_NONCE_SIZE {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "ChaCha20 requires exactly {CHACHA_NONCE_SIZE}-byte nonce, got {}",
                nonce.len()
            ))));
        }

        let mut key_arr = [0u8; CHACHA_KEY_SIZE];
        key_arr.copy_from_slice(key);
        let mut nonce_arr = [0u8; CHACHA_NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce);

        let state = init_state(&key_arr, &nonce_arr, 0);

        // Zero the byte copies now that the state has captured them.
        key_arr.zeroize();
        nonce_arr.zeroize();

        Ok(Self { state })
    }

    /// Streaming XOR encryption / decryption.
    ///
    /// Consumes the keystream at the current block-counter position and
    /// XORs it byte-wise with `data`, advancing the counter as needed.
    /// Because XOR is its own inverse, the same call performs both
    /// encryption and decryption when invoked with matching state.
    ///
    /// # Errors
    ///
    /// This function cannot fail in normal operation; the `CryptoResult`
    /// return type is kept for uniformity with the [`StreamCipher`] trait.
    pub fn process(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut output = vec![0u8; data.len()];
        let mut offset = 0;

        while offset < data.len() {
            let block = chacha20_block(&self.state);
            let remaining = data.len() - offset;
            let todo = if remaining < CHACHA_BLOCK_SIZE {
                remaining
            } else {
                CHACHA_BLOCK_SIZE
            };

            for i in 0..todo {
                output[offset + i] = data[offset + i] ^ block[i];
            }

            offset += todo;
            // Rule R6: wrapping_add matches C `input[12]++` semantics in
            // `ChaCha20_ctr32`. On 32-bit counter overflow the caller
            // is already far past safe usage (2^32 × 64 = 256 GiB per nonce).
            self.state[12] = self.state[12].wrapping_add(1);
        }

        Ok(output)
    }
}

/// Manual [`core::fmt::Debug`] — redacts key material.
///
/// The default derive would print the full 512-bit state (containing the
/// 256-bit key). Instead, we print only the type name.
impl core::fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

impl StreamCipher for ChaCha20 {
    fn process(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::process(self, data)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::ChaCha20
    }
}

// =============================================================================
// ChaCha20Poly1305 — AEAD (RFC 8439)
// =============================================================================

/// `ChaCha20-Poly1305` AEAD cipher (256-bit key, 96-bit nonce, 128-bit tag).
///
/// Combines the [`ChaCha20`] stream cipher with the Poly1305 one-time
/// authenticator per RFC 8439. This is one of the two standard AEAD
/// constructions for TLS 1.3 (alongside AES-GCM) and is particularly
/// well-suited for software implementations on platforms without
/// AES hardware acceleration.
///
/// # Construction (RFC 8439 §2.8)
///
/// 1. Derive one-time Poly1305 key = first 32 bytes of
///    `ChaCha20(key, nonce, counter=0)`.
/// 2. Encrypt the plaintext with `ChaCha20(key, nonce, counter=1)`.
/// 3. Compute `tag = Poly1305(poly_key, mac_input)` where
///    `mac_input = pad16(aad) || pad16(ct) || le64(|aad|) || le64(|ct|)`.
/// 4. Append the 16-byte tag to the ciphertext.
///
/// # Security
///
/// - The 256-bit key is zeroized on drop via [`ZeroizeOnDrop`].
/// - The Poly1305 one-time key is zeroized immediately after tag
///   computation.
/// - Tag verification in [`ChaCha20Poly1305::open`] uses
///   [`ConstantTimeEq`] to prevent timing attacks.
/// - Partial plaintext is zeroized before returning on authentication
///   failure.
/// - A `(key, nonce)` pair MUST NEVER be reused — nonce reuse breaks the
///   authenticity guarantee and leaks XOR of plaintexts.
#[derive(ZeroizeOnDrop)]
pub struct ChaCha20Poly1305 {
    /// 256-bit secret key — zeroized on drop.
    key: [u8; CHACHA_KEY_SIZE],
}

impl ChaCha20Poly1305 {
    /// Creates a new `ChaCha20-Poly1305` AEAD cipher context.
    ///
    /// # Arguments
    ///
    /// * `key` — 32-byte (256-bit) secret key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key` is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != CHACHA_KEY_SIZE {
            return Err(CryptoError::Key(format!(
                "ChaCha20-Poly1305 requires exactly {CHACHA_KEY_SIZE}-byte key, got {}",
                key.len()
            )));
        }
        let mut key_arr = [0u8; CHACHA_KEY_SIZE];
        key_arr.copy_from_slice(key);
        Ok(Self { key: key_arr })
    }

    /// Returns the authentication tag size in bytes (always 16).
    #[inline]
    pub const fn tag_length() -> usize {
        CHACHA_POLY1305_TAG_SIZE
    }

    /// Authenticated encryption with associated data (AEAD seal).
    ///
    /// Encrypts `plaintext` and authenticates it along with `aad`, producing
    /// `ciphertext || tag` where `tag` is 16 bytes.
    ///
    /// # Arguments
    ///
    /// * `nonce`     — 12-byte (96-bit) nonce. MUST be unique per `(key, message)`.
    /// * `aad`       — Additional authenticated data (not encrypted, only authenticated).
    /// * `plaintext` — Data to encrypt.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] wrapping
    /// [`CommonError::ArithmeticOverflow`] if AAD or plaintext length does
    /// not fit in a `u64` (per Rule R6). Forwards any error from the
    /// underlying Poly1305 computation.
    ///
    /// # Panics
    ///
    /// Does not panic under normal operation. Internal consistency is
    /// enforced by typed nonce sizing.
    pub fn seal_typed(
        &self,
        nonce: &[u8; CHACHA_NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Step 1: Derive the Poly1305 one-time key from ChaCha20 block 0
        //         (RFC 8439 §2.6). Only the first 32 bytes are used.
        let mut block0_state = init_state(&self.key, nonce, 0);
        let block0 = chacha20_block(&block0_state);
        block0_state.zeroize();

        let mut poly_key = [0u8; POLY1305_KEY_SIZE];
        poly_key.copy_from_slice(&block0[..POLY1305_KEY_SIZE]);

        // Step 2: Encrypt plaintext with ChaCha20 starting at counter = 1.
        let ciphertext = chacha20_process_raw(&self.key, nonce, 1, plaintext);

        // Step 3: Construct Poly1305 MAC input per RFC 8439 §2.8.
        let mac_input_result = build_poly1305_mac_input(aad, &ciphertext);
        let mac_input = match mac_input_result {
            Ok(m) => m,
            Err(e) => {
                poly_key.zeroize();
                return Err(e);
            }
        };

        // Step 4: Compute Poly1305 tag.
        let tag_result = mac_compute(MacType::Poly1305, &poly_key, &mac_input, None);
        // Zeroize the one-time key immediately — it is never reused.
        poly_key.zeroize();
        let tag = tag_result?;

        // Step 5: Append tag to ciphertext (seal output = ct || tag).
        let mut output = Vec::with_capacity(ciphertext.len() + tag.len());
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);
        Ok(output)
    }

    /// Authenticated decryption with associated data (AEAD open).
    ///
    /// Verifies the tag and decrypts `ciphertext_with_tag`. The input
    /// must be `ciphertext || tag` (tag = last 16 bytes). On successful
    /// verification, returns the decrypted plaintext.
    ///
    /// # Arguments
    ///
    /// * `nonce`               — 12-byte (96-bit) nonce (same as used to seal).
    /// * `aad`                 — Additional authenticated data (same as seal).
    /// * `ciphertext_with_tag` — `ciphertext || 16-byte tag`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] on authentication failure — the
    /// plaintext is NEVER returned in this case; any intermediate buffer
    /// containing recovered plaintext is zeroized before return.
    ///
    /// Returns [`CryptoError::Common`] wrapping
    /// [`CommonError::InvalidArgument`] if `ciphertext_with_tag` is shorter
    /// than the 16-byte tag.
    ///
    /// Returns [`CryptoError::Common`] wrapping
    /// [`CommonError::ArithmeticOverflow`] on length overflow (per Rule R6).
    pub fn open_typed(
        &self,
        nonce: &[u8; CHACHA_NONCE_SIZE],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Split off the 16-byte authentication tag.
        if ciphertext_with_tag.len() < CHACHA_POLY1305_TAG_SIZE {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "ChaCha20-Poly1305 open: input too short ({} < {CHACHA_POLY1305_TAG_SIZE})",
                ciphertext_with_tag.len()
            ))));
        }
        let split_at = ciphertext_with_tag.len() - CHACHA_POLY1305_TAG_SIZE;
        let (ciphertext, tag_in) = ciphertext_with_tag.split_at(split_at);

        // Derive the Poly1305 one-time key (same procedure as seal).
        let mut block0_state = init_state(&self.key, nonce, 0);
        let block0 = chacha20_block(&block0_state);
        block0_state.zeroize();

        let mut poly_key = [0u8; POLY1305_KEY_SIZE];
        poly_key.copy_from_slice(&block0[..POLY1305_KEY_SIZE]);

        // Compute the expected tag over (aad, ciphertext).
        let mac_input_result = build_poly1305_mac_input(aad, ciphertext);
        let mac_input = match mac_input_result {
            Ok(m) => m,
            Err(e) => {
                poly_key.zeroize();
                return Err(e);
            }
        };

        let expected_tag_result = mac_compute(MacType::Poly1305, &poly_key, &mac_input, None);
        poly_key.zeroize();
        let mut expected_tag = expected_tag_result?;

        // Constant-time tag comparison (CRITICAL — never use ==).
        let tag_ok = bool::from(expected_tag.ct_eq(tag_in));
        expected_tag.zeroize();

        if !tag_ok {
            return Err(CryptoError::Verification(
                "ChaCha20-Poly1305 authentication tag mismatch".to_string(),
            ));
        }

        // Tag verified — decrypt plaintext.
        // (If verification had failed, no plaintext would have been recovered.)
        let plaintext = chacha20_process_raw(&self.key, nonce, 1, ciphertext);
        Ok(plaintext)
    }
}

/// Manual [`core::fmt::Debug`] — redacts key material.
impl core::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

impl AeadCipher for ChaCha20Poly1305 {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr: &[u8; CHACHA_NONCE_SIZE] = nonce.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "ChaCha20-Poly1305 nonce must be exactly {CHACHA_NONCE_SIZE} bytes, got {}",
                nonce.len()
            )))
        })?;
        Self::seal_typed(self, nonce_arr, aad, plaintext)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr: &[u8; CHACHA_NONCE_SIZE] = nonce.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "ChaCha20-Poly1305 nonce must be exactly {CHACHA_NONCE_SIZE} bytes, got {}",
                nonce.len()
            )))
        })?;
        Self::open_typed(self, nonce_arr, aad, ciphertext_with_tag)
    }

    fn nonce_length(&self) -> usize {
        CHACHA_NONCE_SIZE
    }

    fn tag_length(&self) -> usize {
        CHACHA_POLY1305_TAG_SIZE
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::ChaCha20Poly1305
    }
}

// =============================================================================
// Tests — RFC 8439 Test Vectors
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "Cryptographic test vectors are inherently long, use single-letter names to match the RFCs they come from, and unwrap is acceptable in test code."
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Parse whitespace-tolerant hex into a `Vec<u8>`.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            clean.len() % 2 == 0,
            "hex_to_bytes: odd length {}",
            clean.len()
        );
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
        let v = hex_to_bytes(hex);
        assert_eq!(v.len(), N);
        let mut a = [0u8; N];
        a.copy_from_slice(&v);
        a
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn constants_match_rfc8439() {
        assert_eq!(CHACHA_BLOCK_SIZE, 64);
        assert_eq!(CHACHA_KEY_SIZE, 32);
        assert_eq!(CHACHA_NONCE_SIZE, 12);
        assert_eq!(CHACHA_NONCE_SIZE_LEGACY, 8);
        assert_eq!(CHACHA_POLY1305_TAG_SIZE, 16);
        assert_eq!(ChaCha20Poly1305::tag_length(), 16);
    }

    #[test]
    fn sigma_constant_is_expand_32_byte_k() {
        // "expand 32-byte k" in little-endian 32-bit words.
        // 'e','x','p','a' -> 0x61707865
        assert_eq!(SIGMA[0], 0x6170_7865);
        assert_eq!(SIGMA[1], 0x3320_646e);
        assert_eq!(SIGMA[2], 0x7962_2d32);
        assert_eq!(SIGMA[3], 0x6b20_6574);
    }

    // -------------------------------------------------------------------------
    // RFC 8439 §2.1.1 — Quarter Round on the ChaCha State
    // -------------------------------------------------------------------------

    #[test]
    fn rfc8439_section_2_1_1_quarter_round_on_state() {
        // Test quarter_round on indices (2, 7, 8, 13) of a full state.
        let mut state: [u32; 16] = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ];
        let expected: [u32; 16] = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
            0x2098d9d6, 0x91dbd320,
        ];
        quarter_round(&mut state, 2, 7, 8, 13);
        assert_eq!(state, expected, "quarter_round on state failed");
    }

    // -------------------------------------------------------------------------
    // RFC 8439 §2.3.2 — ChaCha20 Block Function Test Vector
    // -------------------------------------------------------------------------

    #[test]
    fn rfc8439_section_2_3_2_block_function() {
        let key: [u8; 32] = hex_to_array(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f \
             10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
        );
        let nonce: [u8; 12] = hex_to_array("00 00 00 09 00 00 00 4a 00 00 00 00");
        let counter: u32 = 1;

        let state = init_state(&key, &nonce, counter);
        let block = chacha20_block(&state);

        let expected = hex_to_bytes(
            "10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 \
             c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e \
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2 \
             b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e",
        );
        assert_eq!(&block[..], &expected[..], "chacha20_block RFC 8439 §2.3.2");
    }

    // -------------------------------------------------------------------------
    // RFC 8439 §2.4.2 — ChaCha20 Encryption Test Vector
    //
    //   Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer
    //               you only one tip for the future, sunscreen would be it."
    // -------------------------------------------------------------------------

    #[test]
    fn rfc8439_section_2_4_2_sunscreen_encryption() {
        let key: [u8; 32] = hex_to_array(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f \
             10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
        );
        let nonce: [u8; 12] = hex_to_array("00 00 00 00 00 00 00 4a 00 00 00 00");

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";

        // Encrypt with ChaCha20 starting at counter = 1 (per §2.4.2).
        let ciphertext = chacha20_process_raw(&key, &nonce, 1, plaintext);

        let expected = hex_to_bytes(
            "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 \
             e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b \
             f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 \
             16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 \
             07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e \
             52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 \
             5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 \
             87 4d",
        );
        assert_eq!(ciphertext, expected, "RFC 8439 §2.4.2 sunscreen ciphertext");

        // Decrypt (same function — XOR is symmetric).
        let recovered = chacha20_process_raw(&key, &nonce, 1, &ciphertext);
        assert_eq!(recovered.as_slice(), plaintext, "ChaCha20 round-trip");
    }

    #[test]
    fn chacha20_struct_streaming_matches_oneshot() {
        let key: [u8; 32] = hex_to_array(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f \
             10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
        );
        let nonce: [u8; 12] = hex_to_array("00 00 00 00 00 00 00 4a 00 00 00 00");

        // The public ChaCha20 struct starts at counter = 0, so for the
        // RFC 8439 §2.4.2 vector (which starts at counter = 1) we discard
        // the first 64 bytes of keystream by processing a 64-byte dummy.
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";

        let mut cipher = ChaCha20::new(&key, &nonce).unwrap();
        // Discard block 0.
        let _discard = cipher.process(&[0u8; 64]).unwrap();
        // Encrypt plaintext.
        let ciphertext = cipher.process(plaintext).unwrap();

        let expected = hex_to_bytes(
            "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 \
             e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b \
             f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 \
             16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 \
             07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e \
             52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 \
             5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 \
             87 4d",
        );
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn chacha20_process_partial_block_boundary() {
        // Verify that partial trailing blocks (< 64 bytes) are handled.
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let mut cipher = ChaCha20::new(&key, &nonce).unwrap();

        // 100 bytes — 1 full block + 36 bytes.
        let plaintext = vec![0x42u8; 100];
        let ciphertext = cipher.process(&plaintext).unwrap();
        assert_eq!(ciphertext.len(), 100);

        // Decrypt with fresh cipher — round trip should match.
        let mut decipher = ChaCha20::new(&key, &nonce).unwrap();
        let recovered = decipher.process(&ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chacha20_new_rejects_wrong_key_length() {
        let nonce = [0u8; 12];
        for bad_len in [0usize, 1, 16, 31, 33, 64] {
            let bad_key = vec![0u8; bad_len];
            let result = ChaCha20::new(&bad_key, &nonce);
            assert!(matches!(result, Err(CryptoError::Key(_))), "len {bad_len}");
        }
    }

    #[test]
    fn chacha20_new_rejects_wrong_nonce_length() {
        let key = [0u8; 32];
        for bad_len in [0usize, 1, 8, 11, 13, 16] {
            let bad_nonce = vec![0u8; bad_len];
            let result = ChaCha20::new(&key, &bad_nonce);
            assert!(
                matches!(
                    result,
                    Err(CryptoError::Common(CommonError::InvalidArgument(_)))
                ),
                "len {bad_len}"
            );
        }
    }

    #[test]
    fn chacha20_stream_trait_algorithm() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut cipher = ChaCha20::new(&key, &nonce).unwrap();
        assert_eq!(
            <ChaCha20 as StreamCipher>::algorithm(&cipher),
            CipherAlgorithm::ChaCha20
        );
        // Trait process() matches inherent process().
        let plaintext = b"hello";
        let ct_trait = <ChaCha20 as StreamCipher>::process(&mut cipher, plaintext).unwrap();
        let mut cipher2 = ChaCha20::new(&key, &nonce).unwrap();
        let ct_inherent = cipher2.process(plaintext).unwrap();
        assert_eq!(ct_trait, ct_inherent);
    }

    #[test]
    fn chacha20_debug_does_not_leak_key() {
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        let cipher = ChaCha20::new(&key, &nonce).unwrap();
        let dbg = format!("{cipher:?}");
        assert!(!dbg.contains("aa"));
        assert!(!dbg.contains("AA"));
        assert!(!dbg.contains("bb"));
        assert!(!dbg.contains("BB"));
        assert!(dbg.contains("ChaCha20"));
    }

    // -------------------------------------------------------------------------
    // RFC 8439 §2.8.2 — ChaCha20-Poly1305 AEAD Test Vector
    // -------------------------------------------------------------------------

    #[test]
    fn rfc8439_section_2_8_2_aead_seal() {
        let key: [u8; 32] = hex_to_array(
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f \
             90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        );
        let nonce: [u8; 12] = hex_to_array("07 00 00 00 40 41 42 43 44 45 46 47");
        let aad = hex_to_bytes("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = aead.seal_typed(&nonce, &aad, plaintext).unwrap();

        let expected_ct = hex_to_bytes(
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 \
             a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 \
             3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b \
             1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 \
             92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 \
             fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc \
             3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b \
             61 16",
        );
        let expected_tag = hex_to_bytes("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91");

        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        assert_eq!(ct, &expected_ct[..], "AEAD ciphertext");
        assert_eq!(tag, &expected_tag[..], "AEAD tag");
    }

    #[test]
    fn rfc8439_section_2_8_2_aead_open() {
        let key: [u8; 32] = hex_to_array(
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f \
             90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        );
        let nonce: [u8; 12] = hex_to_array("07 00 00 00 40 41 42 43 44 45 46 47");
        let aad = hex_to_bytes("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = aead.seal_typed(&nonce, &aad, plaintext).unwrap();
        let recovered = aead.open_typed(&nonce, &aad, &sealed).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn chacha20_poly1305_tamper_ciphertext_rejected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret message";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let mut sealed = aead.seal_typed(&nonce, aad, plaintext).unwrap();
        // Flip a bit inside the ciphertext (before the tag).
        sealed[0] ^= 0x01;
        let result = aead.open_typed(&nonce, aad, &sealed);
        assert!(matches!(result, Err(CryptoError::Verification(_))));
    }

    #[test]
    fn chacha20_poly1305_tamper_tag_rejected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret message";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let mut sealed = aead.seal_typed(&nonce, aad, plaintext).unwrap();
        // Flip a bit inside the tag (last 16 bytes).
        let last_idx = sealed.len() - 1;
        sealed[last_idx] ^= 0x01;
        let result = aead.open_typed(&nonce, aad, &sealed);
        assert!(matches!(result, Err(CryptoError::Verification(_))));
    }

    #[test]
    fn chacha20_poly1305_tamper_aad_rejected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad_seal = b"authentic header";
        let aad_open = b"tampered header";
        let plaintext = b"secret message";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = aead.seal_typed(&nonce, aad_seal, plaintext).unwrap();
        let result = aead.open_typed(&nonce, aad_open, &sealed);
        assert!(matches!(result, Err(CryptoError::Verification(_))));
    }

    #[test]
    fn chacha20_poly1305_wrong_nonce_rejected() {
        let key = [0x42u8; 32];
        let nonce_seal = [0x24u8; 12];
        let mut nonce_open = nonce_seal;
        nonce_open[0] ^= 0x01;
        let aad = b"header";
        let plaintext = b"secret message";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = aead.seal_typed(&nonce_seal, aad, plaintext).unwrap();
        let result = aead.open_typed(&nonce_open, aad, &sealed);
        assert!(matches!(result, Err(CryptoError::Verification(_))));
    }

    #[test]
    fn chacha20_poly1305_open_too_short() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        // Inputs shorter than the tag size are rejected with InvalidArgument.
        for short_len in [0usize, 1, 8, 15] {
            let result = aead.open_typed(&nonce, &[], &vec![0u8; short_len]);
            assert!(
                matches!(
                    result,
                    Err(CryptoError::Common(CommonError::InvalidArgument(_)))
                ),
                "short len {short_len}"
            );
        }
    }

    #[test]
    fn chacha20_poly1305_empty_plaintext_and_aad() {
        let key = [0x01u8; 32];
        let nonce = [0x02u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        let sealed = aead.seal_typed(&nonce, &[], &[]).unwrap();
        assert_eq!(sealed.len(), 16, "empty input -> just 16-byte tag");
        let recovered = aead.open_typed(&nonce, &[], &sealed).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn chacha20_poly1305_new_rejects_wrong_key_length() {
        for bad_len in [0usize, 1, 16, 31, 33, 64] {
            let bad_key = vec![0u8; bad_len];
            let result = ChaCha20Poly1305::new(&bad_key);
            assert!(matches!(result, Err(CryptoError::Key(_))), "len {bad_len}");
        }
    }

    // -------------------------------------------------------------------------
    // AeadCipher trait impl — byte-slice nonce entry points
    // -------------------------------------------------------------------------

    #[test]
    fn aead_trait_validates_nonce_length() {
        let key = [0x01u8; 32];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        // Wrong nonce length via trait interface returns InvalidArgument.
        let bad_nonce = [0u8; 8]; // legacy size, not RFC 8439
        let result = <ChaCha20Poly1305 as AeadCipher>::seal(&aead, &bad_nonce, &[], b"x");
        assert!(matches!(
            result,
            Err(CryptoError::Common(CommonError::InvalidArgument(_)))
        ));
        let result2 = <ChaCha20Poly1305 as AeadCipher>::open(&aead, &bad_nonce, &[], &[0u8; 20]);
        assert!(matches!(
            result2,
            Err(CryptoError::Common(CommonError::InvalidArgument(_)))
        ));
    }

    #[test]
    fn aead_trait_roundtrip_via_slice_nonce() {
        let key = [0x01u8; 32];
        let nonce = [0x02u8; 12];
        let aad = b"tls13-aad";
        let plaintext = b"payload over the wire";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = <ChaCha20Poly1305 as AeadCipher>::seal(&aead, &nonce, aad, plaintext).unwrap();
        let recovered =
            <ChaCha20Poly1305 as AeadCipher>::open(&aead, &nonce, aad, &sealed).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
        assert_eq!(
            <ChaCha20Poly1305 as AeadCipher>::nonce_length(&aead),
            CHACHA_NONCE_SIZE
        );
        assert_eq!(
            <ChaCha20Poly1305 as AeadCipher>::tag_length(&aead),
            CHACHA_POLY1305_TAG_SIZE
        );
        assert_eq!(
            <ChaCha20Poly1305 as AeadCipher>::algorithm(&aead),
            CipherAlgorithm::ChaCha20Poly1305
        );
    }

    #[test]
    fn chacha20_poly1305_debug_does_not_leak_key() {
        let key = [0xAAu8; 32];
        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let dbg = format!("{aead:?}");
        assert!(!dbg.contains("aa"));
        assert!(!dbg.contains("AA"));
        assert!(dbg.contains("ChaCha20Poly1305"));
    }

    // -------------------------------------------------------------------------
    // Poly1305 MAC input construction — RFC 8439 §2.8.1
    // -------------------------------------------------------------------------

    #[test]
    fn poly1305_mac_input_padding_aligned_boundaries() {
        // AAD = 16 bytes, ciphertext = 32 bytes — both already aligned,
        // zero pad bytes expected.
        let aad = vec![0xAAu8; 16];
        let ct = vec![0xCCu8; 32];
        let mac = build_poly1305_mac_input(&aad, &ct).unwrap();
        // Expected length = 16 + 0 + 32 + 0 + 8 + 8 = 64.
        assert_eq!(mac.len(), 64);
        // Trailing 16 bytes = le64(16) || le64(32).
        let tail = &mac[mac.len() - 16..];
        assert_eq!(&tail[0..8], &16u64.to_le_bytes());
        assert_eq!(&tail[8..16], &32u64.to_le_bytes());
    }

    #[test]
    fn poly1305_mac_input_padding_misaligned() {
        // Layout (positions):
        //   AAD    :  0..12   (12 bytes of 0xAA)
        //   AAD pad: 12..16   (4 zero bytes)
        //   CT     : 16..33   (17 bytes of 0xCC)
        //   CT pad : 33..48   (15 zero bytes)
        //   len AAD: 48..56   (le64(12))
        //   len CT : 56..64   (le64(17))
        let aad = vec![0xAAu8; 12];
        let ct = vec![0xCCu8; 17];
        let mac = build_poly1305_mac_input(&aad, &ct).unwrap();
        assert_eq!(mac.len(), 64);

        // AAD bytes preserved.
        for b in &mac[0..12] {
            assert_eq!(*b, 0xAA, "AAD must be preserved");
        }
        // AAD pad zeroes.
        for b in &mac[12..16] {
            assert_eq!(*b, 0, "AAD pad must be zero");
        }
        // CT bytes preserved.
        for b in &mac[16..33] {
            assert_eq!(*b, 0xCC, "CT must be preserved");
        }
        // CT pad zeroes.
        for b in &mac[33..48] {
            assert_eq!(*b, 0, "CT pad must be zero");
        }
        // Trailing length encoding.
        assert_eq!(&mac[48..56], &12u64.to_le_bytes());
        assert_eq!(&mac[56..64], &17u64.to_le_bytes());
    }

    #[test]
    fn poly1305_mac_input_empty() {
        // Both AAD and ciphertext empty — only two length words (16 bytes).
        let mac = build_poly1305_mac_input(&[], &[]).unwrap();
        assert_eq!(mac.len(), 16);
        assert_eq!(&mac[0..8], &0u64.to_le_bytes());
        assert_eq!(&mac[8..16], &0u64.to_le_bytes());
    }

    // -------------------------------------------------------------------------
    // Security — key zeroing on drop
    // -------------------------------------------------------------------------

    #[test]
    fn chacha20_zeroizes_state_on_drop() {
        // We can't observe post-drop memory directly, but we can verify the
        // Drop impl runs without panic. The ZeroizeOnDrop derive guarantees
        // the state array is cleared.
        let key = [0xFFu8; 32];
        let nonce = [0xEEu8; 12];
        {
            let _cipher = ChaCha20::new(&key, &nonce).unwrap();
        }
    }

    #[test]
    fn chacha20_poly1305_zeroizes_key_on_drop() {
        let key = [0xFFu8; 32];
        {
            let _aead = ChaCha20Poly1305::new(&key).unwrap();
        }
    }
}
