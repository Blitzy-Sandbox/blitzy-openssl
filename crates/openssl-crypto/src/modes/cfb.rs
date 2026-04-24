//! Cipher Feedback (CFB) mode of operation — NIST SP 800-38A §6.3.
//!
//! Translates `crypto/modes/cfb128.c`.  CFB turns a block cipher into a
//! self-synchronising stream cipher where each ciphertext block is fed
//! back through the cipher's forward encryption to produce the keystream
//! block for the next plaintext block.
//!
//! Only CFB128 (byte-wise, `s = b`) is exposed at this layer; CFB1 and
//! CFB8 are out of scope of the AAP.  The shared engine used here is
//! [`crate::symmetric::cfb_encrypt`].

use crate::symmetric::{CipherDirection, SymmetricCipher};
use openssl_common::error::CryptoResult;

/// Nominal CFB feedback register size (bytes).  CFB always operates on
/// blocks of the underlying cipher's block size; this constant matches
/// the 128-bit pathway used for AES, Camellia, ARIA, SEED, and SM4.
pub const CFB_BLOCK_SIZE: usize = 16;

/// Encrypt or decrypt a message using CFB mode.
///
/// # Arguments
///
/// * `cipher`    — block cipher providing `encrypt_block` (CFB never
///   invokes `decrypt_block` — the forward cipher is used in both
///   directions).
/// * `data`      — plaintext (encrypt) or ciphertext (decrypt).
/// * `iv`        — 16-byte initialisation vector.  Each `(key, iv)` pair
///   must be unique.
/// * `direction` — [`CipherDirection::Encrypt`] or
///   [`CipherDirection::Decrypt`].
///
/// # Errors
///
/// Returns an error when the IV length does not match the cipher's block
/// size or when the underlying block cipher fails.
pub fn cfb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    crate::symmetric::cfb_encrypt(cipher, data, iv, direction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfb_block_size_constant_is_16() {
        assert_eq!(CFB_BLOCK_SIZE, 16);
    }
}
