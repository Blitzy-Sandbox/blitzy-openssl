//! Output Feedback (OFB) mode of operation — NIST SP 800-38A §6.4.
//!
//! Translates `crypto/modes/ofb128.c`.  OFB turns a block cipher into a
//! synchronous stream cipher by iteratively encrypting the feedback
//! register (initialised to the IV) and XOR-ing the resulting keystream
//! with plaintext.  Unlike CFB, the feedback input is the *output of the
//! cipher*, not the ciphertext, so a single-bit error propagates only
//! into one plaintext bit on decryption.
//!
//! OFB is symmetric: the same transformation recovers plaintext from
//! ciphertext when the same IV is supplied.

use crate::symmetric::SymmetricCipher;
use openssl_common::error::CryptoResult;

/// Nominal OFB feedback register size (bytes).
pub const OFB_BLOCK_SIZE: usize = 16;

/// Encrypt or decrypt a message using OFB mode.
///
/// OFB is symmetric: the same function recovers plaintext from
/// ciphertext when the same IV is supplied.
///
/// # Arguments
///
/// * `cipher` — block cipher providing `encrypt_block`.
/// * `data`   — plaintext (encrypt) or ciphertext (decrypt).
/// * `iv`     — initialisation vector; length must equal the cipher's
///   block size.  Each `(key, iv)` pair must be unique.
///
/// # Errors
///
/// Returns an error when the IV length does not match the cipher's
/// block size, or when the underlying block cipher fails.
pub fn ofb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
) -> CryptoResult<Vec<u8>> {
    crate::symmetric::ofb_encrypt(cipher, data, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofb_block_size_constant_is_16() {
        assert_eq!(OFB_BLOCK_SIZE, 16);
    }
}
