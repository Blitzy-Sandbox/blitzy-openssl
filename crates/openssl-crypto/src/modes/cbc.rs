//! Cipher Block Chaining (CBC) mode of operation — NIST SP 800-38A §6.2.
//!
//! Translates `crypto/modes/cbc128.c`.  CBC XORs each plaintext block
//! with the previous ciphertext block (or the IV for the first block)
//! before encrypting, chaining encryptions to diffuse patterns across
//! blocks.  PKCS#7 padding is applied on encryption and removed on
//! decryption.
//!
//! ## Security note
//!
//! CBC is **vulnerable to padding oracle attacks** when the caller
//! reveals whether unpadding succeeded or failed and an attacker can
//! submit chosen ciphertexts.  Prefer an AEAD mode (GCM, CCM, SIV) for
//! any application that does not need strict CBC wire-format
//! compatibility.  Lucky13-style timing side channels in the record
//! layer are discussed in `openssl-ssl::record`.

use crate::symmetric::{CipherDirection, SymmetricCipher};
use openssl_common::error::CryptoResult;

/// Nominal CBC block size (bytes) for 128-bit block ciphers.  For 64-bit
/// ciphers (DES, Blowfish, CAST5, IDEA, RC2, RC5) the actual block size
/// is 8; query [`SymmetricCipher::block_size`] at runtime for the
/// authoritative value.
pub const CBC_BLOCK_SIZE: usize = 16;

/// Encrypt or decrypt a message using CBC mode.
///
/// # Arguments
///
/// * `cipher`    — block cipher providing `encrypt_block` /
///   `decrypt_block`.
/// * `data`      — plaintext (encrypt) or ciphertext (decrypt).
/// * `iv`        — initialisation vector; length must equal the
///   cipher's block size.  Each `(key, iv)` pair must be unique for
///   confidentiality.
/// * `direction` — [`CipherDirection::Encrypt`] or
///   [`CipherDirection::Decrypt`].
///
/// # Errors
///
/// Returns an error when the IV length does not match the cipher's
/// block size, when decryption ciphertext length is not a multiple of
/// the block size, when PKCS#7 padding is malformed, or when the
/// underlying block cipher fails.
pub fn cbc_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    iv: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    crate::symmetric::cbc_encrypt(cipher, data, iv, direction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_block_size_constant_is_16() {
        assert_eq!(CBC_BLOCK_SIZE, 16);
    }
}
