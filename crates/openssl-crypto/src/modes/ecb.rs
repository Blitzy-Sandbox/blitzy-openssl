//! Electronic Codebook (ECB) mode of operation — NIST SP 800-38A §6.1.
//!
//! Translates `crypto/modes/cbc128.c` (ECB path) and the ECB-style
//! wrappers spread across `crypto/aes/aes_ecb.c`,
//! `crypto/camellia/cmll_ecb.c`, etc.  ECB processes each block
//! independently, applying PKCS#7 padding on encryption and removing it
//! on decryption.
//!
//! **⚠ INSECURE:**  Identical plaintext blocks produce identical
//! ciphertext blocks, leaking structural patterns such as ECB penguin.
//! This mode is provided **only for legacy compatibility and algorithm
//! test vectors** — use CBC, CTR, or an AEAD mode for any real
//! application.

use crate::symmetric::{CipherDirection, SymmetricCipher};
use openssl_common::error::CryptoResult;

/// Nominal ECB block size (bytes).  Matches the 128-bit block cipher
/// default; for 64-bit ciphers callers should query
/// [`SymmetricCipher::block_size`] directly.
pub const ECB_BLOCK_SIZE: usize = 16;

/// Encrypt or decrypt a message using ECB mode.
///
/// PKCS#7 padding is applied on encryption and removed on decryption.
///
/// # Arguments
///
/// * `cipher`    — block cipher providing `encrypt_block` /
///   `decrypt_block`.
/// * `data`      — plaintext (encrypt) or ciphertext (decrypt).
/// * `direction` — [`CipherDirection::Encrypt`] or
///   [`CipherDirection::Decrypt`].
///
/// # Errors
///
/// Returns an error when decryption is requested and the data length is
/// not a multiple of the block size, when PKCS#7 padding is malformed,
/// or when the underlying block cipher fails.
pub fn ecb_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    crate::symmetric::ecb_encrypt(cipher, data, direction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_block_size_constant_is_16() {
        assert_eq!(ECB_BLOCK_SIZE, 16);
    }
}
