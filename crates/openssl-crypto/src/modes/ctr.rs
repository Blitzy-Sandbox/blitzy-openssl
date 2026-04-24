//! Counter (CTR) mode of operation — NIST SP 800-38A §6.5.
//!
//! Translates `crypto/modes/ctr128.c`.  In CTR mode the block cipher is
//! used to encrypt a sequence of counter values, producing a keystream
//! that is XOR-ed with the plaintext to form the ciphertext.  The same
//! keystream recovers the plaintext on decryption — CTR is a stream
//! cipher in which the forward block cipher is the only primitive invoked
//! in both directions.
//!
//! The concrete engine is implemented in
//! [`crate::symmetric::ctr_encrypt`] and is shared between AES, DES,
//! 3DES, Camellia, ARIA, SEED, SM4, and the other block ciphers in the
//! crate.  This module re-exports it on the stable `modes::ctr::` path
//! mandated by the AAP §0.4.1 crate layout.
//!
//! ## Security note
//!
//! **Never reuse the same `(key, nonce)` pair.**  Nonce reuse produces
//! the same keystream, enabling XOR recovery of plaintext from any two
//! ciphertexts.

use crate::symmetric::SymmetricCipher;
use openssl_common::error::CryptoResult;

/// Nominal CTR counter block size (bytes) for 128-bit block ciphers.
///
/// CTR mode operates with a counter whose width matches the block size of
/// the underlying cipher; for 64-bit legacy ciphers this value does not
/// apply.  Use [`SymmetricCipher::block_size`] at runtime for the
/// authoritative answer.
pub const CTR_BLOCK_SIZE: usize = 16;

/// Encrypt or decrypt a message using CTR mode.
///
/// CTR is symmetric: the same transformation recovers plaintext from
/// ciphertext when the same `nonce` is supplied.
///
/// # Arguments
///
/// * `cipher` — block cipher providing `encrypt_block`.
/// * `data`   — plaintext (encrypt) or ciphertext (decrypt).
/// * `nonce`  — counter block; length must equal the cipher's block
///   size.  Mutable counter state is maintained internally; callers are
///   responsible for nonce uniqueness per key.
///
/// # Errors
///
/// Returns an error when the nonce length does not match the cipher's
/// block size, or when the underlying block cipher fails.
pub fn ctr_encrypt<C: SymmetricCipher>(
    cipher: &C,
    data: &[u8],
    nonce: &[u8],
) -> CryptoResult<Vec<u8>> {
    crate::symmetric::ctr_encrypt(cipher, data, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_block_size_constant_is_16() {
        assert_eq!(CTR_BLOCK_SIZE, 16);
    }
}
