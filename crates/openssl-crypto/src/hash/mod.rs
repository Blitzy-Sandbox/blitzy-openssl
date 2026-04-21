//! Cryptographic hash function implementations.
//!
//! This module provides SHA-1 (legacy), SHA-2, SHA-3, and SHAKE hash functions,
//! along with MD5 and legacy hash algorithms in their respective submodules.

pub mod md5;
pub mod sha;

// Re-export commonly used items from the sha module for convenience.
pub use sha::{
    create_sha_digest, Digest, KeccakState, Sha1Context, Sha256Context, Sha3Context, Sha512Context,
    ShaAlgorithm, ShakeContext,
};

// Re-export MD5 types (legacy; still used by TLS 1.0/1.1 and SSLv3 composite digests).
#[allow(deprecated)]
pub use md5::{md5, Md5Context, Md5Sha1Context};
