//! Cryptographic hash function implementations.
//!
//! This module provides SHA-1 (legacy), SHA-2, SHA-3, and SHAKE hash functions,
//! along with MD5 and legacy hash algorithms in their respective submodules.

pub mod sha;

// Re-export commonly used items from the sha module for convenience.
pub use sha::{
    create_sha_digest, Digest, KeccakState, Sha1Context, Sha256Context, Sha3Context, Sha512Context,
    ShaAlgorithm, ShakeContext,
};
