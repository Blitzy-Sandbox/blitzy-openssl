//! Cryptographic hash function implementations.
//!
//! This module provides SHA-1 (legacy), SHA-2, SHA-3, and SHAKE hash functions,
//! along with MD5 and legacy hash algorithms in their respective submodules.

pub mod legacy;
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

// Re-export legacy hash algorithms (AAP §0.5.1 — MD2/MD4/MDC-2/RIPEMD-160/SM3/Whirlpool).
//
// R9 JUSTIFICATION for `#[allow(deprecated)]`:
//   The one-shot functions and `new()` constructors carry `#[deprecated]`
//   attributes because each algorithm is legacy-grade (MD2/MD4/MDC-2 are
//   cryptographically broken; RIPEMD-160/Whirlpool are obsolete; SM3 is a
//   regional standard with limited modern adoption). The public re-export is
//   required by AAP §0.5.1 which mandates translation of the corresponding
//   `crypto/{md2,md4,mdc2,ripemd,whrlpool,sm3}/*.c` C source. Callers will
//   still observe the `#[deprecated]` warning at their own call-sites; this
//   allow silences the warning *only* at the re-export boundary.
#[allow(deprecated)]
pub use legacy::{
    create_legacy_digest, md2, md4, ripemd160, sm3, whirlpool, LegacyAlgorithm, Md2Context,
    Md4Context, Ripemd160Context, Sm3Context, WhirlpoolContext,
};

// MDC-2 is constructed from DES; gate its re-exports behind the `des` feature.
#[cfg(feature = "des")]
#[allow(deprecated)]
pub use legacy::{mdc2, Mdc2Context};
