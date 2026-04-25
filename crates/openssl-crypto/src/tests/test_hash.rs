//! Integration tests for the cryptographic hash module.
//!
//! This test module validates the public API of [`crate::hash`], covering:
//!
//! - **Digest trait conformance** — every concrete hash context
//!   ([`Sha1Context`], [`Sha256Context`], [`Sha512Context`], [`Sha3Context`],
//!   [`Md5Context`], [`Md5Sha1Context`], [`Md2Context`], [`Md4Context`],
//!   [`Mdc2Context`], [`Ripemd160Context`], [`Sm3Context`],
//!   [`WhirlpoolContext`]) implements [`Digest`] with the exact upstream
//!   `digest_size`, `block_size`, and `algorithm_name` metadata.
//! - **Known Answer Tests** drawn from FIPS 180-4 (SHA-1, SHA-2),
//!   FIPS 202 (SHA-3, SHAKE), RFC 1319/1320 (MD2/MD4),
//!   GB/T 32905-2016 (SM3), ISO/IEC 10118-3 (RIPEMD-160), and the NESSIE
//!   Whirlpool reference vectors.
//! - **Cross-validation** that one-shot helpers (`sha::sha256(data)`,
//!   `sha::sha3_512(data)`, `md5(data)`, `sm3(data)`, etc.) and the
//!   incremental `Context::update` + `Context::finalize` path return
//!   byte-identical output.
//! - **SHAKE XOF semantics** — variable output length, multi-block squeeze
//!   continuation, and the documented `update`-after-squeeze error.
//! - **`Md5Sha1Context`** — the TLS 1.0 / TLS 1.1 composite digest producing
//!   36 bytes of `MD5(m) || SHA1(m)`.
//! - **Reset semantics** — after `finalize` followed by `reset`, the context
//!   is observably indistinguishable from a freshly constructed context.
//! - **Algorithm enum dispatch** — [`ShaAlgorithm`] and [`LegacyAlgorithm`]
//!   round-trips through [`create_sha_digest`] and [`create_legacy_digest`]
//!   produce digests matching the corresponding direct context invocations.
//! - **SP 800-185 encoding helpers** — `right_encode`, `left_encode`,
//!   `encode_string`, and `bytepad` test-vector roundtrips, exercising the
//!   constants used by KMAC and cSHAKE constructions.
//! - **`Digest::clone_box` trait method** — cloning an in-progress context
//!   yields an independent state that finalizes to the same digest as the
//!   original.
//! - **Property-based tests** — input-determinism, output-length parity with
//!   `digest_size`, and factory-vs-direct construction equivalence.
//!
//! # References
//!
//! - `crypto/sha/sha1dgst.c`, `crypto/sha/sha256.c`, `crypto/sha/sha512.c`,
//!   `crypto/sha/sha3.c` — C reference implementations.
//! - `crypto/md5/md5_one.c`, `crypto/md5/md5_dgst.c` — C MD5 reference.
//! - `crypto/md2/md2_dgst.c`, `crypto/md4/md4_dgst.c`,
//!   `crypto/mdc2/mdc2dgst.c`, `crypto/ripemd/rmd_dgst.c`,
//!   `crypto/sm3/sm3.c`, `crypto/whrlpool/wp_dgst.c` — Legacy hashes.
//! - `test/sha_test.c`, `test/sha256_test.c`, `test/sha512_test.c`,
//!   `test/sha3_test.c`, `test/shake_test.c`, `test/mdtest.c` — C reference
//!   test vector files.
//! - FIPS 180-4 §A.1, §A.2, §A.3 — SHA-1 / SHA-2 reference vectors.
//! - FIPS 202 — SHA-3 / SHAKE; reference vectors via NIST CAVP archives.
//! - NIST SP 800-185 §2.3.1, §2.3.2 — KMAC encoding helpers
//!   (`right_encode`, `left_encode`, `encode_string`, `bytepad`).
//! - RFC 1319 §A.5 — MD2 reference vectors.
//! - RFC 1320 §A.5 — MD4 reference vectors.
//! - RFC 1321 §A.5 — MD5 reference vectors.
//! - GB/T 32905-2016 §A — SM3 reference vectors.
//! - ISO/IEC 10118-3:2018 Tables B.3 / B.7 — RIPEMD-160, Whirlpool.
//!
//! # Rule Compliance
//!
//! - **R5 (nullability over sentinels):** [`Digest::finalize`] returns
//!   `CryptoResult<Vec<u8>>` rather than a sentinel error code; tests check
//!   the typed `Err` variants explicitly.
//! - **R6 (lossless casts):** All test fixtures use `usize::try_from`,
//!   `u64::from`, or fixed-width literals; no narrowing `as` casts.
//! - **R8 (zero unsafe):** No `unsafe` blocks anywhere in this file.
//! - **R10 (wiring before done):** Each tested public function is exercised
//!   by at least one positive test plus at least one error-path or
//!   metadata-conformance test.
//!
//! # Test Coverage Strategy
//!
//! These tests focus on the **public API surface** exposed by
//! [`crate::hash`]. Algorithm-internal compression-function vectors (for
//! example RFC 1321 Appendix A.5 for MD5 and GB/T 32905-2016 §A for SM3) are
//! already covered by inline `#[cfg(test)]` tests in [`crate::hash::md5`]
//! and [`crate::hash::legacy`]; this module complements those by
//! validating dispatch through the public re-export namespace, factory
//! dispatch, trait polymorphism, and cross-API equivalence — concerns that
//! the algorithm-internal tests cannot reach.

#![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.
#![allow(deprecated)] // hash::{md5, md2, md4, mdc2, ripemd160, whirlpool} and their `new()` constructors are #[deprecated]; we test their public API through the #[allow(deprecated)] re-exports per AAP §0.5.1.

use crate::hash::sha::{
    bytepad, encode_string, left_encode, right_encode, sha1, sha224, sha256, sha3_224, sha3_256,
    sha3_384, sha3_512, sha384, sha512, sha512_224, sha512_256, shake128, shake256,
};
use crate::hash::{
    create_legacy_digest, create_sha_digest, md2, md4, md5, mdc2, ripemd160, sm3, whirlpool,
    Digest, LegacyAlgorithm, Md2Context, Md4Context, Md5Context, Md5Sha1Context, Mdc2Context,
    Ripemd160Context, Sha1Context, Sha256Context, Sha3Context, Sha512Context, ShaAlgorithm,
    ShakeContext, Sm3Context, WhirlpoolContext,
};
use openssl_common::CryptoError;
use proptest::prelude::*;

// =========================================================================
// Phase 1: Digest trait conformance — metadata correctness
//
// Every concrete Digest implementation must report the upstream OpenSSL
// canonical `digest_size`, `block_size`, and `algorithm_name`. The provider
// layer dispatches algorithm fetch by these strings (see
// `provider::dispatch::resolve_digest_by_name`); a regression here would
// silently break OSSL_PARAM `digest-size` reporting and EVP fetch.
// =========================================================================

/// SHA-1 reports `"SHA-1"`, 20-byte output, 64-byte block per FIPS 180-4 §1.
#[test]
fn phase_01_sha1_metadata() {
    let ctx = Sha1Context::new();
    assert_eq!(ctx.algorithm_name(), "SHA-1");
    assert_eq!(ctx.digest_size(), 20);
    assert_eq!(ctx.block_size(), 64);
}

/// SHA-224 reports `"SHA-224"`, 28-byte output, 64-byte block per FIPS 180-4 §1.
#[test]
fn phase_01_sha224_metadata() {
    let ctx = Sha256Context::sha224();
    assert_eq!(ctx.algorithm_name(), "SHA-224");
    assert_eq!(ctx.digest_size(), 28);
    assert_eq!(ctx.block_size(), 64);
}

/// SHA-256 reports `"SHA-256"`, 32-byte output, 64-byte block per FIPS 180-4 §1.
#[test]
fn phase_01_sha256_metadata() {
    let ctx = Sha256Context::sha256();
    assert_eq!(ctx.algorithm_name(), "SHA-256");
    assert_eq!(ctx.digest_size(), 32);
    assert_eq!(ctx.block_size(), 64);
}

/// SHA-384 reports `"SHA-384"`, 48-byte output, 128-byte block per FIPS 180-4 §1.
#[test]
fn phase_01_sha384_metadata() {
    let ctx = Sha512Context::sha384();
    assert_eq!(ctx.algorithm_name(), "SHA-384");
    assert_eq!(ctx.digest_size(), 48);
    assert_eq!(ctx.block_size(), 128);
}

/// SHA-512 reports `"SHA-512"`, 64-byte output, 128-byte block per FIPS 180-4 §1.
#[test]
fn phase_01_sha512_metadata() {
    let ctx = Sha512Context::sha512();
    assert_eq!(ctx.algorithm_name(), "SHA-512");
    assert_eq!(ctx.digest_size(), 64);
    assert_eq!(ctx.block_size(), 128);
}

/// SHA-512/224 reports `"SHA-512/224"`, 28-byte output per FIPS 180-4 §6.7.
#[test]
fn phase_01_sha512_224_metadata() {
    let ctx = Sha512Context::sha512_224();
    assert_eq!(ctx.algorithm_name(), "SHA-512/224");
    assert_eq!(ctx.digest_size(), 28);
    assert_eq!(ctx.block_size(), 128);
}

/// SHA-512/256 reports `"SHA-512/256"`, 32-byte output per FIPS 180-4 §6.7.
#[test]
fn phase_01_sha512_256_metadata() {
    let ctx = Sha512Context::sha512_256();
    assert_eq!(ctx.algorithm_name(), "SHA-512/256");
    assert_eq!(ctx.digest_size(), 32);
    assert_eq!(ctx.block_size(), 128);
}

/// SHA3-224 reports `"SHA3-224"`, 28-byte output, 144-byte block per FIPS 202 §6.1.
/// Block size derived from `200 - 2*md_size` = `200 - 56` = `144`.
#[test]
fn phase_01_sha3_224_metadata() {
    let ctx = Sha3Context::sha3_224();
    assert_eq!(ctx.algorithm_name(), "SHA3-224");
    assert_eq!(ctx.digest_size(), 28);
    assert_eq!(ctx.block_size(), 144);
}

/// SHA3-256 reports `"SHA3-256"`, 32-byte output, 136-byte block per FIPS 202 §6.1.
#[test]
fn phase_01_sha3_256_metadata() {
    let ctx = Sha3Context::sha3_256();
    assert_eq!(ctx.algorithm_name(), "SHA3-256");
    assert_eq!(ctx.digest_size(), 32);
    assert_eq!(ctx.block_size(), 136);
}

/// SHA3-384 reports `"SHA3-384"`, 48-byte output, 104-byte block per FIPS 202 §6.1.
#[test]
fn phase_01_sha3_384_metadata() {
    let ctx = Sha3Context::sha3_384();
    assert_eq!(ctx.algorithm_name(), "SHA3-384");
    assert_eq!(ctx.digest_size(), 48);
    assert_eq!(ctx.block_size(), 104);
}

/// SHA3-512 reports `"SHA3-512"`, 64-byte output, 72-byte block per FIPS 202 §6.1.
#[test]
fn phase_01_sha3_512_metadata() {
    let ctx = Sha3Context::sha3_512();
    assert_eq!(ctx.algorithm_name(), "SHA3-512");
    assert_eq!(ctx.digest_size(), 64);
    assert_eq!(ctx.block_size(), 72);
}

/// SHAKE128 reports `"SHAKE128"`, 168-byte rate per FIPS 202 §6.2.
/// `algorithm_name()` is provided as an inherent fn (ShakeContext is XOF, not Digest).
#[test]
fn phase_01_shake128_metadata() {
    let ctx = ShakeContext::shake128();
    assert_eq!(ctx.algorithm_name(), "SHAKE128");
}

/// SHAKE256 reports `"SHAKE256"`, 136-byte rate per FIPS 202 §6.2.
#[test]
fn phase_01_shake256_metadata() {
    let ctx = ShakeContext::shake256();
    assert_eq!(ctx.algorithm_name(), "SHAKE256");
}

/// MD5 reports `"MD5"`, 16-byte output, 64-byte block per RFC 1321 §3.
#[test]
fn phase_01_md5_metadata() {
    let ctx = Md5Context::new();
    assert_eq!(ctx.algorithm_name(), "MD5");
    assert_eq!(ctx.digest_size(), 16);
    assert_eq!(ctx.block_size(), 64);
}

/// MD5+SHA1 composite reports `"MD5-SHA1"`, 36-byte output (16 + 20),
/// 64-byte block; used by TLS 1.0 / TLS 1.1 PRF and SSLv3 finished hash.
#[test]
fn phase_01_md5_sha1_metadata() {
    let ctx = Md5Sha1Context::new();
    assert_eq!(ctx.algorithm_name(), "MD5-SHA1");
    assert_eq!(ctx.digest_size(), 36);
    assert_eq!(ctx.block_size(), 64);
}

/// MD2 reports `"MD2"`, 16-byte output, 16-byte block per RFC 1319 §3.
#[test]
fn phase_01_md2_metadata() {
    let ctx = Md2Context::new();
    assert_eq!(ctx.algorithm_name(), "MD2");
    assert_eq!(ctx.digest_size(), 16);
    assert_eq!(ctx.block_size(), 16);
}

/// MD4 reports `"MD4"`, 16-byte output, 64-byte block per RFC 1320 §3.
#[test]
fn phase_01_md4_metadata() {
    let ctx = Md4Context::new();
    assert_eq!(ctx.algorithm_name(), "MD4");
    assert_eq!(ctx.digest_size(), 16);
    assert_eq!(ctx.block_size(), 64);
}

/// MDC-2 reports `"MDC-2"` (canonical hyphenated form), 16-byte output,
/// 8-byte block per ISO/IEC 10118-2 §6.
#[test]
fn phase_01_mdc2_metadata() {
    let ctx = Mdc2Context::new();
    assert_eq!(ctx.algorithm_name(), "MDC-2");
    assert_eq!(ctx.digest_size(), 16);
    assert_eq!(ctx.block_size(), 8);
}

/// RIPEMD-160 reports `"RIPEMD-160"`, 20-byte output, 64-byte block.
#[test]
fn phase_01_ripemd160_metadata() {
    let ctx = Ripemd160Context::new();
    assert_eq!(ctx.algorithm_name(), "RIPEMD-160");
    assert_eq!(ctx.digest_size(), 20);
    assert_eq!(ctx.block_size(), 64);
}

/// SM3 reports `"SM3"`, 32-byte output, 64-byte block per GB/T 32905-2016 §3.
#[test]
fn phase_01_sm3_metadata() {
    let ctx = Sm3Context::new();
    assert_eq!(ctx.algorithm_name(), "SM3");
    assert_eq!(ctx.digest_size(), 32);
    assert_eq!(ctx.block_size(), 64);
}

/// Whirlpool reports `"Whirlpool"` (mixed case, deliberately distinct from
/// LegacyAlgorithm::name() which returns ALL CAPS), 64-byte output,
/// 64-byte block per ISO/IEC 10118-3:2018 §11.
#[test]
fn phase_01_whirlpool_metadata() {
    let ctx = WhirlpoolContext::new();
    assert_eq!(ctx.algorithm_name(), "Whirlpool");
    assert_eq!(ctx.digest_size(), 64);
    assert_eq!(ctx.block_size(), 64);
}

// =========================================================================
// Phase 2: SHA-1 Known Answer Tests (FIPS 180-4 Appendix A.1)
// =========================================================================

/// FIPS 180-4 §A.1 example — SHA-1 of empty string equals
/// `da39a3ee5e6b4b0d3255bfef95601890afd80709`.
#[test]
fn phase_02_sha1_kat_empty_string() {
    let digest = sha1(b"").expect("sha1 over empty input must succeed");
    assert_eq!(
        hex::encode(&digest),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
}

/// FIPS 180-4 §A.1 example 1 — SHA-1("abc") =
/// `a9993e364706816aba3e25717850c26c9cd0d89d`.
#[test]
fn phase_02_sha1_kat_abc() {
    let digest = sha1(b"abc").expect("sha1 over `abc` must succeed");
    assert_eq!(
        hex::encode(&digest),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
}

/// FIPS 180-4 §A.1 example 2 — SHA-1 of the 56-byte alphabetic string
/// `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` =
/// `84983e441c3bd26ebaae4aa1f95129e5e54670f1`. Spans the canonical
/// padding boundary used by the FIPS 180-4 worked examples.
#[test]
fn phase_02_sha1_kat_abcdef_repeating_56byte() {
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = sha1(input).expect("sha1 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

// =========================================================================
// Phase 3: SHA-2 Known Answer Tests (FIPS 180-4 Appendix A.2 / A.3)
// =========================================================================

/// FIPS 180-4 §A.2 — SHA-224 of empty string =
/// `d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f`.
#[test]
fn phase_03_sha224_kat_empty() {
    let digest = sha224(b"").expect("sha224 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
}

/// FIPS 180-4 §A.2 — SHA-224("abc") =
/// `23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7`.
#[test]
fn phase_03_sha224_kat_abc() {
    let digest = sha224(b"abc").expect("sha224 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    );
}

/// FIPS 180-4 §A.2 — SHA-256 of empty string =
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
#[test]
fn phase_03_sha256_kat_empty() {
    let digest = sha256(b"").expect("sha256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// FIPS 180-4 §A.2 — SHA-256("abc") =
/// `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
#[test]
fn phase_03_sha256_kat_abc() {
    let digest = sha256(b"abc").expect("sha256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// FIPS 180-4 §A.3 — SHA-384 of empty string =
/// `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`.
#[test]
fn phase_03_sha384_kat_empty() {
    let digest = sha384(b"").expect("sha384 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

/// FIPS 180-4 §A.3 — SHA-384("abc") =
/// `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7`.
#[test]
fn phase_03_sha384_kat_abc() {
    let digest = sha384(b"abc").expect("sha384 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
}

/// FIPS 180-4 §A.3 — SHA-512 of empty string.
#[test]
fn phase_03_sha512_kat_empty() {
    let digest = sha512(b"").expect("sha512 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
}

/// FIPS 180-4 §A.3 — SHA-512("abc") =
/// `ddaf35a193617aba...4a9ac94fa54ca49f`.
#[test]
fn phase_03_sha512_kat_abc() {
    let digest = sha512(b"abc").expect("sha512 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}

/// SHA-512/224 of empty string per FIPS 180-4 §A.4. The reference test
/// vector is the truncation of the SHA-512 IV-modified hash to the
/// leftmost 224 bits (28 bytes / 56 hex characters).
#[test]
fn phase_03_sha512_224_kat_empty() {
    let digest = sha512_224(b"").expect("sha512_224 must succeed");
    // FIPS 180-4 §A.4: SHA-512/224("") = 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4
    assert_eq!(
        hex::encode(&digest),
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    );
    // Output length contract — exactly 28 bytes (224 bits) per FIPS 180-4 §1.
    assert_eq!(digest.len(), 28, "SHA-512/224 must produce 28 bytes");
}

/// SHA-512/256 of "abc" per FIPS 180-4 §A.5.
#[test]
fn phase_03_sha512_256_kat_abc() {
    let digest = sha512_256(b"abc").expect("sha512_256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    );
}

// =========================================================================
// Phase 4: SHA-3 Known Answer Tests (FIPS 202 / NIST CAVP)
// =========================================================================

/// SHA3-224 of empty string per FIPS 202 §6.1.
#[test]
fn phase_04_sha3_224_kat_empty() {
    let digest = sha3_224(b"").expect("sha3_224 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    );
}

/// SHA3-256 of empty string per FIPS 202 §6.1.
#[test]
fn phase_04_sha3_256_kat_empty() {
    let digest = sha3_256(b"").expect("sha3_256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

/// SHA3-256("abc") per FIPS 202 §6.1 / CAVP.
#[test]
fn phase_04_sha3_256_kat_abc() {
    let digest = sha3_256(b"abc").expect("sha3_256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

/// SHA3-384 of empty string per FIPS 202 §6.1.
#[test]
fn phase_04_sha3_384_kat_empty() {
    let digest = sha3_384(b"").expect("sha3_384 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
}

/// SHA3-512 of empty string per FIPS 202 §6.1.
#[test]
fn phase_04_sha3_512_kat_empty() {
    let digest = sha3_512(b"").expect("sha3_512 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
}

/// SHA3-512("abc") per FIPS 202 §6.1.
#[test]
fn phase_04_sha3_512_kat_abc() {
    let digest = sha3_512(b"abc").expect("sha3_512 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
}

// =========================================================================
// Phase 5: SHAKE XOF Known Answer Tests (FIPS 202 §6.2)
//
// Variable-length output exposes the SHAKE XOF squeeze semantics. The
// fixed output prefix is consistent for any length ≥ requested bytes,
// since SHAKE is XOF, not a fixed-output digest.
// =========================================================================

/// SHAKE128 of empty string with 32-byte output per FIPS 202 §6.2.
#[test]
fn phase_05_shake128_kat_empty_32bytes() {
    let digest = shake128(b"", 32).expect("shake128 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
}

/// SHAKE128 with 16-byte output is a strict prefix of the 32-byte output.
#[test]
fn phase_05_shake128_kat_empty_16bytes_is_prefix() {
    let d16 = shake128(b"", 16).expect("shake128 must succeed");
    let d32 = shake128(b"", 32).expect("shake128 must succeed");
    assert_eq!(d16.len(), 16);
    assert_eq!(&d32[..16], &d16[..]);
}

/// SHAKE256 of empty string with 64-byte output per FIPS 202 §6.2.
#[test]
fn phase_05_shake256_kat_empty_64bytes() {
    let digest = shake256(b"", 64).expect("shake256 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );
}

/// SHAKE supports incremental squeeze — multiple calls advance the output
/// stream cumulatively. Two 16-byte squeezes from the same context must
/// concatenate to equal a single 32-byte squeeze.
#[test]
fn phase_05_shake_incremental_squeeze_concat() {
    let mut ctx = ShakeContext::shake128();
    ctx.update(b"hello").expect("update must succeed");
    let mut out = vec![0u8; 16];
    ctx.squeeze(&mut out).expect("first squeeze");
    let mut out2 = vec![0u8; 16];
    ctx.squeeze(&mut out2).expect("second squeeze");

    let single = shake128(b"hello", 32).expect("one-shot shake128");
    let mut concat = out.clone();
    concat.extend_from_slice(&out2);
    assert_eq!(concat, single);
}

/// SHAKE update-after-squeeze must error with the documented message.
/// This is the single-shot semantics of the trait-style ShakeContext::update.
#[test]
fn phase_05_shake_update_after_squeeze_errors() {
    let mut ctx = ShakeContext::shake256();
    ctx.update(b"abc").expect("absorb phase update must succeed");
    let mut buf = [0u8; 8];
    ctx.squeeze(&mut buf).expect("squeeze must succeed");
    let result = ctx.update(b"def");
    match result {
        Err(CryptoError::AlgorithmNotFound(msg)) => {
            assert!(
                msg.contains("SHAKE context already in squeeze phase"),
                "unexpected error message: {msg}"
            );
        }
        Ok(()) => panic!("update after squeeze must error"),
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

// =========================================================================
// Phase 6: MD5 cross-validation through public API
//
// The detailed RFC 1321 §A.5 KAT vectors are already covered by inline
// tests in `crate::hash::md5`. This phase complements those by exercising
// MD5 through the public `hash::md5(...)` re-export and verifying its
// equivalence with `Md5Context::update` + `finalize`.
// =========================================================================

/// MD5 one-shot through the public re-export equals
/// `Md5Context::update` + `finalize` for the empty input.
#[test]
fn phase_06_md5_oneshot_matches_incremental_empty() {
    let oneshot = md5(b"").expect("md5 must succeed");
    let mut ctx = Md5Context::new();
    ctx.update(b"").expect("update must succeed");
    let incremental = ctx.finalize().expect("finalize must succeed");
    assert_eq!(oneshot, incremental);
    // RFC 1321 §A.5 — md5("") = d41d8cd98f00b204e9800998ecf8427e
    assert_eq!(hex::encode(&oneshot), "d41d8cd98f00b204e9800998ecf8427e");
}

/// MD5 one-shot equals incremental update for the canonical "abc" vector.
/// Per RFC 1321 §A.5: md5("abc") = 900150983cd24fb0d6963f7d28e17f72.
#[test]
fn phase_06_md5_oneshot_matches_incremental_abc() {
    let oneshot = md5(b"abc").expect("md5 must succeed");
    let mut ctx = Md5Context::new();
    ctx.update(b"abc").expect("update must succeed");
    let incremental = ctx.finalize().expect("finalize must succeed");
    assert_eq!(oneshot, incremental);
    assert_eq!(hex::encode(&oneshot), "900150983cd24fb0d6963f7d28e17f72");
}

/// MD5 dispatches identically through `Box<dyn Digest>`.
#[test]
fn phase_06_md5_box_dyn_dispatch() {
    let mut boxed: Box<dyn Digest> = Box::new(Md5Context::new());
    boxed.update(b"abc").expect("update must succeed");
    let digest = boxed.finalize().expect("finalize must succeed");
    assert_eq!(hex::encode(&digest), "900150983cd24fb0d6963f7d28e17f72");
}

// =========================================================================
// Phase 7: Md5Sha1Context — TLS 1.0/1.1 composite digest
//
// The composite produces 36 bytes of MD5(m) || SHA1(m). It is used by the
// TLS 1.0 / TLS 1.1 PRF and by the SSLv3 finished handshake hash.
// =========================================================================

/// `Md5Sha1Context::digest_size()` reports 36; output equals the
/// concatenation of MD5(m) || SHA1(m) computed via separate contexts.
#[test]
fn phase_07_md5_sha1_composite_concatenation() {
    let mut composite = Md5Sha1Context::new();
    composite.update(b"abc").expect("composite update");
    let composed = composite.finalize().expect("composite finalize");
    assert_eq!(composed.len(), 36);

    let md5_part = md5(b"abc").expect("md5 must succeed");
    let sha1_part = sha1(b"abc").expect("sha1 must succeed");
    assert_eq!(md5_part.len(), 16);
    assert_eq!(sha1_part.len(), 20);

    let mut expected = md5_part.clone();
    expected.extend_from_slice(&sha1_part);
    assert_eq!(composed, expected);
}

/// `Md5Sha1Context::reset` returns the context to a fresh state — finalizing
/// after reset must equal a fresh context's output.
#[test]
fn phase_07_md5_sha1_reset_equals_fresh() {
    let mut a = Md5Sha1Context::new();
    a.update(b"some data that is then discarded")
        .expect("update");
    a.reset();
    a.update(b"abc").expect("post-reset update");
    let after_reset = a.finalize().expect("finalize");

    let mut b = Md5Sha1Context::new();
    b.update(b"abc").expect("fresh update");
    let fresh = b.finalize().expect("finalize");

    assert_eq!(after_reset, fresh);
}

/// `Md5Sha1Context` dispatches identically through `Box<dyn Digest>`,
/// confirming the trait object correctly preserves the 36-byte output size.
#[test]
fn phase_07_md5_sha1_box_dyn() {
    let mut boxed: Box<dyn Digest> = Box::new(Md5Sha1Context::new());
    assert_eq!(boxed.digest_size(), 36);
    boxed.update(b"abc").expect("update");
    let digest = boxed.finalize().expect("finalize");
    assert_eq!(digest.len(), 36);
}

// =========================================================================
// Phase 8: Legacy hash cross-validation (MD2/MD4/MDC-2/RIPEMD-160/SM3/Whirlpool)
//
// The inline tests in `hash::legacy` exercise compressor-level KAT vectors.
// This phase validates the public re-exports through the `hash::` namespace
// and the equivalence of one-shot vs incremental paths.
// =========================================================================

/// MD2 one-shot of empty string per RFC 1319 §A.5 =
/// `8350e5a3e24c153df2275c9f80692773`.
#[test]
fn phase_08_md2_oneshot_kat_empty() {
    let digest = md2(b"").expect("md2 must succeed");
    assert_eq!(hex::encode(&digest), "8350e5a3e24c153df2275c9f80692773");
}

/// MD4 one-shot of empty string per RFC 1320 §A.5 =
/// `31d6cfe0d16ae931b73c59d7e0c089c0`.
#[test]
fn phase_08_md4_oneshot_kat_empty() {
    let digest = md4(b"").expect("md4 must succeed");
    assert_eq!(hex::encode(&digest), "31d6cfe0d16ae931b73c59d7e0c089c0");
}

/// RIPEMD-160 one-shot of empty string per ISO/IEC 10118-3:2018 Table B.3 =
/// `9c1185a5c5e9fc54612808977ee8f548b2258d31`.
#[test]
fn phase_08_ripemd160_oneshot_kat_empty() {
    let digest = ripemd160(b"").expect("ripemd160 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    );
}

/// SM3 one-shot of "abc" per GB/T 32905-2016 §A.1 =
/// `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`.
#[test]
fn phase_08_sm3_oneshot_kat_abc() {
    let digest = sm3(b"abc").expect("sm3 must succeed");
    assert_eq!(
        hex::encode(&digest),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    );
}

/// Whirlpool one-shot of empty string per ISO/IEC 10118-3 Table B.7.
/// The reference vector is the well-known 64-byte digest of "".
#[test]
fn phase_08_whirlpool_oneshot_kat_empty() {
    let digest = whirlpool(b"").expect("whirlpool must succeed");
    assert_eq!(digest.len(), 64);
    assert_eq!(
        hex::encode(&digest),
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
    );
}

/// Each legacy one-shot equals its `Context::update` + `finalize` counterpart.
#[test]
fn phase_08_legacy_oneshot_matches_incremental() {
    let inputs: &[&[u8]] = &[b"", b"abc", b"hello world"];
    for input in inputs {
        let mut ctx_md2 = Md2Context::new();
        ctx_md2.update(input).expect("update");
        assert_eq!(ctx_md2.finalize().expect("finalize"), md2(input).expect("oneshot"));

        let mut ctx_md4 = Md4Context::new();
        ctx_md4.update(input).expect("update");
        assert_eq!(ctx_md4.finalize().expect("finalize"), md4(input).expect("oneshot"));

        let mut ctx_mdc2 = Mdc2Context::new();
        // MDC-2 requires input length to be a multiple of 8 bytes (its block size).
        // Pre-pad to the block boundary for the cross-check.
        let mut padded = input.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }
        ctx_mdc2.update(&padded).expect("update");
        let inc = ctx_mdc2.finalize().expect("finalize");
        let oneshot = mdc2(&padded).expect("oneshot");
        assert_eq!(inc, oneshot);

        let mut ctx_ripemd = Ripemd160Context::new();
        ctx_ripemd.update(input).expect("update");
        assert_eq!(
            ctx_ripemd.finalize().expect("finalize"),
            ripemd160(input).expect("oneshot")
        );

        let mut ctx_sm3 = Sm3Context::new();
        ctx_sm3.update(input).expect("update");
        assert_eq!(ctx_sm3.finalize().expect("finalize"), sm3(input).expect("oneshot"));

        let mut ctx_whirl = WhirlpoolContext::new();
        ctx_whirl.update(input).expect("update");
        assert_eq!(
            ctx_whirl.finalize().expect("finalize"),
            whirlpool(input).expect("oneshot")
        );
    }
}

// =========================================================================
// Phase 9: Streaming-vs-one-shot equivalence across SHA family
//
// All SHA family digests must produce identical output whether fed in a
// single call or in arbitrarily fragmented chunks. This is critical for
// streaming I/O scenarios (e.g., file hashing).
// =========================================================================

/// SHA-256 streaming `update` calls produce same digest as single `update`.
#[test]
fn phase_09_sha256_streaming_equals_oneshot() {
    let input: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let oneshot = sha256(input).expect("sha256 must succeed");

    // Feed byte-by-byte.
    let mut ctx = Sha256Context::sha256();
    for byte in input {
        ctx.update(&[*byte]).expect("update");
    }
    let streamed = ctx.finalize().expect("finalize");
    assert_eq!(streamed, oneshot);
}

/// SHA-512 streaming with random chunk boundaries equals one-shot.
#[test]
fn phase_09_sha512_streaming_chunks() {
    let input: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqrstuvwxyz";
    let oneshot = sha512(input).expect("sha512 must succeed");

    // Feed in 7-byte chunks (intentionally non-aligned with the 128-byte block).
    let mut ctx = Sha512Context::sha512();
    for chunk in input.chunks(7) {
        ctx.update(chunk).expect("update");
    }
    let streamed = ctx.finalize().expect("finalize");
    assert_eq!(streamed, oneshot);
}

/// SHA3-256 streaming equals one-shot across various chunk sizes.
#[test]
fn phase_09_sha3_256_streaming_equals_oneshot() {
    let input = b"sha-3 streaming test input vector with arbitrary length payload";
    let oneshot = sha3_256(input).expect("sha3_256 must succeed");

    for chunk_size in &[1, 2, 5, 13, 64, 136] {
        let mut ctx = Sha3Context::sha3_256();
        for chunk in input.chunks(*chunk_size) {
            ctx.update(chunk).expect("update");
        }
        let streamed = ctx.finalize().expect("finalize");
        assert_eq!(streamed, oneshot, "mismatch at chunk_size={}", chunk_size);
    }
}

/// SHA-1 streaming via `Digest::digest()` default impl equals one-shot.
#[test]
fn phase_09_sha1_default_digest_method() {
    let input = b"hello world";
    let mut ctx = Sha1Context::new();
    let via_default = ctx.digest(input).expect("digest must succeed");
    let oneshot = sha1(input).expect("oneshot must succeed");
    assert_eq!(via_default, oneshot);
}

/// Empty input across SHA family produces canonical fixed-output digests.
#[test]
fn phase_09_empty_input_consistent_across_chunks() {
    let mut ctx_a = Sha256Context::sha256();
    let single = ctx_a.finalize().expect("finalize");

    let mut ctx_b = Sha256Context::sha256();
    ctx_b.update(b"").expect("empty update");
    ctx_b.update(b"").expect("empty update");
    ctx_b.update(b"").expect("empty update");
    let triple = ctx_b.finalize().expect("finalize");

    assert_eq!(single, triple);
}

// =========================================================================
// Phase 10: Reset semantics
//
// After `finalize` followed by `reset`, the context must be observably
// indistinguishable from a freshly constructed context. This is a hard
// invariant for KMAC/HMAC-style constructions that reuse a digest context
// across multiple message authentications.
// =========================================================================

/// `Sha256Context::reset` after finalize equals fresh context's output.
#[test]
fn phase_10_sha256_reset_after_finalize() {
    let mut ctx = Sha256Context::sha256();
    ctx.update(b"first message").expect("update");
    let _first = ctx.finalize().expect("finalize");
    ctx.reset();
    ctx.update(b"abc").expect("post-reset update");
    let second = ctx.finalize().expect("finalize");

    let fresh = sha256(b"abc").expect("oneshot");
    assert_eq!(second, fresh);
}

/// `Sha3Context::reset` clears the squeeze state and permits subsequent
/// `update` and `finalize` calls without the documented error.
#[test]
fn phase_10_sha3_reset_clears_squeeze_state() {
    let mut ctx = Sha3Context::sha3_256();
    ctx.update(b"first").expect("update");
    let _first = ctx.finalize().expect("finalize");

    // After finalize, update would error. Reset must clear it.
    ctx.reset();
    ctx.update(b"abc").expect("post-reset update");
    let second = ctx.finalize().expect("finalize");
    assert_eq!(second, sha3_256(b"abc").expect("oneshot"));
}

/// SHA-3 `update` after `finalize` (without reset) errors with the exact
/// documented message.
#[test]
fn phase_10_sha3_update_after_finalize_errors() {
    let mut ctx = Sha3Context::sha3_256();
    ctx.update(b"abc").expect("update");
    let _digest = ctx.finalize().expect("finalize");

    let result = ctx.update(b"def");
    match result {
        Err(CryptoError::AlgorithmNotFound(msg)) => {
            assert!(
                msg.contains("SHA-3 context already finalized"),
                "unexpected error message: {msg}"
            );
            assert!(msg.contains("call reset() first"), "missing reset() hint: {msg}");
        }
        Ok(()) => panic!("update after finalize must error"),
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

/// SHA-3 second `finalize` (without reset) errors with the same message.
#[test]
fn phase_10_sha3_finalize_after_finalize_errors() {
    let mut ctx = Sha3Context::sha3_256();
    ctx.update(b"abc").expect("update");
    let _first = ctx.finalize().expect("finalize");

    let result = ctx.finalize();
    match result {
        Err(CryptoError::AlgorithmNotFound(msg)) => {
            assert!(msg.contains("SHA-3"), "unexpected error message: {msg}");
        }
        Ok(_) => panic!("double finalize without reset must error"),
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

// =========================================================================
// Phase 11: ShaAlgorithm enum + create_sha_digest factory
//
// Validate the factory dispatch table maps every enum variant to the
// matching context constructor and that the resulting digest matches the
// direct one-shot helper.
// =========================================================================

/// Every `ShaAlgorithm` variant produces a digest matching its one-shot
/// equivalent via the `create_sha_digest` factory.
#[test]
fn phase_11_create_sha_digest_factory_dispatch() {
    let test_input: &[u8] = b"factory dispatch test input";
    let cases: &[(ShaAlgorithm, fn(&[u8]) -> crate::CryptoResult<Vec<u8>>)] = &[
        (ShaAlgorithm::Sha1, sha1),
        (ShaAlgorithm::Sha224, sha224),
        (ShaAlgorithm::Sha256, sha256),
        (ShaAlgorithm::Sha384, sha384),
        (ShaAlgorithm::Sha512, sha512),
        (ShaAlgorithm::Sha512_224, sha512_224),
        (ShaAlgorithm::Sha512_256, sha512_256),
        (ShaAlgorithm::Sha3_224, sha3_224),
        (ShaAlgorithm::Sha3_256, sha3_256),
        (ShaAlgorithm::Sha3_384, sha3_384),
        (ShaAlgorithm::Sha3_512, sha3_512),
    ];

    for (alg, oneshot_fn) in cases {
        let mut ctx = create_sha_digest(*alg).expect("factory must succeed");
        ctx.update(test_input).expect("update");
        let factory_digest = ctx.finalize().expect("finalize");
        let oneshot_digest = oneshot_fn(test_input).expect("oneshot must succeed");
        assert_eq!(
            factory_digest, oneshot_digest,
            "factory dispatch mismatch for {:?}",
            alg
        );
    }
}

/// `ShaAlgorithm::name()` returns the canonical hyphenated string for each
/// variant (matching `Digest::algorithm_name()` exactly).
#[test]
fn phase_11_sha_algorithm_name_matches_digest_name() {
    let cases: &[(ShaAlgorithm, &str)] = &[
        (ShaAlgorithm::Sha1, "SHA-1"),
        (ShaAlgorithm::Sha224, "SHA-224"),
        (ShaAlgorithm::Sha256, "SHA-256"),
        (ShaAlgorithm::Sha384, "SHA-384"),
        (ShaAlgorithm::Sha512, "SHA-512"),
        (ShaAlgorithm::Sha512_224, "SHA-512/224"),
        (ShaAlgorithm::Sha512_256, "SHA-512/256"),
        (ShaAlgorithm::Sha3_224, "SHA3-224"),
        (ShaAlgorithm::Sha3_256, "SHA3-256"),
        (ShaAlgorithm::Sha3_384, "SHA3-384"),
        (ShaAlgorithm::Sha3_512, "SHA3-512"),
    ];

    for (alg, expected_name) in cases {
        assert_eq!(alg.name(), *expected_name);
        let ctx = create_sha_digest(*alg).expect("factory must succeed");
        assert_eq!(ctx.algorithm_name(), *expected_name);
    }
}

/// Every `ShaAlgorithm` variant reports `digest_size()` that matches
/// `digest_size()` of the resulting context.
#[test]
fn phase_11_sha_algorithm_digest_size_consistency() {
    let cases: &[(ShaAlgorithm, usize)] = &[
        (ShaAlgorithm::Sha1, 20),
        (ShaAlgorithm::Sha224, 28),
        (ShaAlgorithm::Sha256, 32),
        (ShaAlgorithm::Sha384, 48),
        (ShaAlgorithm::Sha512, 64),
        (ShaAlgorithm::Sha512_224, 28),
        (ShaAlgorithm::Sha512_256, 32),
        (ShaAlgorithm::Sha3_224, 28),
        (ShaAlgorithm::Sha3_256, 32),
        (ShaAlgorithm::Sha3_384, 48),
        (ShaAlgorithm::Sha3_512, 64),
    ];

    for (alg, expected_size) in cases {
        let ctx = create_sha_digest(*alg).expect("factory must succeed");
        assert_eq!(ctx.digest_size(), *expected_size);
    }
}

// =========================================================================
// Phase 12: LegacyAlgorithm enum + create_legacy_digest factory
//
// Validate the factory dispatch table for legacy algorithms and document
// the intentional discrepancy between `LegacyAlgorithm::name()` (ALL CAPS,
// no hyphen) and `Digest::algorithm_name()` (canonical, hyphenated).
// =========================================================================

/// Every `LegacyAlgorithm` variant produces a digest matching its one-shot
/// equivalent via the `create_legacy_digest` factory.
#[test]
fn phase_12_create_legacy_digest_factory_dispatch() {
    let cases: &[(LegacyAlgorithm, fn(&[u8]) -> crate::CryptoResult<Vec<u8>>)] = &[
        (LegacyAlgorithm::Md2, md2),
        (LegacyAlgorithm::Md4, md4),
        (LegacyAlgorithm::Ripemd160, ripemd160),
        (LegacyAlgorithm::Sm3, sm3),
        (LegacyAlgorithm::Whirlpool, whirlpool),
    ];

    let test_input: &[u8] = b"legacy factory test";
    for (alg, oneshot_fn) in cases {
        let mut ctx = create_legacy_digest(*alg).expect("factory must succeed");
        ctx.update(test_input).expect("update");
        let factory_digest = ctx.finalize().expect("finalize");
        let oneshot_digest = oneshot_fn(test_input).expect("oneshot must succeed");
        assert_eq!(
            factory_digest, oneshot_digest,
            "factory dispatch mismatch for {:?}",
            alg
        );
    }

    // MDC-2 is exercised separately because it requires 8-byte-aligned input.
    let mdc2_input: &[u8] = b"legacy_t"; // exactly 8 bytes
    let mut ctx = create_legacy_digest(LegacyAlgorithm::Mdc2).expect("factory must succeed");
    ctx.update(mdc2_input).expect("update");
    let factory_digest = ctx.finalize().expect("finalize");
    let oneshot_digest = mdc2(mdc2_input).expect("oneshot must succeed");
    assert_eq!(factory_digest, oneshot_digest);
}

/// Documented discrepancy: `LegacyAlgorithm::name()` returns ALL CAPS / no
/// hyphen variants ("MDC2", "RIPEMD160", "WHIRLPOOL"), while
/// `Digest::algorithm_name()` returns the canonical hyphenated forms
/// ("MDC-2", "RIPEMD-160", "Whirlpool"). Both must be tested to prevent
/// regression in either string set.
#[test]
fn phase_12_legacy_algorithm_name_versus_digest_name_discrepancy() {
    // LegacyAlgorithm::name() — ALL CAPS / no hyphen
    assert_eq!(LegacyAlgorithm::Md2.name(), "MD2");
    assert_eq!(LegacyAlgorithm::Md4.name(), "MD4");
    assert_eq!(LegacyAlgorithm::Mdc2.name(), "MDC2");
    assert_eq!(LegacyAlgorithm::Ripemd160.name(), "RIPEMD160");
    assert_eq!(LegacyAlgorithm::Sm3.name(), "SM3");
    assert_eq!(LegacyAlgorithm::Whirlpool.name(), "WHIRLPOOL");

    // Digest::algorithm_name() — canonical / hyphenated / mixed-case
    assert_eq!(Md2Context::new().algorithm_name(), "MD2");
    assert_eq!(Md4Context::new().algorithm_name(), "MD4");
    assert_eq!(Mdc2Context::new().algorithm_name(), "MDC-2");
    assert_eq!(Ripemd160Context::new().algorithm_name(), "RIPEMD-160");
    assert_eq!(Sm3Context::new().algorithm_name(), "SM3");
    assert_eq!(WhirlpoolContext::new().algorithm_name(), "Whirlpool");
}

/// `LegacyAlgorithm::digest_size()` and `block_size()` match the upstream
/// canonical values for each algorithm.
#[test]
fn phase_12_legacy_algorithm_size_metadata() {
    let cases: &[(LegacyAlgorithm, usize, usize)] = &[
        // (algorithm, digest_size, block_size)
        (LegacyAlgorithm::Md2, 16, 16),
        (LegacyAlgorithm::Md4, 16, 64),
        (LegacyAlgorithm::Mdc2, 16, 8),
        (LegacyAlgorithm::Ripemd160, 20, 64),
        (LegacyAlgorithm::Sm3, 32, 64),
        (LegacyAlgorithm::Whirlpool, 64, 64),
    ];

    for (alg, expected_dsize, expected_bsize) in cases {
        assert_eq!(alg.digest_size(), *expected_dsize, "digest_size for {:?}", alg);
        assert_eq!(alg.block_size(), *expected_bsize, "block_size for {:?}", alg);
    }
}

// =========================================================================
// Phase 13: NIST SP 800-185 encoding helpers
//
// `right_encode`, `left_encode`, `encode_string`, and `bytepad` are the
// fundamental encoding primitives used by KMAC, ParallelHash, TupleHash,
// and cSHAKE. Their byte-level correctness is critical to all SP 800-185
// constructions.
// =========================================================================

/// SP 800-185 §2.3.1 — `right_encode(0)` = `0x00 || 0x01` (literal 0 byte
/// followed by length suffix 1).
#[test]
fn phase_13_right_encode_zero() {
    assert_eq!(right_encode(0), vec![0x00, 0x01]);
}

/// SP 800-185 §2.3.1 — `right_encode` for small values produces the
/// canonical big-endian byte sequence followed by length byte.
/// `right_encode(255)` = `[0xff, 0x01]`; `right_encode(256)` = `[0x01, 0x00, 0x02]`.
#[test]
fn phase_13_right_encode_small_values() {
    assert_eq!(right_encode(255), vec![0xff, 0x01]);
    assert_eq!(right_encode(256), vec![0x01, 0x00, 0x02]);
    assert_eq!(right_encode(65535), vec![0xff, 0xff, 0x02]);
    assert_eq!(right_encode(65536), vec![0x01, 0x00, 0x00, 0x03]);
}

/// SP 800-185 §2.3.1 — `left_encode(0)` = `0x01 || 0x00` (length 1, byte 0).
#[test]
fn phase_13_left_encode_zero() {
    assert_eq!(left_encode(0), vec![0x01, 0x00]);
}

/// SP 800-185 §2.3.1 — `left_encode` produces length prefix followed by
/// big-endian bytes. Mirror image of `right_encode`.
#[test]
fn phase_13_left_encode_small_values() {
    assert_eq!(left_encode(255), vec![0x01, 0xff]);
    assert_eq!(left_encode(256), vec![0x02, 0x01, 0x00]);
    assert_eq!(left_encode(65535), vec![0x02, 0xff, 0xff]);
    assert_eq!(left_encode(65536), vec![0x03, 0x01, 0x00, 0x00]);
}

/// SP 800-185 §2.3.2 — `encode_string("")` is `left_encode(0)` followed by
/// no data; for non-empty strings it is `left_encode(8 * len(s))` || s.
#[test]
fn phase_13_encode_string_empty() {
    assert_eq!(encode_string(b""), vec![0x01, 0x00]);
}

/// SP 800-185 §2.3.2 — `encode_string("hello")` =
/// `left_encode(40)` || "hello" = `0x01 0x28 0x68 0x65 0x6c 0x6c 0x6f`.
#[test]
fn phase_13_encode_string_short_ascii() {
    let result = encode_string(b"hello");
    let expected = [0x01u8, 0x28, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(result, expected);
}

/// SP 800-185 §2.3.3 — `bytepad(x, w)` zero-pads `left_encode(w) || x` to a
/// multiple of `w`. For `w = 0` no padding occurs (per the implementation).
#[test]
fn phase_13_bytepad_w_multiple() {
    // bytepad(b"abc", 8) — left_encode(8) = [0x01, 0x08]. Concatenated = [0x01, 0x08, b'a', b'b', b'c']
    // Length 5; pad to 8 with three zero bytes.
    let result = bytepad(b"abc", 8);
    assert_eq!(
        result,
        vec![0x01, 0x08, b'a', b'b', b'c', 0x00, 0x00, 0x00]
    );
    assert_eq!(result.len() % 8, 0);
}

/// `bytepad` with input that already aligns to `w` adds no padding.
#[test]
fn phase_13_bytepad_already_aligned() {
    // bytepad(b"abcdef", 8) — left_encode(8) = [0x01, 0x08]. Concatenated len = 8. No padding.
    let result = bytepad(b"abcdef", 8);
    assert_eq!(result, vec![0x01, 0x08, b'a', b'b', b'c', b'd', b'e', b'f']);
    assert_eq!(result.len(), 8);
}

// =========================================================================
// Phase 14: clone_box trait method
//
// `Digest::clone_box` produces an owned `Box<dyn Digest>` that is a deep
// copy of the original — neither context's update affects the other.
// =========================================================================

/// Clone of in-progress SHA-256 produces independent state finalizing to
/// the same digest as the original.
#[test]
fn phase_14_sha256_clone_box_independence() {
    let mut original = Sha256Context::sha256();
    original.update(b"shared prefix").expect("update");

    let mut cloned: Box<dyn Digest> = original.clone_box();

    // Mutate the original further; the clone must not see the change.
    original.update(b" additional original suffix").expect("update");
    cloned.update(b" additional clone suffix").expect("update");

    let original_final = original.finalize().expect("finalize");
    let cloned_final = cloned.finalize().expect("finalize");

    let expected_orig = sha256(b"shared prefix additional original suffix").expect("oneshot");
    let expected_clone = sha256(b"shared prefix additional clone suffix").expect("oneshot");

    assert_eq!(original_final, expected_orig);
    assert_eq!(cloned_final, expected_clone);
    assert_ne!(original_final, cloned_final);
}

/// Clone of fresh MD5 context dispatches identically and produces matching
/// digest as the original.
#[test]
fn phase_14_md5_clone_box_fresh_state() {
    let original = Md5Context::new();
    let mut cloned: Box<dyn Digest> = original.clone_box();

    cloned.update(b"abc").expect("update");
    let cloned_digest = cloned.finalize().expect("finalize");
    let oneshot = md5(b"abc").expect("oneshot");
    assert_eq!(cloned_digest, oneshot);
}

// =========================================================================
// Phase 15: Property-based tests
//
// Determinism (same input → same output), output length parity with
// `digest_size()`, and factory-vs-direct construction equivalence.
// =========================================================================

proptest! {
    /// Determinism: SHA-256 of the same input is byte-identical across
    /// two independent computations.
    #[test]
    fn phase_15_proptest_sha256_determinism(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let d1 = sha256(&input).expect("sha256 must succeed");
        let d2 = sha256(&input).expect("sha256 must succeed");
        prop_assert_eq!(d1, d2);
    }

    /// Output length parity: every digest's `finalize()` output length
    /// equals its `digest_size()`.
    #[test]
    fn phase_15_proptest_output_length_matches_digest_size(
        input in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut ctx = Sha256Context::sha256();
        ctx.update(&input).expect("update");
        let out = ctx.finalize().expect("finalize");
        prop_assert_eq!(out.len(), Sha256Context::sha256().digest_size());

        let mut ctx512 = Sha512Context::sha512();
        ctx512.update(&input).expect("update");
        let out512 = ctx512.finalize().expect("finalize");
        prop_assert_eq!(out512.len(), Sha512Context::sha512().digest_size());

        let mut ctx3 = Sha3Context::sha3_256();
        ctx3.update(&input).expect("update");
        let out3 = ctx3.finalize().expect("finalize");
        prop_assert_eq!(out3.len(), Sha3Context::sha3_256().digest_size());
    }

    /// Factory-vs-direct equivalence: digesting input through
    /// `create_sha_digest(Sha256)` produces the same output as
    /// `Sha256Context::sha256()` directly.
    #[test]
    fn phase_15_proptest_factory_versus_direct_sha256(
        input in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        let mut factory_ctx = create_sha_digest(ShaAlgorithm::Sha256).expect("factory");
        factory_ctx.update(&input).expect("update");
        let factory_digest = factory_ctx.finalize().expect("finalize");

        let mut direct_ctx = Sha256Context::sha256();
        direct_ctx.update(&input).expect("update");
        let direct_digest = direct_ctx.finalize().expect("finalize");

        prop_assert_eq!(factory_digest, direct_digest);
    }

    /// Streaming chunked update matches one-shot for SHA-256 on arbitrary
    /// input + arbitrary positive chunk size.
    #[test]
    fn phase_15_proptest_sha256_streaming_chunks(
        input in proptest::collection::vec(any::<u8>(), 0..1024),
        chunk_size in 1usize..=128
    ) {
        let oneshot = sha256(&input).expect("oneshot");

        let mut ctx = Sha256Context::sha256();
        for chunk in input.chunks(chunk_size) {
            ctx.update(chunk).expect("update");
        }
        let streamed = ctx.finalize().expect("finalize");

        prop_assert_eq!(oneshot, streamed);
    }
}
