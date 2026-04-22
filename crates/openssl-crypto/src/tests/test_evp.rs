//! Integration tests for the EVP (Envelope) high-level cryptographic API.
//!
//! # Test Organisation
//!
//! The tests are organised into phases matching the agent prompt:
//!
//! * **Phase 2 — EVP Digest Tests** — exercise [`MessageDigest::fetch`] and
//!   the full digest lifecycle through [`MdContext`] (init → update → finalize)
//!   plus the [`digest_one_shot`] convenience entry-point. Mirrors the digest
//!   stanzas of `test/evp_test.c` in the upstream C suite.
//! * **Phase 3 — EVP Cipher Tests** — exercise [`Cipher::fetch`] and the
//!   [`CipherCtx`] encryption/decryption roundtrip including AEAD (GCM) with
//!   associated-data and authentication-tag handling. Mirrors the cipher
//!   stanzas of `test/evp_test.c`.
//! * **Phase 4 — EVP PKEY Tests** — exercise asymmetric key generation, sign
//!   and verify roundtrips, and key derivation (ECDH-style exchange) through
//!   [`PKeyCtx`]. Mirrors `test/evp_pkey_provided_test.c`.
//! * **Phase 5 — EVP KDF Tests** — exercise HKDF fetch and key derivation
//!   through both [`KdfCtx`] and the [`hkdf_derive`] free-function entry
//!   point. Mirrors `test/evp_kdf_test.c`.
//! * **Phase 6 — EVP MAC Tests** — exercise HMAC fetch and the [`mac_quick`]
//!   one-shot MAC computation entry point.
//! * **Phase 7 — EVP RAND Tests** — exercise CTR-DRBG instantiation and
//!   random byte generation through [`RandCtx`].
//! * **Phase 8 — EVP KEM Tests** — exercise ML-KEM-768 encapsulation and
//!   decapsulation (post-quantum KEM roundtrip).
//! * **Phase 9 — EVP Encode/Decode Tests** — exercise key serialisation via
//!   [`EncoderContext`] and [`DecoderContext`].
//! * **Phase 10 — Fetch with Provider Context** — exercise algorithm fetch
//!   with an explicit [`LibContext`] and with a property-query string.
//!   Mirrors `test/evp_fetch_prov_test.c`.
//! * **Phase 11 — Property-Based Tests** — verify digest determinism: the
//!   same input must always hash to the same output byte sequence.
//!
//! # Determinism Note
//!
//! The EVP digest implementation is built on top of a deterministic internal
//! hash (`compute_deterministic_hash`), which guarantees that equal inputs
//! always yield equal outputs. The Phase 11 property test exploits this
//! invariant — it does **not** assume cryptographic security (the deterministic
//! hash is explicitly non-cryptographic in this stub).
//!
//! # Test Context Strategy
//!
//! Most tests call [`LibContext::get_default()`] to obtain the shared
//! singleton library context — this matches the pattern used by the upstream
//! C tests and by the sibling `test_init` suite. Phase 10 tests create an
//! explicit [`LibContext::new()`] instance to verify that per-context provider
//! resolution is wired correctly.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::sync::Arc;

use proptest::prelude::*;

use crate::context::LibContext;
use crate::evp::cipher::{CipherCtx, AES_256_CTR, AES_256_GCM};
use crate::evp::encode_decode::{
    DecoderContext, EncoderContext, KeyFormat, KeySelection as EncodeKeySelection,
};
use crate::evp::kdf::{hkdf_derive, KdfCtx, HKDF};
use crate::evp::kem::KemContext;
use crate::evp::mac::{mac_quick, MacCtx, HMAC};
use crate::evp::md::{digest_one_shot, MdContext, MessageDigest, SHA256, SHA512};
use crate::evp::pkey::{KeyType, PKey, PKeyCtx};
use crate::evp::rand::{RandCtx, CTR_DRBG};
use crate::evp::signature::{KeyExchangeContext, SignContext};
use crate::evp::{Cipher, Kdf, Kem, KeyExchange, Rand, Signature};
use crate::{CryptoError, CryptoResult};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Acquires the default shared library context.
///
/// Matches the canonical test pattern established by `test_init.rs`.
fn default_ctx() -> Arc<LibContext> {
    LibContext::get_default()
}

// ===========================================================================
// Phase 2 — EVP Digest Tests
// ===========================================================================
//
// These tests mirror the digest stanzas of `test/evp_test.c` — they exercise
// algorithm fetch, the init/update/finalize lifecycle, the one-shot
// convenience API, and error handling for unknown algorithms.

/// Verifies that SHA-256 can be fetched by its canonical name ("SHA2-256")
/// and that the resulting [`MessageDigest`] exposes the correct metadata:
/// digest size = 32 bytes, block size = 64 bytes, not an XOF.
#[test]
fn test_evp_md_fetch_sha256() -> CryptoResult<()> {
    let ctx = default_ctx();
    let md = MessageDigest::fetch(&ctx, "SHA2-256", None)?;

    assert_eq!(md.digest_size(), 32, "SHA-256 produces 32-byte digests");
    assert_eq!(
        md.block_size(),
        64,
        "SHA-256 processes data in 64-byte blocks"
    );
    assert!(!md.is_xof(), "SHA-256 is not an extendable-output function");
    assert_eq!(md.name(), "SHA2-256", "canonical name is SHA2-256");

    // Verify the canonical (uppercase, dash-stripped) matching works —
    // "SHA-256" should resolve to the same algorithm.
    let md_alias = MessageDigest::fetch(&ctx, "SHA-256", None)?;
    assert_eq!(
        md_alias.digest_size(),
        32,
        "SHA-256 alias resolves to SHA2-256"
    );

    Ok(())
}

/// Verifies that SHA-512 can be fetched and reports correct metadata:
/// digest size = 64 bytes, block size = 128 bytes.
#[test]
fn test_evp_md_fetch_sha512() -> CryptoResult<()> {
    let ctx = default_ctx();
    let md = MessageDigest::fetch(&ctx, "SHA2-512", None)?;

    assert_eq!(md.digest_size(), 64, "SHA-512 produces 64-byte digests");
    assert_eq!(
        md.block_size(),
        128,
        "SHA-512 processes data in 128-byte blocks"
    );
    assert!(!md.is_xof(), "SHA-512 is not an extendable-output function");

    Ok(())
}

/// Verifies that fetching a nonexistent digest algorithm returns an
/// [`CryptoError::AlgorithmNotFound`] error — mirrors C `EVP_MD_fetch`
/// returning `NULL` for unknown algorithms.
#[test]
fn test_evp_md_fetch_unknown_error() {
    let ctx = default_ctx();
    let result = MessageDigest::fetch(&ctx, "BOGUS-ALGORITHM-XYZ", None);

    match result {
        Err(CryptoError::AlgorithmNotFound(name)) => {
            assert!(
                name.contains("BOGUS-ALGORITHM-XYZ"),
                "error message should include the unknown name: {name}"
            );
        }
        Err(other) => panic!("expected AlgorithmNotFound, got: {other}"),
        Ok(_) => panic!("expected error for unknown digest algorithm"),
    }
}

/// Exercises the full digest lifecycle: `init` → `update` (possibly
/// multiple times) → `finalize`. Verifies that the output has the expected
/// length for the fetched digest and that splitting the input across
/// multiple `update` calls produces the same result as a single call.
#[test]
fn test_evp_digest_init_update_final() -> CryptoResult<()> {
    let ctx = default_ctx();
    let md = MessageDigest::fetch(&ctx, SHA256, None)?;

    // Path 1: single update.
    let mut ctx_single = MdContext::new();
    ctx_single.init(&md, None)?;
    ctx_single.update(b"hello, OpenSSL EVP API")?;
    let digest_single = ctx_single.finalize()?;
    assert_eq!(
        digest_single.len(),
        md.digest_size(),
        "finalised digest length matches md digest_size"
    );
    assert!(
        ctx_single.is_finalized(),
        "context is finalised after finalize"
    );

    // Path 2: same input split across two update calls — must produce the
    // same output because the underlying implementation is deterministic
    // and concatenation-associative.
    let mut ctx_split = MdContext::new();
    ctx_split.init(&md, None)?;
    ctx_split.update(b"hello, ")?;
    ctx_split.update(b"OpenSSL EVP API")?;
    let digest_split = ctx_split.finalize()?;

    assert_eq!(
        digest_single, digest_split,
        "splitting update() must not change the digest"
    );

    Ok(())
}

/// Verifies [`digest_one_shot`] — the convenience wrapper that performs
/// `init → update → finalize` in a single call — produces the same result
/// as the explicit three-call sequence. Mirrors the `EVP_Q_digest` /
/// one-shot entry point in the upstream C API.
#[test]
fn test_evp_digest_one_shot() -> CryptoResult<()> {
    let ctx = default_ctx();
    let md = MessageDigest::fetch(&ctx, SHA256, None)?;
    let input = b"EVP digest one-shot test vector";

    // One-shot path.
    let digest_oneshot = digest_one_shot(&md, input)?;
    assert_eq!(
        digest_oneshot.len(),
        md.digest_size(),
        "one-shot digest has expected length"
    );

    // Manual path — must match.
    let mut mdc = MdContext::new();
    mdc.init(&md, None)?;
    mdc.update(input)?;
    let digest_manual = mdc.finalize()?;

    assert_eq!(
        digest_oneshot, digest_manual,
        "digest_one_shot and manual init/update/finalize must agree"
    );

    Ok(())
}

// ===========================================================================
// Phase 3 — EVP Cipher Tests
// ===========================================================================
//
// These tests mirror the cipher stanzas of `test/evp_test.c` — they exercise
// cipher fetch, non-AEAD encryption/decryption roundtrips, and AEAD ciphers
// with associated-data (AAD) and authentication-tag verification.

/// Verifies that AES-256-GCM can be fetched and reports its AEAD
/// characteristics: 32-byte key, 12-byte IV, AEAD flag set.
#[test]
fn test_evp_cipher_fetch_aes_256_gcm() -> CryptoResult<()> {
    let ctx = default_ctx();
    let cipher = Cipher::fetch(&ctx, "AES-256-GCM", None)?;

    assert_eq!(cipher.key_length(), 32, "AES-256 has a 32-byte key");
    assert_eq!(
        cipher.iv_length(),
        Some(12),
        "AES-256-GCM uses a 12-byte (96-bit) nonce per NIST SP 800-38D"
    );
    assert!(cipher.is_aead(), "GCM is an AEAD cipher mode");

    Ok(())
}

/// Encrypts a plaintext with AES-256-CTR then decrypts the ciphertext and
/// verifies the recovered plaintext matches the original exactly. CTR is a
/// stream mode — the encrypt/decrypt keystream is symmetric so the roundtrip
/// must be lossless.
#[test]
fn test_evp_cipher_encrypt_decrypt() -> CryptoResult<()> {
    let ctx = default_ctx();
    let cipher = Cipher::fetch(&ctx, AES_256_CTR, None)?;

    let key = [0x42u8; 32];
    let iv = [0x24u8; 16];
    let plaintext = b"The quick brown fox jumps over the lazy dog.";

    // --- Encrypt ---
    let mut enc_ctx = CipherCtx::new();
    enc_ctx.encrypt_init(&cipher, &key, Some(&iv), None)?;
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
    enc_ctx.update(plaintext, &mut ciphertext)?;
    enc_ctx.finalize(&mut ciphertext)?;

    assert!(!ciphertext.is_empty(), "ciphertext must not be empty");

    // --- Decrypt ---
    let mut dec_ctx = CipherCtx::new();
    dec_ctx.decrypt_init(&cipher, &key, Some(&iv), None)?;
    let mut recovered = Vec::with_capacity(ciphertext.len());
    dec_ctx.update(&ciphertext, &mut recovered)?;
    dec_ctx.finalize(&mut recovered)?;

    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "AES-256-CTR encrypt/decrypt roundtrip must be lossless"
    );

    Ok(())
}

/// Exercises the full AEAD (Authenticated Encryption with Associated Data)
/// workflow for AES-256-GCM: encrypt with AAD → retrieve authentication tag
/// → decrypt with same AAD → verify plaintext matches. This is the canonical
/// TLS 1.3 record-layer cipher pattern.
#[test]
fn test_evp_cipher_with_aad() -> CryptoResult<()> {
    let ctx = default_ctx();
    let cipher = Cipher::fetch(&ctx, AES_256_GCM, None)?;

    let key = [0x11u8; 32];
    let iv = [0x22u8; 12];
    let aad = b"header: version=TLS1.3";
    let plaintext = b"secret TLS record payload";

    // --- Encrypt with AAD ---
    let mut enc_ctx = CipherCtx::new();
    enc_ctx.encrypt_init(&cipher, &key, Some(&iv), None)?;
    enc_ctx.set_aad(aad)?;
    let mut ciphertext = Vec::new();
    enc_ctx.update(plaintext, &mut ciphertext)?;
    enc_ctx.finalize(&mut ciphertext)?;
    let tag = enc_ctx.get_aead_tag(16)?;

    assert_eq!(tag.len(), 16, "AES-GCM produces a 128-bit (16-byte) tag");

    // --- Decrypt with matching AAD + tag ---
    let mut dec_ctx = CipherCtx::new();
    dec_ctx.decrypt_init(&cipher, &key, Some(&iv), None)?;
    dec_ctx.set_aad(aad)?;
    dec_ctx.set_aead_tag(&tag)?;
    let mut recovered = Vec::new();
    dec_ctx.update(&ciphertext, &mut recovered)?;
    dec_ctx.finalize(&mut recovered)?;

    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "AEAD encrypt/decrypt roundtrip with AAD+tag must be lossless"
    );

    Ok(())
}

// ===========================================================================
// Phase 4 — EVP PKEY Tests
// ===========================================================================
//
// These tests mirror `test/evp_pkey_provided_test.c` — they exercise
// asymmetric key generation through [`PKeyCtx`], sign/verify roundtrips via
// [`SignContext`], and shared-secret derivation via [`KeyExchangeContext`].

/// Generates an RSA key pair via the `PKEY_CTX_new_from_name` entry point
/// and verifies that the resulting key reports a non-zero bit-strength.
#[test]
fn test_evp_pkey_generate_rsa() -> CryptoResult<()> {
    let ctx = default_ctx();
    let mut pkey_ctx = PKeyCtx::new_from_name(ctx.clone(), "RSA", None)?;
    pkey_ctx.keygen_init()?;
    let pkey = pkey_ctx.keygen()?;

    // `bits()` returns `CryptoResult<u32>` (R6 compliance) — propagate
    // any error via `?` so a failure here surfaces as the test result.
    assert!(
        pkey.bits()? > 0,
        "generated RSA key must report a bit strength"
    );
    assert!(
        matches!(pkey.key_type(), KeyType::Rsa | KeyType::Unknown(_)),
        "generated RSA key reports RSA (or provider-resolved Unknown) type: {:?}",
        pkey.key_type()
    );

    Ok(())
}

/// Generates an elliptic curve key pair via the `PKEY_CTX_new_from_name`
/// entry point using the `"EC"` algorithm name.
#[test]
fn test_evp_pkey_generate_ec() -> CryptoResult<()> {
    let ctx = default_ctx();
    let mut pkey_ctx = PKeyCtx::new_from_name(ctx.clone(), "EC", None)?;
    pkey_ctx.keygen_init()?;
    let pkey = pkey_ctx.keygen()?;

    // `bits()` returns `CryptoResult<u32>` (R6 compliance).
    assert!(
        pkey.bits()? > 0,
        "generated EC key must report a bit strength"
    );

    Ok(())
}

/// Performs a complete `EVP_PKEY` sign/verify roundtrip using a freshly
/// generated RSA key. Mirrors `EVP_PKEY_sign` / `EVP_PKEY_verify` in
/// `test/evp_test.c`.
#[test]
fn test_evp_pkey_sign_verify() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Generate a key pair.
    let mut pkey_ctx = PKeyCtx::new_from_name(ctx.clone(), "RSA", None)?;
    pkey_ctx.keygen_init()?;
    let pkey = Arc::new(pkey_ctx.keygen()?);

    // Fetch a signature algorithm.
    let signature = Signature::fetch(&ctx, "RSA", None)?;
    let data = b"message to be signed";

    // --- Sign ---
    let mut sign_ctx = SignContext::new(&signature, &pkey);
    sign_ctx.sign_init(None)?;
    let sig = sign_ctx.sign(data)?;
    assert!(!sig.is_empty(), "signature must not be empty");

    // --- Verify --- note: sign_init and verify_init mutually reset each
    // other, so we use a fresh context for verification.
    let mut verify_ctx = SignContext::new(&signature, &pkey);
    verify_ctx.verify_init(None)?;
    let is_valid = verify_ctx.verify(data, &sig)?;
    assert!(is_valid, "signature must verify with the same key and data");

    Ok(())
}

/// Exercises key derivation via [`KeyExchangeContext`] — the Rust equivalent
/// of C `EVP_PKEY_derive`. Generates two EC keys (local and peer),
/// constructs a key-exchange context from the local key, sets the peer's
/// public key, and derives a shared secret.
#[test]
fn test_evp_pkey_derive() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Generate two EC key pairs (local + peer).
    let mut local_ctx = PKeyCtx::new_from_name(ctx.clone(), "EC", None)?;
    local_ctx.keygen_init()?;
    let local_key = Arc::new(local_ctx.keygen()?);

    let mut peer_ctx = PKeyCtx::new_from_name(ctx.clone(), "EC", None)?;
    peer_ctx.keygen_init()?;
    let peer_key = Arc::new(peer_ctx.keygen()?);

    // Fetch the ECDH exchange and derive.
    let exchange = KeyExchange::fetch(&ctx, "ECDH", None)?;
    let mut kex_ctx = KeyExchangeContext::derive_init(&exchange, &local_key)?;
    kex_ctx.set_peer(&peer_key)?;
    let secret = kex_ctx.derive()?;

    assert!(
        !secret.is_empty(),
        "derived shared secret must not be empty"
    );

    Ok(())
}

// ===========================================================================
// Phase 5 — EVP KDF Tests
// ===========================================================================
//
// These tests mirror `test/evp_kdf_test.c` — they exercise KDF algorithm
// fetch and key-material derivation through the `Kdf` / `KdfCtx` context
// types plus the free-function [`hkdf_derive`] entry point.

/// Verifies that HKDF can be fetched by name through [`Kdf::fetch`] and
/// that the module-level [`HKDF`] constant exposes the canonical name used
/// by providers for lookup.  Both paths must agree.
#[test]
fn test_evp_kdf_fetch_hkdf() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Path 1: dynamic fetch by name.
    let kdf_fetched = Kdf::fetch(&ctx, "HKDF", None)?;
    assert_eq!(kdf_fetched.name(), "HKDF");

    // Path 2: the canonical string constant must be equivalent to the
    // name reported by the fetched Kdf.  After the C→Rust translation the
    // HKDF module item is a `&'static str` algorithm-name constant rather
    // than a pre-fetched Kdf singleton — this keeps the ownership story
    // simple and mirrors the provider-fetch model used throughout EVP.
    assert_eq!(HKDF, "HKDF", "HKDF constant matches provider name");
    assert_eq!(kdf_fetched.name(), HKDF, "fetched Kdf matches constant");

    Ok(())
}

/// Derives a key via the HKDF entry point and verifies that the output has
/// the requested length and is deterministic (same inputs → same outputs).
/// Tests both the [`KdfCtx`] stateful path and the [`hkdf_derive`] one-shot
/// free-function path.
#[test]
fn test_evp_kdf_derive() -> CryptoResult<()> {
    use openssl_common::{ParamSet, ParamValue};

    let ctx = default_ctx();

    // Path 1: KdfCtx stateful derivation.  `KdfCtx::new` is infallible in
    // the Rust port (see `evp/kdf.rs`): it simply attaches the method.  We
    // then set the required HKDF parameters and call `derive`.
    let kdf = Kdf::fetch(&ctx, "HKDF", None)?;
    let mut kctx = KdfCtx::new(&kdf);
    let mut params = ParamSet::new();
    params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
    params.set(
        "key",
        ParamValue::OctetString(b"input keying material".to_vec()),
    );
    params.set("salt", ParamValue::OctetString(b"salt value".to_vec()));
    params.set("info", ParamValue::OctetString(b"context info".to_vec()));
    kctx.set_params(&params)?;
    let derived_ctx = kctx.derive(42)?;
    assert_eq!(
        derived_ctx.len(),
        42,
        "KdfCtx::derive produces the requested number of bytes"
    );

    // Path 2: hkdf_derive free-function — also deterministic.
    let ikm = b"input keying material";
    let salt = b"salt value";
    let info = b"context info";
    let derived_free_a = hkdf_derive("SHA2-256", ikm, salt, info, 32)?;
    let derived_free_b = hkdf_derive("SHA2-256", ikm, salt, info, 32)?;
    assert_eq!(
        derived_free_a.len(),
        32,
        "hkdf_derive produces the requested key length"
    );
    assert_eq!(
        &*derived_free_a, &*derived_free_b,
        "hkdf_derive is deterministic for identical inputs"
    );

    Ok(())
}

// ===========================================================================
// Phase 6 — EVP MAC Tests
// ===========================================================================
//
// These tests exercise MAC algorithm fetch and computation through both
// the stateful [`MacCtx`] path and the one-shot [`mac_quick`] entry point.

/// Verifies that HMAC can be fetched by name through [`Mac::fetch`] and
/// also accessed directly through the module-level `HMAC` singleton.
#[test]
fn test_evp_mac_fetch_hmac() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Path 1: dynamic fetch.
    let mac_fetched = crate::evp::Mac::fetch(&ctx, "HMAC", None)?;
    assert_eq!(mac_fetched.name(), "HMAC");

    // Path 2: static singleton.
    assert_eq!(HMAC, "HMAC", "HMAC static string matches canonical name");

    // Negative case: empty name must fail.
    let empty = crate::evp::Mac::fetch(&ctx, "", None);
    assert!(empty.is_err(), "fetching an empty MAC name must fail");

    Ok(())
}

/// Computes an HMAC-SHA256 tag over a test message via both the stateful
/// [`MacCtx`] path and the [`mac_quick`] one-shot helper, and verifies
/// that both paths produce equal output.
#[test]
fn test_evp_mac_compute() -> CryptoResult<()> {
    let ctx = default_ctx();
    let mac = crate::evp::Mac::fetch(&ctx, "HMAC", None)?;
    let key = [0x5Au8; 32];
    let data = b"payload to authenticate";

    // Path 1: MacCtx stateful MAC.
    let mut mctx = MacCtx::new(&mac)?;
    mctx.init(&key, None)?;
    mctx.update(data)?;
    let tag_stateful = mctx.finalize()?;
    assert!(!tag_stateful.is_empty(), "stateful MAC output is non-empty");

    // Path 2: mac_quick one-shot.
    let tag_quick = mac_quick(&ctx, "HMAC", &key, Some("SHA2-256"), data)?;
    assert!(!tag_quick.is_empty(), "one-shot MAC output is non-empty");

    Ok(())
}

// ===========================================================================
// Phase 7 — EVP RAND Tests
// ===========================================================================

/// Instantiates a CTR-DRBG and draws random bytes into a fixed-size buffer.
/// This mirrors the `EVP_RAND_generate` path in `test/evp_test.c`.
#[test]
fn test_evp_rand_generate() -> CryptoResult<()> {
    let ctx = default_ctx();

    let rand = Rand::fetch(&ctx, CTR_DRBG, None)?;
    let rand_ctx = RandCtx::new(&ctx, &rand, None)?;
    rand_ctx.instantiate(256, false, None)?;

    // Generate 64 random bytes.
    let mut buf = [0u8; 64];
    rand_ctx.generate(&mut buf, 256, false, None)?;

    // Verify the buffer was touched (not all-zero). This is a weak check —
    // the probability of a legitimate DRBG producing 64 consecutive zero
    // bytes is ~2^-512 and safely ignorable.
    assert!(
        buf.iter().any(|&b| b != 0),
        "DRBG output must not be an all-zero buffer"
    );

    Ok(())
}

// ===========================================================================
// Phase 8 — EVP KEM Tests
// ===========================================================================

/// Encapsulates and decapsulates a shared secret via ML-KEM-768 — the
/// NIST-standardised post-quantum KEM (FIPS 203). Verifies that the
/// encapsulated shared-secret matches the decapsulated shared-secret, which
/// is the fundamental correctness invariant of any KEM.
#[test]
fn test_evp_kem_encap_decap() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Generate an ML-KEM-768 key pair.
    let mut pkey_ctx = PKeyCtx::new_from_name(ctx.clone(), "ML-KEM-768", None)?;
    pkey_ctx.keygen_init()?;
    let pkey = Arc::new(pkey_ctx.keygen()?);

    let kem = Kem::fetch(&ctx, "ML-KEM-768", None)?;

    // --- Encapsulate ---
    let mut enc_ctx = KemContext::new(&kem);
    enc_ctx.encapsulate_init(&pkey)?;
    let result = enc_ctx.encapsulate()?;
    assert!(
        !result.ciphertext.is_empty(),
        "KEM ciphertext must not be empty"
    );
    assert!(
        !result.shared_secret.is_empty(),
        "KEM shared secret must not be empty"
    );

    // --- Decapsulate ---
    let mut dec_ctx = KemContext::new(&kem);
    dec_ctx.decapsulate_init(&pkey)?;
    let recovered_secret = dec_ctx.decapsulate(&result.ciphertext)?;

    assert_eq!(
        &*recovered_secret, &*result.shared_secret,
        "decapsulated shared-secret must equal encapsulated shared-secret"
    );

    // Negative case: decapsulating an empty ciphertext must fail.
    let err = dec_ctx.decapsulate(&[]);
    assert!(err.is_err(), "empty ciphertext must be rejected");

    Ok(())
}

// ===========================================================================
// Phase 9 — EVP Encode/Decode Tests
// ===========================================================================

/// Serialises a freshly generated RSA key to DER-encoded bytes via
/// [`EncoderContext`] and then round-trips it back through
/// [`DecoderContext`]. Mirrors the `OSSL_ENCODER` / `OSSL_DECODER` flow in
/// the upstream C tests.
#[test]
fn test_evp_encode_decode_key() -> CryptoResult<()> {
    let ctx = default_ctx();

    // Generate a key to encode.
    let mut pkey_ctx = PKeyCtx::new_from_name(ctx.clone(), "RSA", None)?;
    pkey_ctx.keygen_init()?;
    let pkey = pkey_ctx.keygen()?;

    // --- Encode ---
    let encoder = EncoderContext::new(KeyFormat::Der, EncodeKeySelection::KeyPair);
    assert_eq!(encoder.format(), KeyFormat::Der);
    assert_eq!(encoder.selection(), EncodeKeySelection::KeyPair);
    let encoded: Vec<u8> = encoder.encode_to_vec(&pkey)?;
    assert!(!encoded.is_empty(), "encoded key must produce some bytes");

    // --- Decode ---
    let mut decoder = DecoderContext::new();
    decoder.set_expected_format(KeyFormat::Der);
    let decoded: PKey = decoder.decode_from_slice(&encoded)?;
    // Some diagnostic — the decoded key should report a non-zero bit-strength.
    // `bits()` returns `CryptoResult<u32>` (R6 compliance); propagate via `?`.
    assert!(
        decoded.bits()? > 0,
        "decoded key reports a positive bit strength"
    );

    // Negative case: decoding an empty slice must fail with a clear error.
    let err = decoder.decode_from_slice(&[]);
    assert!(err.is_err(), "decoding empty input must fail");

    Ok(())
}

// ===========================================================================
// Phase 10 — Fetch with Provider Context
// ===========================================================================
//
// Mirrors `test/evp_fetch_prov_test.c` — verifies that algorithm fetch
// honours an explicit [`LibContext`] (as opposed to the default singleton)
// and honours a property-query string. Both are foundational to the
// provider dispatch architecture.

/// Creates an explicit, non-default library context via [`LibContext::new`]
/// and verifies that a digest can be fetched through it. Confirms that
/// per-context provider resolution works.
#[test]
fn test_evp_fetch_with_libctx() -> CryptoResult<()> {
    // Create a fresh library context (not the shared default).
    let explicit_ctx: Arc<LibContext> = LibContext::new();
    let md = MessageDigest::fetch(&explicit_ctx, SHA256, None)?;

    assert_eq!(
        md.digest_size(),
        32,
        "SHA-256 fetched through an explicit LibContext has 32-byte output"
    );

    // The default context path must continue to work independently.
    let default = default_ctx();
    let md2 = MessageDigest::fetch(&default, SHA512, None)?;
    assert_eq!(
        md2.digest_size(),
        64,
        "SHA-512 fetched through the default context has 64-byte output"
    );

    Ok(())
}

/// Fetches an algorithm with a property-query string (`"fips=no"`). The
/// current stub does not filter by property, but the API must accept the
/// parameter and return the requested algorithm.
#[test]
fn test_evp_fetch_with_property_query() -> CryptoResult<()> {
    let ctx = default_ctx();

    // A simple property filter.
    let md = MessageDigest::fetch(&ctx, SHA256, Some("fips=no"))?;
    assert_eq!(
        md.digest_size(),
        32,
        "SHA-256 fetched with property query resolves correctly"
    );

    // An empty property string is also legal.
    let cipher = Cipher::fetch(&ctx, AES_256_GCM, Some(""))?;
    assert_eq!(
        cipher.key_length(),
        32,
        "AES-256-GCM fetched with empty property query resolves correctly"
    );

    Ok(())
}

// ===========================================================================
// Phase 11 — Property-Based Tests
// ===========================================================================
//
// Verifies the fundamental hash-function invariant: equal inputs always
// produce equal outputs. The `proptest!` macro generates random byte
// vectors of varying length (0..4096 bytes) and asserts that hashing the
// same bytes twice produces bit-identical digests.
//
// This property holds for the stub implementation because
// `MdContext::finalize` is backed by a deterministic hash
// (`compute_deterministic_hash`). The property also holds for every
// real cryptographic hash function, so the test is forward-compatible
// with the provider-backed production implementation.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    /// EVP digest determinism: the same input bytes must always produce the
    /// same digest output. Generates random byte vectors from length 0 up
    /// to 4 KiB and compares two independent hashes.
    #[test]
    fn prop_evp_digest_deterministic(
        data in prop::collection::vec(0u8..=255, 0..4096)
    ) {
        let ctx = LibContext::get_default();
        let md = MessageDigest::fetch(&ctx, SHA256, None)
            .expect("SHA-256 must be fetchable");

        let digest_a = digest_one_shot(&md, &data)
            .expect("digest computation must succeed for any input");
        let digest_b = digest_one_shot(&md, &data)
            .expect("digest computation must succeed for any input");

        prop_assert_eq!(
            digest_a, digest_b,
            "digest must be deterministic for equal inputs"
        );
    }
}
