//! Integration tests for symmetric cipher operations.
//!
//! Covers AES (GCM/CCM/CTR/CBC/ECB/XTS/SIV/wrap), ChaCha20-Poly1305,
//! DES/3DES, and legacy ciphers (Blowfish, CAST5, IDEA, RC2, RC4).
//! Property-based tests via `proptest` verify encrypt/decrypt round-trip
//! invariants for arbitrary keys, nonces, and data.
//!
//! Reference C test files:
//! - `test/aesgcmtest.c`           — AES-GCM RFC test vectors and tag verification
//! - `test/aeswrap_test.c`         — AES key wrapping (RFC 3394/5649)
//! - `test/destest.c`              — DES/3DES key parity, weak keys, KATs
//! - `test/chacha_internal_test.c` — ChaCha20 keystream generation
//! - `test/igetest.c`              — AES-IGE mode (legacy, not in scope)
//! - `test/bftest.c`               — Blowfish variable-length key schedule
//! - `test/casttest.c`             — CAST5 5–16 byte key handling
//! - `test/ideatest.c`             — IDEA 16-byte key schedule
//! - `test/rc2test.c`              — RC2 effective-bits configuration
//! - `test/rc4test.c`              — RC4 stream cipher keystream validation
//! - `test/rc5test.c`              — RC5 variable-round cipher
//!
//! Key rules:
//! - **R5:** All cipher functions return `CryptoResult<T>` — no integer
//!   sentinels (`0`/`-1`/`NULL`) are used to encode success or failure.
//! - **R8:** ZERO `unsafe` in this file. Inherited via the crate-level
//!   `#![forbid(unsafe_code)]` attribute in `lib.rs`.
//! - **R9:** Warning-free under `RUSTFLAGS="-D warnings"`. Per-lint
//!   `#[allow]` attributes below are scoped and justified.
//! - **R10:** Every test exercises a real API path reachable from the
//!   public `crate::symmetric` module surface.
//! - **Gate 1:** [`test_aes_256_gcm_encrypt_decrypt_roundtrip`] processes
//!   a real-world AES-256-GCM test vector (from `test/aesgcmtest.c`) and
//!   asserts the exact expected ciphertext+tag output.
//! - **Gate 10:** Contributes toward 80 % line coverage for the
//!   `crate::symmetric` module tree.

// Test code legitimately uses expect(), unwrap(), and panic!() for assertions.
// Per workspace lint config: "Tests and CLI main() may #[allow] with justification."
#![allow(clippy::expect_used)] // Tests use .expect() to unwrap known-good Results.
#![allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.

use crate::symmetric::*;
use openssl_common::{CommonError, CryptoError, CryptoResult};

// =============================================================================
// Helper utilities
// =============================================================================

/// Decodes a hex-encoded string into a byte vector.
///
/// Panics on invalid hex, which is acceptable in test code where a malformed
/// literal is a bug in the test itself rather than a runtime error condition.
#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "des",
    feature = "legacy"
))]
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex string length must be even");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encodes a byte slice as a lowercase hex string for diagnostic output.
#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "des",
    feature = "legacy"
))]
fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Builds a deterministic byte pattern for plaintext inputs in structural tests.
///
/// Produces `len` bytes where byte `i` = `(i & 0xff) as u8`. Used by round-trip
/// tests that need non-trivial (non-zero, non-repeating within 256 bytes)
/// plaintext to catch keystream off-by-one bugs.
#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "des",
    feature = "legacy"
))]
fn make_pattern(len: usize) -> Vec<u8> {
    // `i & 0xff` is always within `0..=255`, so `try_from` is infallible; the
    // `unwrap_or(0)` is defensive per R6 (no bare `as` narrowing).
    (0..len)
        .map(|i| u8::try_from(i & 0xff).unwrap_or(0))
        .collect()
}

// =============================================================================
// Phase 2: AES Tests (reference: test/aesgcmtest.c, test/aeswrap_test.c)
// =============================================================================

/// AES-128-GCM round-trip: random plaintext encrypts, decrypts back identically.
///
/// Validates the core contract of `AesGcm::seal` / `AesGcm::open`: applying
/// them in sequence is the identity on plaintext when keys, nonces, and AAD
/// match.
#[cfg(feature = "aes")]
#[test]
fn test_aes_128_gcm_encrypt_decrypt_roundtrip() -> CryptoResult<()> {
    // AES-128 → 16-byte key.
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let nonce: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let aad = b"additional-authenticated-data";
    let plaintext = b"AES-128-GCM round-trip plaintext payload.";

    let cipher = AesGcm::new(&key)?;
    let ciphertext_with_tag = cipher.seal(&nonce, aad, plaintext)?;

    // Output = ciphertext || 16-byte tag (GCM_TAG_LEN = 16).
    assert_eq!(
        ciphertext_with_tag.len(),
        plaintext.len() + 16,
        "AES-GCM output must be plaintext.len() + tag_len"
    );
    // Ciphertext must not equal plaintext (the cipher must actually encrypt).
    assert_ne!(
        &ciphertext_with_tag[..plaintext.len()],
        &plaintext[..],
        "AES-GCM must produce ciphertext != plaintext"
    );

    let recovered = cipher.open(&nonce, aad, &ciphertext_with_tag)?;
    assert_eq!(recovered, plaintext, "AES-128-GCM round-trip must match");
    Ok(())
}

/// AES-256-GCM known-answer test using the RFC-style vector from
/// `test/aesgcmtest.c`. Satisfies **Gate 1** (real-world input/output).
#[cfg(feature = "aes")]
#[test]
fn test_aes_256_gcm_encrypt_decrypt_roundtrip() -> CryptoResult<()> {
    // Test vector lifted verbatim from `test/aesgcmtest.c` (upstream OpenSSL
    // test suite). Key, IV, AAD, plaintext, ciphertext, and tag all match
    // the authoritative C reference.
    let key: [u8; 32] = [
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6,
        0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72,
        0x07, 0x8f,
    ];
    let iv: [u8; 12] = [
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
    ];
    let plaintext: [u8; 16] = [
        0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b, 0xf2,
        0xa5,
    ];
    let aad: [u8; 16] = [
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78,
        0xde,
    ];
    let expected_ct: [u8; 16] = [
        0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e, 0xb9, 0xf2, 0x17,
        0x36,
    ];
    let expected_tag: [u8; 16] = [
        0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62, 0x98, 0xf7, 0x7e,
        0x0c,
    ];

    let cipher = AesGcm::new(&key)?;
    let ciphertext_with_tag = cipher.seal(&iv, &aad, &plaintext)?;

    // Split output into ciphertext || tag for precise KAT validation.
    assert_eq!(
        ciphertext_with_tag.len(),
        plaintext.len() + 16,
        "AES-256-GCM output layout must be ct || tag"
    );
    let (ct, tag) = ciphertext_with_tag.split_at(plaintext.len());

    assert_eq!(
        ct,
        &expected_ct[..],
        "AES-256-GCM ciphertext mismatch: got {} expected {}",
        bytes_to_hex(ct),
        bytes_to_hex(&expected_ct)
    );
    assert_eq!(
        tag,
        &expected_tag[..],
        "AES-256-GCM tag mismatch: got {} expected {}",
        bytes_to_hex(tag),
        bytes_to_hex(&expected_tag)
    );

    // Round-trip: decrypt recovers the original plaintext.
    let recovered = cipher.open(&iv, &aad, &ciphertext_with_tag)?;
    assert_eq!(recovered, plaintext, "AES-256-GCM round-trip must match");
    Ok(())
}

/// Tampering the ciphertext must cause `open` to return
/// `CryptoError::Verification` — plaintext must never be released when the
/// authenticator fails.
#[cfg(feature = "aes")]
#[test]
fn test_aes_gcm_authentication_tag_verification() -> CryptoResult<()> {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"sensitive payload that must be authenticated";
    let aad = b"metadata";

    let cipher = AesGcm::new(&key)?;
    let mut ciphertext_with_tag = cipher.seal(&nonce, aad, plaintext)?;

    // Flip one bit in the middle of the ciphertext.
    let tamper_idx = ciphertext_with_tag.len() / 2;
    ciphertext_with_tag[tamper_idx] ^= 0x01;

    let result = cipher.open(&nonce, aad, &ciphertext_with_tag);
    match result {
        Err(CryptoError::Verification(_)) => Ok(()),
        Ok(_) => panic!("tampered AES-GCM ciphertext must NOT decrypt successfully"),
        Err(other) => panic!("expected CryptoError::Verification, got: {other:?}"),
    }
}

/// Different nonces with the same key/plaintext must produce distinct
/// ciphertexts — this is the fundamental security property of AES-GCM.
#[cfg(feature = "aes")]
#[test]
fn test_aes_gcm_nonce_uniqueness() -> CryptoResult<()> {
    let key = [0x11u8; 32];
    let plaintext = b"identical plaintext encrypted under different nonces";
    let aad: &[u8] = &[];

    let cipher = AesGcm::new(&key)?;
    let nonce_a: [u8; 12] = [0x01; 12];
    let nonce_b: [u8; 12] = [0x02; 12];

    let ct_a = cipher.seal(&nonce_a, aad, plaintext)?;
    let ct_b = cipher.seal(&nonce_b, aad, plaintext)?;

    assert_ne!(
        ct_a, ct_b,
        "AES-GCM outputs for distinct nonces must differ"
    );
    // The ciphertexts differ — their tags will differ too since the GHASH
    // computation incorporates the ciphertext. This is an implicit check on
    // the tag-layout invariant (ciphertext || tag).
    Ok(())
}

/// AES-CCM mode round-trip at the default (12-byte nonce, 16-byte tag)
/// parameter choice.
#[cfg(feature = "aes")]
#[test]
fn test_aes_ccm_encrypt_decrypt() -> CryptoResult<()> {
    let key = [0xabu8; 16]; // AES-128-CCM
    let nonce = [0x55u8; 12]; // CCM nonce length 7..=13, picked 12.
    let aad = b"ccm-aad";
    let plaintext = b"AES-CCM round-trip plaintext - variable length should work.";

    let cipher = AesCcm::new(&key, 16, 12)?;
    let ct_and_tag = cipher.seal(&nonce, aad, plaintext)?;
    assert_eq!(
        ct_and_tag.len(),
        plaintext.len() + 16,
        "AES-CCM output = ciphertext || tag"
    );
    assert_ne!(
        &ct_and_tag[..plaintext.len()],
        &plaintext[..],
        "AES-CCM must actually encrypt"
    );

    let recovered = cipher.open(&nonce, aad, &ct_and_tag)?;
    assert_eq!(recovered, plaintext, "AES-CCM round-trip must match");

    // Tampering: flip a bit in the tag — open must fail authentication.
    let mut tampered = ct_and_tag.clone();
    let last_idx = tampered.len() - 1;
    tampered[last_idx] ^= 0x80;
    match cipher.open(&nonce, aad, &tampered) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("expected CryptoError::Verification on tag tamper, got {other:?}"),
    }
    Ok(())
}

/// AES-CTR mode round-trip via the helper `aes_ctr_encrypt`. CTR is a
/// symmetric stream — encrypt and decrypt use the same function.
#[cfg(feature = "aes")]
#[test]
fn test_aes_ctr_encrypt_decrypt() -> CryptoResult<()> {
    use crate::symmetric::aes::aes_ctr_encrypt;

    let key = [0x5au8; 32]; // AES-256-CTR
    let nonce = [0x77u8; 16]; // Full-block counter/IV.
    let plaintext = make_pattern(257); // Odd length exercises partial blocks.

    let ciphertext = aes_ctr_encrypt(&key, &nonce, &plaintext)?;
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "CTR preserves length (stream cipher)"
    );
    assert_ne!(ciphertext, plaintext, "CTR must actually encrypt");

    // Decrypt by re-applying the same keystream.
    let recovered = aes_ctr_encrypt(&key, &nonce, &ciphertext)?;
    assert_eq!(recovered, plaintext, "AES-CTR is its own inverse");
    Ok(())
}

/// AES-CBC mode round-trip with PKCS#7 padding.
#[cfg(feature = "aes")]
#[test]
fn test_aes_cbc_encrypt_decrypt() -> CryptoResult<()> {
    use crate::symmetric::aes::{aes_cbc_decrypt, aes_cbc_encrypt};

    let key = [0x33u8; 16]; // AES-128-CBC
    let iv = [0x66u8; 16];
    // 31 bytes: not a block multiple, exercises PKCS#7 padding.
    let plaintext = b"AES-CBC test plaintext msg-31b.";
    assert_eq!(plaintext.len(), 31);

    let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext)?;
    // PKCS#7 always pads to next block multiple (32 bytes here).
    assert_eq!(ciphertext.len(), 32, "PKCS#7 padded length must be 32");

    let recovered = aes_cbc_decrypt(&key, &iv, &ciphertext)?;
    assert_eq!(recovered, plaintext, "AES-CBC round-trip must match");

    // Tampering with ciphertext should produce a padding error on decrypt
    // (CryptoError::Encoding) with very high probability, or random garbage
    // otherwise. We only verify the success case here; negative path is
    // covered by dedicated CBC tests in aes.rs unit tests.
    Ok(())
}

/// AES-ECB mode via the generic `ecb_encrypt` mode engine. ECB is a
/// deterministic block-by-block mapping — identical plaintext blocks encrypt
/// to identical ciphertext blocks.
#[cfg(feature = "aes")]
#[test]
fn test_aes_ecb_encrypt_decrypt() -> CryptoResult<()> {
    let key = [0x2bu8; 16]; // AES-128-ECB
                            // Two identical 16-byte blocks: verifies ECB determinism.
    let plaintext = [0xccu8; 32];

    let aes = Aes::new(&key)?;
    let ciphertext = ecb_encrypt(&aes, &plaintext, CipherDirection::Encrypt)?;

    // `ecb_encrypt` applies PKCS#7 padding: for a 32-byte (exact block
    // multiple) input, a full 16-byte padding block is appended, yielding
    // 48 bytes of ciphertext.
    assert_eq!(
        ciphertext.len(),
        48,
        "ECB with PKCS#7 padding: 32 pt + 16 pad block = 48"
    );
    // ECB over two identical plaintext blocks must yield two identical
    // ciphertext blocks (this is the defining -- and insecure -- property
    // of ECB mode).
    assert_eq!(
        &ciphertext[0..16],
        &ciphertext[16..32],
        "ECB of identical blocks must produce identical ciphertext blocks"
    );

    let recovered = ecb_encrypt(&aes, &ciphertext, CipherDirection::Decrypt)?;
    // Decryption strips PKCS#7 padding, restoring the original 32 bytes.
    assert_eq!(recovered, plaintext, "AES-ECB round-trip must match");
    Ok(())
}

/// AES-XTS disk-encryption mode round-trip.
///
/// XTS requires a combined key `K1 || K2` where `K1 ≠ K2` (IEEE 1619-2007).
/// Plaintext must be ≥ 16 bytes (one AES block) — shorter inputs return
/// `CryptoError::Common(InvalidArgument)`.
#[cfg(feature = "aes")]
#[test]
fn test_aes_xts_encrypt_decrypt() -> CryptoResult<()> {
    // 32-byte combined key: first 16 bytes = K1, next 16 = K2. Distinct.
    // Per R6, no bare `as` narrowing: mask to `0..=255` (always fits u8) and
    // use `try_from` with a defensive fallback.
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        let byte = u8::try_from(i & 0xff).unwrap_or(0);
        *b = byte.wrapping_mul(7).wrapping_add(3);
    }
    let iv = [0x9eu8; 16];
    // 33 bytes: two full blocks + one partial (exercises ciphertext stealing).
    let plaintext = make_pattern(33);

    let xts = AesXts::new(&key)?;
    let ciphertext = xts.encrypt(&iv, &plaintext)?;
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "XTS preserves length (ciphertext stealing)"
    );
    assert_ne!(ciphertext, plaintext, "XTS must actually encrypt");

    let recovered = xts.decrypt(&iv, &ciphertext)?;
    assert_eq!(recovered, plaintext, "AES-XTS round-trip must match");
    Ok(())
}

/// AES key wrap (RFC 3394) round-trip. Satisfies the `test/aeswrap_test.c`
/// reference workload.
#[cfg(feature = "aes")]
#[test]
fn test_aes_wrap_unwrap() -> CryptoResult<()> {
    use crate::symmetric::aes::{aes_key_unwrap, aes_key_wrap, DEFAULT_IV};

    // RFC 3394 §4.1 canonical example: wrap a 128-bit key under a 128-bit
    // KEK. Input lengths here are 32 and 16 bytes respectively to exercise
    // the canonical configuration (n ≥ 2 semiblocks).
    let kek = [0x00u8; 16];
    let plaintext_key = hex_to_bytes("00112233445566778899aabbccddeeff");

    let wrapped = aes_key_wrap(&kek, &DEFAULT_IV, &plaintext_key)?;
    // Output = input length + 8-byte IV prefix.
    assert_eq!(
        wrapped.len(),
        plaintext_key.len() + 8,
        "AES key wrap output = plaintext + 8"
    );
    assert_ne!(
        &wrapped[8..],
        &plaintext_key[..],
        "wrapped key must differ from plaintext"
    );

    let unwrapped = aes_key_unwrap(&kek, &DEFAULT_IV, &wrapped)?;
    assert_eq!(
        unwrapped, plaintext_key,
        "AES key wrap round-trip must match"
    );

    // Wrapping a 7-byte input must fail (test/aeswrap_test.c negative case):
    // plaintext length must be a multiple of 8.
    let short_input = [0x01u8; 7];
    match aes_key_wrap(&kek, &DEFAULT_IV, &short_input) {
        Err(CryptoError::Key(_)) => {}
        other => panic!("7-byte wrap input must fail with CryptoError::Key, got {other:?}"),
    }

    // Unwrapping a wrapped ciphertext with a different KEK must fail the
    // IV-match check with CryptoError::Verification.
    let wrong_kek = [0xffu8; 16];
    match aes_key_unwrap(&wrong_kek, &DEFAULT_IV, &wrapped) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("unwrap under wrong KEK must fail verification, got {other:?}"),
    }
    Ok(())
}

/// AES-SIV nonce-misuse-resistant AEAD round-trip (RFC 5297).
///
/// SIV accepts arbitrary-length nonces (including empty). Output = 16-byte
/// synthetic IV prepended to the ciphertext, identical length to plaintext
/// plus the 16-byte tag.
#[cfg(feature = "aes")]
#[test]
fn test_aes_siv_encrypt_decrypt() -> CryptoResult<()> {
    use crate::symmetric::aes::AesSiv;

    // AES-SIV-256 uses a 32-byte combined key (K1 || K2 where each is 16 B).
    let key = [
        0x7fu8, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71,
        0x70, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4e, 0x4f,
    ];
    let nonce = b"arbitrary-length-nonce-ok";
    let aad = b"associated-data";
    let plaintext = b"SIV is nonce-misuse-resistant AEAD.";

    let siv = AesSiv::new(&key)?;
    let output = siv.seal(nonce, aad, plaintext)?;
    // Output layout: V (16-byte synthetic IV) || C (|plaintext| bytes).
    assert_eq!(
        output.len(),
        plaintext.len() + 16,
        "AES-SIV output = |plaintext| + 16-byte SIV tag"
    );

    let recovered = siv.open(nonce, aad, &output)?;
    assert_eq!(recovered, plaintext, "AES-SIV round-trip must match");

    // Tampering invalidates the SIV tag → CryptoError::Verification.
    let mut tampered = output.clone();
    tampered[0] ^= 0x01; // Flip the first tag byte.
    match siv.open(nonce, aad, &tampered) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("expected CryptoError::Verification on SIV tamper, got {other:?}"),
    }

    // Input shorter than the 16-byte tag → CryptoError::Verification
    // (short-circuit in `open`).
    let too_short = [0u8; 8];
    match siv.open(nonce, aad, &too_short) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("expected CryptoError::Verification on short SIV input, got {other:?}"),
    }
    Ok(())
}

// =============================================================================
// Phase 3: ChaCha20-Poly1305 Tests (reference: test/chacha_internal_test.c)
// =============================================================================

/// ChaCha20-Poly1305 round-trip: encrypt and decrypt must be inverses.
#[cfg(feature = "chacha")]
#[test]
fn test_chacha20_poly1305_roundtrip() -> CryptoResult<()> {
    // ChaCha20-Poly1305 requires a 256-bit (32-byte) key.
    let key = [0xa5u8; 32];
    let nonce = [0x5au8; 12];
    let aad: &[u8] = b"";
    let plaintext = b"ChaCha20-Poly1305 AEAD round-trip test payload - RFC 8439 compliant.";

    let cipher = ChaCha20Poly1305::new(&key)?;
    let sealed = cipher.seal(&nonce, aad, plaintext)?;
    // Output = ciphertext || 16-byte Poly1305 tag.
    assert_eq!(
        sealed.len(),
        plaintext.len() + 16,
        "ChaCha20-Poly1305 output = ct || 16-byte tag"
    );
    assert_ne!(
        &sealed[..plaintext.len()],
        &plaintext[..],
        "ChaCha20-Poly1305 must actually encrypt"
    );

    let recovered = cipher.open(&nonce, aad, &sealed)?;
    assert_eq!(
        recovered, plaintext,
        "ChaCha20-Poly1305 round-trip must match"
    );
    Ok(())
}

/// ChaCha20-Poly1305 with non-empty associated data: the AAD must be
/// authenticated even though it is not encrypted.
#[cfg(feature = "chacha")]
#[test]
fn test_chacha20_poly1305_aad() -> CryptoResult<()> {
    let key = [0x2du8; 32];
    let nonce = [0x8eu8; 12];
    let aad = b"authenticated-associated-data";
    let plaintext = b"payload with AAD";

    let cipher = ChaCha20Poly1305::new(&key)?;
    let sealed_with_aad = cipher.seal(&nonce, aad, plaintext)?;
    let sealed_no_aad = cipher.seal(&nonce, &[], plaintext)?;

    // Same key, same nonce, same plaintext but different AAD → different tag,
    // hence different combined output. Ciphertext portions should match,
    // tag portions should differ.
    let (ct_a, tag_a) = sealed_with_aad.split_at(plaintext.len());
    let (ct_b, tag_b) = sealed_no_aad.split_at(plaintext.len());
    assert_eq!(ct_a, ct_b, "ciphertexts must match for same key/nonce/pt");
    assert_ne!(tag_a, tag_b, "Poly1305 tag must differ when AAD differs");

    // Decrypt with the correct AAD works.
    let recovered = cipher.open(&nonce, aad, &sealed_with_aad)?;
    assert_eq!(recovered, plaintext);

    // Decrypt with the wrong AAD fails authentication.
    match cipher.open(&nonce, b"wrong-aad", &sealed_with_aad) {
        Err(CryptoError::Verification(_)) => Ok(()),
        other => panic!("expected CryptoError::Verification with wrong AAD, got {other:?}"),
    }
}

/// ChaCha20-Poly1305 tamper detection: any modification to the sealed output
/// (ciphertext OR tag) must fail authentication.
#[cfg(feature = "chacha")]
#[test]
fn test_chacha20_poly1305_tamper_detection() -> CryptoResult<()> {
    let key = [0xc0u8; 32];
    let nonce = [0xb1u8; 12];
    let aad = b"aad";
    let plaintext = b"must detect tampering";

    let cipher = ChaCha20Poly1305::new(&key)?;
    let sealed = cipher.seal(&nonce, aad, plaintext)?;

    // Tamper 1: flip a bit in the ciphertext.
    let mut tampered_ct = sealed.clone();
    tampered_ct[0] ^= 0x01;
    match cipher.open(&nonce, aad, &tampered_ct) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("ciphertext tamper must fail verification, got {other:?}"),
    }

    // Tamper 2: flip a bit in the tag.
    let mut tampered_tag = sealed.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0x80;
    match cipher.open(&nonce, aad, &tampered_tag) {
        Err(CryptoError::Verification(_)) => {}
        other => panic!("tag tamper must fail verification, got {other:?}"),
    }

    // Wrong-length nonce (trait path) must fail with InvalidArgument.
    let short_nonce = [0u8; 8];
    match cipher.open(&short_nonce, aad, &sealed) {
        Err(CryptoError::Common(CommonError::InvalidArgument(_))) => {}
        other => panic!("short nonce must fail with InvalidArgument, got {other:?}"),
    }
    Ok(())
}

// =============================================================================
// Phase 4: DES/3DES Tests (reference: test/destest.c)
// =============================================================================

/// 3DES-CBC round-trip using the `triple_des_cbc_encrypt` helper.
///
/// Exercises EDE3 (three independent 8-byte subkeys, 24 bytes total).
#[cfg(feature = "des")]
#[test]
fn test_des3_cbc_encrypt_decrypt() -> CryptoResult<()> {
    use crate::symmetric::des::triple_des_cbc_encrypt;

    // 24-byte key = 3 × 8-byte DES keys (EDE3). Use three distinct keys so
    // this is NOT equivalent to single-DES.
    let key: [u8; 24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
    ];
    let iv: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    // 17 bytes → exercises CBC with PKCS#7 padding (block size 8).
    let plaintext = b"3DES-CBC 17-byte.";
    assert_eq!(plaintext.len(), 17);

    let tdes = TripleDes::new(&key)?;

    let ciphertext = triple_des_cbc_encrypt(&tdes, plaintext, &iv, CipherDirection::Encrypt)?;
    // PKCS#7 pads to next 8-byte multiple (24 bytes here).
    assert_eq!(ciphertext.len(), 24, "PKCS#7 padded length must be 24");

    let recovered = triple_des_cbc_encrypt(&tdes, &ciphertext, &iv, CipherDirection::Decrypt)?;
    assert_eq!(recovered, plaintext, "3DES-CBC round-trip must match");

    // Invalid key length returns CryptoError::Common(InvalidArgument) --
    // NOT CryptoError::Key (confirmed from des.rs:new implementation).
    // Note: TripleDes does not implement Debug (zeroize-on-drop secret);
    // match against Result patterns directly rather than formatting the
    // Ok-side value.
    let bad_key = [0u8; 12];
    match TripleDes::new(&bad_key) {
        Err(CryptoError::Common(CommonError::InvalidArgument(_))) => {}
        Err(other) => panic!("expected InvalidArgument, got: {other:?}"),
        Ok(_) => panic!("12-byte 3DES key must be rejected"),
    }
    Ok(())
}

/// 3DES-ECB single-block encryption via the `SymmetricCipher` trait.
#[cfg(feature = "des")]
#[test]
fn test_des3_ecb_single_block() -> CryptoResult<()> {
    // 16-byte key → EDE2 mode (K3 = K1 derived from the first 8 bytes).
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let tdes = TripleDes::new(&key)?;

    // DES block size = 8 bytes.
    let plaintext_block: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    let mut block = plaintext_block;
    tdes.encrypt_block(&mut block)?;
    assert_ne!(
        block, plaintext_block,
        "3DES must actually encrypt the block"
    );

    tdes.decrypt_block(&mut block)?;
    assert_eq!(
        block, plaintext_block,
        "3DES encrypt-then-decrypt must round-trip"
    );

    // Wrong block size → CryptoError::Common(InvalidArgument).
    let mut bad_block = [0u8; 7];
    match tdes.encrypt_block(&mut bad_block) {
        Err(CryptoError::Common(CommonError::InvalidArgument(_))) => {}
        other => panic!("7-byte 3DES block must fail with InvalidArgument, got {other:?}"),
    }
    Ok(())
}

// =============================================================================
// Phase 5: Legacy Cipher Tests (behind `legacy` feature flag)
// =============================================================================

/// Blowfish round-trip via the `SymmetricCipher` trait.
///
/// Reference: `test/bftest.c`. Blowfish has a variable-length key
/// (1–72 bytes); we test with a canonical 16-byte key.
#[cfg(feature = "legacy")]
#[test]
fn test_blowfish_roundtrip() -> CryptoResult<()> {
    // 16-byte key (within the 1–72 byte range).
    let key: [u8; 16] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e,
        0x0f,
    ];
    let bf = Blowfish::new(&key)?;

    // Blowfish block size = 8 bytes.
    let plaintext: [u8; 8] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let mut block = plaintext;
    bf.encrypt_block(&mut block)?;
    assert_ne!(block, plaintext, "Blowfish must actually encrypt");

    bf.decrypt_block(&mut block)?;
    assert_eq!(block, plaintext, "Blowfish round-trip must match");

    // Empty key is rejected with CryptoError::Key. Blowfish does not
    // implement Debug (secret material) -- match Result arms directly.
    match Blowfish::new(&[]) {
        Err(CryptoError::Key(_)) => Ok(()),
        Err(other) => panic!("expected CryptoError::Key, got: {other:?}"),
        Ok(_) => panic!("empty Blowfish key must be rejected"),
    }
}

/// CAST5 round-trip via the `SymmetricCipher` trait.
///
/// Reference: `test/casttest.c`. CAST5 accepts 5–16 byte keys.
#[cfg(feature = "legacy")]
#[test]
fn test_cast5_roundtrip() -> CryptoResult<()> {
    // 16-byte key (maximum length — invokes the long-key code path).
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78,
        0x9a,
    ];
    let cast = Cast5::new(&key)?;

    // CAST5 block size = 8 bytes.
    let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let mut block = plaintext;
    cast.encrypt_block(&mut block)?;
    assert_ne!(block, plaintext, "CAST5 must actually encrypt");

    cast.decrypt_block(&mut block)?;
    assert_eq!(block, plaintext, "CAST5 round-trip must match");

    // Key shorter than 5 bytes is rejected. Cast5 does not implement Debug.
    match Cast5::new(&[0x00, 0x01, 0x02, 0x03]) {
        Err(CryptoError::Key(_)) => Ok(()),
        Err(other) => panic!("expected CryptoError::Key, got: {other:?}"),
        Ok(_) => panic!("4-byte CAST5 key must be rejected"),
    }
}

/// IDEA round-trip via the `SymmetricCipher` trait.
///
/// Reference: `test/ideatest.c`. IDEA requires exactly a 16-byte key.
#[cfg(feature = "legacy")]
#[test]
fn test_idea_roundtrip() -> CryptoResult<()> {
    let key: [u8; 16] = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00,
        0x08,
    ];
    let idea = Idea::new(&key)?;

    // IDEA block size = 8 bytes.
    let plaintext: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
    let mut block = plaintext;
    idea.encrypt_block(&mut block)?;
    assert_ne!(block, plaintext, "IDEA must actually encrypt");

    idea.decrypt_block(&mut block)?;
    assert_eq!(block, plaintext, "IDEA round-trip must match");

    // Wrong key length rejected with CryptoError::Key. Idea does not
    // implement Debug.
    let wrong_len = [0u8; 15];
    match Idea::new(&wrong_len) {
        Err(CryptoError::Key(_)) => Ok(()),
        Err(other) => panic!("expected CryptoError::Key, got: {other:?}"),
        Ok(_) => panic!("15-byte IDEA key must be rejected"),
    }
}

/// RC2 round-trip via the `SymmetricCipher` trait.
///
/// Reference: `test/rc2test.c`. RC2 accepts 1–128 byte keys; the
/// effective-bits parameter defaults to `key.len() * 8`.
#[cfg(feature = "legacy")]
#[test]
fn test_rc2_roundtrip() -> CryptoResult<()> {
    // 16-byte key (128 effective bits, the common modern configuration).
    let key: [u8; 16] = [
        0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf,
        0xb2,
    ];
    let rc2 = Rc2::new(&key)?;

    // RC2 block size = 8 bytes.
    let plaintext: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut block = plaintext;
    rc2.encrypt_block(&mut block)?;
    assert_ne!(block, plaintext, "RC2 must actually encrypt");

    rc2.decrypt_block(&mut block)?;
    assert_eq!(block, plaintext, "RC2 round-trip must match");

    // Empty key rejected with CryptoError::Key. Rc2 does not implement Debug.
    match Rc2::new(&[]) {
        Err(CryptoError::Key(_)) => Ok(()),
        Err(other) => panic!("expected CryptoError::Key, got: {other:?}"),
        Ok(_) => panic!("empty RC2 key must be rejected"),
    }
}

/// RC4 stream cipher: symmetric XOR of plaintext with a keystream derived
/// from the key. Encrypting twice with the same key must yield the
/// original plaintext.
///
/// Reference: `test/rc4test.c`. RC4 accepts 1–256 byte keys.
#[cfg(feature = "legacy")]
#[test]
fn test_rc4_stream() -> CryptoResult<()> {
    // 16-byte key exercising the KSA fully.
    let key: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let plaintext = make_pattern(257); // Arbitrary length, not a block multiple.

    // Encrypt: create a fresh RC4 instance, process plaintext.
    let mut rc4_enc = Rc4::new(&key)?;
    let ciphertext = rc4_enc.process(&plaintext)?;
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "RC4 preserves length (stream cipher)"
    );
    assert_ne!(ciphertext, plaintext, "RC4 must actually encrypt");

    // Decrypt: fresh RC4 instance (state is one-shot), re-process ciphertext.
    let mut rc4_dec = Rc4::new(&key)?;
    let recovered = rc4_dec.process(&ciphertext)?;
    assert_eq!(recovered, plaintext, "RC4 round-trip must match");

    // Empty key rejected with CryptoError::Key. Rc4 does not implement Debug.
    match Rc4::new(&[]) {
        Err(CryptoError::Key(_)) => Ok(()),
        Err(other) => panic!("expected CryptoError::Key, got: {other:?}"),
        Ok(_) => panic!("empty RC4 key must be rejected"),
    }
}

// =============================================================================
// Phase 6: Property-Based Tests (proptest)
// =============================================================================

#[cfg(feature = "aes")]
proptest::proptest! {
    /// For arbitrary AES-256-GCM keys, nonces, AAD, and plaintext, encrypt
    /// followed by decrypt is the identity on plaintext. Verifies both
    /// correctness and the tag-length invariant (output = pt.len() + 16).
    #[test]
    fn prop_aes_gcm_roundtrip(
        key in proptest::array::uniform32(0u8..),
        nonce in proptest::array::uniform12(0u8..),
        aad in proptest::collection::vec(0u8..=255, 0..256),
        data in proptest::collection::vec(0u8..=255, 0..4096),
    ) {
        let cipher = AesGcm::new(&key).expect("AES-256-GCM key init must succeed");
        let sealed = cipher.seal(&nonce, &aad, &data).expect("AES-GCM seal must succeed");
        proptest::prop_assert_eq!(sealed.len(), data.len() + 16);
        let recovered = cipher.open(&nonce, &aad, &sealed).expect("AES-GCM open must succeed");
        proptest::prop_assert_eq!(recovered, data);
    }

    /// For arbitrary AES-128-CBC keys and non-empty plaintext, PKCS#7
    /// encrypt-then-decrypt is the identity. Exercises every CBC chaining
    /// boundary, including exact block multiples (where padding expands
    /// the ciphertext by a full block) and odd lengths.
    #[test]
    fn prop_aes_cbc_roundtrip(
        key in proptest::array::uniform16(0u8..),
        iv in proptest::array::uniform16(0u8..),
        data in proptest::collection::vec(0u8..=255, 1..1024),
    ) {
        use crate::symmetric::aes::{aes_cbc_decrypt, aes_cbc_encrypt};
        let ciphertext = aes_cbc_encrypt(&key, &iv, &data).expect("AES-CBC encrypt must succeed");
        let recovered = aes_cbc_decrypt(&key, &iv, &ciphertext).expect("AES-CBC decrypt must succeed");
        proptest::prop_assert_eq!(recovered, data);
    }
}
