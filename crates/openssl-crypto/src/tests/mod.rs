//! Integration tests for the openssl-crypto crate.
//!
//! This module aggregates all test submodules covering the full public API surface of libcrypto.
//! Target: 80% line coverage per Gate 10.

// =============================================================================
// Core Infrastructure Test Modules (always compiled)
// =============================================================================

/// Library initialization tests — validates RUN_ONCE stage equivalents,
/// init/cleanup ordering, and thread-safe one-time initialization via `std::sync::Once`.
mod test_init;

/// `LibContext` lifecycle tests — validates `OSSL_LIB_CTX` equivalent (`LibContext`)
/// creation, cloning, dropping, and per-context provider isolation.
mod test_context;

/// Provider system tests — validates provider loading, activation, deactivation,
/// property-based algorithm fetch, and dynamic dispatch via trait objects.
mod test_provider;

/// EVP high-level API tests — validates EVP abstraction layer including
/// message digests, ciphers, KDFs, MACs, signatures, KEM, and key management.
mod test_evp;

/// BIO I/O abstraction tests — validates trait-based I/O (`Read`/`Write`)
/// for memory, file, socket, and filter chain BIO implementations.
mod test_bio;

/// Threading primitive tests — validates Rust-native threading abstractions
/// replacing `CRYPTO_THREAD_lock_new`, RCU read/write, and thread-local storage.
mod test_thread;

/// CPU detection tests — validates runtime CPU capability detection
/// (AES-NI, SHA extensions, AVX, NEON) via `std::arch::is_x86_feature_detected`.
mod test_cpu_detect;

// =============================================================================
// Algorithm Test Modules (always compiled — core algorithms)
// =============================================================================

/// BigNum arithmetic tests — validates arbitrary-precision integer operations
/// including add, mul, div, mod, Montgomery multiplication, and primality testing.
mod test_bn;

/// Hash/digest tests — validates SHA-1, SHA-2, SHA-3, SHAKE, and legacy hash
/// algorithms through the EVP digest interface.
mod test_hash;

/// Symmetric cipher tests — validates AES (GCM/CCM/CTR/XTS), ChaCha20-Poly1305,
/// DES/3DES, and legacy ciphers through the EVP cipher interface.
mod test_symmetric;

/// MAC tests — validates HMAC, CMAC, GMAC, KMAC, Poly1305, and SipHash
/// through the EVP MAC interface.
mod test_mac;

/// KDF tests — validates HKDF, PBKDF2, Argon2, scrypt, and KBKDF
/// through the EVP KDF interface.
mod test_kdf;

/// Random number generation tests — validates DRBG (CTR, Hash, HMAC),
/// entropy seeding, and the `EVP_RAND` interface equivalents.
mod test_rand;

/// ASN.1 encoding tests — validates DER encoding/decoding, ASN.1 template
/// system, and round-trip correctness for all supported ASN.1 types.
mod test_asn1;

/// PEM encoding tests — validates PEM encode/decode round-trips for
/// certificates, private keys, public keys, and CSRs per RFC 7468.
mod test_pem;

// =============================================================================
// Feature-Gated Test Modules (protocol extensions and optional algorithms)
// =============================================================================

/// RSA tests — validates RSA keygen, encrypt/decrypt, OAEP padding,
/// and PSS signatures through the EVP interface.
#[cfg(feature = "rsa")]
mod test_rsa;

/// Elliptic curve tests — validates EC groups, point operations, ECDSA
/// sign/verify, ECDH key exchange, and X25519/Ed25519/X448/Ed448.
#[cfg(feature = "ec")]
mod test_ec;

/// Diffie-Hellman tests — validates DH parameter generation, key exchange,
/// and finite-field cryptography (FFC) parameter validation.
#[cfg(feature = "dh")]
mod test_dh;

/// DSA tests — validates DSA parameter generation, sign/verify operations,
/// and key serialization round-trips.
#[cfg(feature = "dsa")]
mod test_dsa;

/// Post-quantum tests — validates ML-KEM (FIPS 203), ML-DSA (FIPS 204),
/// SLH-DSA (FIPS 205), and LMS (SP 800-208) implementations.
#[cfg(feature = "pqc")]
mod test_pqc;

/// X.509 tests — validates certificate parsing, chain verification (RFC 5280),
/// CRL processing, extensions, and certificate store operations.
mod test_x509;

/// PKCS tests — validates PKCS#7, PKCS#12, and CMS operations including
/// signed/enveloped data, key import/export, and MAC verification.
mod test_pkcs;

/// HPKE tests — validates Hybrid Public Key Encryption per RFC 9180
/// including all KEM/KDF/AEAD combinations.
#[cfg(feature = "hpke")]
mod test_hpke;

/// OCSP tests — validates Online Certificate Status Protocol client
/// operations including request/response encoding and stapling.
#[cfg(feature = "ocsp")]
mod test_ocsp;

/// Certificate Transparency tests — validates SCT parsing, verification,
/// and CT log integration per RFC 6962.
#[cfg(feature = "ct")]
mod test_ct;

/// CMP tests — validates Certificate Management Protocol client operations
/// including IR, CR, KUR, and error handling.
#[cfg(feature = "cmp")]
mod test_cmp;

/// Timestamping tests — validates RFC 3161 timestamp request/response
/// encoding, verification, and token processing.
#[cfg(feature = "ts")]
mod test_ts;
