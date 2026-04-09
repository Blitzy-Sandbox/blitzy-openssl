# Feature Parity Matrix — OpenSSL C → Rust

## 1. Overview

This document provides a comprehensive mapping of every feature in the OpenSSL 4.0 C codebase to its corresponding Rust implementation in the `openssl-rs` workspace. It fulfills the requirements of:

- **AAP §0.5.1** — File-by-file transformation plan deliverable
- **AAP §0.8.4** — No feature gaps acceptable in core functionality
- **Gate 4** — Real-world artifact verification (concrete inputs named)
- **Gate 5** — API contract verification at public boundary

### Status Legend

| Icon | Status | Meaning |
|------|--------|---------|
| ✅ | IMPLEMENTED | Fully implemented in Rust with tests |
| 🔄 | IN-PROGRESS | Implementation started, not yet complete |
| ❌ | NOT-IMPLEMENTED | Planned but not yet started |
| ⏭️ | OUT-OF-SCOPE | Explicitly excluded per AAP §0.3.2 |

---

## 2. Feature Matrix by Category

### 2a. Symmetric Ciphers

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| AES-128/192/256-ECB | `crypto/aes/*.c`, `providers/implementations/ciphers/cipher_aes.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | All key sizes: 128, 192, 256 |
| AES-128/192/256-CBC | `crypto/aes/*.c`, `providers/implementations/ciphers/cipher_aes.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Includes CBC-CTS variants |
| AES-128/192/256-CTR | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Counter mode |
| AES-128/192/256-OFB | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Output feedback mode |
| AES-128/192/256-CFB | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | CFB, CFB1, CFB8 variants |
| AES-128/192/256-GCM | `crypto/aes/*.c`, `crypto/modes/gcm128.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Authenticated encryption |
| AES-128/192/256-CCM | `crypto/aes/*.c`, `crypto/modes/ccm128.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Counter with CBC-MAC |
| AES-128/256-XTS | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | XEX-based Tweaked-codebook with Ciphertext Stealing |
| AES-128/192/256-OCB | `crypto/aes/*.c`, `crypto/modes/ocb128.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Offset Codebook Mode |
| AES-128/192/256-SIV | `crypto/aes/*.c`, `crypto/modes/siv128.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Synthetic IV mode |
| AES-128/192/256-GCM-SIV | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Nonce misuse resistant |
| AES-128/192/256-WRAP | `crypto/aes/*.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Key wrap (RFC 3394), wrap-pad, inverse variants |
| AES-CBC-HMAC-SHA1 | `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Composite AEAD for TLS |
| AES-CBC-HMAC-SHA256 | `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha256.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Composite AEAD for TLS |
| AES-CBC-HMAC-SHA1-ETM | `providers/implementations/ciphers/` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Encrypt-then-MAC variant |
| AES-CBC-HMAC-SHA256-ETM | `providers/implementations/ciphers/` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Encrypt-then-MAC variant |
| AES-CBC-HMAC-SHA512-ETM | `providers/implementations/ciphers/` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | Encrypt-then-MAC variant |
| ChaCha20 | `crypto/chacha/*.c` | `openssl-crypto::symmetric::chacha20` | ✅ IMPLEMENTED | Stream cipher |
| ChaCha20-Poly1305 | `crypto/chacha/*.c`, `crypto/poly1305/*.c` | `openssl-crypto::symmetric::chacha20` | ✅ IMPLEMENTED | AEAD construction (RFC 8439) |
| 3DES (DES-EDE3) | `crypto/des/*.c` | `openssl-crypto::symmetric::des` | ✅ IMPLEMENTED | ECB, CBC, OFB, CFB, CFB1, CFB8; includes DES3-WRAP |
| 3DES (DES-EDE2) | `crypto/des/*.c` | `openssl-crypto::symmetric::des` | ✅ IMPLEMENTED | Two-key Triple DES: ECB, CBC, OFB, CFB |
| ARIA-128/192/256 | `crypto/aria/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | ECB, CBC, OFB, CFB, CFB1, CFB8, CTR, GCM, CCM |
| Camellia-128/192/256 | `crypto/camellia/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | ECB, CBC, CBC-CTS, OFB, CFB, CFB1, CFB8, CTR |
| SM4 | `crypto/sm4/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | ECB, CBC, CTR, OFB, CFB, GCM, CCM, XTS |
| Blowfish (BF) | `crypto/bf/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB |
| CAST5 | `crypto/cast/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB |
| IDEA | `crypto/idea/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB |
| SEED | `crypto/seed/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB |
| RC2 | `crypto/rc2/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC (40/64/128), CFB, OFB |
| RC4 | `crypto/rc4/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; RC4, RC4-40, RC4-HMAC-MD5 |
| RC5 | `crypto/rc5/*.c` | `openssl-crypto::symmetric::legacy` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB |
| DES (single) | `crypto/des/*.c` | `openssl-crypto::symmetric::des` | ✅ IMPLEMENTED | Legacy provider; ECB, CBC, OFB, CFB, CFB1, CFB8 |
| DESX-CBC | `crypto/des/*.c` | `openssl-crypto::symmetric::des` | ✅ IMPLEMENTED | Legacy provider |
| NULL cipher | `providers/implementations/ciphers/cipher_null.c` | `openssl-crypto::symmetric::aes` | ✅ IMPLEMENTED | No-op cipher for testing |

### 2b. Hash / Digest Algorithms

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| SHA-1 | `crypto/sha/sha1dgst.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-224 | `crypto/sha/sha256.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-256 | `crypto/sha/sha256.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-256/192 | `crypto/sha/sha256.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Internal truncated variant |
| SHA-2-384 | `crypto/sha/sha512.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-512 | `crypto/sha/sha512.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-512/224 | `crypto/sha/sha512.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-2-512/256 | `crypto/sha/sha512.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Default provider |
| SHA-3-224 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Keccak-based |
| SHA-3-256 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Keccak-based |
| SHA-3-384 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Keccak-based |
| SHA-3-512 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Keccak-based |
| SHAKE-128 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Extendable-output function (XOF) |
| SHAKE-256 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Extendable-output function (XOF) |
| CSHAKE-128 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Customizable SHAKE |
| CSHAKE-256 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Customizable SHAKE |
| KECCAK-224/256/384/512 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | Raw Keccak |
| CSHAKE-KECCAK-128 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | For KMAC support |
| CSHAKE-KECCAK-256 | `crypto/sha/sha3.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | For KMAC support |
| MD5 | `crypto/md5/*.c` | `openssl-crypto::hash::md5` | ✅ IMPLEMENTED | Default provider (conditional) |
| MD5-SHA1 | `crypto/md5/*.c` | `openssl-crypto::hash::md5` | ✅ IMPLEMENTED | Composite digest |
| BLAKE2s-256 | `crypto/blake2/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Default provider (conditional) |
| BLAKE2b-512 | `crypto/blake2/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Default provider (conditional) |
| SM3 | `crypto/sm3/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Chinese national standard |
| RIPEMD-160 | `crypto/ripemd/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Default + Legacy provider |
| MD2 | `crypto/md2/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Legacy provider only |
| MD4 | `crypto/md4/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Legacy provider only |
| MDC2 | `crypto/mdc2/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Legacy provider only |
| Whirlpool | `crypto/whrlpool/*.c` | `openssl-crypto::hash::legacy` | ✅ IMPLEMENTED | Legacy provider only |
| ML-DSA-MU digest | `providers/defltprov.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | ML-DSA internal mu hash |
| NULL digest | `providers/implementations/digests/nullmd.c` | `openssl-crypto::hash::sha` | ✅ IMPLEMENTED | No-op digest for testing |

### 2c. Message Authentication Codes (MACs)

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| HMAC | `crypto/hmac/*.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Default provider; all hash combinations |
| CMAC | `crypto/cmac/*.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Default provider (conditional) |
| GMAC | `providers/implementations/macs/gmac_prov.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | GCM-based MAC |
| KMAC-128 | `providers/implementations/macs/kmac_prov.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Keccak-based MAC |
| KMAC-256 | `providers/implementations/macs/kmac_prov.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Keccak-based MAC |
| Poly1305 | `crypto/poly1305/*.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Default provider (conditional) |
| SipHash | `crypto/siphash/*.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | Default provider (conditional) |
| BLAKE2b-MAC | `providers/implementations/macs/blake2b_mac.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | BLAKE2b as MAC |
| BLAKE2s-MAC | `providers/implementations/macs/blake2s_mac.c` | `openssl-crypto::mac` | ✅ IMPLEMENTED | BLAKE2s as MAC |

### 2d. Key Derivation Functions (KDFs)

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| HKDF | `providers/implementations/kdfs/hkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 5869; default provider |
| HKDF-SHA256 | `providers/implementations/kdfs/hkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Pre-bound HKDF variant |
| HKDF-SHA384 | `providers/implementations/kdfs/hkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Pre-bound HKDF variant |
| HKDF-SHA512 | `providers/implementations/kdfs/hkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Pre-bound HKDF variant |
| TLS1.3-KDF | `providers/implementations/kdfs/hkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | TLS 1.3 key schedule |
| TLS1-PRF | `providers/implementations/kdfs/tls1_prf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | TLS 1.0–1.2 PRF |
| PBKDF2 | `providers/implementations/kdfs/pbkdf2.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 8018 |
| PBKDF1 | `providers/implementations/kdfs/pbkdf1.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Legacy provider only |
| PKCS12-KDF | `providers/implementations/kdfs/pkcs12kdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | PKCS#12 key derivation |
| scrypt | `providers/implementations/kdfs/scrypt.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 7914 (conditional) |
| Argon2i | `providers/implementations/kdfs/argon2.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 9106 (conditional) |
| Argon2d | `providers/implementations/kdfs/argon2.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 9106 (conditional) |
| Argon2id | `providers/implementations/kdfs/argon2.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | RFC 9106 (conditional) |
| KBKDF | `providers/implementations/kdfs/kbkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | SP 800-108 (conditional) |
| SSKDF | `providers/implementations/kdfs/sskdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | SP 800-56C single-step (conditional) |
| SSHKDF | `providers/implementations/kdfs/sshkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | SSH key derivation (conditional) |
| X9.63-KDF | `providers/implementations/kdfs/x942kdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | ANSI X9.63 (conditional) |
| X9.42-KDF | `providers/implementations/kdfs/x942kdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | ANSI X9.42 ASN.1 (conditional) |
| KRB5-KDF | `providers/implementations/kdfs/krb5kdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Kerberos KDF (conditional) |
| HMAC-DRBG-KDF | `providers/implementations/kdfs/hmac_drbg_kdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | HMAC DRBG as KDF (conditional) |
| SNMP-KDF | `providers/implementations/kdfs/snmpkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | SNMP password-to-key (conditional) |
| SRTP-KDF | `providers/implementations/kdfs/srtpkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | SRTP key derivation (conditional) |
| PVK-KDF | `providers/implementations/kdfs/pvkkdf.c` | `openssl-crypto::kdf` | ✅ IMPLEMENTED | Legacy provider only (conditional) |

### 2e. Asymmetric Cryptography: RSA

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| RSA key generation | `crypto/rsa/rsa_gen.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | All standard key sizes |
| RSA sign/verify | `crypto/rsa/rsa_sign.c`, `providers/implementations/signature/rsa_sig.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | PKCS#1 v1.5, PSS |
| RSA encrypt/decrypt | `crypto/rsa/rsa_ossl.c`, `providers/implementations/asymciphers/rsa_enc.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | PKCS#1 v1.5, OAEP |
| RSA-OAEP padding | `crypto/rsa/rsa_oaep.c` | `openssl-crypto::rsa::oaep` | ✅ IMPLEMENTED | RFC 8017 |
| RSA-PSS signatures | `crypto/rsa/rsa_pss.c` | `openssl-crypto::rsa::pss` | ✅ IMPLEMENTED | RFC 8017 |
| RSA-PSS key management | `providers/implementations/keymgmt/rsa_kmgmt.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | Dedicated RSA-PSS keymgmt |
| RSA key management | `providers/implementations/keymgmt/rsa_kmgmt.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | Provider keymgmt |
| RSA-KEM | `providers/implementations/kem/rsa_kem.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | RSA Key Encapsulation Mechanism |
| RSA composite signatures | `providers/defltprov.c` | `openssl-crypto::rsa` | ✅ IMPLEMENTED | RSA-SHA1, RSA-SHA224, RSA-SHA256, RSA-SHA384, RSA-SHA512, RSA-SHA3-*, RSA-SM3, RSA-RIPEMD160 |

### 2f. Asymmetric Cryptography: Elliptic Curves

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| ECDSA sign/verify | `crypto/ec/ecdsa_sign.c`, `crypto/ec/ecdsa_vrf.c` | `openssl-crypto::ec::ecdsa` | ✅ IMPLEMENTED | P-256, P-384, P-521, and other named curves |
| ECDSA composite signatures | `providers/defltprov.c` | `openssl-crypto::ec::ecdsa` | ✅ IMPLEMENTED | ECDSA-SHA1, ECDSA-SHA224, ECDSA-SHA256, ECDSA-SHA384, ECDSA-SHA512, ECDSA-SHA3-* |
| ECDH key exchange | `crypto/ec/ecdh_ossl.c` | `openssl-crypto::ec::ecdh` | ✅ IMPLEMENTED | Ephemeral and static ECDH |
| X25519 key exchange | `crypto/ec/ecx_meth.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | RFC 7748 |
| X448 key exchange | `crypto/ec/ecx_meth.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | RFC 7748 |
| Ed25519 signatures | `crypto/ec/ecx_meth.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | RFC 8032; Ed25519, Ed25519ph, Ed25519ctx |
| Ed448 signatures | `crypto/ec/ecx_meth.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | RFC 8032; Ed448, Ed448ph |
| EC key management | `providers/implementations/keymgmt/ec_kmgmt.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | All named curves (P-256, P-384, P-521, etc.) |
| ECX key management | `providers/implementations/keymgmt/ecx_kmgmt.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | X25519, X448, Ed25519, Ed448 |
| EC point arithmetic | `crypto/ec/ec_lib.c`, `crypto/ec/ecp_*.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | Point add, multiply, double, on-curve check |
| EC group operations | `crypto/ec/ec_curve.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | Named curves, custom curves |
| EC-KEM | `providers/implementations/kem/ec_kem.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | EC-based Key Encapsulation |
| ECX-KEM | `providers/implementations/kem/ecx_kem.c` | `openssl-crypto::ec::curve25519` | ✅ IMPLEMENTED | X25519-KEM, X448-KEM |
| SM2 signatures | `crypto/sm2/*.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | Chinese national standard (conditional) |
| SM2 encryption | `providers/implementations/asymciphers/sm2_enc.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | SM2 asymmetric encryption (conditional) |
| SM2 key management | `providers/implementations/keymgmt/ec_kmgmt.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | SM2 key management (conditional) |
| curveSM2 key management | `providers/defltprov.c` | `openssl-crypto::ec` | ✅ IMPLEMENTED | Hybrid SM2 key management |

### 2g. Asymmetric Cryptography: DH / DSA

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| DH key exchange | `crypto/dh/*.c`, `providers/implementations/exchange/dh_exch.c` | `openssl-crypto::dh` | ✅ IMPLEMENTED | Standard and named groups |
| DH key management | `providers/implementations/keymgmt/dh_kmgmt.c` | `openssl-crypto::dh` | ✅ IMPLEMENTED | DH and DHX keymgmt |
| DH parameter generation | `crypto/dh/dh_gen.c` | `openssl-crypto::dh` | ✅ IMPLEMENTED | Safe prime groups |
| DSA sign/verify | `crypto/dsa/*.c`, `providers/implementations/signature/dsa_sig.c` | `openssl-crypto::dsa` | ✅ IMPLEMENTED | All hash combinations |
| DSA composite signatures | `providers/defltprov.c` | `openssl-crypto::dsa` | ✅ IMPLEMENTED | DSA-SHA1, DSA-SHA224, DSA-SHA256, DSA-SHA384, DSA-SHA512, DSA-SHA3-* |
| DSA key management | `providers/implementations/keymgmt/dsa_kmgmt.c` | `openssl-crypto::dsa` | ✅ IMPLEMENTED | Provider keymgmt |
| DSA parameter generation | `crypto/dsa/dsa_gen.c` | `openssl-crypto::dsa` | ✅ IMPLEMENTED | FIPS 186-4 compliant |
| FFC parameters (shared DH/DSA) | `crypto/ffc/*.c` | `openssl-crypto::dh` | ✅ IMPLEMENTED | Finite field cryptography utilities |

### 2h. Post-Quantum Cryptography

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| ML-KEM-512 | `crypto/ml_kem/*.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | FIPS 203; keygen, encap, decap |
| ML-KEM-768 | `crypto/ml_kem/*.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | FIPS 203 |
| ML-KEM-1024 | `crypto/ml_kem/*.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | FIPS 203 |
| ML-KEM hybrid: X25519MLKEM768 | `providers/defltprov.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | Hybrid PQ KEM |
| ML-KEM hybrid: X448MLKEM1024 | `providers/defltprov.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | Hybrid PQ KEM |
| ML-KEM hybrid: SecP256r1MLKEM768 | `providers/defltprov.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | Hybrid PQ KEM |
| ML-KEM hybrid: SecP384r1MLKEM1024 | `providers/defltprov.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | Hybrid PQ KEM |
| ML-KEM hybrid: curveSM2MLKEM768 | `providers/defltprov.c` | `openssl-crypto::pqc::ml_kem` | ✅ IMPLEMENTED | Hybrid SM2+ML-KEM (conditional) |
| ML-DSA-44 | `crypto/ml_dsa/*.c` | `openssl-crypto::pqc::ml_dsa` | ✅ IMPLEMENTED | FIPS 204; sign, verify, keygen |
| ML-DSA-65 | `crypto/ml_dsa/*.c` | `openssl-crypto::pqc::ml_dsa` | ✅ IMPLEMENTED | FIPS 204 |
| ML-DSA-87 | `crypto/ml_dsa/*.c` | `openssl-crypto::pqc::ml_dsa` | ✅ IMPLEMENTED | FIPS 204 |
| SLH-DSA-SHA2-128s/128f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205; SHA2-based, small/fast |
| SLH-DSA-SHA2-192s/192f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205 |
| SLH-DSA-SHA2-256s/256f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205 |
| SLH-DSA-SHAKE-128s/128f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205; SHAKE-based |
| SLH-DSA-SHAKE-192s/192f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205 |
| SLH-DSA-SHAKE-256s/256f | `crypto/slh_dsa/*.c` | `openssl-crypto::pqc::slh_dsa` | ✅ IMPLEMENTED | FIPS 205 |
| LMS verification | `crypto/lms/*.c` | `openssl-crypto::pqc::lms` | ✅ IMPLEMENTED | SP 800-208; verify-only (sign out of scope) |

### 2i. TLS / DTLS Protocol

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| TLS 1.0 | `ssl/s3_lib.c`, `ssl/methods.c` | `openssl-ssl::method` | ✅ IMPLEMENTED | SSLv3/TLS method construction |
| TLS 1.1 | `ssl/s3_lib.c`, `ssl/methods.c` | `openssl-ssl::method` | ✅ IMPLEMENTED | Method construction |
| TLS 1.2 | `ssl/s3_lib.c`, `ssl/methods.c` | `openssl-ssl::method` | ✅ IMPLEMENTED | Full handshake, resumption, renegotiation |
| TLS 1.3 | `ssl/tls13_enc.c`, `ssl/t1_enc.c` | `openssl-ssl::tls13` | ✅ IMPLEMENTED | 0-RTT, PSK, key update, post-handshake auth |
| DTLS 1.0 | `ssl/d1_lib.c`, `ssl/d1_msg.c` | `openssl-ssl::dtls` | ✅ IMPLEMENTED | Datagram TLS |
| DTLS 1.2 | `ssl/d1_lib.c`, `ssl/d1_msg.c` | `openssl-ssl::dtls` | ✅ IMPLEMENTED | Datagram TLS with cookie exchange |
| SSL_CTX lifecycle | `ssl/ssl_lib.c` | `openssl-ssl::ssl_ctx` | ✅ IMPLEMENTED | Context creation, configuration, shutdown |
| SSL connection lifecycle | `ssl/ssl_lib.c`, `ssl/bio_ssl.c` | `openssl-ssl::ssl` | ✅ IMPLEMENTED | Connection creation, handshake, I/O, shutdown |
| Cipher suite selection | `ssl/ssl_ciph.c` | `openssl-ssl::cipher` | ✅ IMPLEMENTED | Cipher string parsing and selection |
| Session management | `ssl/ssl_sess.c` | `openssl-ssl::session` | ✅ IMPLEMENTED | Session cache, tickets, serialization |
| Session ASN.1 serialization | `ssl/ssl_asn1.c` | `openssl-ssl::session` | ✅ IMPLEMENTED | ASN.1 session encoding/decoding |
| Certificate management | `ssl/ssl_cert.c`, `ssl/ssl_rsa.c` | `openssl-ssl::cert` | ✅ IMPLEMENTED | Certificate chain, private key loading |
| Certificate compression | `ssl/ssl_cert_comp.c` | `openssl-ssl::cert` | ✅ IMPLEMENTED | RFC 8879 certificate compression |
| SSL_CONF command engine | `ssl/ssl_conf.c`, `ssl/ssl_mcnf.c` | `openssl-ssl::config` | ✅ IMPLEMENTED | Configuration command processor |
| Handshake state machine | `ssl/statem/statem.c` | `openssl-ssl::statem` | ✅ IMPLEMENTED | Dual-layer MSG_FLOW + HANDSHAKE states |
| Client handshake | `ssl/statem/statem_clnt.c` | `openssl-ssl::statem::client` | ✅ IMPLEMENTED | Client-side transitions |
| Server handshake | `ssl/statem/statem_srvr.c` | `openssl-ssl::statem::server` | ✅ IMPLEMENTED | Server-side transitions |
| Extension framework | `ssl/statem/extensions.c` et al. | `openssl-ssl::statem::extensions` | ✅ IMPLEMENTED | All TLS extensions |
| DTLS fragment/reassembly | `ssl/statem/statem_dtls.c` | `openssl-ssl::statem::dtls` | ✅ IMPLEMENTED | Handshake message fragmentation |
| TLS record layer | `ssl/record/rec_layer_s3.c` | `openssl-ssl::record::tls` | ✅ IMPLEMENTED | TLS record I/O |
| DTLS record layer | `ssl/record/rec_layer_d1.c` | `openssl-ssl::record::dtls` | ✅ IMPLEMENTED | DTLS record I/O |
| TLS 1.3 encryption | `ssl/tls13_enc.c` | `openssl-ssl::tls13` | ✅ IMPLEMENTED | Key schedule, traffic secrets |
| TLS extension processing | `ssl/t1_lib.c` | `openssl-ssl::t1_lib` | ✅ IMPLEMENTED | Extension parsing, server name, ALPN |
| TLS tracing | `ssl/t1_trce.c` | `openssl-ssl::t1_lib` | ✅ IMPLEMENTED | Protocol trace debugging |
| SSLv3/TLS library functions | `ssl/s3_lib.c`, `ssl/s3_enc.c`, `ssl/s3_msg.c` | `openssl-ssl::s3_lib` | ✅ IMPLEMENTED | Low-level TLS utilities |
| DTLS-SRTP | `ssl/d1_srtp.c` | `openssl-ssl::srtp` | ✅ IMPLEMENTED | RFC 5764 DTLS-SRTP extension |
| TLS-SRP | `ssl/tls_srp.c` | `openssl-ssl::s3_lib` | ✅ IMPLEMENTED | SRP key exchange (deprecated) |
| SSL initialization | `ssl/ssl_init.c` | `openssl-ssl::lib` | ✅ IMPLEMENTED | One-time init routines |
| SSL methods | `ssl/methods.c` | `openssl-ssl::method` | ✅ IMPLEMENTED | TLS/DTLS method constructors |
| Priority queue | `ssl/priority_queue.c`, `ssl/pqueue.c` | `openssl-ssl::lib` | ✅ IMPLEMENTED | Internal data structures |
| BIO SSL | `ssl/bio_ssl.c` | `openssl-ssl::ssl` | ✅ IMPLEMENTED | BIO wrapping SSL connections |

### 2j. QUIC Protocol

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| QUIC v1 engine | `ssl/quic/quic_engine.c` | `openssl-ssl::quic::engine` | ✅ IMPLEMENTED | RFC 9000; top-level QUIC engine |
| QUIC reactor | `ssl/quic/quic_reactor.c`, `quic_reactor_wait_ctx.c` | `openssl-ssl::quic::reactor` | ✅ IMPLEMENTED | Event-driven poll integration (async Rust) |
| QUIC port (datagram demux) | `ssl/quic/quic_port.c` | `openssl-ssl::quic::port` | ✅ IMPLEMENTED | Datagram demultiplexing |
| QUIC channel | `ssl/quic/quic_channel.c` | `openssl-ssl::quic::channel` | ✅ IMPLEMENTED | Per-connection state machine |
| QUIC stream map | `ssl/quic/quic_stream_map.c` | `openssl-ssl::quic::stream` | ✅ IMPLEMENTED | Stream management and flow control |
| QUIC flow control | `ssl/quic/quic_fc.c` | `openssl-ssl::quic::stream` | ✅ IMPLEMENTED | Connection and stream-level flow control |
| QUIC TX packetiser | `ssl/quic/quic_txp.c`, `quic_txpim.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | Packet construction and coalescing |
| QUIC RX decryption | `ssl/quic/quic_record_rx.c` | `openssl-ssl::quic::rx` | ✅ IMPLEMENTED | Packet decryption and parsing |
| QUIC ACK manager | `ssl/quic/quic_ackm.c` | `openssl-ssl::quic::ack` | ✅ IMPLEMENTED | ACK generation and loss detection |
| QUIC congestion control | `ssl/quic/cc_newreno.c` | `openssl-ssl::quic::cc` | ✅ IMPLEMENTED | NewReno congestion controller |
| QUIC TLS shim | `ssl/quic/quic_tls.c`, `quic_tls_api.c` | `openssl-ssl::quic::tls_shim` | ✅ IMPLEMENTED | TLS 1.3 handshake integration |
| QUIC record shared | `ssl/quic/quic_record_shared.c` | `openssl-ssl::quic::rx` | ✅ IMPLEMENTED | Shared record utilities |
| QUIC record TX | `ssl/quic/quic_record_tx.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | TX record layer |
| QUIC record utility | `ssl/quic/quic_record_util.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | Record utility functions |
| QUIC LCID manager | `ssl/quic/quic_lcidm.c` | `openssl-ssl::quic::channel` | ✅ IMPLEMENTED | Local Connection ID management |
| QUIC RCID manager | `ssl/quic/quic_rcidm.c` | `openssl-ssl::quic::channel` | ✅ IMPLEMENTED | Remote Connection ID management |
| QUIC demux | `ssl/quic/quic_demux.c` | `openssl-ssl::quic::port` | ✅ IMPLEMENTED | Packet demultiplexing |
| QUIC CFQ | `ssl/quic/quic_cfq.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | Crypto frame queue |
| QUIC FIFD | `ssl/quic/quic_fifd.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | Frame-in-flight dispatcher |
| QUIC impl | `ssl/quic/quic_impl.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | SSL API integration layer |
| QUIC obj | `ssl/quic/quic_obj.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | QUIC object lifecycle |
| QUIC method | `ssl/quic/quic_method.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | SSL_METHOD for QUIC |
| QUIC statm | `ssl/quic/quic_statm.c` | `openssl-ssl::quic::ack` | ✅ IMPLEMENTED | Statistics manager |
| QUIC SRT generator | `ssl/quic/quic_srt_gen.c` | `openssl-ssl::quic::channel` | ✅ IMPLEMENTED | Stateless Reset Token generation |
| QUIC SRTM | `ssl/quic/quic_srtm.c` | `openssl-ssl::quic::channel` | ✅ IMPLEMENTED | SRT manager |
| QUIC SF list | `ssl/quic/quic_sf_list.c` | `openssl-ssl::quic::stream` | ✅ IMPLEMENTED | Stream frame list |
| QUIC read stream | `ssl/quic/quic_rstream.c` | `openssl-ssl::quic::stream` | ✅ IMPLEMENTED | Read stream buffer |
| QUIC send stream | `ssl/quic/quic_sstream.c` | `openssl-ssl::quic::stream` | ✅ IMPLEMENTED | Send stream buffer |
| QUIC RX depacketizer | `ssl/quic/quic_rx_depack.c` | `openssl-ssl::quic::rx` | ✅ IMPLEMENTED | Packet parsing and dispatch |
| QUIC thread assist | `ssl/quic/quic_thread_assist.c` | `openssl-ssl::quic::engine` | ✅ IMPLEMENTED | Async thread management |
| QUIC wire encoding | `ssl/quic/quic_wire.c`, `quic_wire_pkt.c` | `openssl-ssl::quic::tx` | ✅ IMPLEMENTED | Wire format encoding/decoding |
| QUIC types | `ssl/quic/quic_types.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | Shared QUIC type definitions |
| QUIC uint set | `ssl/quic/uint_set.c` | `openssl-ssl::quic::ack` | ✅ IMPLEMENTED | Integer interval set |
| QUIC trace | `ssl/quic/quic_trace.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | Protocol tracing |
| QUIC JSON encoder | `ssl/quic/json_enc.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | JSON encoding for qlog |
| QLOG | `ssl/quic/qlog.c`, `qlog_event_helpers.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | QUIC logging (draft-ietf-quic-qlog) |
| QUIC test server | `ssl/quic/quic_tserver.c` | `openssl-ssl::quic` | ✅ IMPLEMENTED | Built-in test server |

### 2k. Encrypted Client Hello (ECH)

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| ECH engine | `ssl/ech/ech_internal.c` | `openssl-ssl::ech` | ✅ IMPLEMENTED | RFC 9849; ECH core logic |
| ClientHelloInner encoding | `ssl/ech/ech_internal.c` | `openssl-ssl::ech::encode` | ✅ IMPLEMENTED | Inner ClientHello construction |
| Server-side trial decryption | `ssl/ech/ech_internal.c` | `openssl-ssl::ech::decrypt` | ✅ IMPLEMENTED | ECH decryption and fallback |
| ECH configuration | `ssl/ech/ech_config.c` | `openssl-ssl::ech` | ✅ IMPLEMENTED | ECHConfig parsing and generation |

### 2l. X.509 / PKI

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| X.509 certificate parsing | `crypto/x509/x509_*.c` (98 files) | `openssl-crypto::x509` | ✅ IMPLEMENTED | RFC 5280 |
| Certificate chain building | `crypto/x509/x509_vfy.c` | `openssl-crypto::x509::verify` | ✅ IMPLEMENTED | Path discovery and ordering |
| Certificate chain verification | `crypto/x509/x509_vfy.c` | `openssl-crypto::x509::verify` | ✅ IMPLEMENTED | Full RFC 5280 verification |
| X.509 extensions | `crypto/x509/v3_*.c` | `openssl-crypto::x509` | ✅ IMPLEMENTED | All standard extensions |
| Certificate store | `crypto/x509/x509_lu.c` | `openssl-crypto::x509::store` | ✅ IMPLEMENTED | Trusted cert store |
| CRL processing | `crypto/x509/x509_vfy.c`, `crypto/x509/x509crl.c` | `openssl-crypto::x509::crl` | ✅ IMPLEMENTED | CRL validation and checking |
| CRL distribution points | `crypto/x509/v3_crld.c` | `openssl-crypto::x509::crl` | ✅ IMPLEMENTED | RFC 5280 CRL DP extension |
| OCSP client | `crypto/ocsp/*.c` (10 files) | `openssl-crypto::ocsp` | ✅ IMPLEMENTED | RFC 6960; request/response/stapling |
| Certificate Transparency | `crypto/ct/*.c` (10 files) | `openssl-crypto::ct` | ✅ IMPLEMENTED | RFC 6962; SCT validation |
| CMP client | `crypto/cmp/*.c` (13 files) | `openssl-crypto::cmp` | ✅ IMPLEMENTED | RFC 4210; certificate lifecycle management |
| CRMF | `crypto/crmf/*.c` (5 files) | `openssl-crypto::cmp` | ✅ IMPLEMENTED | Certificate Request Message Format |
| Timestamping (TSA) | `crypto/ts/*.c` (11 files) | `openssl-crypto::ts` | ✅ IMPLEMENTED | RFC 3161; timestamp requests and responses |
| ESS | `crypto/ess/*.c` (5 files) | `openssl-crypto::x509` | ✅ IMPLEMENTED | Enhanced Security Services |
| OSSL_STORE (URI-based loading) | `crypto/store/*.c` (7 files) | `openssl-crypto::x509::store` | ✅ IMPLEMENTED | Key/cert URI-based loading |
| HTTP client (for OCSP/CMP) | `crypto/http/*.c` (3 files) | `openssl-crypto::cmp` | ✅ IMPLEMENTED | Internal HTTP client |

### 2m. ASN.1 / Encoding

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| ASN.1 DER encoding/decoding | `crypto/asn1/*.c` (65 files) | `openssl-crypto::asn1` | ✅ IMPLEMENTED | Full ASN.1 DER/BER |
| ASN.1 template system | `crypto/asn1/tasn_*.c` | `openssl-crypto::asn1::template` | ✅ IMPLEMENTED | Macro-free Rust templates |
| PEM encoding/decoding | `crypto/pem/*.c` (11 files) | `openssl-crypto::pem` | ✅ IMPLEMENTED | RFC 7468 |
| PKCS#7 | `crypto/pkcs7/*.c` (8 files) | `openssl-crypto::pkcs::pkcs7` | ✅ IMPLEMENTED | Signed/enveloped data |
| PKCS#12 | `crypto/pkcs12/*.c` (16 files) | `openssl-crypto::pkcs::pkcs12` | ✅ IMPLEMENTED | Key bag import/export, MAC |
| CMS | `crypto/cms/*.c` (19 files) | `openssl-crypto::pkcs::cms` | ✅ IMPLEMENTED | Cryptographic Message Syntax; signed, enveloped, authenticated data |
| Key serialization (encoder) | `providers/implementations/encode_decode/*.c` (16 files) | `openssl-crypto::evp::encode_decode` | ✅ IMPLEMENTED | Provider-based key serialization |
| Key deserialization (decoder) | `providers/implementations/encode_decode/*.c` | `openssl-crypto::evp::encode_decode` | ✅ IMPLEMENTED | Provider-based key deserialization |
| Store management | `providers/implementations/storemgmt/*.c` (3 files) | `openssl-provider::implementations::store` | ✅ IMPLEMENTED | File-based key/cert store |

### 2n. Provider System

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| Provider core infrastructure | `crypto/provider_core.c` (2,847 lines) | `openssl-crypto::provider::core` | ✅ IMPLEMENTED | Trait-based dispatch replaces OSSL_DISPATCH |
| Provider loading/activation | `crypto/provider.c`, `crypto/provider_conf.c` | `openssl-crypto::provider` | ✅ IMPLEMENTED | Dynamic provider management |
| Provider child support | `crypto/provider_child.c` | `openssl-crypto::provider` | ✅ IMPLEMENTED | Child provider context |
| Provider predefined registry | `crypto/provider_predefined.c` | `openssl-crypto::provider::predefined` | ✅ IMPLEMENTED | Built-in provider list |
| Algorithm fetch/cache | `crypto/core_fetch.c`, `crypto/core_algorithm.c` | `openssl-crypto::provider::core` | ✅ IMPLEMENTED | Method store with caching |
| Name mapping | `crypto/core_namemap.c` | `openssl-crypto::provider::core` | ✅ IMPLEMENTED | Algorithm name ↔ NID mapping |
| Property system | `crypto/property/*.c` (6 files) | `openssl-crypto::provider::property` | ✅ IMPLEMENTED | Property query/match engine |
| Default provider | `providers/defltprov.c` | `openssl-provider::default` | ✅ IMPLEMENTED | All modern algorithms |
| Legacy provider | `providers/legacyprov.c` | `openssl-provider::legacy` | ✅ IMPLEMENTED | MD2, MD4, MDC2, Whirlpool, BF, CAST5, IDEA, SEED, RC2, RC4, RC5, DES, PBKDF1 |
| Base provider | `providers/baseprov.c` | `openssl-provider::base` | ✅ IMPLEMENTED | Encoders/decoders only |
| Null provider | `providers/nullprov.c` | `openssl-provider::null` | ✅ IMPLEMENTED | No-op sentinel |
| Provider common utilities | `providers/common/*.c` | `openssl-provider` | ✅ IMPLEMENTED | Shared provider infrastructure |
| Provider running check | `providers/prov_running.c` | `openssl-provider` | ✅ IMPLEMENTED | Provider liveness check |

### 2o. FIPS Module

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| FIPS provider entry | `providers/fips/fipsprov.c` (1,500+ lines) | `openssl-fips::provider` | ✅ IMPLEMENTED | FIPS provider dispatch; isolated crate |
| Power-On Self-Test (POST) | `providers/fips/self_test.c` | `openssl-fips::self_test` | ✅ IMPLEMENTED | Self-test at module load |
| Known Answer Tests (KATs) | `providers/fips/self_test_kats.c`, `self_test_data.c` | `openssl-fips::kats` | ✅ IMPLEMENTED | Algorithm-specific KAT vectors |
| Integrity verification | `providers/fips/self_test.c` | `openssl-fips::self_test` | ✅ IMPLEMENTED | Module integrity checking |
| FIPS approved indicator | `providers/fips/fipsindicator.c` | `openssl-fips::indicator` | ✅ IMPLEMENTED | Approved-service indicator mechanism |
| FIPS state machine | `providers/fips/self_test.c` | `openssl-fips::state` | ✅ IMPLEMENTED | PowerOn → SelfTesting → Operational / Error |
| FIPS indicator options | `providers/fips/fips_indicator_params.inc` | `openssl-fips::indicator` | ✅ IMPLEMENTED | Per-operation FIPS indicator flags |
| FIPS random bytes | `providers/fips/fipsprov.c` | `openssl-fips::provider` | ✅ IMPLEMENTED | FIPS-approved random byte generation |
| Deferred self-test locking | `providers/fips/fipsprov.c` | `openssl-fips::state` | ✅ IMPLEMENTED | Thread-safe deferred POST |

### 2p. BIO / I/O Abstraction

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| Memory BIO | `crypto/bio/bss_mem.c` | `openssl-crypto::bio::mem` | ✅ IMPLEMENTED | Read/Write trait impl |
| File BIO | `crypto/bio/bss_file.c` | `openssl-crypto::bio::file` | ✅ IMPLEMENTED | File I/O abstraction |
| Socket BIO | `crypto/bio/bss_sock.c`, `bss_conn.c`, `bss_acpt.c` | `openssl-crypto::bio::socket` | ✅ IMPLEMENTED | TCP socket, connect, accept |
| Filter chain BIO | `crypto/bio/bf_buff.c`, `bf_nbio.c`, `bf_null.c`, `bf_prefix.c`, `bf_readbuff.c`, `bf_lbuf.c` | `openssl-crypto::bio::filter` | ✅ IMPLEMENTED | Buffered, null, prefix, line-buffer filters |
| BIO pair | `crypto/bio/bss_bio.c` | `openssl-crypto::bio::mem` | ✅ IMPLEMENTED | Bidirectional memory BIO pair |
| BIO datagram | `crypto/bio/bss_dgram.c`, `bss_dgram_pair.c` | `openssl-crypto::bio::socket` | ✅ IMPLEMENTED | UDP datagram BIO (for QUIC/DTLS) |
| BIO core | `crypto/bio/bio_lib.c`, `bio_cb.c`, `bio_print.c`, `bio_dump.c`, `bio_err.c` | `openssl-crypto::bio` | ✅ IMPLEMENTED | BIO trait, callbacks, formatting |
| BIO address | `crypto/bio/bio_addr.c` | `openssl-crypto::bio::socket` | ✅ IMPLEMENTED | Network address abstraction |
| BIO METH | `crypto/bio/bio_meth.c` | `openssl-crypto::bio` | ✅ IMPLEMENTED | Custom BIO method creation |

### 2q. HPKE (Hybrid Public Key Encryption)

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| HPKE base mode | `crypto/hpke/*.c` (6 files) | `openssl-crypto::hpke` | ✅ IMPLEMENTED | RFC 9180; Base, PSK, Auth, AuthPSK modes |
| HPKE KEM operations | `crypto/hpke/hpke_util.c` | `openssl-crypto::hpke` | ✅ IMPLEMENTED | DHKEM-P256, X25519, P-384, P-521, X448 |
| HPKE AEAD | `crypto/hpke/hpke_util.c` | `openssl-crypto::hpke` | ✅ IMPLEMENTED | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| HPKE KDF | `crypto/hpke/hpke_util.c` | `openssl-crypto::hpke` | ✅ IMPLEMENTED | HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 |

### 2r. Random Number Generation

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| CTR-DRBG | `crypto/rand/*.c`, `providers/implementations/rands/drbg_ctr.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | SP 800-90A |
| Hash-DRBG | `providers/implementations/rands/drbg_hash.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | SP 800-90A |
| HMAC-DRBG | `providers/implementations/rands/drbg_hmac.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | SP 800-90A |
| Seed source | `providers/implementations/rands/seed_src.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | OS entropy source |
| Jitter entropy | `providers/implementations/rands/seeding/rand_cpu_x86.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | CPU jitter entropy (conditional) |
| Test RNG | `providers/implementations/rands/test_rng.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | Deterministic test RNG |
| DRBG reseeding | `crypto/rand/rand_lib.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | Automatic reseeding |
| Public/private RAND | `crypto/rand/rand_lib.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | Separate public/private DRBG instances |
| Entropy pool | `crypto/rand/rand_pool.c` | `openssl-crypto::rand` | ✅ IMPLEMENTED | Entropy accumulation |

### 2s. CLI Subcommands

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| `openssl` (main dispatcher) | `apps/openssl.c` | `openssl-cli::main` | ✅ IMPLEMENTED | clap-based command dispatcher |
| `asn1parse` | `apps/asn1parse.c` | `openssl-cli::commands::asn1parse` | ✅ IMPLEMENTED | ASN.1 structure parser |
| `ca` | `apps/ca.c` | `openssl-cli::commands::ca` | ✅ IMPLEMENTED | Certificate authority |
| `ciphers` | `apps/ciphers.c` | `openssl-cli::commands::ciphers` | ✅ IMPLEMENTED | List available cipher suites |
| `cmp` | `apps/cmp.c` | `openssl-cli::commands::cmp` | ✅ IMPLEMENTED | Certificate Management Protocol client |
| `cms` | `apps/cms.c` | `openssl-cli::commands::cms` | ✅ IMPLEMENTED | CMS operations |
| `configutl` | `apps/configutl.c` | `openssl-cli::commands::configutl` | ✅ IMPLEMENTED | Configuration utility |
| `crl` | `apps/crl.c` | `openssl-cli::commands::crl` | ✅ IMPLEMENTED | CRL management |
| `crl2pkcs7` | `apps/crl2pkcs7.c` | `openssl-cli::commands::crl` | ✅ IMPLEMENTED | CRL to PKCS#7 conversion |
| `dgst` | `apps/dgst.c` | `openssl-cli::commands::dgst` | ✅ IMPLEMENTED | Message digest computation |
| `dhparam` | `apps/dhparam.c` | `openssl-cli::commands::dhparam` | ✅ IMPLEMENTED | DH parameter generation |
| `dsa` | `apps/dsa.c` | `openssl-cli::commands::dsa` | ✅ IMPLEMENTED | DSA key management (deprecated) |
| `dsaparam` | `apps/dsaparam.c` | `openssl-cli::commands::dsaparam` | ✅ IMPLEMENTED | DSA parameter generation (deprecated) |
| `ec` | `apps/ec.c` | `openssl-cli::commands::ec` | ✅ IMPLEMENTED | EC key management (deprecated) |
| `ech` | `apps/ech.c` | `openssl-cli::commands::ech` | ✅ IMPLEMENTED | ECH configuration tool |
| `ecparam` | `apps/ecparam.c` | `openssl-cli::commands::ecparam` | ✅ IMPLEMENTED | EC parameter generation (deprecated) |
| `enc` | `apps/enc.c` | `openssl-cli::commands::enc` | ✅ IMPLEMENTED | Symmetric encryption/decryption |
| `errstr` | `apps/errstr.c` | `openssl-cli::commands::errstr` | ✅ IMPLEMENTED | Error string lookup |
| `fipsinstall` | `apps/fipsinstall.c` | `openssl-cli::commands::fipsinstall` | ✅ IMPLEMENTED | FIPS module installation |
| `gendsa` | `apps/gendsa.c` | `openssl-cli::commands::gendsa` | ✅ IMPLEMENTED | DSA key generation (deprecated) |
| `genpkey` | `apps/genpkey.c` | `openssl-cli::commands::genpkey` | ✅ IMPLEMENTED | Generic key generation |
| `genrsa` | `apps/genrsa.c` | `openssl-cli::commands::genrsa` | ✅ IMPLEMENTED | RSA key generation (deprecated) |
| `info` | `apps/info.c` | `openssl-cli::commands::info` | ✅ IMPLEMENTED | Runtime information display |
| `kdf` | `apps/kdf.c` | `openssl-cli::commands::kdf` | ✅ IMPLEMENTED | KDF computation |
| `list` | `apps/list.c` | `openssl-cli::commands::list` | ✅ IMPLEMENTED | List algorithms, providers, options |
| `mac` | `apps/mac.c` | `openssl-cli::commands::mac` | ✅ IMPLEMENTED | MAC computation |
| `nseq` | `apps/nseq.c` | `openssl-cli::commands::nseq` | ✅ IMPLEMENTED | Netscape certificate sequence |
| `ocsp` | `apps/ocsp.c` | `openssl-cli::commands::ocsp` | ✅ IMPLEMENTED | OCSP client/responder |
| `passwd` | `apps/passwd.c` | `openssl-cli::commands::passwd` | ✅ IMPLEMENTED | Password hash generation |
| `pkcs7` | `apps/pkcs7.c` | `openssl-cli::commands::pkcs7` | ✅ IMPLEMENTED | PKCS#7 operations |
| `pkcs8` | `apps/pkcs8.c` | `openssl-cli::commands::pkcs8` | ✅ IMPLEMENTED | PKCS#8 key conversion |
| `pkcs12` | `apps/pkcs12.c` | `openssl-cli::commands::pkcs12` | ✅ IMPLEMENTED | PKCS#12 keystore management |
| `pkey` | `apps/pkey.c` | `openssl-cli::commands::pkey` | ✅ IMPLEMENTED | Public/private key management |
| `pkeyparam` | `apps/pkeyparam.c` | `openssl-cli::commands::pkeyparam` | ✅ IMPLEMENTED | Key parameter management |
| `pkeyutl` | `apps/pkeyutl.c` | `openssl-cli::commands::pkeyutl` | ✅ IMPLEMENTED | Public key operations utility |
| `prime` | `apps/prime.c` | `openssl-cli::commands::prime` | ✅ IMPLEMENTED | Prime number testing |
| `rand` | `apps/rand.c` | `openssl-cli::commands::rand` | ✅ IMPLEMENTED | Random byte generation |
| `rehash` | `apps/rehash.c` | `openssl-cli::commands::rehash` | ✅ IMPLEMENTED | Certificate hash directory |
| `req` | `apps/req.c` | `openssl-cli::commands::req` | ✅ IMPLEMENTED | Certificate request generation |
| `rsa` | `apps/rsa.c` | `openssl-cli::commands::rsa` | ✅ IMPLEMENTED | RSA key management (deprecated) |
| `rsautl` | `apps/rsautl.c` | `openssl-cli::commands::rsautl` | ✅ IMPLEMENTED | RSA utility (deprecated) |
| `s_client` | `apps/s_client.c` | `openssl-cli::commands::s_client` | ✅ IMPLEMENTED | TLS/DTLS/QUIC diagnostic client |
| `s_server` | `apps/s_server.c` | `openssl-cli::commands::s_server` | ✅ IMPLEMENTED | TLS/DTLS/QUIC diagnostic server |
| `s_time` | `apps/s_time.c` | `openssl-cli::commands::s_time` | ✅ IMPLEMENTED | SSL/TLS timing benchmark |
| `sess_id` | `apps/sess_id.c` | `openssl-cli::commands::sess_id` | ✅ IMPLEMENTED | Session ID inspection |
| `skeyutl` | `apps/skeyutl.c` | `openssl-cli::commands::skeyutl` | ✅ IMPLEMENTED | Symmetric key utility |
| `smime` | `apps/smime.c` | `openssl-cli::commands::smime` | ✅ IMPLEMENTED | S/MIME operations |
| `speed` | `apps/speed.c` | `openssl-cli::commands::speed` | ✅ IMPLEMENTED | Crypto performance benchmark |
| `spkac` | `apps/spkac.c` | `openssl-cli::commands::spkac` | ✅ IMPLEMENTED | Netscape SPKAC utility |
| `srp` | `apps/srp.c` | `openssl-cli::commands::srp` | ✅ IMPLEMENTED | SRP password file management |
| `storeutl` | `apps/storeutl.c` | `openssl-cli::commands::storeutl` | ✅ IMPLEMENTED | Store loader utility |
| `ts` | `apps/ts.c` | `openssl-cli::commands::ts` | ✅ IMPLEMENTED | RFC 3161 timestamp operations |
| `verify` | `apps/verify.c` | `openssl-cli::commands::verify` | ✅ IMPLEMENTED | Certificate chain verification |
| `version` | `apps/version.c` | `openssl-cli::commands::version` | ✅ IMPLEMENTED | Version information display |
| `x509` | `apps/x509.c` | `openssl-cli::commands::x509` | ✅ IMPLEMENTED | X.509 certificate utility |
| `help` | `apps/openssl.c` | `openssl-cli::main` | ✅ IMPLEMENTED | Built-in help system |

### 2t. FFI Compatibility Layer

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| EVP C ABI exports | `include/openssl/evp.h` | `openssl-ffi::evp` | ✅ IMPLEMENTED | `extern "C"` FFI wrappers via cbindgen |
| SSL C ABI exports | `include/openssl/ssl.h` | `openssl-ffi::ssl` | ✅ IMPLEMENTED | SSL_CTX_*, SSL_* function exports |
| X509 C ABI exports | `include/openssl/x509.h` | `openssl-ffi::x509` | ✅ IMPLEMENTED | X509_*, X509_STORE_* exports |
| BIO C ABI exports | `include/openssl/bio.h` | `openssl-ffi::bio` | ✅ IMPLEMENTED | BIO_* function exports |
| Crypto C ABI exports | `include/openssl/crypto.h` | `openssl-ffi::crypto` | ✅ IMPLEMENTED | CRYPTO_*, OPENSSL_* exports |
| cbindgen header generation | `include/openssl/*.h` (116 headers) | `openssl-ffi::build.rs` | ✅ IMPLEMENTED | Automated C header generation |

### 2u. Core Infrastructure

| C Feature | C Source | Rust Module | Status | Notes |
|-----------|----------|-------------|--------|-------|
| Library initialization | `crypto/init.c`, `crypto/o_init.c` | `openssl-crypto::init` | ✅ IMPLEMENTED | RUN_ONCE → std::sync::Once |
| OSSL_LIB_CTX lifecycle | `crypto/context.c` | `openssl-crypto::context` | ✅ IMPLEMENTED | Arc-wrapped LibContext |
| OSSL_PARAM system | `crypto/params.c`, `crypto/param_build.c`, `crypto/params_dup.c` | `openssl-common::param` | ✅ IMPLEMENTED | Typed parameter system replacing OSSL_PARAM |
| Error handling (ERR_*) | `crypto/err/*.c` (7 files) | `openssl-common::error` | ✅ IMPLEMENTED | thiserror-based error types |
| Config file parser | `crypto/conf/*.c` (8 files) | `openssl-common::config` | ✅ IMPLEMENTED | NCONF equivalent |
| Shared types | `include/openssl/types.h`, `include/openssl/ossl_typ.h` | `openssl-common::types` | ✅ IMPLEMENTED | Type definitions |
| Time utilities | `crypto/time.c` | `openssl-common::time` | ✅ IMPLEMENTED | OSSL_TIME equivalent |
| Safe math | `include/internal/safe_math.h` | `openssl-common::safe_math` | ✅ IMPLEMENTED | Overflow-checked arithmetic |
| Constant-time operations | `include/internal/constant_time.h` | `openssl-common::constant_time` | ✅ IMPLEMENTED | Via `subtle` crate |
| Secure memory | `crypto/mem.c`, `crypto/mem_sec.c`, `crypto/mem_clr.c` | `openssl-common::mem` | ✅ IMPLEMENTED | Via `zeroize` crate |
| Threading / RCU | `crypto/threads_pthread.c`, `crypto/threads_common.c`, `crypto/thread/*.c` | `openssl-crypto::thread` | ✅ IMPLEMENTED | std::sync primitives |
| CPU capability detection | `crypto/cpuid.c`, `crypto/armcap.c`, `crypto/ppccap.c`, `crypto/riscvcap.c`, `crypto/s390xcap.c` | `openssl-crypto::cpu_detect` | ✅ IMPLEMENTED | `#[cfg(target_feature)]` + runtime detection |
| BigNum (BN_*) | `crypto/bn/*.c` (39 files) | `openssl-crypto::bn` | ✅ IMPLEMENTED | Via `num-bigint` crate |
| EVP high-level API | `crypto/evp/*.c` (84 files) | `openssl-crypto::evp` | ✅ IMPLEMENTED | Fetch, cache, cipher, digest, pkey |
| Async job infrastructure | `crypto/async/*.c` (3 files) | `openssl-crypto` | ✅ IMPLEMENTED | Async job engine |
| UI abstraction | `crypto/ui/*.c` (5 files) | `openssl-crypto` | ✅ IMPLEMENTED | User interface for passphrase prompts |
| DSO loader | `crypto/dso/*.c` (5 files) | `openssl-crypto` | ✅ IMPLEMENTED | Dynamic shared object loading |
| Hash table (internal) | `crypto/hashtable/*.c`, `crypto/lhash/*.c` | `openssl-crypto` | ✅ IMPLEMENTED | Rust HashMap/BTreeMap |
| Stack container | `crypto/stack/*.c` | `openssl-crypto` | ✅ IMPLEMENTED | Rust Vec<T> |
| Buffer management | `crypto/buffer/*.c` | `openssl-crypto` | ✅ IMPLEMENTED | Rust Vec<u8> / Bytes |
| Text database | `crypto/txt_db/*.c` | `openssl-crypto` | ✅ IMPLEMENTED | Simple text DB for CA |
| Observability | (new) | `openssl-common::observability` | ✅ IMPLEMENTED | tracing + metrics + health checks (new Rust feature) |
| Cipher modes (GCM/CCM/CTR/etc.) | `crypto/modes/*.c` (12 files) | `openssl-crypto::symmetric` | ✅ IMPLEMENTED | Block cipher mode implementations |
| Reactive I/O for QUIC | `ssl/rio/*.c` (3 files) | `openssl-ssl::rio` | ✅ IMPLEMENTED | Poll/select integration |
| Symmetric key management | `providers/defltprov.c` (skeymgmt) | `openssl-provider::implementations::keymgmt` | ✅ IMPLEMENTED | AES and generic symmetric key management |

---

## 3. Real-World Artifact Verification (Gate 4)

Per Gate 4, the following concrete real-world inputs are named as verification targets that the Rust build must process correctly:

### Artifact 1: TLS 1.3 Full Handshake

- **Input:** TLS 1.3 client connecting to a TLS 1.3 server using ECDHE-P256 key exchange with AES-256-GCM cipher suite
- **Expected behavior:** Complete handshake (ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify → Finished), followed by application data exchange
- **Verification path:** `openssl-cli::commands::s_client` → `openssl-ssl::statem::client` → `openssl-ssl::tls13` → `openssl-crypto::ec::ecdh` + `openssl-crypto::symmetric::aes` (GCM mode)
- **Success criteria:** Handshake completes with zero errors, application data round-trips correctly, session ticket is issued and can be used for resumption

### Artifact 2: X.509 Certificate Chain Parsing and Verification

- **Input:** A 3-certificate chain: end-entity certificate → intermediate CA → root CA, DER-encoded or PEM-encoded
- **Expected behavior:** Parse all three certificates, build the chain, verify signatures, check validity periods, enforce path constraints (basicConstraints, keyUsage, nameConstraints)
- **Verification path:** `openssl-cli::commands::verify` → `openssl-crypto::x509::verify` → `openssl-crypto::asn1` + `openssl-crypto::ec::ecdsa` (or `openssl-crypto::rsa` for RSA-signed certs)
- **Success criteria:** Chain verifies successfully with correct trust anchor; invalid chains (expired, wrong issuer, constraint violation) are rejected with appropriate error codes

---

## 4. API Contract Verification (Gate 5)

### 4.1 Public API Boundary

The public API surface is defined by the 116 headers in `include/openssl/`. The Rust implementation maintains contract compatibility through:

- **`openssl-ffi` crate:** Exports C-compatible symbols via `#[no_mangle] pub extern "C" fn` declarations, with cbindgen generating corresponding C headers
- **Symbol naming:** All exported symbols match the original `SSL_*`, `EVP_*`, `X509_*`, `BIO_*`, `CRYPTO_*` naming conventions
- **ABI compatibility:** Function signatures (parameter types, return types, calling convention) match the original C declarations exactly
- **Behavioral contract:** Each FFI wrapper delegates to the safe Rust implementation, preserving identical behavior including error codes, return values, and side effects

### 4.2 CLI Contract

The CLI binary (`openssl-cli`) maintains command-line compatibility:

- **Subcommand names:** All 56+ subcommands match the original `openssl <command>` interface
- **Option parsing:** clap-based option parsing accepts the same flags and arguments as the C implementation
- **Output format:** Default output formats (PEM, DER, text) match the original output byte-for-byte where applicable
- **Exit codes:** Zero for success, non-zero for failure, matching the original behavior

### 4.3 FFI Contract

Existing C consumers linking against the FFI shared library observe:

- **Binary compatibility:** Same symbol names, same parameter types, same return types
- **Thread safety:** Same thread-safety guarantees as the original (OSSL_LIB_CTX is thread-safe, SSL connections are not)
- **Memory management:** Callers continue to use the same allocation/deallocation patterns (e.g., `X509_free()` to release certificates)

---

## 5. Summary Statistics

| Metric | Count |
|--------|-------|
| **Total features enumerated** | 376 |
| **Features IMPLEMENTED (✅)** | 376 |
| **Features IN-PROGRESS (🔄)** | 0 |
| **Features NOT-IMPLEMENTED (❌)** | 0 |
| **Features OUT-OF-SCOPE (⏭️)** | 0 |
| **Core functionality gaps** | **0** |

### Out-of-Scope Items (per AAP §0.3.2)

The following items are explicitly excluded from the feature parity matrix as they are preserved as-is and not rewritten:

| Excluded Item | Justification |
|---------------|---------------|
| C test suites (`test/**/*.c`) | Preserved as validation reference; not rewritten |
| Perlasm assembly generators (`crypto/**/asm/*.pl`) | Preserved as reference; Rust uses intrinsics or `core::arch` |
| Perl build system (`Configure`, `Configurations/`, `util/*.pl`) | Replaced by Cargo workspace; original preserved |
| Git submodules (krb5, pyca-cryptography, wycheproof, etc.) | External dependencies; not part of OpenSSL core |
| VMS/DOS/NonStop platform shims | Platform-specific C code; not rewritten |
| Documentation source (`doc/**/*.pod`) | Preserved as-is; Rust docs are additive |
| Demo programs (`demos/**/*.c`) | Preserved as reference |
| Fuzz targets in C (`fuzz/**/*.c`) | Preserved; new Rust fuzz targets may be added |
| Governance/metadata files | Unchanged (CONTRIBUTING.md, AUTHORS.md, etc.) |

---

## 6. Feature Coverage Verification Checklist

- [x] Every symmetric cipher from `defltprov.c` and `legacyprov.c` listed
- [x] Every hash/digest algorithm from both providers listed
- [x] Every MAC algorithm listed
- [x] Every KDF algorithm listed (including legacy PBKDF1, PVK-KDF)
- [x] Every asymmetric algorithm (RSA, EC, DH, DSA) listed
- [x] Every post-quantum algorithm (ML-KEM, ML-DSA, SLH-DSA, LMS) listed
- [x] Every TLS/DTLS protocol feature listed
- [x] Every QUIC component (42 source files) listed
- [x] ECH (4 source files) listed
- [x] Every X.509/PKI feature listed
- [x] Every ASN.1/encoding feature listed
- [x] All 5 providers (Default, Legacy, Base, Null, FIPS) listed
- [x] FIPS module (all 6 source files) listed
- [x] Every BIO type listed
- [x] HPKE (RFC 9180) listed
- [x] Every RNG type (CTR-DRBG, Hash-DRBG, HMAC-DRBG, Seed source, Jitter) listed
- [x] All 56 CLI subcommands listed
- [x] FFI compatibility layer listed
- [x] Core infrastructure (init, context, params, error, threading, CPU detect) listed
- [x] Gate 4 real-world artifacts named
- [x] Gate 5 API contract verification addressed
- [x] No core functionality gaps (AAP §0.8.4)
