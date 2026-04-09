# Bidirectional Traceability Matrix — OpenSSL C → Rust

## 1. Overview

This document provides a **complete, bidirectional traceability matrix** mapping every C source construct in the OpenSSL 4.0 codebase to its corresponding Rust implementation in the `openssl-rs` Cargo workspace.

### Purpose

- **Forward traceability (C → Rust):** For any C source file or construct, identify the exact Rust crate, module, and construct that replaces it.
- **Reverse traceability (Rust → C):** For any Rust module or construct, identify the C source file(s) it was derived from.
- **Coverage guarantee:** 100% of in-scope C source files have a mapped Rust target — no gaps permitted per AAP §0.8.5 (Explainability Rule).

### Scope

| Metric | Count |
|--------|-------|
| C source files in scope | ~1,247 |
| C header files referenced | ~524 |
| Rust crates | 7 |
| Coverage target | 100% |

### Directions

| Direction | Description |
|-----------|-------------|
| **Forward (C → Rust)** | Section 2: Organized by C source directory |
| **Reverse (Rust → C)** | Section 3: Organized by Rust crate and module |
| **Construct Patterns** | Section 4: Systematic transformation rules applied across the codebase |
| **Coverage Summary** | Section 5: Quantitative verification of 100% mapping |

---

## 2. Forward Traceability: C → Rust

### 2.1 crypto/ Top-Level Files (~70 files)

Core library initialization, context management, provider infrastructure, parameter system, threading, memory, and CPU detection.

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/init.c` | `OPENSSL_init_crypto()`, `OPENSSL_cleanup()`, `RUN_ONCE` stages | `openssl-crypto` | `src/init.rs` | `init_crypto()`, `cleanup()`, `std::sync::Once` stages | `DEFINE_RUN_ONCE_STATIC` → `std::sync::Once::call_once`; `CRYPTO_ONCE` → `Once`; manual cleanup → `Drop` |
| `crypto/context.c` | `ossl_lib_ctx_st`, `OSSL_LIB_CTX_new()`, `OSSL_LIB_CTX_free()` | `openssl-crypto` | `src/context.rs` | `LibContext`, `LibContext::new()`, `impl Drop` | `struct ossl_lib_ctx_st` → `pub struct LibContext { ... }`; `CRYPTO_RWLOCK` → `parking_lot::RwLock`; `void *provider_store` → typed `ProviderStore` field |
| `crypto/cryptlib.c` | `OPENSSL_die()`, `OPENSSL_showfatal()`, `OPENSSL_isservice()` | `openssl-crypto` | `src/init.rs` | `openssl_die()`, error formatting helpers | Fatal error handlers → `panic!()` with `tracing::error!()` logging |
| `crypto/provider.c` | `OSSL_PROVIDER_load()`, `OSSL_PROVIDER_unload()`, public provider API | `openssl-crypto` | `src/provider/mod.rs` | `Provider::load()`, `Provider::unload()` | C function API → Rust method API on `Provider` struct |
| `crypto/provider_core.c` | `provider_st`, `provider_store_st`, `OSSL_DISPATCH` dispatch | `openssl-crypto` | `src/provider/core.rs` | `ProviderInner`, `ProviderStore`, trait-based dispatch | `OSSL_DISPATCH` function pointer tables → Rust trait implementations; `CRYPTO_RWLOCK` → `parking_lot::RwLock`; refcounting → `Arc` |
| `crypto/provider_child.c` | Child provider callbacks, `OSSL_PROVIDER_CHILD_CB` | `openssl-crypto` | `src/provider/core.rs` | `ChildProviderCallbacks` | Callback function pointers → closure-based callbacks |
| `crypto/provider_conf.c` | Config-driven provider activation | `openssl-crypto` | `src/provider/core.rs` | `ProviderConfig` | `CONF`-based activation → `serde` deserialized config structs |
| `crypto/provider_predefined.c` | Built-in provider registry | `openssl-crypto` | `src/provider/predefined.rs` | `PredefinedProviders` | Static `OSSL_PROVIDER` array → `const` registry with `once_cell::sync::Lazy` |
| `crypto/params.c` | `OSSL_PARAM_locate()`, `OSSL_PARAM_get_*()`, `OSSL_PARAM_set_*()` | `openssl-common` | `src/param.rs` | `ParamSet`, `ParamValue`, typed accessors | String-keyed `OSSL_PARAM` arrays → `HashMap<&'static str, ParamValue>` with typed enum; runtime type tags → compile-time type safety |
| `crypto/param_build.c` | `OSSL_PARAM_BLD_new()`, `OSSL_PARAM_BLD_push_*()`, `OSSL_PARAM_BLD_to_param()` | `openssl-common` | `src/param.rs` | `ParamBuilder` | Builder pattern preserved; manual alloc → `Vec<ParamValue>` |
| `crypto/param_build_set.c` | `ossl_param_build_set_*()` helpers | `openssl-common` | `src/param.rs` | `ParamBuilder::set_*()` methods | Helper functions → builder method chain |
| `crypto/params_dup.c` | `OSSL_PARAM_dup()`, `OSSL_PARAM_merge()`, `OSSL_PARAM_free()` | `openssl-common` | `src/param.rs` | `impl Clone for ParamSet`, `ParamSet::merge()` | Manual dup/merge/free → `Clone` trait + `Drop` |
| `crypto/params_from_text.c` | `OSSL_PARAM_allocate_from_text()` | `openssl-common` | `src/param.rs` | `ParamSet::from_text()` | Text parsing → `FromStr` implementation |
| `crypto/core_algorithm.c` | `ossl_core_algorithm_iterate()`, provider algorithm enumeration | `openssl-crypto` | `src/provider/core.rs` | `ProviderStore::iterate_algorithms()` | Callback-based iteration → iterator pattern |
| `crypto/core_fetch.c` | `ossl_method_construct()`, method store population | `openssl-crypto` | `src/provider/core.rs` | `MethodStore::fetch()` | Function-pointer method construction → trait-object fetching |
| `crypto/core_namemap.c` | Name-to-number mapping for algorithms | `openssl-crypto` | `src/provider/core.rs` | `NameMap` | `OSSL_NAMEMAP` → `HashMap<String, u32>` with `parking_lot::RwLock` |
| `crypto/threads_pthread.c` | `CRYPTO_THREAD_*` (pthread), `ossl_rcu_*` | `openssl-crypto` | `src/thread.rs` | `std::sync` primitives, `parking_lot` locks | `CRYPTO_RWLOCK` → `parking_lot::RwLock`; `CRYPTO_THREAD_lock_new/free` → RAII lock guards; RCU → `arc_swap` or epoch-based |
| `crypto/threads_win.c` | Windows threading primitives | `openssl-crypto` | `src/thread.rs` | `std::sync` primitives (platform-agnostic) | Platform-specific C → cross-platform Rust `std::sync` |
| `crypto/threads_common.c` | Libctx-scoped TLS, thread-stop handlers | `openssl-crypto` | `src/thread.rs` | `thread_local!`, cleanup handlers | `CRYPTO_THREAD_LOCAL` → `std::thread::LocalKey`; `initthread` → Rust thread-local destructors |
| `crypto/threads_none.c` | No-threading stubs | `openssl-crypto` | `src/thread.rs` | (not needed — Rust always has threading support) | Stub file has no Rust equivalent; cfg-gated no-ops if needed |
| `crypto/threads_lib.c` | Deprecated `OPENSSL_fork_*` stubs | `openssl-crypto` | `src/thread.rs` | Deprecated API stubs via `#[deprecated]` | Deprecated C stubs → Rust `#[deprecated]` functions |
| `crypto/initthread.c` | Thread-stop handler registration | `openssl-crypto` | `src/thread.rs` | Thread-local Drop handlers | Manual handler list → RAII thread-local cleanup |
| `crypto/mem.c` | `CRYPTO_malloc()`, `CRYPTO_realloc()`, `CRYPTO_free()`, custom allocators | `openssl-common` | `src/mem.rs` | Rust global allocator, `Vec`, `Box` (standard allocation) | Custom C allocator → Rust ownership model; `CRYPTO_malloc` → `Box::new()` / `Vec::new()` |
| `crypto/mem_sec.c` | `CRYPTO_secure_malloc()`, secure heap with `mlock` | `openssl-common` | `src/mem.rs` | `SecureVec<T>`, `zeroize::Zeroizing<Vec<u8>>` | Secure heap → `mlock`-backed allocator + `zeroize` on drop |
| `crypto/mem_clr.c` | `OPENSSL_cleanse()` | `openssl-common` | `src/mem.rs` | `zeroize::Zeroize` trait derivation | Manual volatile memset → `zeroize::Zeroize` trait |
| `crypto/aligned_alloc.c` | `ossl_malloc_align()` | `openssl-common` | `src/mem.rs` | `std::alloc::Layout`-based aligned allocation | Custom aligned alloc → `std::alloc::alloc` with `Layout::from_size_align` |
| `crypto/array_alloc.c` | Overflow-checked array allocation wrappers | `openssl-common` | `src/safe_math.rs` | `checked_mul()`, `Vec::try_reserve()` | Manual overflow checks → Rust `checked_*` arithmetic |
| `crypto/cpuid.c` | `OPENSSL_ia32cap_P`, x86 CPUID detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_x86()` | Inline asm CPUID → `std::arch::is_x86_feature_detected!()` |
| `crypto/armcap.c` | ARM NEON/SHA/AES feature detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_arm()` | Signal-based probing → `std::arch::is_aarch64_feature_detected!()` |
| `crypto/ppccap.c` | PowerPC capability detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_ppc()` | `getauxval`-based → `cfg(target_arch)` + runtime detection |
| `crypto/riscvcap.c` | RISC-V capability detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_riscv()` | `hwprobe`-based → `cfg(target_arch)` feature detection |
| `crypto/s390xcap.c` | s390x STFLE/KIMD detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_s390x()` | `STFLE`-based → `cfg(target_arch)` feature detection |
| `crypto/sparcv9cap.c` | SPARC V9 capability detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_sparc()` | Platform-specific → `cfg(target_arch)` |
| `crypto/loongarchcap.c` | LoongArch capability detection | `openssl-crypto` | `src/cpu_detect.rs` | `CpuFeatures::detect_loongarch()` | `getauxval`-based → `cfg(target_arch)` |
| `crypto/ex_data.c` | `CRYPTO_EX_DATA`, ex_data index management | `openssl-crypto` | `src/context.rs` | `ExData<T>` generic container | `void *` ex_data slots → typed `HashMap<TypeId, Box<dyn Any>>` |
| `crypto/o_str.c` | String utility functions | `openssl-common` | `src/types.rs` | Standard Rust `str`/`String` methods | C string helpers → Rust standard library string methods |
| `crypto/o_fopen.c` | Portable file open | `openssl-common` | `src/types.rs` | `std::fs::File::open()` | Platform-specific fopen → `std::fs::File` |
| `crypto/o_dir.c` | Directory enumeration abstraction | `openssl-common` | `src/types.rs` | `std::fs::read_dir()` | Platform backends (`LPdir_*`) → `std::fs::read_dir` |
| `crypto/o_init.c` | Additional init helpers | `openssl-crypto` | `src/init.rs` | Init helper functions | Merged into `init.rs` |
| `crypto/getenv.c` | `ossl_safe_getenv()` | `openssl-common` | `src/types.rs` | `std::env::var()` with privilege checks | `secure_getenv` → `std::env::var` with `is_setugid()` guard |
| `crypto/uid.c` | `OPENSSL_issetugid()` | `openssl-common` | `src/types.rs` | `is_setugid()` | Platform-specific → `libc::issetugid()` or equivalent |
| `crypto/sleep.c` | `OSSL_sleep()` | `openssl-common` | `src/time.rs` | `std::thread::sleep()` | Portable sleep → `std::thread::sleep(Duration)` |
| `crypto/time.c` | `ossl_time_now()`, `OSSL_TIME` | `openssl-common` | `src/time.rs` | `OsslTime`, `OsslTime::now()` | Custom time type → `std::time::Instant` / `SystemTime` newtype wrapper |
| `crypto/trace.c` | `OSSL_TRACE()` macro, category/channel infra | `openssl-common` | `src/observability.rs` | `tracing::trace!()`, `tracing::Span` | C trace channels → `tracing` crate spans and events |
| `crypto/self_test_core.c` | Per-libctx self-test callback | `openssl-crypto` | `src/context.rs` | `LibContext::set_self_test_callback()` | Callback registration → closure-based callback |
| `crypto/indicator_core.c` | Per-libctx FIPS indicator callback | `openssl-crypto` | `src/context.rs` | `LibContext::set_indicator_callback()` | Callback registration → closure-based callback |
| `crypto/cpt_err.c` | CRYPTO error reason codes | `openssl-common` | `src/error.rs` | `CryptoError` enum variants | `ERR_LIB_CRYPTO` reason codes → `thiserror` enum variants |
| `crypto/ssl_err.c` | SSL error reason codes | `openssl-common` | `src/error.rs` | `SslError` enum variants | `ERR_LIB_SSL` reason codes → `thiserror` enum variants |
| `crypto/err/err.c` | `ERR_put_error()`, `ERR_get_error()`, thread-local error queue | `openssl-common` | `src/error.rs` | `Result<T, E>`, `Error::source()` chain | Thread-local error stack → `Result<T, E>` propagation with `?` |
| `crypto/err/err_prn.c` | `ERR_print_errors_fp()` | `openssl-common` | `src/error.rs` | `Display` / `Debug` trait implementations | Print-to-FILE → `Display`/`Debug` formatting |
| `crypto/err/err_all.c` | `ERR_load_*_strings()` | `openssl-common` | `src/error.rs` | Enum variant display strings (automatic via `thiserror`) | Manual string loading → derive macro |
| `crypto/packet.c` | `PACKET`/`WPACKET` wire-format helpers | `openssl-common` | `src/types.rs` | `bytes::Buf` / `bytes::BufMut` based helpers | `PACKET` → `bytes::Buf`; `WPACKET` → `bytes::BufMut` |
| `crypto/sparse_array.c` | Sparse array data structure | `openssl-common` | `src/types.rs` | `HashMap<usize, T>` | Custom sparse array → standard `HashMap` |
| `crypto/bsearch.c` | Binary search helper | `openssl-common` | `src/types.rs` | `[T]::binary_search()` | C bsearch wrapper → Rust slice method |
| `crypto/ctype.c` | Character classification | `openssl-common` | `src/types.rs` | `char::is_ascii_*()` methods | Custom ctype → Rust `char` methods |
| `crypto/cversion.c` | `OpenSSL_version()` | `openssl-common` | `src/types.rs` | `version()` const function | Version string function → `const` version info |
| `crypto/defaults.c` | Default paths/directories | `openssl-common` | `src/config.rs` | `Defaults` struct | Static default paths → `const` / config-derived |
| `crypto/info.c` | `OPENSSL_info()` | `openssl-common` | `src/types.rs` | `info()` function | Info retrieval → structured info return |
| `crypto/der_writer.c` | DER writing helpers | `openssl-common` | `src/types.rs` | `der` crate DER encoding | Manual DER writing → `der::Encode` trait |
| `crypto/deterministic_nonce.c` | RFC 6979 deterministic nonce | `openssl-crypto` | `src/ec/ecdsa.rs` | Deterministic nonce generation | Custom impl → integrated into signature module |
| `crypto/asn1_dsa.c` | ASN.1 DSA signature helpers | `openssl-crypto` | `src/dsa.rs` | DSA ASN.1 encoding/decoding | Custom ASN.1 → `der` crate encoding |
| `crypto/comp_methods.c` | Compression method stubs | `openssl-crypto` | `src/context.rs` | Compression method registry | Compression stubs → `Option<CompressionMethod>` |
| `crypto/dllmain.c` | Windows DLL entry point | `openssl-crypto` | `src/init.rs` | (not needed — Rust handles DLL lifecycle) | Windows-specific → not applicable in Rust |
| `crypto/ebcdic.c` | EBCDIC conversion tables | `openssl-common` | `src/types.rs` | `cfg`-gated EBCDIC support | Platform-specific charset → `cfg(target_os)` gated |
| `crypto/passphrase.c` | Passphrase prompting/caching | `openssl-crypto` | `src/bio/mod.rs` | `PassphraseHandler` | UI callback → `Fn` closure-based passphrase prompt |
| `crypto/punycode.c` | IDNA A-label decoding | `openssl-crypto` | `src/x509/mod.rs` | Punycode decoder | Custom impl → Rust punycode helper |
| `crypto/quic_vlint.c` | QUIC variable-length integer codec | `openssl-ssl` | `src/quic/mod.rs` | `VarInt::encode()` / `VarInt::decode()` | C encode/decode → Rust `TryFrom<u64>` |

### 2.2 crypto/ Subdirectories

#### 2.2.1 crypto/evp/ (84 files — EVP Abstraction Layer)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/evp/evp_lib.c` | `EVP_CIPHER_*` accessors, ASN.1 integration | `openssl-crypto` | `src/evp/cipher.rs` | `Cipher` accessors and ASN.1 helpers | Accessor functions → struct methods |
| `crypto/evp/evp_enc.c` | `EVP_EncryptInit/Update/Final`, `EVP_DecryptInit/Update/Final` | `openssl-crypto` | `src/evp/cipher.rs` | `CipherCtx::encrypt_init/update/finalize()` | Init/Update/Final pattern → builder + method chain |
| `crypto/evp/evp_fetch.c` | `EVP_*_fetch()`, method store caching | `openssl-crypto` | `src/evp/mod.rs` | `Evp::fetch()` generic fetcher | Provider fetch → trait-based algorithm resolution |
| `crypto/evp/digest.c` | `EVP_DigestInit/Update/Final` | `openssl-crypto` | `src/evp/md.rs` | `DigestCtx::init/update/finalize()` | Init/Update/Final → streaming digest API |
| `crypto/evp/evp_rand.c` | `EVP_RAND_*` | `openssl-crypto` | `src/evp/rand.rs` | `RandCtx` | EVP_RAND context → `RandCtx` struct |
| `crypto/evp/mac_lib.c` | `EVP_MAC_*` | `openssl-crypto` | `src/evp/mac.rs` | `MacCtx` | EVP_MAC context → `MacCtx` struct |
| `crypto/evp/kem.c` | `EVP_KEM_*` | `openssl-crypto` | `src/evp/kem.rs` | `KemCtx` | EVP_KEM encap/decap → `KemCtx` methods |
| `crypto/evp/kdf_lib.c` | `EVP_KDF_*` | `openssl-crypto` | `src/evp/kdf.rs` | `KdfCtx` | EVP_KDF context → `KdfCtx` struct |
| `crypto/evp/signature.c` | `EVP_PKEY_sign/verify` | `openssl-crypto` | `src/evp/signature.rs` | `SignatureCtx` | Signature operations → `SignatureCtx` methods |
| `crypto/evp/exchange.c` | `EVP_PKEY_derive` | `openssl-crypto` | `src/evp/pkey.rs` | `KeyExchangeCtx` | Key exchange → `KeyExchangeCtx` methods |
| `crypto/evp/keymgmt_lib.c` | Key management helpers | `openssl-crypto` | `src/evp/keymgmt.rs` | `KeyMgmt` | Key management functions → `KeyMgmt` struct |
| `crypto/evp/keymgmt_meth.c` | Key management method dispatch | `openssl-crypto` | `src/evp/keymgmt.rs` | `KeyMgmtMethod` trait | Dispatch table → trait implementation |
| `crypto/evp/p_lib.c` | `EVP_PKEY_*` utility functions | `openssl-crypto` | `src/evp/pkey.rs` | `EvpPkey` methods | EVP_PKEY helpers → `EvpPkey` struct methods |
| `crypto/evp/pmeth_lib.c` | `EVP_PKEY_CTX_*` lifecycle | `openssl-crypto` | `src/evp/pkey.rs` | `PkeyCtx` | PKEY context lifecycle → RAII `PkeyCtx` |
| `crypto/evp/e_aes.c` | AES EVP cipher methods | `openssl-crypto` | `src/evp/cipher.rs` | AES cipher registration | Legacy EVP method → provider-fetched cipher |
| `crypto/evp/encode.c` | Base64 encoding/decoding (EVP_Encode*) | `openssl-crypto` | `src/evp/mod.rs` | `base64ct` crate integration | Manual base64 → `base64ct` crate |
| `crypto/evp/evp_pbe.c` | Password-based encryption params | `openssl-crypto` | `src/evp/mod.rs` | PBE parameter handling | PBE functions → typed PBE config |
| `crypto/evp/evp_key.c` | Legacy key derivation | `openssl-crypto` | `src/evp/mod.rs` | Legacy key derivation (deprecated) | Legacy EVP key → `#[deprecated]` wrapper |
| `crypto/evp/ctrl_params_translate.c` | `EVP_PKEY_CTX_ctrl` → `OSSL_PARAM` bridge | `openssl-crypto` | `src/evp/pkey.rs` | Direct `ParamSet` API (no translation needed) | Bridge eliminated — Rust uses typed params directly |
| `crypto/evp/evp_cnf.c` | EVP config module | `openssl-crypto` | `src/evp/mod.rs` | EVP configuration | Config module → serde-based config |
| `crypto/evp/asymcipher.c` | Asymmetric cipher operations | `openssl-crypto` | `src/evp/pkey.rs` | `AsymCipherCtx` | Asym cipher → `AsymCipherCtx` methods |
| `crypto/evp/evp_local.h` + remaining `crypto/evp/*.c` | All remaining EVP internals | `openssl-crypto` | `src/evp/*.rs` | Distributed across EVP submodules | Internal helpers consolidated into relevant Rust modules |

#### 2.2.2 crypto/bn/ (39 files — Big Number Arithmetic)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/bn/bn_lib.c` | `BN_new()`, `BN_free()`, `BN_num_bits()`, basic operations | `openssl-crypto` | `src/bn/mod.rs` | `BigNum::new()`, `impl Drop`, `BigNum::num_bits()` | Manual alloc/free → RAII; `BIGNUM` → `BigNum` wrapping `num_bigint::BigUint` |
| `crypto/bn/bn_add.c` | `BN_add()`, `BN_sub()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `impl Add for BigNum`, `impl Sub for BigNum` | C functions → Rust operator trait implementations |
| `crypto/bn/bn_mul.c` | `BN_mul()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `impl Mul for BigNum` | C function → Rust `Mul` trait |
| `crypto/bn/bn_div.c` | `BN_div()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `impl Div for BigNum` | C function → Rust `Div` trait |
| `crypto/bn/bn_mod.c` | `BN_mod()`, `BN_nnmod()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `impl Rem for BigNum`, `BigNum::nnmod()` | C mod functions → Rust `Rem` trait + method |
| `crypto/bn/bn_exp.c` | `BN_exp()`, `BN_mod_exp()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `BigNum::mod_exp()` | Modular exponentiation → method |
| `crypto/bn/bn_mont.c` | `BN_MONT_CTX`, Montgomery multiplication | `openssl-crypto` | `src/bn/montgomery.rs` | `MontgomeryCtx` | Montgomery context → RAII struct |
| `crypto/bn/bn_prime.c` | `BN_is_prime_ex()`, `BN_generate_prime_ex()` | `openssl-crypto` | `src/bn/prime.rs` | `BigNum::is_prime()`, `BigNum::generate_prime()` | Primality testing → methods with `Result<bool>` |
| `crypto/bn/bn_gcd.c` | `BN_gcd()`, `BN_mod_inverse()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `BigNum::gcd()`, `BigNum::mod_inverse()` | C functions → struct methods |
| `crypto/bn/bn_rand.c` | `BN_rand()`, `BN_priv_rand()` | `openssl-crypto` | `src/bn/mod.rs` | `BigNum::random()`, `BigNum::private_random()` | C random generation → `rand` crate integration |
| `crypto/bn/bn_ctx.c` | `BN_CTX` temporary pool | `openssl-crypto` | `src/bn/mod.rs` | Stack-allocated temporaries (Rust manages via scope) | `BN_CTX` pool → Rust automatic stack/heap management |
| `crypto/bn/bn_shift.c` | `BN_lshift()`, `BN_rshift()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `impl Shl for BigNum`, `impl Shr for BigNum` | C shift → Rust `Shl`/`Shr` traits |
| `crypto/bn/bn_word.c` | `BN_add_word()`, `BN_mod_word()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `BigNum::add_word()`, `BigNum::mod_word()` | Word-level operations → methods |
| `crypto/bn/bn_sqr.c` | `BN_sqr()` | `openssl-crypto` | `src/bn/arithmetic.rs` | `BigNum::sqr()` | C squaring → method |
| `crypto/bn/bn_conv.c` | `BN_bn2hex()`, `BN_hex2bn()`, `BN_bn2dec()` | `openssl-crypto` | `src/bn/mod.rs` | `impl Display for BigNum`, `impl FromStr for BigNum` | Conversion functions → `Display`/`FromStr` traits |
| `crypto/bn/bn_print.c` | `BN_print()` | `openssl-crypto` | `src/bn/mod.rs` | `impl Debug for BigNum` | Print function → `Debug` trait |
| `crypto/bn/bn_recp.c` | `BN_RECP_CTX`, reciprocal division | `openssl-crypto` | `src/bn/arithmetic.rs` | `ReciprocalCtx` | Reciprocal context → RAII struct |
| Remaining `crypto/bn/*.c` | Internal BN helpers, asm bridges | `openssl-crypto` | `src/bn/*.rs` | Internal helpers distributed across BN modules | Internal C helpers → private Rust functions |

#### 2.2.3 crypto/ec/ (49 files — Elliptic Curves)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/ec/ec_lib.c` | `EC_GROUP_new()`, `EC_POINT_*()`, group operations | `openssl-crypto` | `src/ec/mod.rs` | `EcGroup`, `EcPoint` | `EC_GROUP`/`EC_POINT` → RAII structs |
| `crypto/ec/ec_curve.c` | Named curve parameter tables | `openssl-crypto` | `src/ec/mod.rs` | `NamedCurve` enum, parameter constants | Static tables → const arrays / enum variants |
| `crypto/ec/ec_key.c` | `EC_KEY_*()` lifecycle | `openssl-crypto` | `src/ec/mod.rs` | `EcKey` | `EC_KEY` → RAII struct with `zeroize` on Drop |
| `crypto/ec/ecdsa_sign.c` | `ECDSA_sign()` | `openssl-crypto` | `src/ec/ecdsa.rs` | `EcdsaSigner::sign()` | C function → struct method |
| `crypto/ec/ecdsa_vrf.c` | `ECDSA_verify()` | `openssl-crypto` | `src/ec/ecdsa.rs` | `EcdsaVerifier::verify()` | C function → struct method |
| `crypto/ec/ecdh_ossl.c` | `ECDH_compute_key()` | `openssl-crypto` | `src/ec/ecdh.rs` | `Ecdh::compute_key()` | C function → struct method |
| `crypto/ec/ecx_meth.c` | X25519/X448/Ed25519/Ed448 methods | `openssl-crypto` | `src/ec/curve25519.rs` | `X25519`, `X448`, `Ed25519`, `Ed448` types | Method dispatch → enum-based type selection |
| `crypto/ec/curve25519.c` | X25519/Ed25519 core arithmetic | `openssl-crypto` | `src/ec/curve25519.rs` | `X25519::diffie_hellman()`, `Ed25519::sign/verify()` | C arithmetic → pure Rust or `core::arch` intrinsics |
| `crypto/ec/curve448/` | X448/Ed448 core arithmetic | `openssl-crypto` | `src/ec/curve25519.rs` | `X448`/`Ed448` operations | Curve448 field arithmetic → Rust implementation |
| Remaining `crypto/ec/*.c` | EC internal helpers, point formats, ASN.1 | `openssl-crypto` | `src/ec/*.rs` | Internal EC helpers | Distributed across EC submodules |

#### 2.2.4 crypto/rsa/ (26 files — RSA)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/rsa/rsa_lib.c` | `RSA_new()`, `RSA_free()`, RSA key lifecycle | `openssl-crypto` | `src/rsa/mod.rs` | `RsaKey` | `RSA` struct → RAII `RsaKey` with `zeroize` |
| `crypto/rsa/rsa_gen.c` | `RSA_generate_key_ex()` | `openssl-crypto` | `src/rsa/mod.rs` | `RsaKey::generate()` | Key generation → method returning `Result<RsaKey>` |
| `crypto/rsa/rsa_ossl.c` | RSA primitive operations | `openssl-crypto` | `src/rsa/mod.rs` | `RsaKey::encrypt/decrypt/sign/verify()` | C RSA ops → struct methods |
| `crypto/rsa/rsa_oaep.c` | OAEP padding | `openssl-crypto` | `src/rsa/oaep.rs` | `OaepPadding` | OAEP functions → `OaepPadding` struct |
| `crypto/rsa/rsa_pss.c` | PSS signature padding | `openssl-crypto` | `src/rsa/pss.rs` | `PssPadding` | PSS functions → `PssPadding` struct |
| `crypto/rsa/rsa_sign.c` | `RSA_sign()` | `openssl-crypto` | `src/rsa/mod.rs` | `RsaKey::sign()` | C sign → method |
| `crypto/rsa/rsa_pk1.c` | PKCS#1 v1.5 padding | `openssl-crypto` | `src/rsa/mod.rs` | `Pkcs1v15Padding` | Padding functions → padding struct |
| Remaining `crypto/rsa/*.c` | RSA helpers, blinding, X931, depr | `openssl-crypto` | `src/rsa/*.rs` | Internal RSA helpers | Distributed across RSA modules |

#### 2.2.5 crypto/bio/ (28 files — Abstracted I/O)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/bio/bio_lib.c` | `BIO_new()`, `BIO_free()`, `BIO_read()`, `BIO_write()` | `openssl-crypto` | `src/bio/mod.rs` | `Bio` trait, `impl Read + Write` | `BIO` vtable → `Bio` trait extending `Read + Write` |
| `crypto/bio/bss_mem.c` | `BIO_s_mem()` | `openssl-crypto` | `src/bio/mem.rs` | `MemBio` | Memory BIO → `MemBio` implementing `Bio` trait |
| `crypto/bio/bss_file.c` | `BIO_s_file()` | `openssl-crypto` | `src/bio/file.rs` | `FileBio` | File BIO → `FileBio` wrapping `std::fs::File` |
| `crypto/bio/bss_sock.c` | `BIO_s_socket()` | `openssl-crypto` | `src/bio/socket.rs` | `SocketBio` | Socket BIO → `SocketBio` wrapping `std::net::TcpStream` |
| `crypto/bio/bss_conn.c` | `BIO_s_connect()` | `openssl-crypto` | `src/bio/socket.rs` | `ConnectBio` | Connect BIO → `ConnectBio` |
| `crypto/bio/bss_dgram.c` | `BIO_s_datagram()` | `openssl-crypto` | `src/bio/socket.rs` | `DatagramBio` | Datagram BIO → `DatagramBio` wrapping `UdpSocket` |
| `crypto/bio/bf_buff.c` | `BIO_f_buffer()` | `openssl-crypto` | `src/bio/filter.rs` | `BufferFilter` | Buffer filter → `BufReader`/`BufWriter` wrapper |
| `crypto/bio/bf_null.c` | `BIO_f_null()` | `openssl-crypto` | `src/bio/filter.rs` | `NullFilter` | Null filter → pass-through `Bio` impl |
| Remaining `crypto/bio/*.c` | Additional BIO types and filters | `openssl-crypto` | `src/bio/*.rs` | Additional Bio implementations | Each BIO type → corresponding Rust struct |

#### 2.2.6 crypto/x509/ (98 files — X.509 Certificates)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/x509/x509_vfy.c` | `X509_verify_cert()`, chain verification | `openssl-crypto` | `src/x509/verify.rs` | `X509Verifier::verify_chain()` | Verification function → `X509Verifier` struct |
| `crypto/x509/x509_lu.c` | `X509_STORE`, `X509_LOOKUP` | `openssl-crypto` | `src/x509/store.rs` | `X509Store`, `X509Lookup` | Store/Lookup → RAII structs |
| `crypto/x509/x509_crl.c` | CRL processing | `openssl-crypto` | `src/x509/crl.rs` | `Crl` struct | CRL functions → `Crl` methods |
| `crypto/x509/x509_ext.c` | Extension handling | `openssl-crypto` | `src/x509/mod.rs` | `X509Extension` | Extension functions → typed extension structs |
| `crypto/x509/x_x509.c` | `X509` ASN.1 template | `openssl-crypto` | `src/x509/mod.rs` | `X509Certificate` | ASN.1 template → `der::Decode`/`der::Encode` |
| `crypto/x509/x509_set.c` | `X509_set_*()` setters | `openssl-crypto` | `src/x509/mod.rs` | `X509Builder` methods | Setter functions → builder pattern |
| `crypto/x509/x509_txt.c` | `X509_verify_cert_error_string()` | `openssl-crypto` | `src/x509/verify.rs` | `VerifyError::description()` | Error string function → `Display` trait |
| Remaining `crypto/x509/*.c` | Full X.509 implementation (98 files) | `openssl-crypto` | `src/x509/*.rs` | All X.509 functionality | Distributed across `x509` submodules |

#### 2.2.7 crypto/asn1/ (65 files — ASN.1 Encoding/Decoding)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/asn1/asn1_lib.c` | Core ASN.1 type manipulation | `openssl-crypto` | `src/asn1/mod.rs` | ASN.1 core types via `der` crate | Manual DER → `der::Decode`/`der::Encode` traits |
| `crypto/asn1/asn1_par.c` | ASN.1 printing/parsing | `openssl-crypto` | `src/asn1/mod.rs` | `impl Display` for ASN.1 types | Print functions → `Display` trait |
| `crypto/asn1/tasn_dec.c` | Template-based DER decoding | `openssl-crypto` | `src/asn1/template.rs` | `der::Decode` derive macros | Template decoder → derive macro based |
| `crypto/asn1/tasn_enc.c` | Template-based DER encoding | `openssl-crypto` | `src/asn1/template.rs` | `der::Encode` derive macros | Template encoder → derive macro based |
| Remaining `crypto/asn1/*.c` | Full ASN.1 implementation | `openssl-crypto` | `src/asn1/*.rs` | Complete ASN.1 module | Template system → `der` crate derive macros |

#### 2.2.8 crypto/pem/ (11 files — PEM Encoding)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/pem/pem_lib.c` | `PEM_read_bio()`, `PEM_write_bio()` | `openssl-crypto` | `src/pem.rs` | `PemEncoder`, `PemDecoder` | PEM read/write → `pem_rfc7468` crate integration |
| `crypto/pem/pem_pkey.c` | PEM key read/write | `openssl-crypto` | `src/pem.rs` | Key-specific PEM encoding | PEM key functions → typed encode/decode |
| Remaining `crypto/pem/*.c` | PEM helpers | `openssl-crypto` | `src/pem.rs` | PEM module | Consolidated into `pem.rs` |

#### 2.2.9 crypto/modes/ (12 files — Block Cipher Modes)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/modes/gcm128.c` | GCM mode implementation | `openssl-crypto` | `src/symmetric/aes.rs` | GCM mode via `Cipher` trait | GCM core → integrated into cipher implementations |
| `crypto/modes/ccm128.c` | CCM mode implementation | `openssl-crypto` | `src/symmetric/aes.rs` | CCM mode | CCM core → cipher implementation |
| `crypto/modes/ctr128.c` | CTR mode implementation | `openssl-crypto` | `src/symmetric/aes.rs` | CTR mode | CTR core → cipher implementation |
| `crypto/modes/xts128.c` | XTS mode implementation | `openssl-crypto` | `src/symmetric/aes.rs` | XTS mode | XTS core → cipher implementation |
| `crypto/modes/siv128.c` | SIV mode implementation | `openssl-crypto` | `src/symmetric/aes.rs` | SIV mode | SIV core → cipher implementation |
| Remaining `crypto/modes/*.c` | CFB, OFB, OCB, wrap modes | `openssl-crypto` | `src/symmetric/*.rs` | Remaining cipher modes | Each mode → cipher implementation |

#### 2.2.10 crypto/rand/ (9 files — Random Number Generation)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `crypto/rand/rand_lib.c` | `RAND_bytes()`, `RAND_priv_bytes()` | `openssl-crypto` | `src/rand.rs` | `rand_bytes()`, `rand_priv_bytes()` | C functions → Rust functions using `rand::rngs::OsRng` |
| `crypto/rand/rand_meth.c` | `RAND_METHOD` dispatch | `openssl-crypto` | `src/rand.rs` | `RandMethod` trait | Method dispatch → trait-based |
| `crypto/rand/randfile.c` | Seed file I/O | `openssl-crypto` | `src/rand.rs` | Seed file I/O | File-based seeding → `std::fs` based |
| Remaining `crypto/rand/*.c` | DRBG, pool, entropy | `openssl-crypto` | `src/rand.rs` | DRBG implementation | DRBG → Rust implementation |

#### 2.2.11 Symmetric Ciphers

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/aes/*.c` (9 files) | `openssl-crypto` | `src/symmetric/aes.rs` | AES block cipher → Rust AES with `core::arch` intrinsics for AES-NI |
| `crypto/chacha/*.c` | `openssl-crypto` | `src/symmetric/chacha20.rs` | ChaCha20-Poly1305 → Rust implementation |
| `crypto/des/*.c` (20 files) | `openssl-crypto` | `src/symmetric/des.rs` | DES/3DES → Rust implementation |
| `crypto/camellia/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | Camellia → Rust implementation |
| `crypto/aria/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | ARIA → Rust implementation |
| `crypto/sm4/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | SM4 → Rust implementation |
| `crypto/bf/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | Blowfish → Rust implementation |
| `crypto/cast/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | CAST5 → Rust implementation |
| `crypto/idea/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | IDEA → Rust implementation |
| `crypto/seed/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | SEED → Rust implementation |
| `crypto/rc2/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | RC2 → Rust implementation |
| `crypto/rc4/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | RC4 → Rust implementation |
| `crypto/rc5/*.c` | `openssl-crypto` | `src/symmetric/legacy.rs` | RC5 → Rust implementation |

#### 2.2.12 Hash Algorithms

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/sha/*.c` (9 files) | `openssl-crypto` | `src/hash/sha.rs` | SHA-1, SHA-2, SHA-3, SHAKE → Rust implementation |
| `crypto/md5/*.c` | `openssl-crypto` | `src/hash/md5.rs` | MD5 → Rust implementation |
| `crypto/md2/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | MD2 → Rust (legacy, feature-gated) |
| `crypto/md4/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | MD4 → Rust (legacy, feature-gated) |
| `crypto/mdc2/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | MDC2 → Rust (legacy, feature-gated) |
| `crypto/ripemd/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | RIPEMD-160 → Rust (legacy) |
| `crypto/whrlpool/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | Whirlpool → Rust (legacy) |
| `crypto/sm3/*.c` | `openssl-crypto` | `src/hash/legacy.rs` | SM3 → Rust implementation |

#### 2.2.13 MAC Algorithms

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/hmac/*.c` (4 files) | `openssl-crypto` | `src/mac.rs` | HMAC → Rust implementation |
| `crypto/cmac/*.c` | `openssl-crypto` | `src/mac.rs` | CMAC → Rust implementation |
| `crypto/poly1305/*.c` | `openssl-crypto` | `src/mac.rs` | Poly1305 → Rust implementation |
| `crypto/siphash/*.c` | `openssl-crypto` | `src/mac.rs` | SipHash → Rust implementation |

#### 2.2.14 Key Exchange and Signatures

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/dh/*.c` (14 files) | `openssl-crypto` | `src/dh.rs` | Diffie-Hellman → Rust DH implementation |
| `crypto/dsa/*.c` (14 files) | `openssl-crypto` | `src/dsa.rs` | DSA → Rust DSA implementation |
| `crypto/ffc/*.c` (7 files) | `openssl-crypto` | `src/dh.rs` | Finite field params → integrated into DH module |

#### 2.2.15 Post-Quantum Cryptography

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/ml_kem/*.c` (8 files) | `openssl-crypto` | `src/pqc/ml_kem.rs` | ML-KEM (FIPS 203) → Rust implementation |
| `crypto/ml_dsa/*.c` (8 files) | `openssl-crypto` | `src/pqc/ml_dsa.rs` | ML-DSA (FIPS 204) → Rust implementation |
| `crypto/slh_dsa/*.c` (10 files) | `openssl-crypto` | `src/pqc/slh_dsa.rs` | SLH-DSA (FIPS 205) → Rust implementation |
| `crypto/lms/*.c` (8 files) | `openssl-crypto` | `src/pqc/lms.rs` | LMS (SP 800-208) → Rust implementation |

#### 2.2.16 Protocols and Formats

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/pkcs7/*.c` (8 files) | `openssl-crypto` | `src/pkcs/pkcs7.rs` | PKCS#7 → Rust implementation |
| `crypto/pkcs12/*.c` (16 files) | `openssl-crypto` | `src/pkcs/pkcs12.rs` | PKCS#12 → Rust implementation |
| `crypto/cms/*.c` (19 files) | `openssl-crypto` | `src/pkcs/cms.rs` | CMS → Rust implementation |
| `crypto/ocsp/*.c` (10 files) | `openssl-crypto` | `src/ocsp.rs` | OCSP → Rust implementation |
| `crypto/ct/*.c` (10 files) | `openssl-crypto` | `src/ct.rs` | Certificate Transparency → Rust |
| `crypto/cmp/*.c` (13 files) | `openssl-crypto` | `src/cmp.rs` | CMP → Rust implementation |
| `crypto/ts/*.c` (11 files) | `openssl-crypto` | `src/ts.rs` | RFC 3161 Timestamps → Rust |
| `crypto/hpke/*.c` (6 files) | `openssl-crypto` | `src/hpke.rs` | HPKE (RFC 9180) → Rust implementation |
| `crypto/kdf/*.c` (5 files) | `openssl-crypto` | `src/kdf.rs` | KDF support → Rust implementation |

#### 2.2.17 Remaining crypto/ Subdirectories

| C Source Directory | Rust Crate | Rust Module | Transformation |
|--------------------|------------|-------------|----------------|
| `crypto/conf/*.c` (8 files) | `openssl-common` | `src/config.rs` | Config parser → `serde`-based config |
| `crypto/encode_decode/*.c` (8 files) | `openssl-crypto` | `src/evp/encode_decode.rs` | Key serialization → Rust encode/decode |
| `crypto/store/*.c` (7 files) | `openssl-crypto` | `src/x509/store.rs` | OSSL_STORE → Rust store implementation |
| `crypto/property/*.c` (6 files) | `openssl-crypto` | `src/provider/property.rs` | Property query/match → Rust implementation |
| `crypto/err/*.c` (7 files) | `openssl-common` | `src/error.rs` | Error system → `thiserror` |
| `crypto/http/*.c` (3 files) | `openssl-crypto` | `src/cmp.rs` | HTTP client → Rust HTTP helpers |
| `crypto/async/*.c` (3 files) | `openssl-crypto` | `src/thread.rs` | Async job infra → `tokio` tasks (QUIC only) |
| `crypto/hashtable/*.c` (2 files) | `openssl-common` | `src/types.rs` | Hash table → `std::collections::HashMap` |
| `crypto/thread/*.c` (2 files) | `openssl-crypto` | `src/thread.rs` | Thread pool → `tokio` runtime / `std::thread` |
| `crypto/lhash/*.c` (3 files) | `openssl-common` | `src/types.rs` | Linear hash → `HashMap` |
| `crypto/stack/*.c` (2 files) | `openssl-common` | `src/types.rs` | `STACK_OF` → `Vec<T>` |
| `crypto/buffer/*.c` (2 files) | `openssl-common` | `src/types.rs` | `BUF_MEM` → `Vec<u8>` / `bytes::BytesMut` |
| `crypto/txt_db/*.c` (1 file) | `openssl-crypto` | `src/x509/store.rs` | Text database → Rust parsed struct |
| `crypto/ui/*.c` (5 files) | `openssl-crypto` | `src/bio/mod.rs` | UI abstraction → closure-based prompts |
| `crypto/dso/*.c` (5 files) | `openssl-crypto` | `src/init.rs` | Dynamic library loading → `libloading` equivalent |
| `crypto/ess/*.c` (5 files) | `openssl-crypto` | `src/pkcs/cms.rs` | Enhanced Security Services → CMS integration |
| `crypto/crmf/*.c` (5 files) | `openssl-crypto` | `src/cmp.rs` | CRMF → CMP integration |
| `crypto/objects/*.c` | `openssl-crypto` | `src/asn1/mod.rs` | OID registry → const OID definitions |
| `crypto/comp/*.c` | `openssl-crypto` | `src/context.rs` | Compression → `Option<CompressionMethod>` |
| `crypto/sm2/*.c` | `openssl-crypto` | `src/ec/mod.rs` | SM2 → EC module integration |
| `crypto/srp/*.c` | `openssl-crypto` | `src/dh.rs` | SRP → deprecated DH-based implementation |

### 2.3 ssl/ Files (103 total)

#### 2.3.1 ssl/ Top-Level Files (~34 files)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/ssl_lib.c` | `SSL_CTX_new()`, `SSL_new()`, `SSL_read()`, `SSL_write()`, central API | `openssl-ssl` | `src/lib.rs`, `src/ssl.rs`, `src/ssl_ctx.rs` | `SslContext`, `SslStream`, core API methods | Central C module → split into `ssl_ctx.rs` (context) and `ssl.rs` (connection); `SSL_CTX` → `SslContext`; `SSL` → `SslStream` |
| `ssl/ssl_ciph.c` | Cipher suite selection, cipher list parsing | `openssl-ssl` | `src/cipher.rs` | `CipherSuite`, `CipherList` | Cipher catalog + rule parser → `CipherSuite` enum + `CipherList` |
| `ssl/ssl_sess.c` | `SSL_SESSION` lifecycle, cache | `openssl-ssl` | `src/session.rs` | `SslSession`, `SessionCache` | Session management → RAII `SslSession` + `SessionCache` with `parking_lot::RwLock` |
| `ssl/ssl_asn1.c` | Session DER serialization | `openssl-ssl` | `src/session.rs` | `impl Serialize/Deserialize for SslSession` | `i2d`/`d2i` → `serde` + `der` crate |
| `ssl/ssl_cert.c` | `CERT`/`CERT_PKEY` management | `openssl-ssl` | `src/cert.rs` | `CertStore`, `CertKey` | Manual cert management → RAII structs |
| `ssl/ssl_cert_comp.c` | Certificate compression | `openssl-ssl` | `src/cert.rs` | `CertCompression` | Compression prefs → typed struct |
| `ssl/ssl_rsa.c` | Certificate/key loading APIs | `openssl-ssl` | `src/cert.rs` | `SslContext::load_cert()`, `load_key()` | Load functions → context methods |
| `ssl/ssl_rsa_legacy.c` | Deprecated RSA-specific setters | `openssl-ssl` | `src/cert.rs` | `#[deprecated]` wrapper functions | Deprecated C → `#[deprecated]` Rust |
| `ssl/ssl_conf.c` | `SSL_CONF` command engine | `openssl-ssl` | `src/config.rs` | `SslConfCmd` | Text command dispatch → enum-based command execution |
| `ssl/ssl_mcnf.c` | Config module bridge | `openssl-ssl` | `src/config.rs` | `SslConfig` | Config module → `serde` config |
| `ssl/methods.c` | `SSL_METHOD` constructors | `openssl-ssl` | `src/method.rs` | `SslMethod` enum | Method macros → enum variants |
| `ssl/s3_lib.c` | SSLv3/TLS library, cipher catalog, ctrl | `openssl-ssl` | `src/s3_lib.rs` | `S3Library` utilities | Large utility module → Rust utilities |
| `ssl/s3_msg.c` | ChangeCipherSpec, alert dispatch | `openssl-ssl` | `src/s3_lib.rs` | Alert handling | Alert staging → enum-based alert dispatch |
| `ssl/s3_enc.c` | Finished-MAC, key block cleanup | `openssl-ssl` | `src/s3_lib.rs` | Transcript/MAC management | Transcript → `zeroize`-protected buffers |
| `ssl/tls13_enc.c` | TLS 1.3 key derivation/encryption | `openssl-ssl` | `src/tls13.rs` | `Tls13Encryption` | TLS 1.3 enc → `Tls13Encryption` struct |
| `ssl/t1_enc.c` | TLS 1.x key derivation | `openssl-ssl` | `src/tls13.rs` | `Tls1xEncryption` | TLS 1.x enc → combined encryption module |
| `ssl/t1_lib.c` | TLS extension processing | `openssl-ssl` | `src/t1_lib.rs` | Extension processing, group/sigalg negotiation | Extension helpers → typed extension handlers |
| `ssl/t1_trce.c` | TLS tracing/debugging | `openssl-ssl` | `src/t1_lib.rs` | `tracing` integration | Printf-based trace → `tracing::debug!()` |
| `ssl/ssl_init.c` | `OPENSSL_init_ssl()` | `openssl-ssl` | `src/lib.rs` | `init_ssl()` | Init function → module init |
| `ssl/ssl_txt.c` | Session printing | `openssl-ssl` | `src/session.rs` | `impl Display for SslSession` | Print function → `Display` trait |
| `ssl/ssl_stat.c` | State/alert stringification | `openssl-ssl` | `src/lib.rs` | `impl Display` for state enums | String functions → `Display` traits |
| `ssl/ssl_err_legacy.c` | Legacy error string loading | `openssl-ssl` | `src/lib.rs` | Error strings (automatic via `thiserror`) | Manual loading → derive macro |
| `ssl/ssl_utst.c` | Unit test helpers | `openssl-ssl` | `src/lib.rs` | Test helpers (`#[cfg(test)]`) | Test-only exports → `#[cfg(test)]` module |
| `ssl/bio_ssl.c` | SSL filter BIO | `openssl-ssl` | `src/ssl.rs` | `SslStream` implementing `Read + Write` | BIO filter → `SslStream` as `Read + Write` impl |
| `ssl/d1_lib.c` | DTLS lifecycle, retransmission timer | `openssl-ssl` | `src/dtls.rs` | `DtlsContext` | DTLS lifecycle → `DtlsContext` struct |
| `ssl/d1_msg.c` | DTLS message writing | `openssl-ssl` | `src/dtls.rs` | DTLS message methods | DTLS write → methods on `DtlsContext` |
| `ssl/d1_srtp.c` | DTLS-SRTP extension | `openssl-ssl` | `src/srtp.rs` | `SrtpProfile` | SRTP profiles → enum-based profiles |
| `ssl/tls_depr.c` | Deprecated TLS functions | `openssl-ssl` | `src/lib.rs` | `#[deprecated]` functions | Deprecated C → `#[deprecated]` Rust |
| `ssl/tls_srp.c` | TLS-SRP extension (deprecated) | `openssl-ssl` | `src/lib.rs` | `#[deprecated]` SRP functions | Deprecated SRP → feature-gated deprecated |
| `ssl/pqueue.c` | DTLS priority queue (legacy) | `openssl-ssl` | `src/dtls.rs` | `BinaryHeap` or `BTreeMap` | Legacy pqueue → `std::collections::BinaryHeap` |
| `ssl/priority_queue.c` | Generic heap-based priority queue | `openssl-ssl` | `src/lib.rs` | `BinaryHeap<T>` | Custom heap → `std::collections::BinaryHeap` |

#### 2.3.2 ssl/statem/ (9 files — Handshake State Machine)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/statem/statem.c` | Message-flow state machine, `ossl_statem_connect/accept` | `openssl-ssl` | `src/statem/mod.rs` | `HandshakeStateMachine` | `MSG_FLOW_*` states → enum-based state machine with type-state pattern |
| `ssl/statem/statem_clnt.c` | Client handshake transitions, message constructors | `openssl-ssl` | `src/statem/client.rs` | `ClientHandshake` | Client transitions → `ClientHandshake` state machine |
| `ssl/statem/statem_srvr.c` | Server handshake transitions, message processors | `openssl-ssl` | `src/statem/server.rs` | `ServerHandshake` | Server transitions → `ServerHandshake` state machine |
| `ssl/statem/statem_lib.c` | Shared handshake utilities | `openssl-ssl` | `src/statem/mod.rs` | Shared handshake helpers | Shared functions → module-level functions |
| `ssl/statem/statem_dtls.c` | DTLS fragmentation/reassembly | `openssl-ssl` | `src/statem/dtls.rs` | `DtlsFragmenter`, `DtlsReassembler` | Fragment/reassembly → typed structs |
| `ssl/statem/extensions.c` | Extension registry and dispatcher | `openssl-ssl` | `src/statem/extensions.rs` | `ExtensionRegistry`, `ExtensionHandler` trait | `ext_defs[]` → trait-based extension handlers |
| `ssl/statem/extensions_clnt.c` | Client extension constructors/parsers | `openssl-ssl` | `src/statem/extensions.rs` | `ClientExtension` implementations | `tls_construct_ctos_*` → trait impl methods |
| `ssl/statem/extensions_srvr.c` | Server extension handlers | `openssl-ssl` | `src/statem/extensions.rs` | `ServerExtension` implementations | `tls_parse_ctos_*` → trait impl methods |
| `ssl/statem/extensions_cust.c` | Custom extension infrastructure | `openssl-ssl` | `src/statem/extensions.rs` | `CustomExtension` | Custom ext API → closure-based registration |

#### 2.3.3 ssl/record/ (11 files — Record Layer)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/record/rec_layer_s3.c` | TLS stream record I/O, `ssl3_read/write_bytes` | `openssl-ssl` | `src/record/tls.rs` | `TlsRecordLayer` | TLS record glue → `TlsRecordLayer` struct |
| `ssl/record/rec_layer_d1.c` | DTLS record I/O, epoch management | `openssl-ssl` | `src/record/dtls.rs` | `DtlsRecordLayer` | DTLS record glue → `DtlsRecordLayer` struct |
| `ssl/record/record.h` | `TLS_RECORD`, `RECORD_LAYER` types | `openssl-ssl` | `src/record/mod.rs` | `TlsRecord`, `RecordLayer` trait | C struct/types → Rust structs + trait |
| `ssl/record/methods/` (subfolder) | Record method implementations | `openssl-ssl` | `src/record/mod.rs` | Record method trait implementations | Method vtables → trait implementations |

#### 2.3.4 ssl/quic/ (42 files — QUIC v1 Stack)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/quic/quic_engine.c` | `QUIC_ENGINE` orchestration | `openssl-ssl` | `src/quic/engine.rs` | `QuicEngine` | `QUIC_ENGINE` → `QuicEngine` with tokio runtime handle |
| `ssl/quic/quic_reactor.c` | `QUIC_REACTOR` poll/tick loop | `openssl-ssl` | `src/quic/reactor.rs` | `QuicReactor` | Poll loop → async reactor with `tokio::select!` |
| `ssl/quic/quic_port.c` | `QUIC_PORT` datagram demux | `openssl-ssl` | `src/quic/port.rs` | `QuicPort` | Port management → `QuicPort` async struct |
| `ssl/quic/quic_channel.c` | `QUIC_CHANNEL` per-connection state | `openssl-ssl` | `src/quic/channel.rs` | `QuicChannel` | Channel state machine → `QuicChannel` async struct |
| `ssl/quic/quic_stream_map.c` | Stream management, scheduling | `openssl-ssl` | `src/quic/stream.rs` | `StreamMap` | Stream map → `HashMap<StreamId, QuicStream>` |
| `ssl/quic/quic_sstream.c` | Send stream buffering | `openssl-ssl` | `src/quic/stream.rs` | `SendStream` | Ring buffer → `bytes::BytesMut` |
| `ssl/quic/quic_rstream.c` | Receive stream reassembly | `openssl-ssl` | `src/quic/stream.rs` | `RecvStream` | Reassembly → ordered `BTreeMap` |
| `ssl/quic/quic_txp.c` | TX packetiser | `openssl-ssl` | `src/quic/tx.rs` | `TxPacketiser` | TX assembly → `TxPacketiser` struct |
| `ssl/quic/quic_record_rx.c` | QRX packet decryption | `openssl-ssl` | `src/quic/rx.rs` | `QuicRx` | QRX → `QuicRx` struct |
| `ssl/quic/quic_record_tx.c` | QTX packet encryption | `openssl-ssl` | `src/quic/tx.rs` | `QuicTx` | QTX → integrated into `TxPacketiser` |
| `ssl/quic/quic_ackm.c` | ACK manager, loss detection | `openssl-ssl` | `src/quic/ack.rs` | `AckManager` | ACK manager → `AckManager` struct |
| `ssl/quic/cc_newreno.c` | NewReno congestion control | `openssl-ssl` | `src/quic/cc.rs` | `NewRenoCongestionControl` | NewReno → `NewRenoCongestionControl` struct |
| `ssl/quic/quic_fc.c` | Flow control | `openssl-ssl` | `src/quic/stream.rs` | `FlowControl` | Flow control → `FlowControl` struct |
| `ssl/quic/quic_demux.c` | Datagram demultiplexer | `openssl-ssl` | `src/quic/port.rs` | `Demux` | Demux → integrated into `QuicPort` |
| `ssl/quic/quic_tls.c` | TLS 1.3 handshake shim | `openssl-ssl` | `src/quic/tls_shim.rs` | `TlsShim` | TLS shim → `TlsShim` bridging sync TLS |
| `ssl/quic/quic_impl.c` | QUIC SSL object API | `openssl-ssl` | `src/quic/mod.rs` | QUIC-aware SSL methods | QUIC SSL → trait-based QUIC methods |
| `ssl/quic/quic_wire.c` | Frame encode/decode | `openssl-ssl` | `src/quic/mod.rs` | Frame codec | Wire format → typed frame enum |
| `ssl/quic/quic_wire_pkt.c` | Packet header codec | `openssl-ssl` | `src/quic/mod.rs` | Packet header codec | Header encode/decode → Rust impl |
| `ssl/quic/quic_statm.c` | RTT statistics | `openssl-ssl` | `src/quic/ack.rs` | `RttEstimator` | RTT tracker → struct |
| `ssl/quic/quic_lcidm.c` | Local CID manager | `openssl-ssl` | `src/quic/channel.rs` | `LocalCidManager` | CID management → struct |
| `ssl/quic/quic_rcidm.c` | Remote CID manager | `openssl-ssl` | `src/quic/channel.rs` | `RemoteCidManager` | CID management → struct |
| `ssl/quic/quic_srt_gen.c` | Stateless reset token gen | `openssl-ssl` | `src/quic/channel.rs` | `ResetTokenGenerator` | HMAC-SHA256 token → struct |
| `ssl/quic/quic_srtm.c` | Reset token→connection map | `openssl-ssl` | `src/quic/channel.rs` | `ResetTokenMap` | Token map → `HashMap` |
| `ssl/quic/quic_cfq.c` | Control frame queue | `openssl-ssl` | `src/quic/tx.rs` | `ControlFrameQueue` | CFQ → `VecDeque`-based queue |
| `ssl/quic/quic_fifd.c` | FIFD retransmission binding | `openssl-ssl` | `src/quic/tx.rs` | `FifdRetransmitter` | FIFD → integrated retransmission |
| `ssl/quic/quic_txpim.c` | Per-packet metadata pool | `openssl-ssl` | `src/quic/tx.rs` | `TxPacketInfo` | Metadata pool → `Vec<TxPacketInfo>` |
| `ssl/quic/quic_sf_list.c` | Stream frame reassembly list | `openssl-ssl` | `src/quic/stream.rs` | `StreamFrameList` | Range list → `BTreeMap` |
| `ssl/quic/quic_record_shared.c` | Per-level key material | `openssl-ssl` | `src/quic/mod.rs` | `EncryptionLevel` keys | Shared key state → typed key structs |
| `ssl/quic/quic_record_util.c` | Initial secret derivation | `openssl-ssl` | `src/quic/mod.rs` | `derive_initial_secrets()` | Secret derivation → function |
| `ssl/quic/quic_rx_depack.c` | Frame depacketisation | `openssl-ssl` | `src/quic/rx.rs` | `Depacketiser` | Frame parsing → typed frame dispatch |
| `ssl/quic/quic_trace.c` | QUIC tracing | `openssl-ssl` | `src/quic/mod.rs` | `tracing` integration | C trace → `tracing::debug!()` |
| `ssl/quic/quic_tserver.c` | Test server | `openssl-ssl` | `src/quic/mod.rs` | Test server (`#[cfg(test)]`) | Test-only → `#[cfg(test)]` module |
| `ssl/quic/quic_thread_assist.c` | Thread assist for blocking | `openssl-ssl` | `src/quic/engine.rs` | `tokio::spawn_blocking` | Thread assist → `spawn_blocking` |
| `ssl/quic/quic_tls_api.c` | TLS API integration | `openssl-ssl` | `src/quic/tls_shim.rs` | TLS API shim methods | TLS bridge → shim methods |
| `ssl/quic/quic_types.c` | QUIC type utilities | `openssl-ssl` | `src/quic/mod.rs` | QUIC types | Type utilities → Rust types |
| `ssl/quic/quic_method.c` | QUIC SSL_METHOD | `openssl-ssl` | `src/quic/mod.rs` | `QuicMethod` | Method → enum variant |
| `ssl/quic/quic_obj.c` | QUIC SSL object management | `openssl-ssl` | `src/quic/mod.rs` | QUIC object lifecycle | Object mgmt → RAII structs |
| `ssl/quic/quic_reactor_wait_ctx.c` | Reactor blocking context | `openssl-ssl` | `src/quic/reactor.rs` | `ReactorWaitCtx` | Wait context → struct |
| `ssl/quic/qlog.c` | QUIC logging (qlog format) | `openssl-ssl` | `src/quic/mod.rs` | `tracing` qlog integration | qlog → `tracing` structured events |
| `ssl/quic/qlog_event_helpers.c` | Qlog event helpers | `openssl-ssl` | `src/quic/mod.rs` | Qlog helper functions | Event helpers → Rust functions |
| `ssl/quic/json_enc.c` | JSON encoding for qlog | `openssl-ssl` | `src/quic/mod.rs` | `serde_json` integration | Manual JSON → `serde_json::to_string()` |
| `ssl/quic/uint_set.c` | Integer range set | `openssl-ssl` | `src/quic/ack.rs` | `RangeSet` | Custom set → `BTreeSet<Range<u64>>` |

#### 2.3.5 ssl/ech/ (4 files — Encrypted Client Hello)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/ech/ech_internal.c` | ECH encode/encrypt/decrypt, swaperoo | `openssl-ssl` | `src/ech/mod.rs` | `EchEngine` | ECH engine → `EchEngine` struct |
| `ssl/ech/ech_helper.c` | ECH helper primitives | `openssl-ssl` | `src/ech/encode.rs` | Helper functions | C helpers → Rust utility functions |
| `ssl/ech/ech_ssl_apis.c` | Public ECH SSL/SSL_CTX APIs | `openssl-ssl` | `src/ech/mod.rs` | `SslContext`/`SslStream` ECH methods | Public APIs → methods on context/stream |
| `ssl/ech/ech_store.c` | ECH configuration store | `openssl-ssl` | `src/ech/decrypt.rs` | `EchStore` | Config store → `EchStore` struct |

#### 2.3.6 ssl/rio/ (3 files — Reactive I/O)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `ssl/rio/poll_builder.c` | `RIO_POLL_BUILDER`, select/poll abstraction | `openssl-ssl` | `src/rio.rs` | `tokio::io` / `mio` integration | C poll/select → async I/O with tokio |
| `ssl/rio/poll_immediate.c` | `SSL_poll()` API | `openssl-ssl` | `src/rio.rs` | `SslStream::poll()` | C poll → async poll method |
| `ssl/rio/rio_notifier.c` | `RIO_NOTIFIER` wakeup FD pair | `openssl-ssl` | `src/rio.rs` | `tokio::sync::Notify` | socketpair notifier → `tokio::sync::Notify` |

### 2.4 providers/ Files (199 total)

#### 2.4.1 providers/ Top-Level (5 files)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `providers/defltprov.c` | `ossl_default_provider_init()`, default dispatch tables | `openssl-provider` | `src/default.rs` | `DefaultProvider` implementing provider traits | `OSSL_DISPATCH` → trait implementations; `OSSL_ALGORITHM` tables → trait method returns |
| `providers/baseprov.c` | `ossl_base_provider_init()`, encoder/decoder/store | `openssl-provider` | `src/base.rs` | `BaseProvider` | Base provider → `BaseProvider` struct |
| `providers/legacyprov.c` | `ossl_legacy_provider_init()`, legacy algorithms | `openssl-provider` | `src/legacy.rs` | `LegacyProvider` | Legacy provider → `LegacyProvider` struct |
| `providers/nullprov.c` | `ossl_null_provider_init()`, no-op sentinel | `openssl-provider` | `src/null.rs` | `NullProvider` | Null provider → `NullProvider` (no-op) |
| `providers/prov_running.c` | `ossl_prov_is_running()` default hook | `openssl-provider` | `src/lib.rs` | `Provider::is_running()` default impl | Default hook → trait default method |

#### 2.4.2 providers/fips/ (8 files — FIPS Module)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `providers/fips/fipsprov.c` | FIPS provider init, dispatch, config | `openssl-fips` | `src/provider.rs` | `FipsProvider` | FIPS dispatch → `FipsProvider` struct + trait impls |
| `providers/fips/fips_entry.c` | `OSSL_provider_init` trampoline | `openssl-fips` | `src/lib.rs` | FIPS entry point | Trampoline → direct init in `lib.rs` |
| `providers/fips/self_test.c` | POST orchestration, integrity verification | `openssl-fips` | `src/self_test.rs` | `SelfTest::run_post()` | Self-test state machine → enum-based state machine |
| `providers/fips/self_test_kats.c` | KAT execution engine | `openssl-fips` | `src/kats.rs` | `KnownAnswerTests::execute()` | KAT executor → `KnownAnswerTests` struct methods |
| `providers/fips/self_test_data.c` | Compiled-in KAT vectors | `openssl-fips` | `src/kats.rs` | `const KAT_VECTORS: &[KatVector]` | Static data → const arrays |
| `providers/fips/fipsindicator.c` | Approved/unapproved indicator | `openssl-fips` | `src/indicator.rs` | `FipsIndicator` | Indicator mechanism → `FipsIndicator` struct |
| `providers/fips/self_test.h` | Self-test types and interfaces | `openssl-fips` | `src/self_test.rs` | Self-test types | Header → Rust type definitions |

#### 2.4.3 providers/implementations/ (194 files across 14 subdirectories)

| C Source Directory | File Count | Rust Crate | Rust Module | Transformation |
|--------------------|------------|------------|-------------|----------------|
| `providers/implementations/ciphers/*.c` | 81 | `openssl-provider` | `src/implementations/ciphers/*.rs` | Each cipher impl → trait implementation for `CipherProvider` |
| `providers/implementations/digests/*.c` | 17 | `openssl-provider` | `src/implementations/digests/*.rs` | Each digest impl → `DigestProvider` trait impl |
| `providers/implementations/kdfs/*.c` | 16 | `openssl-provider` | `src/implementations/kdfs/*.rs` | Each KDF impl → `KdfProvider` trait impl |
| `providers/implementations/encode_decode/*.c` | 16 | `openssl-provider` | `src/implementations/encode_decode/*.rs` | Each encoder/decoder → `EncoderDecoderProvider` trait impl |
| `providers/implementations/rands/*.c` | 15 | `openssl-provider` | `src/implementations/rands/*.rs` | DRBG/seed impls → `RandProvider` trait impl |
| `providers/implementations/keymgmt/*.c` | 13 | `openssl-provider` | `src/implementations/keymgmt/*.rs` | Key management → `KeyMgmtProvider` trait impl |
| `providers/implementations/macs/*.c` | 9 | `openssl-provider` | `src/implementations/macs/*.rs` | MAC impls → `MacProvider` trait impl |
| `providers/implementations/signature/*.c` | 9 | `openssl-provider` | `src/implementations/signatures/*.rs` | Signature impls → `SignatureProvider` trait impl |
| `providers/implementations/kem/*.c` | 7 | `openssl-provider` | `src/implementations/kem/*.rs` | KEM impls → `KemProvider` trait impl |
| `providers/implementations/exchange/*.c` | 4 | `openssl-provider` | `src/implementations/exchange/*.rs` | Key exchange → `KeyExchangeProvider` trait impl |
| `providers/implementations/storemgmt/*.c` | 3 | `openssl-provider` | `src/implementations/store/*.rs` | Store impls → `StoreProvider` trait impl |
| `providers/implementations/asymciphers/*.c` | 2 | `openssl-provider` | `src/implementations/ciphers/*.rs` | Asym cipher → `AsymCipherProvider` trait impl |
| `providers/implementations/skeymgmt/*.c` | 2 | `openssl-provider` | `src/implementations/keymgmt/*.rs` | Secret key mgmt → integrated into keymgmt |
| `providers/common/*.c` | ~10 | `openssl-provider` | `src/lib.rs`, shared utilities | Common provider utilities → Rust module helpers |

### 2.5 apps/ Files (77 total)

#### 2.5.1 apps/ Top-Level (56 command files)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `apps/openssl.c` | `main()`, command dispatcher, LHASH lookup | `openssl-cli` | `src/main.rs` | `fn main()`, `clap::Command` dispatcher | C main + LHASH → `clap` derive-based CLI |
| `apps/req.c` | `req_main()` — CSR generation/processing | `openssl-cli` | `src/commands/req.rs` | `ReqCommand` | `*_main()` → clap subcommand struct |
| `apps/x509.c` | `x509_main()` — cert operations | `openssl-cli` | `src/commands/x509.rs` | `X509Command` | Subcommand → clap struct |
| `apps/ca.c` | `ca_main()` — CA workflow | `openssl-cli` | `src/commands/ca.rs` | `CaCommand` | Subcommand → clap struct |
| `apps/verify.c` | `verify_main()` — cert verification | `openssl-cli` | `src/commands/verify.rs` | `VerifyCommand` | Subcommand → clap struct |
| `apps/crl.c` | `crl_main()` | `openssl-cli` | `src/commands/crl.rs` | `CrlCommand` | Subcommand → clap struct |
| `apps/genpkey.c` | `genpkey_main()` | `openssl-cli` | `src/commands/genpkey.rs` | `GenpkeyCommand` | Subcommand → clap struct |
| `apps/pkey.c` | `pkey_main()` | `openssl-cli` | `src/commands/pkey.rs` | `PkeyCommand` | Subcommand → clap struct |
| `apps/genrsa.c` | `genrsa_main()` | `openssl-cli` | `src/commands/genrsa.rs` | `GenrsaCommand` | Subcommand → clap struct |
| `apps/gendsa.c` | `gendsa_main()` | `openssl-cli` | `src/commands/gendsa.rs` | `GendsaCommand` | Subcommand → clap struct |
| `apps/dhparam.c` | `dhparam_main()` | `openssl-cli` | `src/commands/dhparam.rs` | `DhparamCommand` | Subcommand → clap struct |
| `apps/dsaparam.c` | `dsaparam_main()` | `openssl-cli` | `src/commands/dsaparam.rs` | `DsaparamCommand` | Subcommand → clap struct |
| `apps/enc.c` | `enc_main()` | `openssl-cli` | `src/commands/enc.rs` | `EncCommand` | Subcommand → clap struct |
| `apps/cms.c` | `cms_main()` | `openssl-cli` | `src/commands/cms.rs` | `CmsCommand` | Subcommand → clap struct |
| `apps/pkcs12.c` | `pkcs12_main()` | `openssl-cli` | `src/commands/pkcs12.rs` | `Pkcs12Command` | Subcommand → clap struct |
| `apps/pkcs7.c` | `pkcs7_main()` | `openssl-cli` | `src/commands/pkcs7.rs` | `Pkcs7Command` | Subcommand → clap struct |
| `apps/pkcs8.c` | `pkcs8_main()` | `openssl-cli` | `src/commands/pkcs8.rs` | `Pkcs8Command` | Subcommand → clap struct |
| `apps/dgst.c` | `dgst_main()` | `openssl-cli` | `src/commands/dgst.rs` | `DgstCommand` | Subcommand → clap struct |
| `apps/s_client.c` | `s_client_main()` — TLS client tool | `openssl-cli` | `src/commands/s_client.rs` | `SClientCommand` | Subcommand → clap struct |
| `apps/s_server.c` | `s_server_main()` — TLS server tool | `openssl-cli` | `src/commands/s_server.rs` | `SServerCommand` | Subcommand → clap struct |
| `apps/s_time.c` | `s_time_main()` — TLS benchmark | `openssl-cli` | `src/commands/s_time.rs` | `STimeCommand` | Subcommand → clap struct |
| `apps/ciphers.c` | `ciphers_main()` | `openssl-cli` | `src/commands/ciphers.rs` | `CiphersCommand` | Subcommand → clap struct |
| `apps/version.c` | `version_main()` | `openssl-cli` | `src/commands/version.rs` | `VersionCommand` | Subcommand → clap struct |
| `apps/list.c` | `list_main()` | `openssl-cli` | `src/commands/list.rs` | `ListCommand` | Subcommand → clap struct |
| `apps/speed.c` | `speed_main()` | `openssl-cli` | `src/commands/speed.rs` | `SpeedCommand` | Subcommand → clap struct |
| `apps/rand.c` | `rand_main()` | `openssl-cli` | `src/commands/rand.rs` | `RandCommand` | Subcommand → clap struct |
| `apps/prime.c` | `prime_main()` | `openssl-cli` | `src/commands/prime.rs` | `PrimeCommand` | Subcommand → clap struct |
| `apps/ocsp.c` | `ocsp_main()` | `openssl-cli` | `src/commands/ocsp.rs` | `OcspCommand` | Subcommand → clap struct |
| `apps/cmp.c` | `cmp_main()` | `openssl-cli` | `src/commands/cmp.rs` | `CmpCommand` | Subcommand → clap struct |
| `apps/ts.c` | `ts_main()` | `openssl-cli` | `src/commands/ts.rs` | `TsCommand` | Subcommand → clap struct |
| `apps/rehash.c` | `rehash_main()` | `openssl-cli` | `src/commands/rehash.rs` | `RehashCommand` | Subcommand → clap struct |
| `apps/fipsinstall.c` | `fipsinstall_main()` | `openssl-cli` | `src/commands/fipsinstall.rs` | `FipsinstallCommand` | Subcommand → clap struct |
| `apps/skeyutl.c` | `skeyutl_main()` | `openssl-cli` | `src/commands/skeyutl.rs` | `SkeyutlCommand` | Subcommand → clap struct |
| `apps/configutl.c` | `configutl_main()` | `openssl-cli` | `src/commands/configutl.rs` | `ConfigutlCommand` | Subcommand → clap struct |
| `apps/ech.c` | `ech_main()` | `openssl-cli` | `src/commands/ech.rs` | `EchCommand` | Subcommand → clap struct |
| `apps/asn1parse.c` | `asn1parse_main()` | `openssl-cli` | `src/commands/mod.rs` | `Asn1parseCommand` | Subcommand → clap struct |
| `apps/rsa.c` | `rsa_main()` | `openssl-cli` | `src/commands/mod.rs` | `RsaCommand` | Subcommand → clap struct |
| `apps/dsa.c` | `dsa_main()` | `openssl-cli` | `src/commands/mod.rs` | `DsaCommand` | Subcommand → clap struct |
| `apps/ec.c` | `ec_main()` | `openssl-cli` | `src/commands/mod.rs` | `EcCommand` | Subcommand → clap struct |
| `apps/smime.c` | `smime_main()` | `openssl-cli` | `src/commands/mod.rs` | `SmimeCommand` | Subcommand → clap struct |
| `apps/pkeyutl.c` | `pkeyutl_main()` | `openssl-cli` | `src/commands/mod.rs` | `PkeyutlCommand` | Subcommand → clap struct |
| `apps/pkeyparam.c` | `pkeyparam_main()` | `openssl-cli` | `src/commands/mod.rs` | `PkeyparamCommand` | Subcommand → clap struct |
| `apps/rsautl.c` | `rsautl_main()` | `openssl-cli` | `src/commands/mod.rs` | `RsautlCommand` (deprecated) | Deprecated subcommand → `#[deprecated]` |
| `apps/nseq.c` | `nseq_main()` | `openssl-cli` | `src/commands/mod.rs` | `NseqCommand` | Subcommand → clap struct |
| `apps/spkac.c` | `spkac_main()` | `openssl-cli` | `src/commands/mod.rs` | `SpkacCommand` | Subcommand → clap struct |
| `apps/errstr.c` | `errstr_main()` | `openssl-cli` | `src/commands/mod.rs` | `ErrstrCommand` | Subcommand → clap struct |
| `apps/storeutl.c` | `storeutl_main()` | `openssl-cli` | `src/commands/mod.rs` | `StoreutlCommand` | Subcommand → clap struct |
| `apps/passwd.c` | `passwd_main()` | `openssl-cli` | `src/commands/mod.rs` | `PasswdCommand` | Subcommand → clap struct |
| `apps/sess_id.c` | `sess_id_main()` | `openssl-cli` | `src/commands/mod.rs` | `SessIdCommand` | Subcommand → clap struct |
| `apps/crl2pkcs7.c` | `crl2pkcs7_main()` | `openssl-cli` | `src/commands/mod.rs` | `Crl2Pkcs7Command` | Subcommand → clap struct |
| `apps/srp.c` | `srp_main()` (deprecated) | `openssl-cli` | `src/commands/mod.rs` | `SrpCommand` (deprecated) | Deprecated → `#[deprecated]` |
| `apps/info.c` | `info_main()` | `openssl-cli` | `src/commands/mod.rs` | `InfoCommand` | Subcommand → clap struct |
| `apps/mac.c` | `mac_main()` | `openssl-cli` | `src/commands/mod.rs` | `MacCommand` | Subcommand → clap struct |
| `apps/kdf.c` | `kdf_main()` | `openssl-cli` | `src/commands/mod.rs` | `KdfCommand` | Subcommand → clap struct |

#### 2.5.2 apps/lib/ (21 shared infrastructure files)

| C Source File | C Construct | Rust Crate | Rust Module | Rust Construct | Transformation |
|---------------|-------------|------------|-------------|----------------|----------------|
| `apps/lib/opt.c` | `opt_init()`, `opt_next()`, option parsing | `openssl-cli` | `src/lib/opts.rs` | `clap` derive-based option parsing | Custom arg parser → `clap` derive macros |
| `apps/lib/apps.c` | Shared crypto object loading, config | `openssl-cli` | `src/lib/opts.rs` | Shared loading utilities | Apps utilities → Rust helper functions |
| `apps/lib/apps_ui.c` | UI method, passphrase handling | `openssl-cli` | `src/lib/password.rs` | `PasswordHandler` | UI callbacks → closure-based password prompts |
| `apps/lib/app_libctx.c` | App-level `OSSL_LIB_CTX` management | `openssl-cli` | `src/lib/opts.rs` | App-level `LibContext` | Static libctx → thread-local or Arc-wrapped |
| `apps/lib/app_provider.c` | Provider option handling | `openssl-cli` | `src/lib/opts.rs` | Provider loading via clap options | Provider option → clap derive |
| `apps/lib/app_rand.c` | `-rand/-writerand` support | `openssl-cli` | `src/lib/opts.rs` | RAND seed helpers | Seed file → Rust file I/O |
| `apps/lib/app_params.c` | Parameter printing | `openssl-cli` | `src/lib/opts.rs` | Parameter display helpers | Print helpers → `Display` trait |
| `apps/lib/app_x509.c` | X509 control string helpers | `openssl-cli` | `src/lib/opts.rs` | X509 helpers | X509 control → typed methods |
| `apps/lib/s_cb.c` | TLS callbacks (verify, msg, keylog) | `openssl-cli` | `src/lib/opts.rs` | TLS callback closures | Callback functions → closures |
| `apps/lib/s_socket.c` | Client/server socket helpers | `openssl-cli` | `src/lib/opts.rs` | Socket helpers | C socket → `std::net::TcpStream/Listener` |
| `apps/lib/http_server.c` | Basic HTTP responder | `openssl-cli` | `src/lib/http.rs` | `HttpServer` | C HTTP → simple Rust HTTP handler |
| `apps/lib/log.c` | Verbosity logging | `openssl-cli` | `src/lib/opts.rs` | `tracing` integration | Printf logging → `tracing` macros |
| `apps/lib/columns.c` | Help column calculation | `openssl-cli` | `src/lib/opts.rs` | (handled by clap) | Column layout → clap auto-formatting |
| `apps/lib/fmt.c` | Format helpers | `openssl-cli` | `src/lib/opts.rs` | Format helpers | C format → Rust `Display` |
| `apps/lib/names.c` | Name collection/printing | `openssl-cli` | `src/lib/opts.rs` | Name helpers | Name printing → `Display` trait |
| `apps/lib/apps_opt_printf.c` | `opt_printf_stderr` | `openssl-cli` | `src/lib/opts.rs` | `eprintln!()` | Printf wrapper → `eprintln!` |
| `apps/lib/cmp_mock_srv.c` | CMP mock server | `openssl-cli` | `src/lib/http.rs` | `CmpMockServer` (`#[cfg(test)]`) | Mock server → test-only struct |
| `apps/lib/tlssrp_depr.c` | Deprecated TLS-SRP callbacks | `openssl-cli` | `src/lib/opts.rs` | `#[deprecated]` SRP helpers | Deprecated → feature-gated |
| `apps/lib/vms_decc_argv.c` | VMS argv normalization | — | — | (out of scope: VMS platform) | VMS-specific → not mapped |
| `apps/lib/vms_term_sock.c` | VMS terminal-to-socket bridge | — | — | (out of scope: VMS platform) | VMS-specific → not mapped |
| `apps/lib/win32_init.c` | Windows UTF-8 argv rebuild | `openssl-cli` | `src/main.rs` | (not needed: Rust handles UTF-8 natively) | Windows-specific → Rust UTF-8 default |

### 2.6 include/openssl/*.h (116 Public API Headers)

All 116 public headers are mapped to the FFI boundary crate. Each header defines C ABI function signatures that are re-exported via `#[no_mangle] pub extern "C" fn` in the Rust FFI crate.

| C Header Category | Representative Headers | Rust Crate | Rust Module | Transformation |
|--------------------|----------------------|------------|-------------|----------------|
| EVP API | `evp.h`, `evperr.h` | `openssl-ffi` | `src/evp.rs` | EVP C ABI → `extern "C"` wrappers calling `openssl-crypto` |
| SSL API | `ssl.h`, `ssl2.h`, `ssl3.h`, `tls1.h`, `dtls1.h` | `openssl-ffi` | `src/ssl.rs` | SSL C ABI → `extern "C"` wrappers calling `openssl-ssl` |
| X509 API | `x509.h`, `x509v3.h`, `x509_vfy.h` | `openssl-ffi` | `src/x509.rs` | X509 C ABI → `extern "C"` wrappers |
| BIO API | `bio.h`, `bioerr.h` | `openssl-ffi` | `src/bio.rs` | BIO C ABI → `extern "C"` wrappers |
| Crypto API | `crypto.h`, `cryptoerr.h` | `openssl-ffi` | `src/crypto.rs` | Crypto C ABI → `extern "C"` wrappers |
| Provider API | `provider.h`, `core.h`, `core_dispatch.h`, `core_names.h` | `openssl-ffi` | `src/crypto.rs` | Provider C ABI → FFI wrappers |
| ASN.1/PEM | `asn1.h`, `pem.h`, `pkcs7.h`, `pkcs12.h`, `cms.h` | `openssl-ffi` | `src/crypto.rs` | Format C ABI → FFI wrappers |
| Algorithm params | `params.h`, `param_build.h` | `openssl-ffi` | `src/crypto.rs` | Param C ABI → FFI wrappers |
| Error/Trace | `err.h`, `trace.h` | `openssl-ffi` | `src/crypto.rs` | Error C ABI → FFI wrappers |
| Types/Constants | `types.h`, `ossl_typ.h`, `opensslv.h`, `opensslconf.h` | `openssl-ffi` | `src/lib.rs` | Type definitions → FFI type aliases |
| FIPS | `fips_names.h`, `self_test.h`, `indicator.h` | `openssl-ffi` | `src/crypto.rs` | FIPS C ABI → FFI wrappers |
| QUIC/ECH | `quic.h`, `ech.h` | `openssl-ffi` | `src/ssl.rs` | QUIC/ECH C ABI → FFI wrappers |
| Post-quantum | (integrated into `evp.h`, `core_names.h`) | `openssl-ffi` | `src/evp.rs` | PQC via EVP → FFI wrappers |
| Remaining headers | `rand.h`, `dh.h`, `dsa.h`, `ec.h`, `rsa.h`, `hmac.h`, `ocsp.h`, `ct.h`, `ts.h`, `cmp.h`, `hpke.h`, etc. | `openssl-ffi` | `src/crypto.rs`, `src/evp.rs` | Algorithm-specific C ABI → FFI wrappers |

---

## 3. Reverse Traceability: Rust → C

### 3.1 openssl-common

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/error.rs` | `CryptoError`, `SslError`, error chain | `crypto/err/*.c`, `crypto/cpt_err.c`, `crypto/ssl_err.c` | `ERR_*` stack → `thiserror` enum; thread-local queue → `Result<T, E>` |
| `src/config.rs` | `Config`, config parser | `crypto/conf/*.c` (8 files) | `CONF`/`NCONF` → `serde`-based config |
| `src/param.rs` | `ParamSet`, `ParamValue`, `ParamBuilder` | `crypto/params.c`, `crypto/param_build.c`, `crypto/params_dup.c`, `crypto/params_from_text.c`, `crypto/param_build_set.c` | `OSSL_PARAM` → typed parameter system |
| `src/types.rs` | Shared types, collections, utilities | `crypto/o_str.c`, `crypto/o_fopen.c`, `crypto/o_dir.c`, `crypto/sparse_array.c`, `crypto/bsearch.c`, `crypto/ctype.c`, `crypto/cversion.c`, `crypto/info.c`, `crypto/der_writer.c`, `crypto/packet.c`, `crypto/lhash/*.c`, `crypto/stack/*.c`, `crypto/buffer/*.c`, `crypto/hashtable/*.c`, `crypto/ebcdic.c` | C data structures → Rust `std::collections` + standard types |
| `src/time.rs` | `OsslTime` | `crypto/time.c`, `crypto/sleep.c` | `OSSL_TIME` → `std::time` wrappers |
| `src/safe_math.rs` | Checked arithmetic | `include/internal/safe_math.h`, `crypto/array_alloc.c` | Overflow-checked macros → Rust `checked_*` methods |
| `src/constant_time.rs` | Constant-time primitives | `include/internal/constant_time.h` | C macros → `subtle::ConstantTimeEq` |
| `src/mem.rs` | Secure memory, zeroing | `crypto/mem.c`, `crypto/mem_sec.c`, `crypto/mem_clr.c`, `crypto/aligned_alloc.c` | `OPENSSL_cleanse` → `zeroize`; `CRYPTO_secure_malloc` → `SecureVec` |
| `src/observability.rs` | Tracing, metrics, health | `crypto/trace.c` (partial), new functionality | `OSSL_TRACE` → `tracing`; metrics and health checks are new |

### 3.2 openssl-crypto

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/lib.rs` | Module declarations, init | `crypto/init.c`, `crypto/cryptlib.c` | Library init and re-exports |
| `src/init.rs` | `init_crypto()`, `cleanup()` | `crypto/init.c`, `crypto/o_init.c`, `crypto/initthread.c`, `crypto/dllmain.c` | RUN_ONCE → `Once::call_once` |
| `src/context.rs` | `LibContext` | `crypto/context.c`, `crypto/ex_data.c`, `crypto/self_test_core.c`, `crypto/indicator_core.c`, `crypto/comp_methods.c` | `OSSL_LIB_CTX` → `Arc<LibContext>` |
| `src/provider/mod.rs` | `Provider`, public API | `crypto/provider.c` | Provider loading/unloading |
| `src/provider/core.rs` | `ProviderStore`, `ProviderInner`, `NameMap` | `crypto/provider_core.c`, `crypto/provider_child.c`, `crypto/provider_conf.c`, `crypto/core_algorithm.c`, `crypto/core_fetch.c`, `crypto/core_namemap.c` | Provider dispatch, fetch, store |
| `src/provider/predefined.rs` | `PredefinedProviders` | `crypto/provider_predefined.c` | Built-in provider registry |
| `src/provider/property.rs` | Property query/match | `crypto/property/*.c` (6 files) | Property evaluation engine |
| `src/evp/mod.rs` | EVP abstraction hub | `crypto/evp/evp_fetch.c`, `crypto/evp/evp_cnf.c`, `crypto/evp/encode.c`, `crypto/evp/evp_pbe.c`, `crypto/evp/evp_key.c` | EVP method store + fetch |
| `src/evp/md.rs` | `DigestCtx` | `crypto/evp/digest.c` | EVP_MD → Rust digest |
| `src/evp/cipher.rs` | `CipherCtx`, `Cipher` | `crypto/evp/evp_enc.c`, `crypto/evp/evp_lib.c`, `crypto/evp/e_aes.c`, `crypto/evp/ctrl_params_translate.c` | EVP_CIPHER → Rust cipher |
| `src/evp/kdf.rs` | `KdfCtx` | `crypto/evp/kdf_lib.c` | EVP_KDF |
| `src/evp/mac.rs` | `MacCtx` | `crypto/evp/mac_lib.c` | EVP_MAC |
| `src/evp/pkey.rs` | `EvpPkey`, `PkeyCtx` | `crypto/evp/p_lib.c`, `crypto/evp/pmeth_lib.c`, `crypto/evp/exchange.c`, `crypto/evp/asymcipher.c` | EVP_PKEY operations |
| `src/evp/rand.rs` | `RandCtx` | `crypto/evp/evp_rand.c` | EVP_RAND |
| `src/evp/kem.rs` | `KemCtx` | `crypto/evp/kem.c` | EVP_KEM |
| `src/evp/signature.rs` | `SignatureCtx` | `crypto/evp/signature.c` | EVP signature operations |
| `src/evp/keymgmt.rs` | `KeyMgmt` | `crypto/evp/keymgmt_lib.c`, `crypto/evp/keymgmt_meth.c` | Key management |
| `src/evp/encode_decode.rs` | Encoder/decoder | `crypto/encode_decode/*.c` (8 files) | Key serialization |
| `src/bn/mod.rs` | `BigNum` | `crypto/bn/*.c` (39 files) | Big number arithmetic |
| `src/bn/arithmetic.rs` | Arithmetic operations | `crypto/bn/bn_add.c`, `bn_mul.c`, `bn_div.c`, `bn_mod.c`, `bn_exp.c`, `bn_gcd.c`, `bn_sqr.c`, `bn_shift.c`, `bn_word.c`, `bn_recp.c` | Operator traits |
| `src/bn/montgomery.rs` | `MontgomeryCtx` | `crypto/bn/bn_mont.c` | Montgomery multiplication |
| `src/bn/prime.rs` | Primality testing | `crypto/bn/bn_prime.c` | Prime testing/generation |
| `src/ec/mod.rs` | `EcGroup`, `EcPoint`, `EcKey` | `crypto/ec/*.c` (49 files) | Elliptic curve operations |
| `src/ec/ecdsa.rs` | ECDSA sign/verify | `crypto/ec/ecdsa_sign.c`, `crypto/ec/ecdsa_vrf.c`, `crypto/deterministic_nonce.c` | ECDSA operations |
| `src/ec/ecdh.rs` | ECDH key exchange | `crypto/ec/ecdh_ossl.c` | ECDH |
| `src/ec/curve25519.rs` | X25519/X448/Ed25519/Ed448 | `crypto/ec/ecx_meth.c`, `crypto/ec/curve25519.c`, `crypto/ec/curve448/` | Modern curves |
| `src/rsa/mod.rs` | `RsaKey` | `crypto/rsa/*.c` (26 files) | RSA operations |
| `src/rsa/oaep.rs` | OAEP padding | `crypto/rsa/rsa_oaep.c` | OAEP |
| `src/rsa/pss.rs` | PSS padding | `crypto/rsa/rsa_pss.c` | PSS |
| `src/pqc/mod.rs` | PQC hub | — (new) | Aggregates PQC modules |
| `src/pqc/ml_kem.rs` | ML-KEM | `crypto/ml_kem/*.c` (8 files) | FIPS 203 |
| `src/pqc/ml_dsa.rs` | ML-DSA | `crypto/ml_dsa/*.c` (8 files) | FIPS 204 |
| `src/pqc/slh_dsa.rs` | SLH-DSA | `crypto/slh_dsa/*.c` (10 files) | FIPS 205 |
| `src/pqc/lms.rs` | LMS | `crypto/lms/*.c` (8 files) | SP 800-208 |
| `src/symmetric/aes.rs` | AES | `crypto/aes/*.c`, `crypto/modes/*.c` | AES + modes |
| `src/symmetric/chacha20.rs` | ChaCha20-Poly1305 | `crypto/chacha/*.c` | ChaCha20 |
| `src/symmetric/des.rs` | DES/3DES | `crypto/des/*.c` | DES |
| `src/symmetric/legacy.rs` | Legacy ciphers | `crypto/bf/`, `cast/`, `camellia/`, `aria/`, `idea/`, `seed/`, `rc2/`, `rc4/`, `rc5/`, `sm4/*.c` | Legacy symmetric |
| `src/hash/sha.rs` | SHA family | `crypto/sha/*.c` | SHA-1/2/3/SHAKE |
| `src/hash/md5.rs` | MD5 | `crypto/md5/*.c` | MD5 |
| `src/hash/legacy.rs` | Legacy hashes | `crypto/md2/`, `md4/`, `mdc2/`, `ripemd/`, `whrlpool/`, `sm3/*.c` | Legacy hashes |
| `src/mac.rs` | MAC algorithms | `crypto/hmac/`, `cmac/`, `poly1305/`, `siphash/*.c` | MAC implementations |
| `src/kdf.rs` | KDF algorithms | `crypto/kdf/*.c` | KDF support |
| `src/rand.rs` | DRBG, entropy | `crypto/rand/*.c` (9 files) | Random generation |
| `src/bio/mod.rs` | `Bio` trait | `crypto/bio/*.c` (28 files), `crypto/passphrase.c`, `crypto/ui/*.c` | BIO I/O abstraction |
| `src/bio/mem.rs` | `MemBio` | `crypto/bio/bss_mem.c` | Memory BIO |
| `src/bio/file.rs` | `FileBio` | `crypto/bio/bss_file.c` | File BIO |
| `src/bio/socket.rs` | `SocketBio` | `crypto/bio/bss_sock.c`, `bss_conn.c`, `bss_dgram.c` | Socket BIO |
| `src/bio/filter.rs` | Filter BIOs | `crypto/bio/bf_buff.c`, `bf_null.c`, remaining filter BIOs | Filter BIO chain |
| `src/x509/mod.rs` | `X509Certificate` | `crypto/x509/*.c` (98 files), `crypto/objects/*.c` | X.509 certificates |
| `src/x509/verify.rs` | Chain verification | `crypto/x509/x509_vfy.c` | RFC 5280 verification |
| `src/x509/crl.rs` | CRL processing | `crypto/x509/x509_crl.c` | CRL handling |
| `src/x509/store.rs` | Cert/CRL store | `crypto/x509/x509_lu.c`, `crypto/store/*.c`, `crypto/txt_db/*.c` | Certificate store |
| `src/asn1/mod.rs` | ASN.1 types | `crypto/asn1/*.c` (65 files) | ASN.1 encoding/decoding |
| `src/asn1/template.rs` | ASN.1 templates | `crypto/asn1/tasn_dec.c`, `tasn_enc.c` | Template system → derive macros |
| `src/pem.rs` | PEM encode/decode | `crypto/pem/*.c` (11 files) | PEM format handling |
| `src/pkcs/pkcs7.rs` | PKCS#7 | `crypto/pkcs7/*.c` (8 files) | PKCS#7 |
| `src/pkcs/pkcs12.rs` | PKCS#12 | `crypto/pkcs12/*.c` (16 files) | PKCS#12 |
| `src/pkcs/cms.rs` | CMS | `crypto/cms/*.c` (19 files), `crypto/ess/*.c` | CMS/ESS |
| `src/hpke.rs` | HPKE | `crypto/hpke/*.c` (6 files) | RFC 9180 |
| `src/ocsp.rs` | OCSP | `crypto/ocsp/*.c` (10 files) | OCSP client |
| `src/ct.rs` | Certificate Transparency | `crypto/ct/*.c` (10 files) | SCT validation |
| `src/cmp.rs` | CMP | `crypto/cmp/*.c` (13 files), `crypto/crmf/*.c`, `crypto/http/*.c` | CMP client |
| `src/ts.rs` | Timestamping | `crypto/ts/*.c` (11 files) | RFC 3161 |
| `src/dh.rs` | Diffie-Hellman | `crypto/dh/*.c` (14 files), `crypto/ffc/*.c` (7 files), `crypto/srp/*.c` | DH/FFC/SRP |
| `src/dsa.rs` | DSA | `crypto/dsa/*.c` (14 files), `crypto/asn1_dsa.c` | DSA sign/verify |
| `src/thread.rs` | Threading | `crypto/threads_pthread.c`, `threads_win.c`, `threads_common.c`, `threads_none.c`, `threads_lib.c`, `initthread.c`, `crypto/async/*.c`, `crypto/thread/*.c` | Threading primitives |
| `src/cpu_detect.rs` | CPU detection | `crypto/cpuid.c`, `armcap.c`, `ppccap.c`, `riscvcap.c`, `s390xcap.c`, `sparcv9cap.c`, `loongarchcap.c` | CPU feature detection |

### 3.3 openssl-ssl

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/lib.rs` | Module hub, init | `ssl/ssl_lib.c`, `ssl/ssl_init.c`, `ssl/ssl_stat.c`, `ssl/ssl_err_legacy.c`, `ssl/ssl_utst.c`, `ssl/tls_depr.c`, `ssl/tls_srp.c`, `ssl/priority_queue.c` | Central SSL module |
| `src/ssl_ctx.rs` | `SslContext` | `ssl/ssl_lib.c`, `ssl/ssl_conf.c` | SSL_CTX lifecycle |
| `src/ssl.rs` | `SslStream` | `ssl/ssl_lib.c`, `ssl/bio_ssl.c` | SSL connection |
| `src/method.rs` | `SslMethod` | `ssl/methods.c` | SSL methods |
| `src/cipher.rs` | `CipherSuite`, `CipherList` | `ssl/ssl_ciph.c` | Cipher selection |
| `src/session.rs` | `SslSession`, `SessionCache` | `ssl/ssl_sess.c`, `ssl/ssl_asn1.c`, `ssl/ssl_txt.c` | Sessions |
| `src/cert.rs` | `CertStore` | `ssl/ssl_cert.c`, `ssl/ssl_cert_comp.c`, `ssl/ssl_rsa.c`, `ssl/ssl_rsa_legacy.c` | Certificates |
| `src/config.rs` | `SslConfCmd` | `ssl/ssl_conf.c`, `ssl/ssl_mcnf.c` | Configuration |
| `src/s3_lib.rs` | SSLv3/TLS utilities | `ssl/s3_lib.c`, `ssl/s3_msg.c`, `ssl/s3_enc.c` | TLS utilities |
| `src/tls13.rs` | TLS 1.3 encryption | `ssl/tls13_enc.c`, `ssl/t1_enc.c` | TLS 1.3 keying |
| `src/t1_lib.rs` | Extension processing | `ssl/t1_lib.c`, `ssl/t1_trce.c` | TLS extensions |
| `src/dtls.rs` | DTLS | `ssl/d1_lib.c`, `ssl/d1_msg.c`, `ssl/pqueue.c` | DTLS lifecycle |
| `src/srtp.rs` | DTLS-SRTP | `ssl/d1_srtp.c` | SRTP profiles |
| `src/statem/mod.rs` | Handshake state machine | `ssl/statem/statem.c`, `ssl/statem/statem_lib.c` | State machine core |
| `src/statem/client.rs` | Client handshake | `ssl/statem/statem_clnt.c` | Client transitions |
| `src/statem/server.rs` | Server handshake | `ssl/statem/statem_srvr.c` | Server transitions |
| `src/statem/extensions.rs` | Extension framework | `ssl/statem/extensions.c`, `extensions_clnt.c`, `extensions_srvr.c`, `extensions_cust.c` | Extension handlers |
| `src/statem/dtls.rs` | DTLS fragmentation | `ssl/statem/statem_dtls.c` | DTLS mechanics |
| `src/record/mod.rs` | Record layer | `ssl/record/record.h`, `ssl/record/methods/` | Record abstraction |
| `src/record/tls.rs` | TLS records | `ssl/record/rec_layer_s3.c` | TLS record I/O |
| `src/record/dtls.rs` | DTLS records | `ssl/record/rec_layer_d1.c` | DTLS record I/O |
| `src/quic/mod.rs` | QUIC hub | `ssl/quic/quic_impl.c`, `quic_method.c`, `quic_obj.c`, `quic_wire.c`, `quic_wire_pkt.c`, `quic_record_shared.c`, `quic_record_util.c`, `quic_trace.c`, `quic_types.c`, `qlog.c`, `qlog_event_helpers.c`, `json_enc.c` | QUIC module |
| `src/quic/engine.rs` | `QuicEngine` | `ssl/quic/quic_engine.c`, `quic_thread_assist.c` | QUIC engine |
| `src/quic/reactor.rs` | `QuicReactor` | `ssl/quic/quic_reactor.c`, `quic_reactor_wait_ctx.c` | QUIC reactor |
| `src/quic/port.rs` | `QuicPort` | `ssl/quic/quic_port.c`, `quic_demux.c` | QUIC port |
| `src/quic/channel.rs` | `QuicChannel` | `ssl/quic/quic_channel.c`, `quic_lcidm.c`, `quic_rcidm.c`, `quic_srt_gen.c`, `quic_srtm.c` | QUIC channel |
| `src/quic/stream.rs` | Stream management | `ssl/quic/quic_stream_map.c`, `quic_sstream.c`, `quic_rstream.c`, `quic_sf_list.c`, `quic_fc.c` | QUIC streams |
| `src/quic/tx.rs` | TX packetiser | `ssl/quic/quic_txp.c`, `quic_record_tx.c`, `quic_txpim.c`, `quic_cfq.c`, `quic_fifd.c` | Packet transmission |
| `src/quic/rx.rs` | RX processing | `ssl/quic/quic_record_rx.c`, `quic_rx_depack.c` | Packet reception |
| `src/quic/ack.rs` | ACK/loss/RTT | `ssl/quic/quic_ackm.c`, `quic_statm.c`, `uint_set.c` | ACK management |
| `src/quic/cc.rs` | Congestion control | `ssl/quic/cc_newreno.c` | NewReno CC |
| `src/quic/tls_shim.rs` | TLS shim | `ssl/quic/quic_tls.c`, `quic_tls_api.c` | TLS 1.3 shim |
| `src/ech/mod.rs` | ECH engine | `ssl/ech/ech_internal.c`, `ssl/ech/ech_ssl_apis.c` | ECH core |
| `src/ech/encode.rs` | ECH encoding | `ssl/ech/ech_helper.c` | ECH helpers |
| `src/ech/decrypt.rs` | ECH server decryption | `ssl/ech/ech_store.c` | ECH config store |
| `src/rio.rs` | Reactive I/O | `ssl/rio/poll_builder.c`, `poll_immediate.c`, `rio_notifier.c` | RIO for QUIC |

### 3.4 openssl-provider

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/lib.rs` | Provider framework hub | `providers/prov_running.c`, `providers/common/*.c` | Provider utilities |
| `src/traits.rs` | Provider trait definition | `include/openssl/core_dispatch.h` | `OSSL_DISPATCH` → trait |
| `src/dispatch.rs` | Method store, algorithm enum | `crypto/core_fetch.c`, `crypto/core_algorithm.c` | Fetch/store logic |
| `src/default.rs` | `DefaultProvider` | `providers/defltprov.c` | Default provider |
| `src/legacy.rs` | `LegacyProvider` | `providers/legacyprov.c` | Legacy provider |
| `src/base.rs` | `BaseProvider` | `providers/baseprov.c` | Base provider |
| `src/null.rs` | `NullProvider` | `providers/nullprov.c` | Null provider |
| `src/implementations/ciphers/*.rs` | Cipher implementations | `providers/implementations/ciphers/*.c` (81 files) | Cipher provider impls |
| `src/implementations/digests/*.rs` | Digest implementations | `providers/implementations/digests/*.c` (17 files) | Digest provider impls |
| `src/implementations/kdfs/*.rs` | KDF implementations | `providers/implementations/kdfs/*.c` (16 files) | KDF provider impls |
| `src/implementations/macs/*.rs` | MAC implementations | `providers/implementations/macs/*.c` (9 files) | MAC provider impls |
| `src/implementations/signatures/*.rs` | Signature implementations | `providers/implementations/signature/*.c` (9 files) | Signature provider impls |
| `src/implementations/kem/*.rs` | KEM implementations | `providers/implementations/kem/*.c` (7 files) | KEM provider impls |
| `src/implementations/keymgmt/*.rs` | Key management | `providers/implementations/keymgmt/*.c` (13 files), `skeymgmt/*.c` (2 files) | Keymgmt provider impls |
| `src/implementations/exchange/*.rs` | Key exchange | `providers/implementations/exchange/*.c` (4 files) | Exchange provider impls |
| `src/implementations/rands/*.rs` | DRBG/seed impls | `providers/implementations/rands/*.c` (15 files) | Random provider impls |
| `src/implementations/encode_decode/*.rs` | Encoder/decoder | `providers/implementations/encode_decode/*.c` (16 files) | Codec provider impls |
| `src/implementations/store/*.rs` | File store | `providers/implementations/storemgmt/*.c` (3 files) | Store provider impls |

### 3.5 openssl-fips

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/lib.rs` | FIPS module entry | `providers/fips/fips_entry.c`, `providers/fips/fipsprov.c` | FIPS entry point |
| `src/provider.rs` | `FipsProvider` | `providers/fips/fipsprov.c` | FIPS dispatch/config |
| `src/self_test.rs` | `SelfTest` | `providers/fips/self_test.c`, `providers/fips/self_test.h` | POST orchestration |
| `src/kats.rs` | `KnownAnswerTests` | `providers/fips/self_test_kats.c`, `providers/fips/self_test_data.c` | KAT execution |
| `src/indicator.rs` | `FipsIndicator` | `providers/fips/fipsindicator.c` | Approved indicator |
| `src/state.rs` | `FipsState` enum | `providers/fips/self_test.c` | INIT→SELFTEST→RUNNING\|ERROR |

### 3.6 openssl-cli

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/main.rs` | `fn main()`, command dispatcher | `apps/openssl.c`, `apps/lib/win32_init.c` | Entry point |
| `src/commands/*.rs` | 56+ subcommands | `apps/*.c` (56 files) | Each `*_main()` → clap subcommand |
| `src/lib/opts.rs` | Option parsing, shared utils | `apps/lib/opt.c`, `apps/lib/apps.c`, `apps/lib/app_libctx.c`, `apps/lib/app_provider.c`, `apps/lib/app_rand.c`, `apps/lib/app_params.c`, `apps/lib/app_x509.c`, `apps/lib/s_cb.c`, `apps/lib/s_socket.c`, `apps/lib/log.c`, `apps/lib/columns.c`, `apps/lib/fmt.c`, `apps/lib/names.c`, `apps/lib/apps_opt_printf.c`, `apps/lib/tlssrp_depr.c` | Shared CLI infrastructure |
| `src/lib/password.rs` | Passphrase handling | `apps/lib/apps_ui.c` | Password prompts |
| `src/lib/http.rs` | HTTP helpers | `apps/lib/http_server.c`, `apps/lib/cmp_mock_srv.c` | HTTP responder |

### 3.7 openssl-ffi

| Rust Module | Rust Construct | C Source Origin | Notes |
|-------------|----------------|-----------------|-------|
| `src/lib.rs` | FFI re-exports, type aliases | `include/openssl/types.h`, `ossl_typ.h`, `opensslv.h`, `opensslconf.h` | Type definitions |
| `src/evp.rs` | EVP C ABI wrappers | `include/openssl/evp.h` | `extern "C"` functions |
| `src/ssl.rs` | SSL C ABI wrappers | `include/openssl/ssl.h`, `tls1.h`, `dtls1.h`, `quic.h`, `ech.h` | `extern "C"` functions |
| `src/x509.rs` | X509 C ABI wrappers | `include/openssl/x509.h`, `x509v3.h`, `x509_vfy.h` | `extern "C"` functions |
| `src/bio.rs` | BIO C ABI wrappers | `include/openssl/bio.h` | `extern "C"` functions |
| `src/crypto.rs` | Crypto C ABI wrappers | `include/openssl/crypto.h`, `provider.h`, `params.h`, `err.h`, `rand.h`, remaining headers | `extern "C"` functions |

---

## 4. Construct Mapping Patterns

This section documents the systematic transformation rules applied across the entire codebase. Each pattern is applied consistently wherever the corresponding C construct appears.

### 4.1 Lifecycle Management

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `*_new()` / `*_free()` pairs | RAII with `impl Drop` | `SSL_CTX_new()` / `SSL_CTX_free()` → `SslContext::new()` with automatic cleanup on drop |
| `*_up_ref()` / reference counting | `Arc<T>` | `SSL_CTX_up_ref()` → `Arc::clone()` |
| Manual memory zeroing (`OPENSSL_cleanse`) | `zeroize::Zeroize` trait derivation | `OPENSSL_cleanse(key, len)` → `key.zeroize()` on drop |
| `CRYPTO_secure_malloc` / `CRYPTO_secure_free` | `zeroize::Zeroizing<Vec<u8>>` | Secure heap → zeroing wrapper type |

### 4.2 Dispatch and Abstraction

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `OSSL_DISPATCH` function pointer tables | Rust `trait` implementations | Provider dispatch → `impl CipherProvider for AesGcm` |
| `OSSL_PARAM` name-value parameter bags | Typed Rust config structs | `OSSL_PARAM_locate("key")` → `config.key` (compile-time checked) |
| `BIO` method vtable | `Read` / `Write` / `AsyncRead` / `AsyncWrite` traits | `BIO_read()` → `impl Read for MemBio` |
| `SSL_METHOD` function pointer struct | `SslMethod` enum | `TLS_method()` → `SslMethod::Tls` |
| `EVP_MD_meth_*` / method tables | Provider-fetched trait objects | `EVP_MD_fetch()` → `DigestProvider::fetch()` |

### 4.3 Error Handling

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `ERR_put_error()` + thread-local stack | `Result<T, E>` with `?` propagation | Return `0` on error → return `Err(CryptoError::...)` |
| `ERR_get_error()` + reason codes | `thiserror` enum variants | `ERR_R_MALLOC_FAILURE` → `CryptoError::AllocationFailed` |
| `ERR_print_errors_fp()` | `impl Display` + `impl Debug` | Error printing → `Display`/`Debug` formatting |
| `ERR_peek_error()` / `ERR_clear_error()` | Error chain via `Error::source()` | Error introspection → source chain traversal |
| Sentinel return values (`0`, `-1`, `NULL`) | `Option<T>` / `Result<T, E>` (per rule R5) | `return NULL` → `return None`; `return -1` → `return Err(...)` |

### 4.4 Type System

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `#define` constant groups | `enum` variants | `SSL_ERROR_*` → `enum SslError { ... }` |
| Bitfield flags (`SSL_OP_*`) | `bitflags!` macro | `SSL_OP_NO_SSLv3` → `SslOptions::NO_SSLV3` |
| `typedef struct { ... }` | `pub struct` with named fields | `struct ssl_st` → `pub struct SslStream { ... }` |
| `void *` opaque data | Typed generics or `Box<dyn Any>` | `void *ex_data` → `ExData<T>` with type-safe access |
| `STACK_OF(T)` | `Vec<T>` | `STACK_OF(X509)` → `Vec<X509Certificate>` |
| `LHASH_OF(T)` | `HashMap<K, V>` | `LHASH_OF(SSL_SESSION)` → `HashMap<SessionId, SslSession>` |
| `BUF_MEM` | `Vec<u8>` / `bytes::BytesMut` | Dynamic buffer → standard Rust types |

### 4.5 Concurrency and Threading

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `CRYPTO_RWLOCK` | `parking_lot::RwLock<T>` | `CRYPTO_THREAD_write_lock(ctx->lock)` → `ctx.inner.write()` |
| `CRYPTO_ONCE` / `RUN_ONCE` | `std::sync::Once` | `RUN_ONCE(&once, init_fn)` → `ONCE.call_once(\|\| init_fn())` |
| `CRYPTO_THREAD_LOCAL` | `std::thread::LocalKey` | Thread-local storage → `thread_local! { ... }` |
| Global shared state | `Arc<RwLock<T>>` with `// LOCK-SCOPE:` (per rule R7) | Global provider store → `Arc<RwLock<ProviderStore>>` |
| `OPENSSL_fork_*` stubs | `#[deprecated]` functions | Deprecated fork handlers → `#[deprecated]` |

### 4.6 Compile-Time Gating

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| `#ifndef OPENSSL_NO_EC` | `#[cfg(feature = "ec")]` | Feature-gated compilation → Cargo feature flags |
| `#ifdef FIPS_MODULE` | Separate `openssl-fips` crate | FIPS conditional → crate boundary isolation |
| Platform `#ifdef` | `#[cfg(target_os = "...")]` / `#[cfg(target_arch = "...")]` | `#ifdef __linux__` → `#[cfg(target_os = "linux")]` |

### 4.7 Numeric Safety (Rule R6)

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| Bare `(int)value` cast | `TryFrom::try_from(value)?` | `(int)len` → `i32::try_from(len)?` |
| Implicit narrowing | `saturating_cast` or `clamp` | Implicit u64→u32 → `value.try_into().unwrap_or(u32::MAX)` |
| Unchecked arithmetic | `checked_*` methods | `a + b` (overflow UB) → `a.checked_add(b).ok_or(Overflow)?` |

### 4.8 Unsafe Boundary Confinement (Rule R8)

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| Direct pointer manipulation throughout codebase | `unsafe` confined exclusively to `openssl-ffi` crate (per rule R8) | All safe Rust in non-FFI crates; `unsafe` only in `extern "C"` wrappers |
| Raw pointer parameters in API functions | `#[no_mangle] pub extern "C" fn` with `// SAFETY:` comments | `EVP_MD_CTX *ctx` → `unsafe { &*ctx }` with invariant documentation |
| `void *` callback data | `Box<dyn FnOnce(...)>` in safe code; raw pointer only at FFI boundary | Safe closures internally; pointer cast only in `openssl-ffi` |
| C string parameters (`const char *`) | `CStr::from_ptr()` in FFI; `&str` / `String` everywhere else | FFI boundary converts; all internal code uses safe Rust strings |

### 4.9 Async Patterns (QUIC Stack Only)

| C Pattern | Rust Pattern | Example |
|-----------|-------------|---------|
| Poll-based event loop | `tokio::select!` reactor | `QUIC_REACTOR_tick()` → `async fn tick()` with `select!` |
| `BIO_sendmmsg` / `BIO_recvmmsg` | `tokio::net::UdpSocket` | Datagram I/O → async UDP |
| Thread-assist blocking | `tokio::task::spawn_blocking` | Thread assist → `spawn_blocking` |
| Synchronous state machine | `spawn_blocking` bridge | `statem_clnt.c` → `spawn_blocking(|| handshake())` |

---

## 5. Coverage Summary

### 5.1 Quantitative Coverage

| Source Category | C Files | Rust Crate(s) | Rust Modules | Coverage |
|----------------|---------|---------------|--------------|----------|
| `crypto/` top-level | ~70 | `openssl-common`, `openssl-crypto` | ~20 modules | 100% |
| `crypto/` subdirs (50+) | ~1,107 | `openssl-crypto` | ~40 modules | 100% |
| `ssl/` top-level | ~34 | `openssl-ssl` | ~15 modules | 100% |
| `ssl/statem/` | 9 (+2 headers) | `openssl-ssl` | 5 modules | 100% |
| `ssl/record/` | 4 (+subfolder) | `openssl-ssl` | 3 modules | 100% |
| `ssl/quic/` | 42 (+6 headers) | `openssl-ssl` | 12 modules | 100% |
| `ssl/ech/` | 4 (+1 header) | `openssl-ssl` | 3 modules | 100% |
| `ssl/rio/` | 3 (+2 headers) | `openssl-ssl` | 1 module | 100% |
| `providers/` top-level | 5 | `openssl-provider` | 5 modules | 100% |
| `providers/fips/` | 7 (+1 header) | `openssl-fips` | 6 modules | 100% |
| `providers/implementations/` | ~194 | `openssl-provider` | 11 subdirs | 100% |
| `apps/` top-level | ~56 | `openssl-cli` | ~56 command modules | 100% |
| `apps/lib/` | 21 | `openssl-cli` | 3 lib modules | 100% |
| `include/openssl/*.h` | 116 | `openssl-ffi` | 5 FFI modules | 100% |
| **Total** | **~1,247+** | **7 crates** | **~180 modules** | **100%** |

### 5.2 Explicitly Excluded Files (Out of Scope per AAP §0.3.2)

The following files are explicitly out of scope and intentionally NOT mapped:

| File/Directory | Reason |
|----------------|--------|
| `test/**/*.c` (300 files) | Preserved as validation reference; not rewritten |
| `crypto/**/asm/*.pl` (239 files) | Perlasm generators preserved; Rust uses `core::arch` |
| `Configure`, `Configurations/`, `util/*.pl` | Perl build system preserved as-is |
| `doc/**/*.pod` (910 files) | Documentation preserved; Rust docs are additive |
| `demos/**/*.c` (71 files) | Demo programs preserved as reference |
| `fuzz/**/*.c` (38 files) | Fuzz targets preserved; new Rust targets may be added |
| `apps/vms_decc_init.c` | VMS platform shim (out of scope) |
| `apps/lib/vms_decc_argv.c` | VMS platform shim (out of scope) |
| `apps/lib/vms_term_sock.c` | VMS terminal bridge (out of scope) |
| `crypto/LPdir_vms.c` | VMS directory shim (out of scope) |
| `crypto/LPdir_wince.c` | WinCE shim (out of scope) |
| Git submodules (11 repos) | External dependencies; not rewritten |

### 5.3 Coverage Verification Method

Coverage is verified by the following:

1. **Forward completeness:** Every C source file listed in AAP §0.2.2 and §0.2.3 has at least one entry in the forward traceability tables (Section 2).
2. **Reverse completeness:** Every Rust module in the target architecture (AAP §0.4.1) has at least one entry in the reverse traceability tables (Section 3), pointing back to its C source origin.
3. **Pattern completeness:** All transformation patterns from AAP §0.4.3 are documented in Section 4.
4. **No orphan files:** No C source file exists in the in-scope directories without a corresponding Rust target.
5. **No orphan modules:** No Rust module exists without a documented C source origin (except `src/observability.rs` which is new functionality required by the observability rule, and `src/pqc/mod.rs` which is a new aggregation module).

**Coverage: 100% — All in-scope C source files are mapped. No gaps.**
