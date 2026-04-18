//! AES benchmark harness for Gate 3 performance baseline.
//!
//! Measures wall-clock time for AES operations across multiple modes (GCM, CBC)
//! and key sizes (128, 256). Uses the `criterion` framework with statistically
//! rigorous measurement.
//!
//! # Workloads
//!
//! 1. **AES-GCM Seal / Open** — Authenticated encryption with associated data
//!    (AEAD). Measures throughput for 1 KiB, 4 KiB, and 64 KiB payloads.
//! 2. **AES-CBC Encrypt / Decrypt** — Traditional block-cipher mode. Measures
//!    throughput for 1 KiB, 4 KiB, and 64 KiB payloads.
//! 3. **AES Key Construction** — Measures `Aes::new()` / `AesGcm::new()` key
//!    setup overhead across key sizes.
//!
//! # Running
//!
//! ```bash
//! cargo bench --bench aes_bench
//! ```
//!
//! Reports are written to `target/criterion/`.

// Benchmarks are not library code — panicking on setup failure is acceptable.
#![allow(clippy::expect_used)]

use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
    Throughput,
};
use openssl_crypto::symmetric::aes::{aes_cbc_decrypt, aes_cbc_encrypt, Aes, AesGcm};
use openssl_crypto::symmetric::{AeadCipher, SymmetricCipher};

// =============================================================================
// Test Data Constants
// =============================================================================

/// 128-bit AES key (16 bytes) — NIST FIPS 197 Appendix A test vector.
const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
    0x3c,
];

/// 256-bit AES key (32 bytes) — NIST FIPS 197 Appendix A test vector.
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
    0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
    0xdf, 0xf4,
];

/// 96-bit nonce for GCM (12 bytes) — standard GCM IV length.
const NONCE_96: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];

/// 128-bit IV for CBC mode (16 bytes — one AES block).
const IV_128: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f,
];

/// Associated data for AEAD benchmarks (16 bytes).
const AAD: [u8; 16] = [
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
    0x97,
];

/// Payload sizes for throughput benchmarks (1 KiB, 4 KiB, 64 KiB).
const PAYLOAD_SIZES: &[(usize, &str)] = &[(1024, "1KiB"), (4096, "4KiB"), (65536, "64KiB")];

// =============================================================================
// Payload Generation
// =============================================================================

/// Generates a deterministic payload of the given size.
///
/// Uses a simple counter pattern to produce reproducible data that is
/// representative of real-world plaintext entropy distribution.
fn make_payload(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    for (i, byte) in buf.iter_mut().enumerate() {
        // Deterministic pseudo-random fill using xorshift-like mixing.
        let val = i.wrapping_mul(0x9E37_79B9) ^ (i >> 4);
        // TRUNCATION: val & 0xFF is provably in [0, 255], safe for u8.
        #[allow(clippy::cast_possible_truncation)]
        let mixed = (val & 0xFF) as u8;
        *byte = mixed;
    }
    buf
}

// =============================================================================
// AES Key Construction Benchmarks
// =============================================================================

/// Benchmark AES key construction across key sizes.
///
/// Measures the overhead of `Aes::new()` and `AesGcm::new()`, which includes
/// key schedule expansion. This is relevant for short-lived connections where
/// key setup is a significant fraction of total cost.
fn bench_aes_key_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_key_construction");

    group.bench_function("Aes::new AES-128", |b| {
        b.iter(|| {
            let cipher = Aes::new(black_box(&KEY_128)).expect("AES-128 key construction");
            black_box(cipher)
        });
    });

    group.bench_function("Aes::new AES-256", |b| {
        b.iter(|| {
            let cipher = Aes::new(black_box(&KEY_256)).expect("AES-256 key construction");
            black_box(cipher)
        });
    });

    group.bench_function("AesGcm::new AES-128", |b| {
        b.iter(|| {
            let cipher = AesGcm::new(black_box(&KEY_128)).expect("AES-128-GCM key construction");
            black_box(cipher)
        });
    });

    group.bench_function("AesGcm::new AES-256", |b| {
        b.iter(|| {
            let cipher = AesGcm::new(black_box(&KEY_256)).expect("AES-256-GCM key construction");
            black_box(cipher)
        });
    });

    group.finish();
}

// =============================================================================
// AES-GCM Seal / Open Benchmarks (AEAD Workload)
// =============================================================================

/// Helper: benchmark AES-GCM seal for a given key and payload size.
fn bench_gcm_seal_inner(
    group: &mut BenchmarkGroup<'_, WallTime>,
    key: &[u8],
    label_prefix: &str,
    payload_size: usize,
    size_label: &str,
) {
    let payload = make_payload(payload_size);
    let cipher = AesGcm::new(key).expect("AES-GCM key construction");

    group.throughput(Throughput::Bytes(payload_size as u64));
    group.bench_function(format!("{label_prefix} seal {size_label}"), |b| {
        b.iter(|| {
            let result = cipher.seal(
                black_box(&NONCE_96),
                black_box(&AAD),
                black_box(&payload),
            );
            black_box(result)
        });
    });
}

/// Helper: benchmark AES-GCM open for a given key and payload size.
fn bench_gcm_open_inner(
    group: &mut BenchmarkGroup<'_, WallTime>,
    key: &[u8],
    label_prefix: &str,
    payload_size: usize,
    size_label: &str,
) {
    let payload = make_payload(payload_size);
    let cipher = AesGcm::new(key).expect("AES-GCM key construction");
    // Seal first to get valid ciphertext + tag for open benchmark.
    let ciphertext = cipher
        .seal(&NONCE_96, &AAD, &payload)
        .expect("AES-GCM seal for open benchmark");

    group.throughput(Throughput::Bytes(payload_size as u64));
    group.bench_function(format!("{label_prefix} open {size_label}"), |b| {
        b.iter(|| {
            let result = cipher.open(
                black_box(&NONCE_96),
                black_box(&AAD),
                black_box(&ciphertext),
            );
            black_box(result)
        });
    });
}

/// Benchmark AES-GCM seal and open across key sizes and payload sizes.
///
/// This is the primary AEAD workload (Workload 1 per Gate 3). AES-GCM is
/// the most widely used authenticated cipher in TLS 1.3 and QUIC.
fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm");

    for &(payload_size, size_label) in PAYLOAD_SIZES {
        // AES-128-GCM
        bench_gcm_seal_inner(&mut group, &KEY_128, "AES-128-GCM", payload_size, size_label);
        bench_gcm_open_inner(&mut group, &KEY_128, "AES-128-GCM", payload_size, size_label);

        // AES-256-GCM
        bench_gcm_seal_inner(&mut group, &KEY_256, "AES-256-GCM", payload_size, size_label);
        bench_gcm_open_inner(&mut group, &KEY_256, "AES-256-GCM", payload_size, size_label);
    }

    group.finish();
}

// =============================================================================
// AES-CBC Encrypt / Decrypt Benchmarks (Block-Cipher Workload)
// =============================================================================

/// Benchmark AES-CBC encrypt and decrypt across key sizes and payload sizes.
///
/// This is the block-cipher mode workload (Workload 2 per Gate 3). AES-CBC is
/// representative of non-AEAD cipher paths and remains widely used in PKCS#7,
/// PKCS#12, and legacy TLS cipher suites.
fn bench_aes_cbc(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_cbc");

    for &(payload_size, size_label) in PAYLOAD_SIZES {
        let payload = make_payload(payload_size);

        // --- AES-128-CBC encrypt ---
        group.throughput(Throughput::Bytes(payload_size as u64));
        let label = format!("AES-128-CBC encrypt {size_label}");
        group.bench_function(&label, |b| {
            b.iter(|| {
                let result = aes_cbc_encrypt(
                    black_box(&KEY_128),
                    black_box(&IV_128),
                    black_box(&payload),
                );
                black_box(result)
            });
        });

        // --- AES-128-CBC decrypt ---
        let ciphertext_128 = aes_cbc_encrypt(&KEY_128, &IV_128, &payload)
            .expect("AES-128-CBC encrypt for decrypt bench");
        group.throughput(Throughput::Bytes(ciphertext_128.len() as u64));
        let label = format!("AES-128-CBC decrypt {size_label}");
        group.bench_function(&label, |b| {
            b.iter(|| {
                let result = aes_cbc_decrypt(
                    black_box(&KEY_128),
                    black_box(&IV_128),
                    black_box(&ciphertext_128),
                );
                black_box(result)
            });
        });

        // --- AES-256-CBC encrypt ---
        group.throughput(Throughput::Bytes(payload_size as u64));
        let label = format!("AES-256-CBC encrypt {size_label}");
        group.bench_function(&label, |b| {
            b.iter(|| {
                let result = aes_cbc_encrypt(
                    black_box(&KEY_256),
                    black_box(&IV_128),
                    black_box(&payload),
                );
                black_box(result)
            });
        });

        // --- AES-256-CBC decrypt ---
        let ciphertext_256 = aes_cbc_encrypt(&KEY_256, &IV_128, &payload)
            .expect("AES-256-CBC encrypt for decrypt bench");
        group.throughput(Throughput::Bytes(ciphertext_256.len() as u64));
        let label = format!("AES-256-CBC decrypt {size_label}");
        group.bench_function(&label, |b| {
            b.iter(|| {
                let result = aes_cbc_decrypt(
                    black_box(&KEY_256),
                    black_box(&IV_128),
                    black_box(&ciphertext_256),
                );
                black_box(result)
            });
        });
    }

    group.finish();
}

// =============================================================================
// AES Block-Level Benchmarks
// =============================================================================

/// Benchmark raw AES single-block encrypt and decrypt.
///
/// This isolates the core AES round function performance from mode-of-operation
/// overhead. Useful for comparing Rust AES performance against the C reference.
fn bench_aes_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_block");

    let cipher_128 = Aes::new(&KEY_128).expect("AES-128 key construction");
    let cipher_256 = Aes::new(&KEY_256).expect("AES-256 key construction");

    group.throughput(Throughput::Bytes(16));

    group.bench_function("AES-128 encrypt_block", |b| {
        let mut block = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34u8,
        ];
        b.iter(|| {
            cipher_128
                .encrypt_block(black_box(&mut block))
                .expect("encrypt_block");
            black_box(&block);
        });
    });

    group.bench_function("AES-128 decrypt_block", |b| {
        let mut block = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32u8,
        ];
        b.iter(|| {
            cipher_128
                .decrypt_block(black_box(&mut block))
                .expect("decrypt_block");
            black_box(&block);
        });
    });

    group.bench_function("AES-256 encrypt_block", |b| {
        let mut block = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34u8,
        ];
        b.iter(|| {
            cipher_256
                .encrypt_block(black_box(&mut block))
                .expect("encrypt_block");
            black_box(&block);
        });
    });

    group.bench_function("AES-256 decrypt_block", |b| {
        let mut block = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32u8,
        ];
        b.iter(|| {
            cipher_256
                .decrypt_block(black_box(&mut block))
                .expect("decrypt_block");
            black_box(&block);
        });
    });

    group.finish();
}

// =============================================================================
// Criterion Entry Point
// =============================================================================

criterion_group!(
    benches,
    bench_aes_key_construction,
    bench_aes_gcm,
    bench_aes_cbc,
    bench_aes_block,
);
criterion_main!(benches);
