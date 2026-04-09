//! Benchmark harness for openssl-crypto crate.
//!
//! This file serves as the criterion benchmark entry point for measuring
//! performance of cryptographic operations. Gate 3 requires benchmarking
//! ≥2 workloads with wall-clock and peak memory reporting.
//!
//! Run with: `cargo bench --package openssl-crypto`

use criterion::{criterion_group, criterion_main, Criterion};

/// Placeholder benchmark group for cryptographic operations.
///
/// Individual benchmarks will be added as algorithm implementations
/// are completed (AES-GCM, SHA-256, RSA keygen, ECDSA sign/verify, etc.).
fn crypto_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");

    group.bench_function("noop_baseline", |b| {
        b.iter(|| {
            // Baseline measurement — to be replaced with real crypto operations
            std::hint::black_box(42)
        });
    });

    group.finish();
}

criterion_group!(benches, crypto_benchmarks);
criterion_main!(benches);
