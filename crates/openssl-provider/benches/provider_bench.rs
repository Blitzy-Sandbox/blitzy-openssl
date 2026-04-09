//! Benchmark harness for openssl-provider crate.
//!
//! This file serves as the criterion benchmark entry point for measuring
//! performance of provider dispatch operations. Gate 3 requires benchmarking
//! ≥2 workloads with wall-clock and peak memory reporting.
//!
//! Benchmarks cover:
//!   - Provider dispatch latency (algorithm fetch + trait dispatch overhead)
//!   - Method store lookup performance (name → implementation resolution)
//!   - Provider activation/deactivation lifecycle
//!
//! Run with: `cargo bench --package openssl-provider`

use criterion::{criterion_group, criterion_main, Criterion};

/// Benchmark group for provider dispatch operations.
///
/// Individual benchmarks will be added as provider implementations
/// are completed (algorithm fetch, dispatch table lookup, provider
/// activation, property matching, etc.).
fn provider_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("provider");

    group.bench_function("noop_baseline", |b| {
        b.iter(|| {
            // Baseline measurement — to be replaced with real provider dispatch operations
            std::hint::black_box(42)
        });
    });

    group.finish();
}

criterion_group!(benches, provider_benchmarks);
criterion_main!(benches);
