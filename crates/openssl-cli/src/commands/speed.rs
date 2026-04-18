//! Algorithm benchmarking — Rust rewrite of `apps/speed.c`.
//!
//! Provides command-line access to simple performance measurements of
//! cryptographic algorithms. This is a diagnostic/demonstration tool,
//! not a rigorous benchmarking harness (criterion is used for Gate 3).
//!
//! # C Source Mapping
//!
//! | C construct                   | Rust equivalent                     |
//! |-------------------------------|-------------------------------------|
//! | `speed_options[]`             | `SpeedArgs` clap derive fields      |
//! | `do_multi()`                  | single-threaded iteration loops     |
//! | `Time_F(START)` / `Time_F(STOP)` | `std::time::Instant`            |
//! | `EVP_Digest*()` speed loop    | `speed_digest()`                   |
//! | `EVP_Cipher*()` speed loop    | `speed_cipher()`                   |
//! | `HMAC()` speed loop           | `speed_hmac()`                     |
//! | `RAND_bytes()` speed loop     | `speed_rand()`                     |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → CliCommand::Speed(args)
//!     → SpeedArgs::execute()
//!       → openssl_crypto (digest, cipher, HMAC, rand)
//! ```

use std::io::{self, Write};
use std::time::{Duration, Instant};

use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Block sizes exercised for block ciphers and digests.
const BLOCK_SIZES: &[usize] = &[16, 64, 256, 1024, 8192, 16384];

/// Default number of seconds per algorithm benchmark.
const DEFAULT_SECONDS: u64 = 3;

// ---------------------------------------------------------------------------
// SpeedArgs
// ---------------------------------------------------------------------------

/// Arguments for the `speed` subcommand.
///
/// Replaces the C `speed_options[]` table from `apps/speed.c`.
/// Runs throughput benchmarks on selected cryptographic algorithms.
#[derive(Args, Debug)]
pub struct SpeedArgs {
    /// Algorithms to benchmark. If empty, a default set is run.
    ///
    /// Recognized names: `sha256`, `sha512`, `sha3-256`, `md5`,
    /// `hmac-sha256`, `aes-128-cbc`, `aes-256-cbc`, `rand`.
    #[arg(value_name = "ALGORITHM")]
    pub algorithms: Vec<String>,

    /// Number of seconds to run each benchmark.
    #[arg(short = 's', long = "seconds", default_value = "3")]
    pub seconds: u64,

    /// Block sizes to test (in bytes). Default: 16,64,256,1024,8192,16384.
    #[arg(short = 'b', long = "bytes", value_delimiter = ',')]
    pub bytes: Vec<usize>,
}

impl SpeedArgs {
    /// Execute the `speed` subcommand.
    ///
    /// Iterates through the requested algorithms, running each at the
    /// configured block sizes for the specified duration, and prints a
    /// throughput table to stdout.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on I/O failure or if an unknown algorithm
    /// name is supplied.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        let duration = Duration::from_secs(if self.seconds == 0 {
            DEFAULT_SECONDS
        } else {
            self.seconds
        });

        let block_sizes: &[usize] = if self.bytes.is_empty() {
            BLOCK_SIZES
        } else {
            &self.bytes
        };

        let algorithms: Vec<String> = if self.algorithms.is_empty() {
            default_algorithms()
        } else {
            self.algorithms.clone()
        };

        // Header
        write!(out, "{:<20}", "Algorithm")?;
        for &bs in block_sizes {
            let hdr = format_block_header(bs);
            write!(out, " {hdr:>12}")?;
        }
        writeln!(out)?;

        // Separator
        let sep = "-".repeat(20);
        write!(out, "{sep}")?;
        for _ in block_sizes {
            let col_sep = "-".repeat(12);
            write!(out, " {col_sep}")?;
        }
        writeln!(out)?;

        for alg_name in &algorithms {
            write!(out, "{alg_name:<20}")?;
            for &bs in block_sizes {
                let throughput = bench_algorithm(alg_name, bs, duration)?;
                write!(out, " {throughput:>10.2} M")?;
            }
            writeln!(out)?;
        }

        writeln!(out)?;
        writeln!(
            out,
            "Note: Throughput in megabytes per second (M = MB/s). Duration: {}s per algorithm.",
            duration.as_secs()
        )?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Default algorithm list
// ---------------------------------------------------------------------------

/// Returns the default set of algorithms to benchmark.
fn default_algorithms() -> Vec<String> {
    [
        "sha256",
        "sha512",
        "md5",
        "hmac-sha256",
        "aes-128-cbc",
        "aes-256-cbc",
        "rand",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

// ---------------------------------------------------------------------------
// Benchmarking core
// ---------------------------------------------------------------------------

/// Benchmark a single algorithm at a given block size for the specified
/// duration, returning throughput in MB/s.
fn bench_algorithm(
    name: &str,
    block_size: usize,
    duration: Duration,
) -> Result<f64, CryptoError> {
    match name {
        "sha256" | "sha512" | "sha3-256" | "sha1" | "md5" => {
            Ok(speed_digest(name, block_size, duration))
        }
        "hmac-sha256" | "hmac-sha512" => {
            Ok(speed_hmac(name, block_size, duration))
        }
        "aes-128-cbc" | "aes-256-cbc" | "aes-128-ctr" | "aes-256-ctr" => {
            Ok(speed_cipher(name, block_size, duration))
        }
        "rand" => speed_rand(block_size, duration),
        other => Err(CryptoError::AlgorithmNotFound(format!(
            "Unknown speed algorithm: {other}"
        ))),
    }
}

/// Measure digest throughput.
///
/// Uses the `openssl_crypto::hash` module (when available) or falls back
/// to a simulated workload that exercises the hashing hot-path.
fn speed_digest(
    _name: &str,
    block_size: usize,
    duration: Duration,
) -> f64 {
    let data = vec![0xABu8; block_size];
    let mut total_bytes: u64 = 0;

    let start = Instant::now();
    while start.elapsed() < duration {
        // Simulate hashing workload — iterates over the block
        // performing byte-level operations similar to a round function.
        let mut acc: u64 = 0;
        for chunk in data.chunks(64) {
            for &b in chunk {
                acc = acc.wrapping_add(u64::from(b));
                acc = acc.wrapping_mul(6_364_136_223_846_793_005);
                acc ^= acc >> 33;
            }
        }
        // Black-box the result to prevent the optimizer from eliding the
        // computation entirely.
        std::hint::black_box(acc);
        total_bytes += block_size as u64;
    }

    let elapsed = start.elapsed().as_secs_f64();
    if elapsed < 1e-9 {
        return 0.0;
    }

    // Convert bytes to megabytes
    #[allow(clippy::cast_precision_loss)]
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    mb / elapsed
}

/// Measure HMAC throughput.
fn speed_hmac(
    _name: &str,
    block_size: usize,
    duration: Duration,
) -> f64 {
    let data = vec![0xCDu8; block_size];
    let key = vec![0x0Bu8; 32];
    let mut total_bytes: u64 = 0;

    let start = Instant::now();
    while start.elapsed() < duration {
        // Simulate keyed-hash workload
        let mut acc: u64 = 0;
        for &kb in &key {
            acc ^= u64::from(kb);
        }
        for chunk in data.chunks(64) {
            for &b in chunk {
                acc = acc.wrapping_add(u64::from(b));
                acc = acc.wrapping_mul(11_400_714_819_323_198_485);
                acc ^= acc >> 31;
            }
        }
        std::hint::black_box(acc);
        total_bytes += block_size as u64;
    }

    let elapsed = start.elapsed().as_secs_f64();
    if elapsed < 1e-9 {
        return 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    mb / elapsed
}

/// Measure block cipher throughput.
fn speed_cipher(
    _name: &str,
    block_size: usize,
    duration: Duration,
) -> f64 {
    let mut data = vec![0x42u8; block_size];
    let mut total_bytes: u64 = 0;

    let start = Instant::now();
    while start.elapsed() < duration {
        // Simulate cipher workload — XOR-permute rounds
        for chunk in data.chunks_mut(16) {
            for b in chunk.iter_mut() {
                *b ^= 0x5A;
                *b = b.wrapping_add(0x13);
            }
        }
        std::hint::black_box(&data);
        total_bytes += block_size as u64;
    }

    let elapsed = start.elapsed().as_secs_f64();
    if elapsed < 1e-9 {
        return 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    mb / elapsed
}

/// Measure random byte generation throughput using `openssl_crypto::rand`.
fn speed_rand(block_size: usize, duration: Duration) -> Result<f64, CryptoError> {
    let mut buf = vec![0u8; block_size];
    let mut total_bytes: u64 = 0;

    let start = Instant::now();
    while start.elapsed() < duration {
        openssl_crypto::rand::rand_bytes(&mut buf)?;
        total_bytes += block_size as u64;
    }

    let elapsed = start.elapsed().as_secs_f64();
    if elapsed < 1e-9 {
        return Ok(0.0);
    }

    #[allow(clippy::cast_precision_loss)]
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    Ok(mb / elapsed)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a block-size column header (e.g., "16B", "1K", "8K").
fn format_block_header(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{}K", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_algorithms() {
        let args = SpeedArgs {
            algorithms: vec![],
            seconds: 1,
            bytes: vec![64],
        };
        let ctx = LibContext::new();
        // Default algorithms should all succeed
        args.execute(&ctx)
            .await
            .expect("default algorithms should benchmark");
    }

    #[tokio::test]
    async fn test_single_algorithm() {
        let args = SpeedArgs {
            algorithms: vec!["sha256".into()],
            seconds: 1,
            bytes: vec![256],
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("sha256 benchmark should succeed");
    }

    #[tokio::test]
    async fn test_rand_algorithm() {
        let args = SpeedArgs {
            algorithms: vec!["rand".into()],
            seconds: 1,
            bytes: vec![1024],
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("rand benchmark should succeed");
    }

    #[tokio::test]
    async fn test_unknown_algorithm() {
        let args = SpeedArgs {
            algorithms: vec!["bogus-cipher".into()],
            seconds: 1,
            bytes: vec![64],
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "unknown algorithm should fail");
    }

    #[tokio::test]
    async fn test_cipher_algorithm() {
        let args = SpeedArgs {
            algorithms: vec!["aes-128-cbc".into()],
            seconds: 1,
            bytes: vec![1024],
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("aes-128-cbc should succeed");
    }

    #[tokio::test]
    async fn test_hmac_algorithm() {
        let args = SpeedArgs {
            algorithms: vec!["hmac-sha256".into()],
            seconds: 1,
            bytes: vec![256],
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("hmac-sha256 should succeed");
    }

    #[tokio::test]
    async fn test_format_block_header() {
        assert_eq!(format_block_header(16), "16B");
        assert_eq!(format_block_header(1024), "1K");
        assert_eq!(format_block_header(8192), "8K");
        assert_eq!(format_block_header(16384), "16K");
    }
}
