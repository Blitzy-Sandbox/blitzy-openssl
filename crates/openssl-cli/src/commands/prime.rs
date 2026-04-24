//! Prime number generation and testing — Rust rewrite of `apps/prime.c`.
//!
//! Provides command-line access to primality testing and prime generation
//! using the `BigNum` and `bn::prime` APIs from `openssl-crypto`.
//!
//! # C Source Mapping
//!
//! | C construct                      | Rust equivalent                          |
//! |----------------------------------|------------------------------------------|
//! | `prime_options[]`                | `PrimeArgs` clap derive fields           |
//! | `BN_generate_prime_ex2()`        | `bn::prime::generate_prime()`            |
//! | `BN_check_prime()`              | `bn::prime::check_prime()`               |
//! | `BN_is_prime_fasttest_ex()`     | `bn::prime::check_prime_with_rounds()`   |
//! | `BN_print(out, bn)`             | `BigNum::to_hex()` / `BigNum::to_dec()`  |
//! | `BN_hex2bn()` / `BN_dec2bn()`   | `BigNum::from_hex()` / `BigNum::from_dec()` |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → CliCommand::Prime(args)
//!     → PrimeArgs::execute()
//!       → openssl_crypto::bn::prime::check_prime()
//!       → openssl_crypto::bn::prime::generate_prime()
//! ```

use std::io::{self, Write};

use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::bn::prime::{
    check_prime, generate_prime, GeneratePrimeOptions, PrimalityResult,
};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;

// ---------------------------------------------------------------------------
// PrimeArgs
// ---------------------------------------------------------------------------

/// Arguments for the `prime` subcommand.
///
/// Replaces the C `prime_options[]` table from `apps/prime.c` (lines 14–44).
/// Provides two modes of operation:
/// 1. **Test mode** (default): test whether a given number is prime
/// 2. **Generate mode** (`--generate`): generate a random prime of given bit length
#[derive(Args, Debug)]
pub struct PrimeArgs {
    /// The number to test for primality.
    ///
    /// Interpreted as decimal by default. Use `--hex` to parse as hexadecimal.
    /// This argument is required in test mode and ignored in generate mode.
    #[arg(value_name = "NUMBER")]
    pub number: Option<String>,

    /// Generate a random prime of this many bits instead of testing.
    ///
    /// Replaces `apps/prime.c` `-generate` option. The generated prime is
    /// printed in the selected format (hex or decimal).
    #[arg(short = 'g', long = "generate", value_name = "BITS")]
    pub generate: Option<u32>,

    /// Number of Miller-Rabin rounds for primality testing.
    ///
    /// If 0 (default), an appropriate number of rounds is chosen
    /// automatically based on the bit size of the number.
    #[arg(short = 'c', long = "checks", default_value = "0")]
    pub checks: u32,

    /// Parse/display numbers in hexadecimal instead of decimal.
    #[arg(long = "hex")]
    pub hex: bool,

    /// Generate a safe prime (where (p-1)/2 is also prime).
    ///
    /// Only meaningful with `--generate`. Replaces `-safe` from `apps/prime.c`.
    #[arg(long = "safe")]
    pub safe: bool,
}

impl PrimeArgs {
    /// Execute the `prime` subcommand.
    ///
    /// Dispatches to either prime generation or primality testing based on
    /// the provided arguments.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - The number string cannot be parsed as a valid integer
    /// - Prime generation fails (invalid bit count, entropy failure)
    /// - I/O errors occur writing to stdout
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        if let Some(bits) = self.generate {
            self.run_generate(&mut out, bits)
        } else if let Some(ref number_str) = self.number {
            self.run_test(&mut out, number_str)
        } else {
            writeln!(
                out,
                "Usage: openssl prime [--hex] [--generate BITS] [--safe] [--checks N] [NUMBER]"
            )?;
            Err(CryptoError::Key(
                "Either a number or --generate is required".into(),
            ))
        }
    }

    /// Generates a random prime of the specified bit length.
    fn run_generate(&self, out: &mut impl Write, bits: u32) -> Result<(), CryptoError> {
        if bits < 2 {
            return Err(CryptoError::Key("Bit length must be at least 2".into()));
        }
        // Cap at reasonable bit length to prevent resource exhaustion
        if bits > 16384 {
            return Err(CryptoError::Key("Bit length must not exceed 16384".into()));
        }

        let prime = generate_prime(&GeneratePrimeOptions {
            bits,
            safe: self.safe,
            add: None,
            rem: None,
        })?;

        if self.hex {
            writeln!(out, "{}", prime.to_hex())?;
        } else {
            writeln!(out, "{}", prime.to_dec())?;
        }

        Ok(())
    }

    /// Tests a number for primality.
    fn run_test(&self, out: &mut impl Write, number_str: &str) -> Result<(), CryptoError> {
        let bn = if self.hex {
            BigNum::from_hex(number_str)?
        } else {
            BigNum::from_dec(number_str)?
        };

        let result = if self.checks > 0 {
            openssl_crypto::bn::prime::check_prime_with_rounds(&bn, self.checks)?
        } else {
            check_prime(&bn)?
        };

        let display_str = if self.hex { bn.to_hex() } else { bn.to_dec() };

        match result {
            PrimalityResult::ProbablyPrime => {
                writeln!(out, "{display_str} ({} bit) is prime", bn.num_bits())?;
            }
            PrimalityResult::Composite => {
                writeln!(out, "{display_str} ({} bit) is not prime", bn.num_bits())?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_small_prime() {
        let args = PrimeArgs {
            number: Some("7".into()),
            generate: None,
            checks: 0,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should succeed for small prime");
    }

    #[tokio::test]
    async fn test_composite_number() {
        let args = PrimeArgs {
            number: Some("15".into()),
            generate: None,
            checks: 0,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should succeed for composite");
    }

    #[tokio::test]
    async fn test_hex_input() {
        let args = PrimeArgs {
            number: Some("1F".into()),
            generate: None,
            checks: 0,
            hex: true,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should succeed for hex input");
    }

    #[tokio::test]
    async fn test_generate_prime() {
        let args = PrimeArgs {
            number: None,
            generate: Some(64),
            checks: 0,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should generate 64-bit prime");
    }

    #[tokio::test]
    async fn test_generate_prime_hex() {
        let args = PrimeArgs {
            number: None,
            generate: Some(32),
            checks: 0,
            hex: true,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should generate 32-bit prime in hex");
    }

    #[tokio::test]
    async fn test_generate_too_small() {
        let args = PrimeArgs {
            number: None,
            generate: Some(1),
            checks: 0,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "1-bit prime generation should fail");
    }

    #[tokio::test]
    async fn test_no_args_fails() {
        let args = PrimeArgs {
            number: None,
            generate: None,
            checks: 0,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "no args should fail");
    }

    #[tokio::test]
    async fn test_with_explicit_checks() {
        let args = PrimeArgs {
            number: Some("13".into()),
            generate: None,
            checks: 20,
            hex: false,
            safe: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("should succeed with explicit rounds");
    }
}
