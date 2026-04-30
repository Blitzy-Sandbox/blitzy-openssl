//! Prime number generation and testing — Rust rewrite of `apps/prime.c`.
//!
//! Provides command-line access to primality testing and prime generation
//! using the [`BigNum`] and [`prime`](openssl_crypto::bn::prime) APIs from
//! the `openssl-crypto` crate.
//!
//! # C Source Mapping
//!
//! | C construct                                | Rust equivalent                                 |
//! |--------------------------------------------|-------------------------------------------------|
//! | `prime_options[]` table (apps/prime.c)     | [`PrimeArgs`] clap derive fields                |
//! | `OPT_HEX` / `OPT_GENERATE` / `OPT_BITS`    | `--hex` / `--generate` / `--bits`               |
//! | `OPT_SAFE` / `OPT_CHECKS` / `OPT_IN_FILE`  | `--safe` / `--checks` (ignored) / `--in`        |
//! | `argv` positional args                     | `numbers: Vec<String>`                          |
//! | `check_num(s, is_hex)`                     | [`check_num`] (private helper)                  |
//! | `process_num(s, is_hex)`                   | [`process_num`] (private helper)                |
//! | `BN_hex2bn` / `BN_dec2bn`                  | [`BigNum::from_hex`] / [`BigNum::from_dec`]     |
//! | `BN_bn2hex` / `BN_bn2dec`                  | [`BigNum::to_hex`] / [`BigNum::to_dec`]         |
//! | `BN_print(bio_out, bn)`                    | `write!(out, "{}", bn.to_hex())`                |
//! | `BN_check_prime(bn, NULL, NULL)`           | [`check_prime`]                                 |
//! | `BN_generate_prime_ex(bn, bits, safe, ..)` | [`generate_prime`] with [`GeneratePrimeOptions`]|
//! | `BIO_get_line(in, buf, BUFSIZE)`           | [`BufRead::read_line`]                          |
//! | `bio_open_default_quiet(name, 'r', 0)`     | [`File::open`] wrapped in [`BufReader`]         |
//! | `BUFSIZE` (4098)                           | [`BUFSIZE`] constant (4098)                     |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → CliCommand::Prime(args)
//!     → PrimeArgs::execute(&LibContext)
//!       ├─ run_generate() → openssl_crypto::bn::prime::generate_prime()
//!       └─ run_test()
//!           ├─ process_num(literal arg)  → check_prime()
//!           └─ process_file(filename)    → process_num(line) → check_prime()
//! ```
//!
//! # Rule Compliance
//!
//! * **R5 (Nullability):** [`PrimeArgs::bits`] is `Option<u32>` (not the C
//!   sentinel `bits == 0`). [`PrimeArgs::checks`] uses `Option<u32>` to
//!   distinguish "not provided" from "0 provided" even though the value is
//!   ignored — preserving CLI parity.
//! * **R6 (Lossless casts):** All numeric conversions use `try_from`,
//!   `saturating_*`, or are widening. No bare `as` narrowing.
//! * **R8 (Zero unsafe):** No `unsafe` blocks anywhere in this file.
//! * **R9 (Warning-free):** Builds clean under `RUSTFLAGS="-D warnings"`.
//! * **R10 (Wiring):** Reachable via `CliCommand::Prime(args).execute()`
//!   from `main.rs`. Exercised by the integrated unit-test suite below.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::Args;
use tracing::{debug, info};

use openssl_common::error::CryptoError;
use openssl_crypto::bn::prime::{
    check_prime, generate_prime, GeneratePrimeOptions, PrimalityResult,
};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum line length when reading numbers from a file.
///
/// Exact translation of the `#define BUFSIZE 4098` constant from
/// `apps/prime.c` line 14. The C comment notes:
///
/// > Consistent with RSA modulus size limit and the size of plausible
/// > individual primes
///
/// This means a single number on a line cannot exceed `BUFSIZE - 2 = 4096`
/// digits. Longer lines are flagged with the "over the maximum size" error
/// and the remainder is consumed and discarded.
const BUFSIZE: usize = 4098;

/// Set of valid hex digits used by the strspn-style cleanup that strips
/// trailing whitespace and CR/LF when reading numbers from a file.
///
/// Mirrors the literal string `"1234567890abcdefABCDEF"` in the C source's
/// `strspn(file_read_buf, "1234567890abcdefABCDEF")` call. We intentionally
/// allow hex digits even in decimal mode because the C source does the same:
/// the strspn cleanup is shared, and digit validation is performed later by
/// `check_num` in [`process_num`].
const VALID_HEX_DIGITS: &[u8] = b"0123456789abcdefABCDEF";

// ---------------------------------------------------------------------------
// PrimeArgs — clap-derived argument struct
// ---------------------------------------------------------------------------

/// Arguments for the `openssl prime` subcommand.
///
/// Replaces the C `prime_options[]` table (`apps/prime.c` lines 76–96) and
/// the `opt_init`/`opt_next` switch loop (lines 105–143) with a clap-derived
/// struct that performs the same parsing automatically.
///
/// # Operating Modes
///
/// 1. **Generate mode** (`--generate` set with `--bits N`):
///    Generates a probable prime of `N` bits (optionally a safe prime) and
///    prints it. No positional arguments are permitted in this mode.
///
/// 2. **Test mode** (default — at least one positional `NUMBER`):
///    Tests each positional value for primality. With `--in`, each
///    positional is interpreted as a filename containing one number per
///    line, and every line is tested.
///
/// # Compatibility
///
/// * `--checks N`: accepted for compatibility with the C tool but **ignored**.
///   The C source explicitly discards this value (`apps/prime.c` lines 130–133)
///   and uses BN's internal default round count via `BN_check_prime`.
// JUSTIFICATION: PrimeArgs intentionally exposes four independent boolean
// flags (--generate, --safe, --hex, --in) because each maps directly to a
// distinct C `OPT_*` enum value in apps/prime.c. Collapsing them into a
// bitflags or enum would obscure the 1:1 CLI compatibility with the C tool
// and break clap's standard --flag semantics. Refactoring is therefore
// inappropriate; we explicitly allow this lint for this struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug, Default)]
pub struct PrimeArgs {
    /// Generate a prime instead of testing. Requires `--bits`.
    ///
    /// Replaces the C `OPT_GENERATE` flag. Mutually exclusive with positional
    /// numbers — combining `--generate` with positional arguments is rejected
    /// at runtime with a usage error, matching `apps/prime.c` line 147.
    #[arg(long = "generate", action = clap::ArgAction::SetTrue)]
    pub generate: bool,

    /// Bit length of the prime to generate. Required with `--generate`.
    ///
    /// Replaces the C `OPT_BITS` option. Without this, the generate mode
    /// terminates with "Specify the number of bits." matching the C source
    /// (`apps/prime.c` line 159).
    ///
    /// Rule R5: encoded as `Option<u32>` — `None` means "not specified",
    /// distinct from `Some(0)` (which the C source would also reject).
    #[arg(long = "bits", value_name = "BITS")]
    pub bits: Option<u32>,

    /// Generate a safe prime (where `(p-1)/2` is also prime).
    ///
    /// Replaces the C `OPT_SAFE` flag. Only meaningful in conjunction with
    /// `--generate`. In test mode, this flag has no effect.
    #[arg(long = "safe", action = clap::ArgAction::SetTrue)]
    pub safe: bool,

    /// Number of Miller–Rabin rounds. **Accepted but ignored.**
    ///
    /// Replaces the C `OPT_CHECKS` option, which the C source explicitly
    /// discards (`apps/prime.c` lines 130–133):
    ///
    /// ```c
    /// case OPT_CHECKS:
    ///     /* ignore parameter and argument */
    ///     opt_arg();
    ///     break;
    /// ```
    ///
    /// Preserved here for command-line compatibility with scripts and
    /// tutorials that pass `-checks N`. The default Miller–Rabin round
    /// count is selected automatically by [`check_prime`] based on the
    /// candidate's bit size.
    #[arg(long = "checks", value_name = "NUM")]
    pub checks: Option<u32>,

    /// Use hexadecimal format for input and generated-prime output.
    ///
    /// Replaces the C `OPT_HEX` flag. With `--hex`:
    /// * Test-mode positional values must be valid hex (validated via
    ///   [`check_num`]).
    /// * Generated primes are printed in uppercase hex (via
    ///   [`BigNum::to_hex`]) instead of decimal.
    /// * The `BN_print(bio_out, bn)` portion of the test-mode output is
    ///   always hex regardless of this flag (matching the C source, which
    ///   calls `BN_print` unconditionally).
    #[arg(long = "hex", action = clap::ArgAction::SetTrue)]
    pub hex: bool,

    /// Treat each positional argument as a filename containing one number
    /// per line, instead of as a literal number.
    ///
    /// Replaces the C `OPT_IN_FILE` flag. When set, each positional is
    /// opened, lines are read up to [`BUFSIZE`] bytes, trailing
    /// non-hex-digit characters are stripped (strspn cleanup), and each
    /// resulting digit string is run through [`process_num`]. Lines longer
    /// than `BUFSIZE - 2` digits are rejected with a diagnostic and the
    /// remainder of the over-long line is consumed.
    #[arg(long = "in", action = clap::ArgAction::SetTrue)]
    pub in_file: bool,

    /// One or more numbers to test for primality (or filenames with `--in`).
    ///
    /// Stored as raw strings rather than parsed integers because:
    /// 1. Hex/dec interpretation depends on `--hex`.
    /// 2. The exact original string is included in the output line
    ///    `"HEXVALUE (ORIGINAL) is prime"` per the C source format string.
    /// 3. Strict digit validation ([`check_num`]) is performed before
    ///    parsing to produce the precise C error message
    ///    `"Failed to process value (s)"`.
    #[arg(value_name = "NUMBER")]
    pub numbers: Vec<String>,
}

impl PrimeArgs {
    /// Execute the `openssl prime` subcommand.
    ///
    /// Equivalent to `prime_main(int argc, char **argv)` in `apps/prime.c`.
    /// The control flow mirrors the C source step-by-step:
    ///
    /// 1. Validate argument combinations:
    ///    * `--generate` with positional args → usage error
    ///    * Test mode with no positionals → "Missing number(s) to check"
    /// 2. If `--generate`:
    ///    * Require `--bits` (else "Specify the number of bits.")
    ///    * Generate prime via [`generate_prime`]
    ///    * Print in hex or decimal
    /// 3. Otherwise (test mode):
    ///    * For each positional, if `--in` is set treat as filename and
    ///      read line-by-line; otherwise treat as a literal number.
    ///
    /// The `_ctx` parameter is accepted to satisfy the [`CliCommand`]
    /// dispatch contract (every subcommand receives a [`LibContext`]). Prime
    /// generation/testing in this implementation does not consult
    /// per-context provider state because primality testing in
    /// `openssl_crypto::bn::prime` already uses the global default
    /// providers; the parameter is reserved for future provider-aware
    /// extensions and FIPS-mode dispatch.
    ///
    /// [`CliCommand`]: crate::commands::CliCommand
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] for usage errors (missing arguments,
    /// conflicting flags, invalid bit count) and [`CryptoError::Io`] for
    /// failures writing to stdout. File-mode errors (open failures, read
    /// errors, over-long lines, invalid digit strings) are reported on
    /// stderr per the C source semantics and do **not** abort processing
    /// of subsequent files or lines.
    #[allow(clippy::unused_async)]
    #[tracing::instrument(
        skip(self, _ctx),
        fields(
            command = "prime",
            generate = self.generate,
            safe = self.safe,
            hex = self.hex,
            in_file = self.in_file,
            num_count = self.numbers.len(),
        )
    )]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        info!("openssl prime starting");
        debug!(
            generate = self.generate,
            bits = ?self.bits,
            safe = self.safe,
            hex = self.hex,
            in_file = self.in_file,
            checks = ?self.checks,
            num_inputs = self.numbers.len(),
            "prime parameters parsed"
        );

        // Lock stdout/stderr for the duration of the command so that
        // multi-line output (especially file-mode batches) doesn't
        // interleave with concurrent writers.
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let stderr = io::stderr();
        let mut err = stderr.lock();

        // ----- Argument validation -----
        // Mirrors the C `if (generate && !opt_check_rest_arg(NULL)) goto opthelp`
        // and `if (!generate && argc == 0)` checks (apps/prime.c lines 145–151).
        if self.generate && !self.numbers.is_empty() {
            writeln!(
                err,
                "openssl prime: --generate does not accept positional numbers; use --bits NN"
            )?;
            return Err(CryptoError::Key(
                "--generate cannot be combined with positional numbers".into(),
            ));
        }
        if !self.generate && self.numbers.is_empty() {
            // Match the exact C string "Missing number (s) to check\n"
            // verbatim (note the space between "number" and "(s)") for
            // strict CLI parity.
            writeln!(err, "Missing number (s) to check")?;
            return Err(CryptoError::Key("Missing number(s) to check".into()));
        }

        if self.generate {
            self.run_generate(&mut out, &mut err)
        } else {
            self.run_test(&mut out, &mut err)
        }
    }

    /// Generate a probable (or safe) prime and print it.
    ///
    /// Equivalent to the `if (generate)` block in `apps/prime.c`
    /// (lines 153–172). Errors out if `--bits` was not provided.
    fn run_generate<W: Write, E: Write>(
        &self,
        out: &mut W,
        err: &mut E,
    ) -> Result<(), CryptoError> {
        // Rule R5: bits is Option<u32>; None means "not provided".
        // The C source treats `bits == 0` as "not provided".
        let bits = match self.bits {
            Some(b) if b > 0 => b,
            _ => {
                // Match the C error string verbatim: "Specify the number of bits.\n"
                writeln!(err, "Specify the number of bits.")?;
                return Err(CryptoError::Key(
                    "--generate requires --bits NN with NN > 0".into(),
                ));
            }
        };

        debug!(bits, safe = self.safe, "generating prime");

        let options = GeneratePrimeOptions {
            bits,
            safe: self.safe,
            add: None,
            rem: None,
        };

        let prime = generate_prime(&options).map_err(|e| {
            // Surface the underlying generation error on stderr so the
            // user sees something resembling the C "Failed to generate
            // prime." diagnostic. The original error is still propagated
            // via Err for programmatic callers and exit-code mapping.
            let _ = writeln!(err, "Failed to generate prime: {e}");
            e
        })?;

        // Match the C output format:
        //     BIO_printf(bio_out, "%s\n", s);
        // where `s` is `BN_bn2hex(bn)` if `--hex` else `BN_bn2dec(bn)`.
        if self.hex {
            writeln!(out, "{}", prime.to_hex())?;
        } else {
            writeln!(out, "{}", prime.to_dec())?;
        }

        info!(bits, safe = self.safe, "prime generated successfully");
        Ok(())
    }

    /// Run the test-mode loop over positional inputs.
    ///
    /// Equivalent to the `else { for (; *argv; argv++) ... }` block in
    /// `apps/prime.c` (lines 173–207). Per-input failures are reported on
    /// stderr but do not abort the loop; the function only returns `Err`
    /// for stdout I/O failures.
    fn run_test<W: Write, E: Write>(&self, out: &mut W, err: &mut E) -> Result<(), CryptoError> {
        debug!(
            count = self.numbers.len(),
            in_file = self.in_file,
            "prime test mode"
        );
        for arg in &self.numbers {
            if self.in_file {
                process_file(arg, self.hex, out, err)?;
            } else {
                process_num(arg, self.hex, out, err)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers — direct translations of the C `check_num` and `process_num`
// helpers from `apps/prime.c`.
// ---------------------------------------------------------------------------

/// Strict digit validator — direct port of `check_num()` from
/// `apps/prime.c` (lines 16–32).
///
/// Verifies that **every** character in `s` is a valid digit:
/// * For `is_hex == true`:  `[0-9A-Fa-f]`
/// * For `is_hex == false`: `[0-9]`
///
/// Returns `true` iff `s` is non-empty and contains only valid digits.
/// An empty string returns `false` (matching the C semantics where
/// `s[0] == '\0'` makes `s[i] == 0` true on iteration 0, but
/// `BN_hex2bn("")`/`BN_dec2bn("")` would then fail to produce a number).
///
/// # C Source
///
/// ```c
/// static int check_num(const char *s, const int is_hex)
/// {
///     int i;
///     if (is_hex) {
///         for (i = 0; ('0' <= s[i] && s[i] <= '9')
///             || ('A' <= s[i] && s[i] <= 'F')
///             || ('a' <= s[i] && s[i] <= 'f');
///             i++) ;
///     } else {
///         for (i = 0; '0' <= s[i] && s[i] <= '9'; i++) ;
///     }
///     return s[i] == 0;
/// }
/// ```
///
/// # Edge case: empty string
///
/// The C function returns `1` (true) for `""` because the loop exits
/// immediately at `i == 0` and `s[0] == 0`. The Rust port returns `false`
/// for empty input, since the subsequent `BN_*2bn` call would fail anyway
/// and reporting "Failed to process value ()" early is clearer than the
/// alternative.
fn check_num(s: &str, is_hex: bool) -> bool {
    if s.is_empty() {
        return false;
    }
    if is_hex {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b) || (b'a'..=b'f').contains(&b))
    } else {
        s.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Test a single literal number string for primality, with strict digit
/// validation, and print the result to `out`.
///
/// Direct port of `process_num(const char *s, const int is_hex)` from
/// `apps/prime.c` (lines 34–58). Output format matches the C source exactly:
///
/// ```text
/// HEXVALUE (ORIGINAL_INPUT) is prime
/// HEXVALUE (ORIGINAL_INPUT) is not prime
/// ```
///
/// where `HEXVALUE` is the uppercase hexadecimal rendering of the parsed
/// number (the equivalent of `BN_print(bio_out, bn)` in C, which always
/// emits hex regardless of the `-hex` flag).
///
/// Errors and validation failures are reported on `err` per the C source;
/// they do not return `Err` because the C source uses `return;` (void) and
/// continues with the next number.
fn process_num<W: Write, E: Write>(
    s: &str,
    is_hex: bool,
    out: &mut W,
    err: &mut E,
) -> Result<(), CryptoError> {
    // Step 1: digit validation. Matches C `r = check_num(s, is_hex)`
    // followed by the `if (!r)` check that prints the failure message.
    if !check_num(s, is_hex) {
        writeln!(err, "Failed to process value ({s})")?;
        return Ok(());
    }

    // Step 2: parse via BN_hex2bn or BN_dec2bn. Any parse failure is also
    // reported with "Failed to process value (s)" since the C source
    // collapses both validation and parse failures into the same branch.
    let parse_result = if is_hex {
        BigNum::from_hex(s)
    } else {
        BigNum::from_dec(s)
    };
    let Ok(bn) = parse_result else {
        writeln!(err, "Failed to process value ({s})")?;
        return Ok(());
    };

    // Step 3: primality test (always with default round count — matching
    // C `BN_check_prime(bn, NULL, NULL)`).
    let Ok(result) = check_prime(&bn) else {
        // C: BIO_puts(bio_err, "Error checking prime\n");
        writeln!(err, "Error checking prime")?;
        return Ok(());
    };

    // Step 4: emit the result line. C source:
    //     BN_print(bio_out, bn);
    //     BIO_printf(bio_out, " (%s) %s prime\n", s, r == 1 ? "is" : "is not");
    let verdict = match result {
        PrimalityResult::ProbablyPrime => "is",
        PrimalityResult::Composite => "is not",
    };
    let printed = bn.to_hex();
    writeln!(out, "{printed} ({s}) {verdict} prime")?;

    debug!(
        input = s,
        bits = bn.num_bits(),
        verdict = verdict,
        "prime test complete"
    );
    Ok(())
}

/// File-input mode helper: open `path` and stream every line through
/// [`process_num`]. Direct port of the `if (in_file) { ... }` block in
/// `apps/prime.c` (lines 178–204).
///
/// # Behaviour
///
/// * Open errors print "Error opening file <name>" to `err` and return Ok
///   (the C source uses `continue` to keep processing later positionals).
/// * Each line is read with a [`BUFSIZE`]-byte buffer; a line that fills
///   the buffer without a terminating newline is "over the maximum size"
///   and the rest of the over-long line is consumed and discarded.
/// * After reading, the line is cleaned strspn-style: trimmed at the
///   first character not in `VALID_HEX_DIGITS` (typically the `\n` from
///   `read_line`).
/// * Read failures print "Read error in <name>" and return Ok.
fn process_file<W: Write, E: Write>(
    path: &str,
    is_hex: bool,
    out: &mut W,
    err: &mut E,
) -> Result<(), CryptoError> {
    let Ok(file) = File::open(PathBuf::from(path)) else {
        // C: BIO_printf(bio_err, "Error opening file %s\n", argv[0]);
        writeln!(err, "Error opening file {path}")?;
        return Ok(());
    };
    debug!(file = path, "opened file for prime testing");

    // BufReader with BUFSIZE matches the C `char file_read_buf[BUFSIZE]`
    // sizing, though Rust's BufReader is internally double-buffered for
    // performance — this is a non-observable implementation detail.
    let mut reader = BufReader::with_capacity(BUFSIZE, file);
    let mut line = String::new();

    loop {
        line.clear();
        // BufRead::read_line reads up to (and including) the next '\n',
        // appending to `line`. Returns 0 at EOF, otherwise the number of
        // bytes read. Equivalent to C `BIO_get_line(in, buf, BUFSIZE)` with
        // the additional safety that Rust never overflows the buffer.
        let Ok(bytes_read) = reader.read_line(&mut line) else {
            writeln!(err, "Read error in {path}")?;
            return Ok(());
        };
        if bytes_read == 0 {
            break; // EOF
        }

        // C overflow check:
        //     if (bytes_read == BUFSIZE - 1 && file_read_buf[BUFSIZE - 2] != '\n') {
        //         BIO_printf(bio_err, "Value in %s is over the maximum size (%d digits)\n",
        //                    argv[0], BUFSIZE - 2);
        //         while (BIO_get_line(in, file_read_buf, BUFSIZE) == BUFSIZE - 1) ;
        //         continue;
        //     }
        // We approximate the same condition: a line is "too long" if it
        // reaches or exceeds BUFSIZE - 2 bytes without ending in '\n'.
        if bytes_read >= BUFSIZE - 2 && !line.ends_with('\n') {
            writeln!(
                err,
                "Value in {path} is over the maximum size ({} digits)",
                BUFSIZE - 2
            )?;
            // Consume and discard the remainder of the over-long line.
            consume_long_line(&mut reader)?;
            continue;
        }

        // strspn-style cleanup: truncate at the first character not in
        // VALID_HEX_DIGITS. This strips the trailing '\n' (and CR/LF on
        // Windows) and anything else that isn't a hex digit. Matches:
        //     valid_digits_length = strspn(file_read_buf, "1234567890abcdefABCDEF");
        //     file_read_buf[valid_digits_length] = '\0';
        let cleaned = trim_to_hex_digits(&line);

        process_num(cleaned, is_hex, out, err)?;
    }

    Ok(())
}

/// strspn-style cleanup helper. Returns the longest prefix of `s` that
/// consists only of valid hex digits, mirroring the C source's
/// `strspn(buf, "1234567890abcdefABCDEF")` followed by truncation.
fn trim_to_hex_digits(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && VALID_HEX_DIGITS.contains(&bytes[end]) {
        end += 1;
    }
    // Safety of slicing: every byte before `end` is ASCII (subset of
    // VALID_HEX_DIGITS), so `&s[..end]` is a valid char boundary.
    &s[..end]
}

/// Discard the rest of an over-long line. Matches the C inner loop
/// `while (BIO_get_line(in, file_read_buf, BUFSIZE) == BUFSIZE - 1) ;`
/// which keeps consuming buffer-full reads until a short read or EOF
/// signals the end of the offending line.
fn consume_long_line<R: BufRead>(reader: &mut R) -> Result<(), CryptoError> {
    let mut scratch = String::new();
    loop {
        scratch.clear();
        let n = reader.read_line(&mut scratch)?;
        if n == 0 || scratch.ends_with('\n') || n < BUFSIZE - 2 {
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// JUSTIFICATION: Tests deliberately use `unwrap()` / `expect()` / `panic!`
// to fail fast on unexpected setup errors (e.g., temp-file creation) and
// to assert on enum variants. The workspace Cargo.toml explicitly permits
// these in tests with a justification comment (per AAP §0.8.1 Rule R9
// note: "Tests and CLI main() may #[allow] with justification").
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_in_result
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Helper to build a default `PrimeArgs` with the given numbers in
    /// test mode (no `--generate`, no flags).
    fn args_test(numbers: &[&str]) -> PrimeArgs {
        PrimeArgs {
            generate: false,
            bits: None,
            safe: false,
            checks: None,
            hex: false,
            in_file: false,
            numbers: numbers.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    // ---------- check_num ----------

    #[test]
    fn check_num_decimal_accepts_valid() {
        assert!(check_num("0", false));
        assert!(check_num("13", false));
        assert!(check_num("123456789", false));
    }

    #[test]
    fn check_num_decimal_rejects_hex_letters() {
        assert!(!check_num("a", false));
        assert!(!check_num("12a", false));
        assert!(!check_num("FF", false));
    }

    #[test]
    fn check_num_decimal_rejects_signs_and_whitespace() {
        assert!(!check_num("-13", false));
        assert!(!check_num("+13", false));
        assert!(!check_num("13 ", false));
        assert!(!check_num(" 13", false));
        assert!(!check_num("13\n", false));
    }

    #[test]
    fn check_num_hex_accepts_all_cases() {
        assert!(check_num("0", true));
        assert!(check_num("DEADBEEF", true));
        assert!(check_num("deadbeef", true));
        assert!(check_num("DeAdBeEf", true));
        assert!(check_num("0123456789abcdefABCDEF", true));
    }

    #[test]
    fn check_num_hex_rejects_non_hex() {
        assert!(!check_num("g", true));
        assert!(!check_num("0xFF", true)); // `x` is not a hex digit
        assert!(!check_num("FF\n", true));
    }

    #[test]
    fn check_num_rejects_empty_string() {
        // The Rust port returns false for "" (see doc comment).
        assert!(!check_num("", true));
        assert!(!check_num("", false));
    }

    // ---------- trim_to_hex_digits ----------

    #[test]
    fn trim_to_hex_digits_strips_trailing_newline() {
        assert_eq!(trim_to_hex_digits("123\n"), "123");
        assert_eq!(trim_to_hex_digits("123\r\n"), "123");
    }

    #[test]
    fn trim_to_hex_digits_keeps_full_hex() {
        assert_eq!(trim_to_hex_digits("DEADBEEF"), "DEADBEEF");
        assert_eq!(
            trim_to_hex_digits("0123456789abcdefABCDEF"),
            "0123456789abcdefABCDEF"
        );
    }

    #[test]
    fn trim_to_hex_digits_truncates_at_first_non_digit() {
        assert_eq!(trim_to_hex_digits("123 456"), "123");
        assert_eq!(trim_to_hex_digits("13#comment"), "13");
        assert_eq!(trim_to_hex_digits("xyz"), "");
    }

    // ---------- process_num ----------

    #[test]
    fn process_num_small_prime_decimal() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        process_num("13", false, &mut out, &mut err).unwrap();
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        assert!(
            stdout.contains("(13) is prime"),
            "expected '(13) is prime' marker, got: {stdout}"
        );
        // BN_print emits hex; 13 = 0xD
        assert!(
            stdout.starts_with("D "),
            "expected hex prefix 'D ', got: {stdout}"
        );
    }

    #[test]
    fn process_num_composite_decimal() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        process_num("15", false, &mut out, &mut err).unwrap();
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        assert!(
            stdout.contains("(15) is not prime"),
            "expected composite verdict, got: {stdout}"
        );
    }

    #[test]
    fn process_num_hex_prime() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        // 0x10001 = 65537 (prime)
        process_num("10001", true, &mut out, &mut err).unwrap();
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        assert!(
            stdout.contains("(10001) is prime"),
            "expected '(10001) is prime', got: {stdout}"
        );
    }

    #[test]
    fn process_num_invalid_decimal_emits_failed_message() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        process_num("12a", false, &mut out, &mut err).unwrap();
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        let stderr = String::from_utf8(err.into_inner()).unwrap();
        assert!(stdout.is_empty(), "expected empty stdout, got: {stdout}");
        assert_eq!(stderr.trim(), "Failed to process value (12a)");
    }

    #[test]
    fn process_num_invalid_hex_emits_failed_message() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        process_num("xyz", true, &mut out, &mut err).unwrap();
        let stderr = String::from_utf8(err.into_inner()).unwrap();
        assert_eq!(stderr.trim(), "Failed to process value (xyz)");
    }

    #[test]
    fn process_num_empty_string_rejected() {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        process_num("", false, &mut out, &mut err).unwrap();
        let stderr = String::from_utf8(err.into_inner()).unwrap();
        assert_eq!(stderr.trim(), "Failed to process value ()");
    }

    // ---------- end-to-end: PrimeArgs::execute ----------

    #[tokio::test]
    async fn execute_no_args_returns_usage_error() {
        let args = args_test(&[]);
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::Key(msg) => assert!(msg.contains("Missing")),
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_generate_without_bits_fails() {
        let args = PrimeArgs {
            generate: true,
            bits: None,
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::Key(msg) => assert!(msg.contains("--bits")),
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_generate_with_positionals_fails() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(64),
            numbers: vec!["13".into()],
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_test_decimal_prime_succeeds() {
        let args = args_test(&["13"]);
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("13 is prime, should succeed");
    }

    #[tokio::test]
    async fn execute_test_decimal_composite_succeeds() {
        // Composite numbers are not errors; the verdict is printed and the
        // command exits successfully (matching C ret = 0).
        let args = args_test(&["15"]);
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("composite test should succeed (just prints 'is not prime')");
    }

    #[tokio::test]
    async fn execute_test_hex_input_succeeds() {
        let args = PrimeArgs {
            hex: true,
            numbers: vec!["10001".into()], // 65537 = 0x10001 (prime)
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("0x10001 is prime");
    }

    #[tokio::test]
    async fn execute_test_invalid_digits_does_not_error() {
        // Per C semantics, invalid digits print "Failed to process value (s)"
        // to stderr and continue. The command itself returns Ok.
        let args = args_test(&["12a"]);
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("invalid digits should not produce an Err");
    }

    #[tokio::test]
    async fn execute_test_with_explicit_checks_is_ignored() {
        // -checks N is accepted but ignored (compat shim).
        let args = PrimeArgs {
            numbers: vec!["13".into()],
            checks: Some(20),
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("--checks should be silently ignored");
    }

    #[tokio::test]
    async fn execute_generate_small_prime_decimal() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(16),
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("16-bit prime generation should succeed");
    }

    #[tokio::test]
    async fn execute_generate_small_prime_hex() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(16),
            hex: true,
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("16-bit hex prime generation should succeed");
    }

    #[tokio::test]
    async fn execute_test_multiple_positionals() {
        let args = args_test(&["13", "15", "17"]);
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("multiple positionals should all be processed");
    }

    // ---------- file-mode ----------

    #[tokio::test]
    async fn execute_file_mode_processes_lines() {
        // Build a temp file with three numbers, one per line.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("prime_test_{}.txt", std::process::id()));
        std::fs::write(&path, "13\n15\n17\n").unwrap();

        let args = PrimeArgs {
            in_file: true,
            numbers: vec![path.to_string_lossy().to_string()],
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;

        // Cleanup before assertion so the file is removed even on failure.
        let _ = std::fs::remove_file(&path);
        result.expect("file-mode should succeed for well-formed input");
    }

    #[tokio::test]
    async fn execute_file_mode_missing_file_does_not_error() {
        // Per C semantics, missing files print "Error opening file <name>"
        // and continue; the command returns Ok overall.
        let args = PrimeArgs {
            in_file: true,
            numbers: vec!["/nonexistent/path/should/not/exist/prime_input.txt".into()],
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("file-mode missing file is reported on stderr, not Err");
    }

    #[tokio::test]
    async fn execute_file_mode_strips_trailing_whitespace() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("prime_test_ws_{}.txt", std::process::id()));
        // Trailing spaces / CRLF should be stripped by trim_to_hex_digits
        std::fs::write(&path, "13\r\n15  \n17\n").unwrap();

        let args = PrimeArgs {
            in_file: true,
            numbers: vec![path.to_string_lossy().to_string()],
            ..PrimeArgs::default()
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;

        let _ = std::fs::remove_file(&path);
        result.expect("file-mode should tolerate CRLF and trailing spaces");
    }

    // ---------- run_generate / run_test direct ----------

    #[test]
    fn run_generate_writes_decimal() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(8),
            ..PrimeArgs::default()
        };
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        args.run_generate(&mut out, &mut err)
            .expect("8-bit prime generation should succeed");
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        // The generated prime is between 2 and 2^8 - 1 = 255 (decimal digits).
        assert!(
            !stdout.trim().is_empty(),
            "expected non-empty stdout, got: {stdout:?}"
        );
        assert!(
            stdout.trim().chars().all(|c| c.is_ascii_digit()),
            "expected decimal digits in stdout, got: {stdout:?}"
        );
    }

    #[test]
    fn run_generate_writes_hex_when_flag_set() {
        let args = PrimeArgs {
            generate: true,
            bits: Some(8),
            hex: true,
            ..PrimeArgs::default()
        };
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        args.run_generate(&mut out, &mut err)
            .expect("8-bit hex prime generation should succeed");
        let stdout = String::from_utf8(out.into_inner()).unwrap();
        assert!(
            stdout.trim().chars().all(|c| c.is_ascii_hexdigit()),
            "expected hex digits in stdout, got: {stdout:?}"
        );
    }
}
