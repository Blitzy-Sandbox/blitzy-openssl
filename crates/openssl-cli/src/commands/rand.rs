//! Random data generation subcommand — Rust rewrite of `apps/rand.c`.
//!
//! Generates cryptographically secure random bytes using
//! [`openssl_crypto::rand::rand_bytes()`] and writes them to stdout or a file
//! in raw binary, Base64, or hexadecimal encoding.
//!
//! # C Source Mapping
//!
//! | C construct                         | Rust equivalent                          |
//! |-------------------------------------|------------------------------------------|
//! | `rand_options[]` OPT_OUT/BASE64/HEX | `RandArgs` clap derive fields            |
//! | `RAND_bytes_ex(libctx, buf, n, 0)`  | `openssl_crypto::rand::rand_bytes(buf)`  |
//! | `BIO_f_base64()` filter chain       | `base64ct::Base64::encode_string()`      |
//! | `BIO_printf(out, "%02x", buf[i])`   | `hex::encode(chunk)`                     |
//! | `buflen = (1 << 16)`                | `CHUNK_SIZE` = 65 536                  |
//! | `UINT64_MAX >> 3` max guard         | `MAX_OUTPUT_BYTES` = 2^61              |
//! | K/M/G/T suffix bit-shifts           | `parse_byte_count()`                   |

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::rand::rand_bytes;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum chunk size per random-generation call (64 KiB).
///
/// Matches the C `buflen = (1 << 16)` from `apps/rand.c` line 55.
/// Must not exceed [`openssl_crypto::rand`]'s internal `MAX_REQUEST_SIZE`
/// (1 MiB).
const CHUNK_SIZE: usize = 1 << 16; // 65 536

/// Maximum allowed random output (2^61 bytes).
///
/// Matches the C `UINT64_MAX >> 3` guard from `apps/rand.c` line 108.
const MAX_OUTPUT_BYTES: u64 = u64::MAX >> 3;

/// Standard Base64 line width (76 characters per line).
///
/// Matches the `BIO_f_base64()` default line-wrapping behaviour.
const BASE64_LINE_WIDTH: usize = 76;

// ---------------------------------------------------------------------------
// Output format selection
// ---------------------------------------------------------------------------

/// Output encoding format for generated random bytes.
///
/// Replaces the C `FORMAT_BINARY` / `FORMAT_BASE64` / `FORMAT_TEXT` constants
/// used in `apps/rand.c` to select between raw, base64, and hex output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    /// Raw binary bytes written directly to the output stream.
    Binary,
    /// Base64-encoded output with 76-character line wrapping and trailing
    /// newline per line, matching `BIO_f_base64()` behaviour.
    Base64,
    /// Lowercase hexadecimal encoding (two characters per byte) with a
    /// single trailing newline after all bytes, matching the C
    /// `BIO_printf(out, "%02x", buf[i])` loop.
    Hex,
}

// ---------------------------------------------------------------------------
// RandArgs — CLI argument definition
// ---------------------------------------------------------------------------

/// Arguments for the `openssl rand` subcommand.
///
/// Generates cryptographically secure random bytes and writes them to stdout
/// or a file, optionally encoding as Base64 or hexadecimal.
///
/// # Usage
///
/// ```text
/// openssl rand [--out FILE] [--base64 | --hex] NUM[K|M|G|T]
/// ```
///
/// # C Mapping
///
/// | C option / behaviour          | Rust field / behaviour                   |
/// |-------------------------------|------------------------------------------|
/// | `-out FILE`                   | `--out FILE`                             |
/// | `-base64`                     | `--base64`                               |
/// | `-hex`                        | `--hex`                                  |
/// | positional `num[K\|M\|G\|T]` | positional `num` with suffix parse       |
/// | `buflen = (1 << 16)`          | `CHUNK_SIZE` = 65 536                  |
/// | `FORMAT_BINARY/BASE64/TEXT`   | [`OutputFormat`] enum                    |
#[derive(Args, Debug)]
pub struct RandArgs {
    /// Write output to the specified file instead of stdout.
    ///
    /// Replaces `-out FILE` from `apps/rand.c` `rand_options[]`.
    #[arg(long = "out", value_name = "FILE")]
    out: Option<PathBuf>,

    /// Base64-encode the output.
    ///
    /// Uses `base64ct::Base64` constant-time encoding with 76-character
    /// line wrapping, matching `BIO_f_base64()`.
    #[arg(long = "base64", conflicts_with = "hex")]
    base64: bool,

    /// Hex-encode the output (lowercase hexadecimal with trailing newline).
    ///
    /// Encodes each byte as a two-character hex pair, matching the C
    /// `BIO_printf(out, "%02x", buf[i])` loop.
    #[arg(long = "hex", conflicts_with = "base64")]
    hex: bool,

    /// Number of random bytes to generate.
    ///
    /// Accepts an optional single-character suffix for binary scaling:
    ///
    /// | Suffix | Multiplier | Example |
    /// |--------|------------|---------|
    /// | `K`    | × 1 024    | `4K`    |
    /// | `M`    | × 1 048 576| `2M`    |
    /// | `G`    | × 1 073 741 824 | `1G` |
    /// | `T`    | × 1 099 511 627 776 | `1T` |
    ///
    /// Use `max` (case-insensitive) to request the maximum allowed output
    /// (2^61 bytes).
    #[arg(value_name = "NUM")]
    num: String,
}

// ---------------------------------------------------------------------------
// RandArgs — command execution
// ---------------------------------------------------------------------------

impl RandArgs {
    /// Executes the `openssl rand` subcommand.
    ///
    /// Generates `num` random bytes via [`openssl_crypto::rand::rand_bytes()`]
    /// in 64 KiB chunks, writing output in the selected encoding format.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Rand`] — if the byte-count argument is invalid or if
    ///   random-byte generation fails.
    /// * [`CryptoError::Io`] — if the output file cannot be created or data
    ///   cannot be written.
    ///
    /// # Observability
    ///
    /// Emits structured tracing events at `debug` (start), `info` (success),
    /// and `error` (failure) levels.
    #[allow(clippy::unused_async)]
    #[tracing::instrument(skip(self, _ctx), fields(command = "rand"))]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // ---------------------------------------------------------------
        // 1. Parse the byte-count argument (with optional K/M/G/T suffix).
        // ---------------------------------------------------------------
        let total_bytes = parse_byte_count(&self.num).map_err(|msg| {
            tracing::error!(input = %self.num, error = %msg, "failed to parse byte count");
            CryptoError::Rand(msg)
        })?;

        // ---------------------------------------------------------------
        // 2. Determine the output encoding format.
        // ---------------------------------------------------------------
        let format = if self.base64 {
            OutputFormat::Base64
        } else if self.hex {
            OutputFormat::Hex
        } else {
            OutputFormat::Binary
        };

        tracing::debug!(
            total_bytes = total_bytes,
            format = ?format,
            output = ?self.out,
            "starting random byte generation"
        );

        // ---------------------------------------------------------------
        // 3. Open the output destination (file or stdout).
        // ---------------------------------------------------------------
        let mut writer: Box<dyn Write> = match &self.out {
            Some(path) => {
                let file = File::create(path).map_err(|e| {
                    tracing::error!(path = %path.display(), error = %e, "cannot create output file");
                    CryptoError::Io(e)
                })?;
                Box::new(BufWriter::new(file))
            }
            None => Box::new(BufWriter::new(io::stdout())),
        };

        // ---------------------------------------------------------------
        // 4. Generate and write random bytes in 64 KiB chunks.
        //
        //    C reference (apps/rand.c lines 153-170):
        //      while (scaled_num > 0) {
        //          chunk = (scaled_num > buflen) ? (int)buflen : (int)scaled_num;
        //          r = RAND_bytes_ex(libctx, buf, chunk, 0);
        //          ...
        //      }
        // ---------------------------------------------------------------
        let mut remaining: u64 = total_bytes;
        let mut buf = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let chunk_len = compute_chunk_len(remaining);
            let chunk = &mut buf[..chunk_len];

            rand_bytes(chunk).map_err(|e| {
                tracing::error!(
                    error = %e,
                    remaining_bytes = remaining,
                    "random byte generation failed"
                );
                e
            })?;

            write_encoded_chunk(&mut writer, chunk, format)?;

            // chunk_len ≤ CHUNK_SIZE (65 536) — always fits in u64 on any
            // platform where usize ≤ 64 bits.  Using try_from per Rule R6
            // (no bare `as` narrowing casts).
            let chunk_u64 = u64::try_from(chunk_len)
                .map_err(|_| CryptoError::Rand("chunk length conversion overflow".to_string()))?;
            remaining -= chunk_u64;
        }

        // ---------------------------------------------------------------
        // 5. Trailing newline for hex format (matching C behaviour).
        // ---------------------------------------------------------------
        if format == OutputFormat::Hex {
            writer.write_all(b"\n")?;
        }

        // ---------------------------------------------------------------
        // 6. Flush the output stream.
        // ---------------------------------------------------------------
        writer.flush()?;

        tracing::info!(
            total_bytes = total_bytes,
            format = ?format,
            output_file = ?self.out,
            "random byte generation complete"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper — chunk length computation
// ---------------------------------------------------------------------------

/// Computes the number of bytes to generate in the current iteration.
///
/// Returns the smaller of `remaining` and `CHUNK_SIZE`, converting the
/// u64 `remaining` to usize safely via `try_from`.  When `remaining`
/// exceeds `usize::MAX` (only possible on 32-bit platforms), the result
/// is clamped to `CHUNK_SIZE`.
#[inline]
fn compute_chunk_len(remaining: u64) -> usize {
    // On 64-bit targets usize::try_from(remaining) always succeeds.
    // On 32-bit targets it may fail when remaining > u32::MAX; in that case
    // remaining is certainly > CHUNK_SIZE so we use CHUNK_SIZE.
    std::cmp::min(usize::try_from(remaining).unwrap_or(CHUNK_SIZE), CHUNK_SIZE)
}

// ---------------------------------------------------------------------------
// Helper — encoded output writing
// ---------------------------------------------------------------------------

/// Writes a single chunk of random data in the requested encoding format.
///
/// # Errors
///
/// Returns [`CryptoError::Io`] if any write to the underlying stream fails.
fn write_encoded_chunk(
    writer: &mut dyn Write,
    chunk: &[u8],
    format: OutputFormat,
) -> Result<(), CryptoError> {
    match format {
        OutputFormat::Binary => {
            writer.write_all(chunk)?;
        }
        OutputFormat::Base64 => {
            let encoded = Base64::encode_string(chunk);
            write_base64_lines(writer, &encoded)?;
        }
        OutputFormat::Hex => {
            let encoded = hex::encode(chunk);
            writer.write_all(encoded.as_bytes())?;
        }
    }
    Ok(())
}

/// Writes a Base64-encoded string to `writer` with 76-character line wrapping.
///
/// Each line of up to [`BASE64_LINE_WIDTH`] characters is followed by a `\n`,
/// matching the behaviour of `BIO_f_base64()` in the C source.
fn write_base64_lines(writer: &mut dyn Write, encoded: &str) -> Result<(), CryptoError> {
    let bytes = encoded.as_bytes();
    let mut offset: usize = 0;
    while offset < bytes.len() {
        let end = std::cmp::min(offset + BASE64_LINE_WIDTH, bytes.len());
        writer.write_all(&bytes[offset..end])?;
        writer.write_all(b"\n")?;
        offset = end;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper — byte-count parsing with K/M/G/T suffix
// ---------------------------------------------------------------------------

/// Parses a byte-count string with an optional `K`/`M`/`G`/`T` suffix.
///
/// # Accepted formats
///
/// | Input      | Parsed value                                  |
/// |------------|-----------------------------------------------|
/// | `1024`     | 1 024                                         |
/// | `4K`       | 4 × 2^10 = 4 096                              |
/// | `2M`       | 2 × 2^20 = 2 097 152                          |
/// | `1G`       | 1 × 2^30 = 1 073 741 824                      |
/// | `1T`       | 1 × 2^40 = 1 099 511 627 776                   |
/// | `max`      | `MAX_OUTPUT_BYTES` = 2^61                    |
///
/// # Errors
///
/// Returns a descriptive error string if:
/// - The input is empty.
/// - The numeric part is not a valid positive integer.
/// - The suffix is unrecognised or placed incorrectly.
/// - The scaled value overflows `u64` or exceeds `MAX_OUTPUT_BYTES`.
///
/// # C Mapping
///
/// Translates the suffix-parsing loop from `apps/rand.c` lines 89-120.
fn parse_byte_count(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();

    // ---- Special "max" keyword (case-insensitive) ----
    if trimmed.eq_ignore_ascii_case("max") {
        return Ok(MAX_OUTPUT_BYTES);
    }

    if trimmed.is_empty() {
        return Err("byte count must not be empty".to_string());
    }

    // ---- Extract numeric portion and optional shift ----
    let (num_str, shift) = extract_suffix(trimmed)?;

    let base: u64 = num_str
        .parse::<u64>()
        .map_err(|e| format!("invalid byte count '{num_str}': {e}"))?;

    if base == 0 {
        return Err("byte count must be greater than zero".to_string());
    }

    // ---- No suffix — return base directly (after max check) ----
    if shift == 0 {
        if base > MAX_OUTPUT_BYTES {
            return Err(format!(
                "requested {base} bytes exceeds maximum allowed ({MAX_OUTPUT_BYTES})"
            ));
        }
        return Ok(base);
    }

    // ---- Overflow-safe shift (Rule R6: no bare `as` narrowing casts) ----
    //
    // C reference (apps/rand.c line 113):
    //   if ((UINT64_MAX >> shift) < num) { overflow }
    let max_before_shift = u64::MAX >> shift;
    if base > max_before_shift {
        return Err(format!(
            "{}{} overflows u64",
            base,
            suffix_char_for_shift(shift)
        ));
    }

    let scaled = base << shift;
    if scaled > MAX_OUTPUT_BYTES {
        return Err(format!(
            "requested {} bytes ({}{}): exceeds maximum allowed ({})",
            scaled,
            base,
            suffix_char_for_shift(shift),
            MAX_OUTPUT_BYTES
        ));
    }

    Ok(scaled)
}

/// Extracts the numeric portion and the corresponding bit-shift amount from a
/// byte-count string.
///
/// Returns `(numeric_str, shift_bits)` where `shift_bits` is 0 when no
/// suffix is present.
///
/// # C Mapping
///
/// Corresponds to the `factoridx` loop in `apps/rand.c` lines 89-107 that
/// scans digits and then checks for a single K/M/G/T trailing character.
fn extract_suffix(input: &str) -> Result<(&str, u32), String> {
    let last = match input.as_bytes().last() {
        Some(b) => *b,
        None => return Err("empty input".to_string()),
    };

    match last {
        b'K' | b'k' => validate_numeric_prefix(input, 10),
        b'M' | b'm' => validate_numeric_prefix(input, 20),
        b'G' | b'g' => validate_numeric_prefix(input, 30),
        b'T' | b't' => validate_numeric_prefix(input, 40),
        _ => {
            // No recognised suffix — the entire string must be digits.
            if !input.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("invalid byte count '{input}'"));
            }
            Ok((input, 0))
        }
    }
}

/// Validates that the part of `input` before the single-character suffix is a
/// non-empty all-digit string, then returns it together with the given `shift`.
fn validate_numeric_prefix(input: &str, shift: u32) -> Result<(&str, u32), String> {
    let num_part = &input[..input.len() - 1];
    if num_part.is_empty() {
        return Err(format!(
            "missing numeric value before '{}' suffix",
            suffix_char_for_shift(shift)
        ));
    }
    if !num_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid size suffix in '{input}'"));
    }
    Ok((num_part, shift))
}

/// Returns the human-readable suffix character for a given bit-shift amount.
///
/// Used exclusively for error messages.
fn suffix_char_for_shift(shift: u32) -> char {
    match shift {
        10 => 'K',
        20 => 'M',
        30 => 'G',
        40 => 'T',
        _ => '?',
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_byte_count ----

    #[test]
    fn parse_plain_number() {
        assert_eq!(parse_byte_count("256").unwrap(), 256);
    }

    #[test]
    fn parse_kilo_suffix() {
        assert_eq!(parse_byte_count("4K").unwrap(), 4 * 1024);
    }

    #[test]
    fn parse_mega_suffix() {
        assert_eq!(parse_byte_count("2M").unwrap(), 2 * 1024 * 1024);
    }

    #[test]
    fn parse_giga_suffix() {
        assert_eq!(parse_byte_count("1G").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_tera_suffix() {
        assert_eq!(
            parse_byte_count("1T").unwrap(),
            1024_u64 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_max_keyword() {
        assert_eq!(parse_byte_count("max").unwrap(), MAX_OUTPUT_BYTES);
        assert_eq!(parse_byte_count("MAX").unwrap(), MAX_OUTPUT_BYTES);
        assert_eq!(parse_byte_count("Max").unwrap(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn parse_zero_is_error() {
        assert!(parse_byte_count("0").is_err());
        assert!(parse_byte_count("0K").is_err());
    }

    #[test]
    fn parse_empty_is_error() {
        assert!(parse_byte_count("").is_err());
        assert!(parse_byte_count("  ").is_err());
    }

    #[test]
    fn parse_bare_suffix_is_error() {
        assert!(parse_byte_count("K").is_err());
        assert!(parse_byte_count("M").is_err());
    }

    #[test]
    fn parse_invalid_suffix_is_error() {
        assert!(parse_byte_count("10X").is_err());
        assert!(parse_byte_count("abc").is_err());
    }

    #[test]
    fn parse_overflow_is_error() {
        // 2^64 / 2^40 = 2^24 = 16_777_216 — max value before T shift.
        // Anything larger overflows u64.
        let huge = format!("{}T", u64::MAX);
        assert!(parse_byte_count(&huge).is_err());
    }

    #[test]
    fn parse_exceeds_max_output() {
        // MAX_OUTPUT_BYTES = u64::MAX >> 3 = 2^61
        // 2^61 + 1 should fail.
        let over = format!("{}", MAX_OUTPUT_BYTES + 1);
        assert!(parse_byte_count(&over).is_err());
    }

    #[test]
    fn parse_max_output_exactly() {
        let exact = format!("{}", MAX_OUTPUT_BYTES);
        assert_eq!(parse_byte_count(&exact).unwrap(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn parse_lowercase_suffix() {
        assert_eq!(parse_byte_count("4k").unwrap(), 4 * 1024);
        assert_eq!(parse_byte_count("2m").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_count("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(
            parse_byte_count("1t").unwrap(),
            1024_u64 * 1024 * 1024 * 1024
        );
    }

    // ---- compute_chunk_len ----

    #[test]
    fn chunk_len_small_remaining() {
        assert_eq!(compute_chunk_len(100), 100);
    }

    #[test]
    fn chunk_len_exact_chunk_size() {
        assert_eq!(
            compute_chunk_len(u64::try_from(CHUNK_SIZE).unwrap()),
            CHUNK_SIZE
        );
    }

    #[test]
    fn chunk_len_large_remaining() {
        assert_eq!(compute_chunk_len(u64::MAX), CHUNK_SIZE);
    }

    // ---- write_base64_lines ----

    #[test]
    fn base64_line_wrapping_short() {
        let mut out = Vec::new();
        write_base64_lines(&mut out, "AAAA").unwrap();
        assert_eq!(out, b"AAAA\n");
    }

    #[test]
    fn base64_line_wrapping_long() {
        let long_str = "A".repeat(BASE64_LINE_WIDTH + 10);
        let mut out = Vec::new();
        write_base64_lines(&mut out, &long_str).unwrap();

        let output = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), BASE64_LINE_WIDTH);
        assert_eq!(lines[1].len(), 10);
    }

    #[test]
    fn base64_line_wrapping_exact_boundary() {
        let exact = "B".repeat(BASE64_LINE_WIDTH);
        let mut out = Vec::new();
        write_base64_lines(&mut out, &exact).unwrap();

        let output = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), BASE64_LINE_WIDTH);
    }

    // ---- write_encoded_chunk ----

    #[test]
    fn write_chunk_binary() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = Vec::new();
        write_encoded_chunk(&mut out, &data, OutputFormat::Binary).unwrap();
        assert_eq!(out, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_chunk_hex() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = Vec::new();
        write_encoded_chunk(&mut out, &data, OutputFormat::Hex).unwrap();
        assert_eq!(out, b"deadbeef");
    }

    #[test]
    fn write_chunk_base64() {
        let data = [0x00, 0x01, 0x02];
        let mut out = Vec::new();
        write_encoded_chunk(&mut out, &data, OutputFormat::Base64).unwrap();
        // base64ct encodes [0,1,2] as "AAEC"
        let output = String::from_utf8(out).unwrap();
        assert!(output.ends_with('\n'));
        assert_eq!(output.trim(), "AAEC");
    }

    // ---- suffix_char_for_shift ----

    #[test]
    fn suffix_chars() {
        assert_eq!(suffix_char_for_shift(10), 'K');
        assert_eq!(suffix_char_for_shift(20), 'M');
        assert_eq!(suffix_char_for_shift(30), 'G');
        assert_eq!(suffix_char_for_shift(40), 'T');
        assert_eq!(suffix_char_for_shift(0), '?');
    }
}
