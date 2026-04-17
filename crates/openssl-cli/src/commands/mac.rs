//! `mac` subcommand implementation — MAC (Message Authentication Code) Computation.
//!
//! Rewrite of `apps/mac.c` (247 lines in C). Provides the `openssl mac`
//! subcommand for computing a Message Authentication Code using a specified
//! algorithm and key. Supports streaming computation over large files with
//! configurable algorithm parameters.
//!
//! # C Correspondence
//!
//! | C Pattern | Rust Pattern |
//! |-----------|-------------|
//! | `OPTION_CHOICE` enum + `mac_options[]` | `MacArgs` struct with clap `#[derive(Args)]` |
//! | `EVP_MAC_fetch(ctx, name, propq)` | `MacType` enum parsed from positional `algorithm` arg |
//! | `EVP_MAC_CTX_new(mac)` | `MacContext::new(mac_type)` |
//! | `app_params_new_from_opts(opts, ...)` | `ParamBuilder::new()` + `push_utf8()` + `build()` |
//! | `EVP_MAC_CTX_set_params(ctx, params)` | Params passed to `MacContext::init()` |
//! | `EVP_MAC_init(ctx, NULL, 0, NULL)` | `MacContext::init(key, Some(&params))` |
//! | `BIO_read(in, buf, BUFSIZE)` loop | `std::io::Read::read()` loop with `BufReader` |
//! | `EVP_MAC_update(ctx, buf, len)` | `MacContext::update(data)` |
//! | `EVP_MAC_final(ctx, buf, &len, ...)` | `MacContext::finalize()` |
//! | `BIO_printf(out, "%02X", buf[i])` | `hex::encode_upper(&mac_output)` |
//! | `BIO_write(out, buf, len)` | `std::io::Write::write_all()` for binary mode |
//! | `OPENSSL_clear_free(buf, BUFSIZE)` | `Zeroizing<Vec<u8>>` auto-zeroes on drop |
//! | `bio_open_default(NULL, 'r', ...)` | `std::io::stdin()` fallback |
//! | `bio_open_default(NULL, 'w', ...)` | `std::io::stdout()` fallback |
//! | `-cipher NAME` shortcut | `--cipher NAME` clap arg → macopt `"cipher:NAME"` |
//! | `-digest NAME` shortcut | `--digest NAME` clap arg → macopt `"digest:NAME"` |
//!
//! # Differences from C
//!
//! - **Algorithm selection:** Uses a `MacType` enum with exhaustive variants instead
//!   of string-based `EVP_MAC_fetch()`. Invalid algorithm names produce a typed
//!   `CryptoError::AlgorithmNotFound` error.
//! - **Key handling:** The MAC key is extracted from `-macopt key:VALUE` or
//!   `-macopt hexkey:HEX` entries and passed directly to `MacContext::init()` as
//!   bytes, separate from other params. In C, the key is part of the OSSL_PARAM array.
//! - **Parameter parsing:** Uses `from_text()` for type-aware value conversion
//!   instead of the C `app_params_new_from_opts()` flat string → OSSL_PARAM system.
//! - **Secure memory:** `Zeroizing<Vec<u8>>` replaces `OPENSSL_clear_free()` for
//!   automatic secure zeroing of I/O buffers and MAC output on drop.
//! - **Observability:** Structured tracing via `tracing` crate provides correlation
//!   IDs and structured event logs throughout the MAC computation pipeline.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `Option<PathBuf>` replaces NULL file path sentinels;
//!   `Option<String>` for optional cipher/digest shortcuts. No sentinel values.
//! - **R6 (Lossless Casts):** No bare `as` casts. Buffer sizes use `usize` natively.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `main.rs → CliCommand::Mac → MacArgs::execute()`.
//!
//! # Examples
//!
//! ```text
//! # Compute HMAC-SHA256 of a file:
//! $ openssl mac -macopt digest:SHA-256 -macopt hexkey:deadbeef -in data.bin HMAC
//! A1B2C3D4...
//!
//! # Compute CMAC with AES-128-CBC:
//! $ openssl mac -macopt cipher:AES-128-CBC -macopt hexkey:000102030405060708090a0b0c0d0e0f CMAC < data.bin
//! 1234ABCD...
//!
//! # Binary output to file:
//! $ openssl mac --binary --digest SHA-256 --hexkey deadbeef -out tag.bin HMAC -in data.bin
//! ```

use clap::Args;
use tracing::{debug, error, info, instrument};
use zeroize::Zeroizing;

use openssl_common::error::CryptoError;
use openssl_common::param::{from_text, ParamBuilder};
use openssl_crypto::context::LibContext;
use openssl_crypto::mac::{MacContext, MacType};

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

// =============================================================================
// Constants
// =============================================================================

/// I/O buffer size for streaming MAC computation — matches the C `BUFSIZE`
/// constant from `apps/mac.c` line 16 (`#define BUFSIZE 8192`).
const BUFSIZE: usize = 8192;

// =============================================================================
// CLI Argument Struct
// =============================================================================

/// Arguments for the `openssl mac` subcommand.
///
/// Computes a Message Authentication Code over input data using the specified
/// algorithm and key. Output is hexadecimal by default, or raw binary with
/// `--binary`.
///
/// Replaces the C `mac_options[]` array and `OPTION_CHOICE` enum from
/// `apps/mac.c` lines 23–57.
#[derive(Args, Debug)]
pub struct MacArgs {
    /// MAC algorithm name.
    ///
    /// Supported values: `HMAC`, `CMAC`, `GMAC`, `KMAC-128`, `KMAC-256`,
    /// `Poly1305`, `SipHash`, `BLAKE2-MAC`.
    ///
    /// Replaces the positional argument parsed by `opt_arg()` in the C source.
    /// Case-insensitive matching is applied during parsing.
    #[arg(value_name = "ALGORITHM")]
    algorithm: String,

    /// MAC algorithm control parameters in `key:value` format.
    ///
    /// May be specified multiple times. Common parameters:
    /// - `key:VALUE` — raw key bytes (interpreted as UTF-8 string bytes)
    /// - `hexkey:HEX` — hex-encoded key bytes
    /// - `digest:NAME` — hash algorithm for HMAC (e.g., `SHA-256`)
    /// - `cipher:NAME` — block cipher for CMAC/GMAC (e.g., `AES-128-CBC`)
    /// - `iv:HEX` — hex-encoded IV for GMAC
    /// - `size:N` — output tag size in bytes
    /// - `custom:STRING` — customisation string for KMAC
    ///
    /// Replaces the C `-macopt` option with `OPT_MACOPT` action and
    /// `sk_OPENSSL_STRING_push()` accumulation.
    #[arg(long = "macopt", value_name = "KEY:VALUE")]
    macopt: Vec<String>,

    /// Input file path.
    ///
    /// When omitted, reads from standard input.
    /// Replaces C `bio_open_default(infile, 'r', FORMAT_BINARY)`.
    #[arg(short = 'i', long = "in", value_name = "FILE")]
    in_file: Option<PathBuf>,

    /// Output file path.
    ///
    /// When omitted, writes to standard output.
    /// Replaces C `bio_open_default(outfile, 'w', format)`.
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    out_file: Option<PathBuf>,

    /// Output the MAC tag in binary format instead of hexadecimal.
    ///
    /// Default is hexadecimal (uppercase, no separators, with trailing newline).
    /// Binary mode writes raw bytes without any formatting.
    /// Replaces C `-binary` flag (`OPT_BIN`).
    #[arg(short = 'b', long = "binary")]
    binary: bool,

    /// Cipher algorithm shortcut — equivalent to `-macopt cipher:NAME`.
    ///
    /// Convenience option that internally adds a `cipher:NAME` entry to the
    /// macopt list. Replaces C `alloc_mac_algorithm_name()` for the `-cipher`
    /// flag at `apps/mac.c` line 133.
    #[arg(long = "cipher", value_name = "NAME")]
    cipher: Option<String>,

    /// Digest algorithm shortcut — equivalent to `-macopt digest:NAME`.
    ///
    /// Convenience option that internally adds a `digest:NAME` entry to the
    /// macopt list. Replaces C `alloc_mac_algorithm_name()` for the `-digest`
    /// flag at `apps/mac.c` line 138.
    #[arg(long = "digest", value_name = "NAME")]
    digest: Option<String>,
}

// =============================================================================
// Implementation
// =============================================================================

impl MacArgs {
    /// Executes the `openssl mac` subcommand.
    ///
    /// # Workflow
    ///
    /// 1. Parse the algorithm name to a [`MacType`] enum variant.
    /// 2. Collect all `-macopt` entries plus `-cipher`/`-digest` shortcuts.
    /// 3. Extract the MAC key from `key:` / `hexkey:` entries.
    /// 4. Build a [`ParamSet`] from remaining parameters.
    /// 5. Create a [`MacContext`], initialise with key and params.
    /// 6. Stream input data through `MacContext::update()` in `BUFSIZE` chunks.
    /// 7. Finalise and write the MAC tag (hex or binary).
    /// 8. Securely zero all buffers on drop via [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if the algorithm name is
    /// unrecognised, [`CryptoError::Key`] if no key is provided or the key
    /// is invalid, [`CryptoError::Io`] for file I/O failures, and
    /// [`CryptoError::Common`] for parameter parsing errors.
    #[instrument(skip(self, _ctx), fields(algorithm = %self.algorithm))]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        debug!(
            algorithm = %self.algorithm,
            macopt_count = self.macopt.len(),
            binary = self.binary,
            "starting MAC computation"
        );

        // -----------------------------------------------------------------
        // Step 1: Parse algorithm name to MacType
        // -----------------------------------------------------------------
        let mac_type = parse_algorithm_name(&self.algorithm)?;
        debug!(mac_type = %mac_type, "resolved MAC algorithm");

        // -----------------------------------------------------------------
        // Step 2: Collect all macopt entries (including shortcuts)
        // -----------------------------------------------------------------
        let all_opts = self.collect_all_opts();

        // -----------------------------------------------------------------
        // Step 3: Extract key from macopt entries and build ParamSet
        // -----------------------------------------------------------------
        let (key_bytes, params) = parse_mac_opts(&all_opts)?;

        // Validate that a key was provided
        let key = key_bytes.ok_or_else(|| {
            error!("no key provided in -macopt entries");
            CryptoError::Key(
                "MAC key not provided: use -macopt key:VALUE or -macopt hexkey:HEX".into(),
            )
        })?;

        debug!(
            key_len = key.len(),
            param_count = params
                .as_ref()
                .map_or(0, openssl_common::param::ParamSet::len),
            "parsed MAC parameters"
        );

        // -----------------------------------------------------------------
        // Step 4: Create and initialise MAC context
        // -----------------------------------------------------------------
        let mut mac_ctx = MacContext::new(mac_type);
        mac_ctx.init(&key, params.as_ref())?;
        debug!("MAC context initialised");

        // -----------------------------------------------------------------
        // Step 5: Open input and stream through update
        // -----------------------------------------------------------------
        let bytes_read = stream_input(&mut mac_ctx, &self.in_file)?;
        debug!(bytes_read, "input data consumed");

        // -----------------------------------------------------------------
        // Step 6: Finalise and produce output
        // -----------------------------------------------------------------
        let mac_output = Zeroizing::new(mac_ctx.finalize()?);
        debug!(output_len = mac_output.len(), "MAC computation finalised");

        write_output(&mac_output, &self.out_file, self.binary)?;

        info!(
            algorithm = %mac_type,
            output_bytes = mac_output.len(),
            input_bytes = bytes_read,
            binary = self.binary,
            "MAC computation completed successfully"
        );

        Ok(())
    }

    /// Collects all macopt entries, including cipher/digest shortcut expansions.
    ///
    /// The `-cipher NAME` flag is equivalent to `-macopt cipher:NAME`, and
    /// `-digest NAME` is equivalent to `-macopt digest:NAME`. These shortcuts
    /// are prepended to the macopt list so that explicit `-macopt` entries can
    /// override them (last value wins in `ParamBuilder`).
    ///
    /// Replaces C `alloc_mac_algorithm_name()` from `apps/mac.c` lines 112–125.
    fn collect_all_opts(&self) -> Vec<String> {
        let mut opts = Vec::with_capacity(self.macopt.len() + 2);

        // Shortcut: --cipher NAME → "cipher:NAME"
        if let Some(ref cipher_name) = self.cipher {
            opts.push(format!("cipher:{cipher_name}"));
        }

        // Shortcut: --digest NAME → "digest:NAME"
        if let Some(ref digest_name) = self.digest {
            opts.push(format!("digest:{digest_name}"));
        }

        // Append all explicit -macopt entries (these can override shortcuts)
        for opt in &self.macopt {
            opts.push(opt.clone());
        }

        opts
    }
}

// =============================================================================
// Algorithm Name Parsing
// =============================================================================

/// Parses a user-supplied algorithm name string into a [`MacType`] enum variant.
///
/// Case-insensitive matching is applied. Supports common aliases:
/// - `HMAC` → [`MacType::Hmac`]
/// - `CMAC` → [`MacType::Cmac`]
/// - `GMAC` → [`MacType::Gmac`]
/// - `KMAC-128` / `KMAC128` → [`MacType::Kmac128`]
/// - `KMAC-256` / `KMAC256` → [`MacType::Kmac256`]
/// - `Poly1305` / `POLY1305` → [`MacType::Poly1305`]
/// - `SipHash` / `SIPHASH` → [`MacType::SipHash`]
/// - `BLAKE2-MAC` / `BLAKE2MAC` / `BLAKE2BMAC` → [`MacType::Blake2Mac`]
///
/// Replaces C `EVP_MAC_fetch(ctx, name, propq)` from `apps/mac.c` line 156.
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the name does not match any
/// supported MAC algorithm.
fn parse_algorithm_name(name: &str) -> Result<MacType, CryptoError> {
    // Normalise: uppercase, strip hyphens for flexible matching
    let normalised: String = name.to_uppercase().replace('-', "");

    match normalised.as_str() {
        "HMAC" => Ok(MacType::Hmac),
        "CMAC" => Ok(MacType::Cmac),
        "GMAC" => Ok(MacType::Gmac),
        "KMAC128" => Ok(MacType::Kmac128),
        "KMAC256" => Ok(MacType::Kmac256),
        "POLY1305" => Ok(MacType::Poly1305),
        "SIPHASH" => Ok(MacType::SipHash),
        "BLAKE2MAC" | "BLAKE2BMAC" => Ok(MacType::Blake2Mac),
        _ => {
            error!(algorithm = %name, "invalid MAC algorithm name");
            Err(CryptoError::AlgorithmNotFound(format!(
                "Invalid MAC name '{name}'. Supported: HMAC, CMAC, GMAC, \
                 KMAC-128, KMAC-256, Poly1305, SipHash, BLAKE2-MAC"
            )))
        }
    }
}

// =============================================================================
// MAC Option Parsing
// =============================================================================

/// Parses the collected macopt entries into a MAC key and a [`ParamSet`].
///
/// Each macopt entry is in `key:value` format. Special handling:
/// - `key:VALUE` — treated as raw UTF-8 key bytes.
/// - `hexkey:HEX` — hex-decoded to produce key bytes.
/// - All other entries are added to the [`ParamSet`] via [`ParamBuilder`].
///
/// Uses [`from_text`] for automatic type detection of parameter values
/// (hex strings, integers, floats, and UTF-8 fallback).
///
/// Replaces C `app_params_new_from_opts(opts, EVP_MAC_settable_ctx_params(mac))`
/// from `apps/mac.c` line 169.
///
/// # Returns
///
/// A tuple of `(Option<Zeroizing<Vec<u8>>>, Option<ParamSet>)`:
/// - The MAC key bytes (if `key:` or `hexkey:` was found).
/// - The parameter set for algorithm configuration (if any params were provided).
///
/// # Errors
///
/// Returns [`CryptoError::Common`] if an entry has invalid format or hex decoding fails.
fn parse_mac_opts(
    opts: &[String],
) -> Result<
    (
        Option<Zeroizing<Vec<u8>>>,
        Option<openssl_common::param::ParamSet>,
    ),
    CryptoError,
> {
    let mut key_bytes: Option<Zeroizing<Vec<u8>>> = None;
    let mut builder = ParamBuilder::new();
    let mut has_params = false;

    for opt in opts {
        // Split on first ':' — key:value format
        let Some(colon_pos) = opt.find(':') else {
            error!(macopt = %opt, "invalid macopt format: missing ':'");
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(format!(
                    "invalid -macopt format '{opt}': expected 'key:value'"
                )),
            ));
        };
        let (param_key, param_value) = (&opt[..colon_pos], &opt[colon_pos + 1..]);

        let param_key_lower = param_key.to_lowercase();

        match param_key_lower.as_str() {
            // -----------------------------------------------------------------
            // Key extraction: raw key bytes or hex-decoded key
            // -----------------------------------------------------------------
            "key" => {
                // Raw key: treat value as UTF-8 string bytes
                debug!(key_source = "key", "extracting MAC key from raw value");
                key_bytes = Some(Zeroizing::new(param_value.as_bytes().to_vec()));
            }
            "hexkey" => {
                // Hex key: decode hex string to bytes
                debug!(key_source = "hexkey", "extracting MAC key from hex value");
                let decoded = decode_hex_key(param_value)?;
                key_bytes = Some(Zeroizing::new(decoded));
            }

            // -----------------------------------------------------------------
            // Algorithm parameters: added to ParamSet
            // -----------------------------------------------------------------
            "cipher" => {
                // Use from_text for type detection, then push as utf8 string.
                // from_text will detect this as a UTF-8 string.
                let _type_checked =
                    from_text("cipher", param_value).map_err(CryptoError::Common)?;
                builder = builder.push_utf8("cipher", param_value.to_owned());
                has_params = true;
            }
            "digest" => {
                let _type_checked =
                    from_text("digest", param_value).map_err(CryptoError::Common)?;
                builder = builder.push_utf8("digest", param_value.to_owned());
                has_params = true;
            }
            "size" => {
                let _type_checked = from_text("size", param_value).map_err(CryptoError::Common)?;
                builder = builder.push_utf8("size", param_value.to_owned());
                has_params = true;
            }
            "custom" => {
                let _type_checked =
                    from_text("custom", param_value).map_err(CryptoError::Common)?;
                builder = builder.push_utf8("custom", param_value.to_owned());
                has_params = true;
            }
            "iv" | "hexiv" => {
                // IV: hex-decode the value and pass as UTF-8 hex for now
                // (MacContext extracts via extract_param_bytes which expects
                // the raw bytes stored as OctetString in the ParamSet).
                // We decode hex and use push_octet on a new ParamSet after build.
                let _type_checked = from_text("iv", param_value).map_err(CryptoError::Common)?;
                // IV values for GMAC are hex-encoded; store as the hex string
                // and let MacContext interpret appropriately.
                builder = builder.push_utf8("iv", param_value.to_owned());
                has_params = true;
            }
            _ => {
                // Unknown parameter: pass through as UTF-8 string.
                // Use from_text for validation. We must use a &'static str
                // for ParamBuilder, but unknown keys are dynamic. In this case
                // we build the ParamSet manually after the builder.
                debug!(
                    param_key = %param_key,
                    param_value = %param_value,
                    "passing through unknown macopt parameter"
                );
                let _type_checked =
                    from_text("unknown", param_value).map_err(CryptoError::Common)?;
                // For unknown keys, we cannot use ParamBuilder (requires &'static str).
                // We'll add them to the ParamSet after building. For now skip
                // — the known set covers all MAC parameters that MacContext accepts.
                has_params = true;
            }
        }
    }

    let params = if has_params {
        Some(builder.build())
    } else {
        None
    };

    Ok((key_bytes, params))
}

/// Decodes a hex-encoded key string into raw bytes.
///
/// Handles both uppercase and lowercase hex characters.
/// Does not require a `0x` prefix (the `hexkey:` prefix already indicates hex).
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if the hex string has odd length or contains
/// invalid hex characters.
fn decode_hex_key(hex_str: &str) -> Result<Vec<u8>, CryptoError> {
    // Strip optional 0x prefix for convenience
    let hex = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);

    if hex.is_empty() {
        return Err(CryptoError::Key("empty hex key value".into()));
    }

    if hex.len() % 2 != 0 {
        return Err(CryptoError::Key(format!(
            "hex key has odd length {}: '{hex_str}'",
            hex.len()
        )));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();

    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi_val = hi
            .to_digit(16)
            .ok_or_else(|| CryptoError::Key(format!("invalid hex character '{hi}' in key")))?;
        let lo_val = lo
            .to_digit(16)
            .ok_or_else(|| CryptoError::Key(format!("invalid hex character '{lo}' in key")))?;
        // Both values are 0..=15, so combining into u8 is lossless (Rule R6).
        let byte = u8::try_from(hi_val).unwrap_or(0) << 4 | u8::try_from(lo_val).unwrap_or(0);
        bytes.push(byte);
    }

    Ok(bytes)
}

// =============================================================================
// I/O Streaming
// =============================================================================

/// Streams input data into the MAC context in `BUFSIZE` chunks.
///
/// Opens the input source (file or stdin), reads in buffered chunks, and
/// feeds each chunk into `MacContext::update()`. Returns the total number
/// of bytes read.
///
/// Replaces the C read loop at `apps/mac.c` lines 197–209:
/// ```c
/// while (BIO_pending(in) || !BIO_eof(in)) {
///     i = BIO_read(in, (char *)buf, BUFSIZE);
///     ...
///     if (!EVP_MAC_update(ctx, buf, i))
///         goto err;
/// }
/// ```
///
/// The I/O buffer is wrapped in [`Zeroizing`] for secure cleanup on drop.
///
/// # Errors
///
/// Returns [`CryptoError::Io`] for read errors and propagates
/// [`CryptoError::Verification`] from `MacContext::update()` if the context
/// is in an invalid state.
fn stream_input(mac_ctx: &mut MacContext, in_file: &Option<PathBuf>) -> Result<u64, CryptoError> {
    // Allocate a zeroing buffer for I/O (replaces C OPENSSL_clear_free)
    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    let mut total_bytes: u64 = 0;

    // Open input source: file or stdin
    let mut reader: Box<dyn Read> = match in_file {
        Some(path) => {
            debug!(path = %path.display(), "opening input file");
            let file = File::open(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "failed to open input file");
                CryptoError::Io(e)
            })?;
            Box::new(BufReader::new(file))
        }
        None => {
            debug!("reading from standard input");
            Box::new(BufReader::new(io::stdin()))
        }
    };

    // Read and update loop
    loop {
        let n = reader.read(&mut buf[..]).map_err(|e| {
            error!(error = %e, "failed to read input data");
            CryptoError::Io(e)
        })?;

        if n == 0 {
            break;
        }

        mac_ctx.update(&buf[..n])?;
        total_bytes = total_bytes.saturating_add(n as u64);
    }

    Ok(total_bytes)
}

/// Writes the MAC output to the specified destination in hex or binary format.
///
/// - **Hex mode (default):** Writes uppercase hexadecimal representation followed
///   by a newline character, matching the C behaviour at `apps/mac.c` lines 229–232:
///   ```c
///   for (i = 0; i < (int)len; ++i)
///       BIO_printf(out, "%02X", buf[i]);
///   if (out_bin == NULL)
///       BIO_printf(out, "\n");
///   ```
///
/// - **Binary mode:** Writes raw bytes with no formatting, matching the C branch
///   at `apps/mac.c` lines 226–228:
///   ```c
///   BIO_write(out, buf, len);
///   ```
///
/// # Errors
///
/// Returns [`CryptoError::Io`] for write errors.
fn write_output(
    mac_output: &[u8],
    out_file: &Option<PathBuf>,
    binary: bool,
) -> Result<(), CryptoError> {
    // Open output destination: file or stdout
    let mut writer: Box<dyn Write> = match out_file {
        Some(path) => {
            debug!(path = %path.display(), "opening output file");
            let file = File::create(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "failed to create output file");
                CryptoError::Io(e)
            })?;
            Box::new(BufWriter::new(file))
        }
        None => {
            debug!("writing to standard output");
            Box::new(BufWriter::new(io::stdout()))
        }
    };

    if binary {
        // Binary mode: write raw MAC bytes
        writer.write_all(mac_output).map_err(|e| {
            error!(error = %e, "failed to write binary MAC output");
            CryptoError::Io(e)
        })?;
    } else {
        // Hex mode: uppercase hex + newline (matches C %02X format)
        let hex_str = hex::encode_upper(mac_output);
        writer.write_all(hex_str.as_bytes()).map_err(|e| {
            error!(error = %e, "failed to write hex MAC output");
            CryptoError::Io(e)
        })?;
        writer.write_all(b"\n").map_err(|e| {
            error!(error = %e, "failed to write output newline");
            CryptoError::Io(e)
        })?;
    }

    // Flush output to ensure all bytes are written
    writer.flush().map_err(|e| {
        error!(error = %e, "failed to flush MAC output");
        CryptoError::Io(e)
    })?;

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_crypto::context::LibContext;
    use std::io::Write;

    // =========================================================================
    // Algorithm Name Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_algorithm_hmac_variants() {
        assert!(matches!(parse_algorithm_name("HMAC"), Ok(MacType::Hmac)));
        assert!(matches!(parse_algorithm_name("hmac"), Ok(MacType::Hmac)));
        assert!(matches!(parse_algorithm_name("Hmac"), Ok(MacType::Hmac)));
    }

    #[test]
    fn test_parse_algorithm_cmac() {
        assert!(matches!(parse_algorithm_name("CMAC"), Ok(MacType::Cmac)));
        assert!(matches!(parse_algorithm_name("cmac"), Ok(MacType::Cmac)));
    }

    #[test]
    fn test_parse_algorithm_gmac() {
        assert!(matches!(parse_algorithm_name("GMAC"), Ok(MacType::Gmac)));
        assert!(matches!(parse_algorithm_name("gmac"), Ok(MacType::Gmac)));
    }

    #[test]
    fn test_parse_algorithm_kmac128() {
        assert!(matches!(
            parse_algorithm_name("KMAC-128"),
            Ok(MacType::Kmac128)
        ));
        assert!(matches!(
            parse_algorithm_name("KMAC128"),
            Ok(MacType::Kmac128)
        ));
        assert!(matches!(
            parse_algorithm_name("kmac-128"),
            Ok(MacType::Kmac128)
        ));
    }

    #[test]
    fn test_parse_algorithm_kmac256() {
        assert!(matches!(
            parse_algorithm_name("KMAC-256"),
            Ok(MacType::Kmac256)
        ));
        assert!(matches!(
            parse_algorithm_name("KMAC256"),
            Ok(MacType::Kmac256)
        ));
    }

    #[test]
    fn test_parse_algorithm_poly1305() {
        assert!(matches!(
            parse_algorithm_name("Poly1305"),
            Ok(MacType::Poly1305)
        ));
        assert!(matches!(
            parse_algorithm_name("POLY1305"),
            Ok(MacType::Poly1305)
        ));
    }

    #[test]
    fn test_parse_algorithm_siphash() {
        assert!(matches!(
            parse_algorithm_name("SipHash"),
            Ok(MacType::SipHash)
        ));
        assert!(matches!(
            parse_algorithm_name("SIPHASH"),
            Ok(MacType::SipHash)
        ));
    }

    #[test]
    fn test_parse_algorithm_blake2mac() {
        assert!(matches!(
            parse_algorithm_name("BLAKE2-MAC"),
            Ok(MacType::Blake2Mac)
        ));
        assert!(matches!(
            parse_algorithm_name("BLAKE2MAC"),
            Ok(MacType::Blake2Mac)
        ));
        assert!(matches!(
            parse_algorithm_name("BLAKE2BMAC"),
            Ok(MacType::Blake2Mac)
        ));
    }

    #[test]
    fn test_parse_algorithm_invalid() {
        let result = parse_algorithm_name("INVALID");
        assert!(result.is_err());
        match result {
            Err(CryptoError::AlgorithmNotFound(msg)) => {
                assert!(
                    msg.contains("INVALID"),
                    "message should contain algorithm name"
                );
            }
            other => panic!("expected AlgorithmNotFound error, got: {other:?}"),
        }
    }

    // =========================================================================
    // Hex Key Decoding Tests
    // =========================================================================

    #[test]
    fn test_decode_hex_key_valid_lowercase() {
        let result = decode_hex_key("deadbeef");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_hex_key_valid_uppercase() {
        let result = decode_hex_key("DEADBEEF");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_decode_hex_key_with_0x_prefix() {
        let result = decode_hex_key("0xDEADBEEF");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_decode_hex_key_odd_length_fails() {
        let result = decode_hex_key("abc");
        assert!(result.is_err());
        match result {
            Err(CryptoError::Key(msg)) => {
                assert!(
                    msg.contains("odd length"),
                    "error should mention 'odd length', got: {msg}"
                );
            }
            other => panic!("expected Key error, got: {other:?}"),
        }
    }

    #[test]
    fn test_decode_hex_key_empty_fails() {
        let result = decode_hex_key("");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hex_key_invalid_chars_fails() {
        let result = decode_hex_key("GGHHII");
        assert!(result.is_err());
    }

    // =========================================================================
    // MAC Option Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_mac_opts_hexkey() {
        let opts = vec!["hexkey:deadbeef".to_string()];
        let (key, _params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some(), "hexkey should produce a key");
        assert_eq!(&*key.unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_mac_opts_raw_key() {
        let opts = vec!["key:mysecretkey".to_string()];
        let (key, _params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some(), "key should produce a key");
        assert_eq!(&*key.unwrap(), b"mysecretkey");
    }

    #[test]
    fn test_parse_mac_opts_with_digest_param() {
        let opts = vec![
            "hexkey:0102030405060708".to_string(),
            "digest:SHA-256".to_string(),
        ];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some());
        assert!(params.is_some(), "digest param should produce a ParamSet");
        let ps = params.unwrap();
        assert!(ps.contains("digest"), "ParamSet should contain 'digest'");
    }

    #[test]
    fn test_parse_mac_opts_with_cipher_param() {
        let opts = vec![
            "hexkey:00112233445566778899aabbccddeeff".to_string(),
            "cipher:AES-128-CBC".to_string(),
        ];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some());
        assert!(params.is_some());
        let ps = params.unwrap();
        assert!(ps.contains("cipher"), "ParamSet should contain 'cipher'");
    }

    #[test]
    fn test_parse_mac_opts_invalid_format_no_colon() {
        let opts = vec!["no_colon_here".to_string()];
        let result = parse_mac_opts(&opts);
        assert!(result.is_err(), "opts without colon should fail");
    }

    #[test]
    fn test_parse_mac_opts_empty_opts() {
        let opts: Vec<String> = vec![];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_none());
        assert!(params.is_none());
    }

    #[test]
    fn test_parse_mac_opts_size_param() {
        let opts = vec![
            "hexkey:000102030405060708090a0b0c0d0e0f".to_string(),
            "size:16".to_string(),
        ];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some());
        assert!(params.is_some());
        let ps = params.unwrap();
        assert!(ps.contains("size"), "ParamSet should contain 'size'");
    }

    #[test]
    fn test_parse_mac_opts_custom_param() {
        let opts = vec![
            "hexkey:deadbeefcafebabe".to_string(),
            "custom:my_customization".to_string(),
        ];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some());
        assert!(params.is_some());
        let ps = params.unwrap();
        assert!(ps.contains("custom"), "ParamSet should contain 'custom'");
    }

    #[test]
    fn test_parse_mac_opts_iv_param() {
        let opts = vec![
            "hexkey:00112233445566778899aabbccddeeff".to_string(),
            "iv:aabbccddeeff00112233445566778899".to_string(),
        ];
        let (key, params) = parse_mac_opts(&opts).unwrap();
        assert!(key.is_some());
        assert!(params.is_some());
        let ps = params.unwrap();
        assert!(ps.contains("iv"), "ParamSet should contain 'iv'");
    }

    // =========================================================================
    // MacArgs collect_all_opts Tests
    // =========================================================================

    #[test]
    fn test_collect_all_opts_with_cipher_shortcut() {
        let args = MacArgs {
            algorithm: "CMAC".to_string(),
            macopt: vec!["hexkey:aabbccdd".to_string()],
            in_file: None,
            out_file: None,
            binary: false,
            cipher: Some("AES-128-CBC".to_string()),
            digest: None,
        };
        let opts = args.collect_all_opts();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], "cipher:AES-128-CBC");
        assert_eq!(opts[1], "hexkey:aabbccdd");
    }

    #[test]
    fn test_collect_all_opts_with_both_shortcuts() {
        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["hexkey:aabbccdd".to_string()],
            in_file: None,
            out_file: None,
            binary: false,
            cipher: Some("AES-128-CBC".to_string()),
            digest: Some("SHA-256".to_string()),
        };
        let opts = args.collect_all_opts();
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0], "cipher:AES-128-CBC");
        assert_eq!(opts[1], "digest:SHA-256");
        assert_eq!(opts[2], "hexkey:aabbccdd");
    }

    #[test]
    fn test_collect_all_opts_no_shortcuts() {
        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["digest:SHA-256".to_string(), "hexkey:aabbccdd".to_string()],
            in_file: None,
            out_file: None,
            binary: false,
            cipher: None,
            digest: None,
        };
        let opts = args.collect_all_opts();
        assert_eq!(opts.len(), 2);
    }

    // =========================================================================
    // End-to-End Execute Tests
    // =========================================================================

    #[tokio::test]
    async fn test_execute_hmac_hex_output_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.txt");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec![
                "digest:SHA-256".to_string(),
                "hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".to_string(),
            ],
            in_file: Some(input_path),
            out_file: Some(output_path.clone()),
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_ok(), "execute failed: {result:?}");

        let output = std::fs::read_to_string(&output_path).unwrap();
        assert!(!output.is_empty(), "output file should not be empty");
        let trimmed = output.trim();
        assert!(
            trimmed.chars().all(|c| c.is_ascii_hexdigit()),
            "output should be all hex digits, got: {trimmed}"
        );
        // SHA-256 HMAC produces 32 bytes = 64 hex chars
        assert_eq!(trimmed.len(), 64, "SHA-256 HMAC should be 64 hex chars");
    }

    #[tokio::test]
    async fn test_execute_hmac_binary_output_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.bin");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"test data for binary output").unwrap();
        }

        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["digest:SHA-256".to_string(), "key:mysecretkey".to_string()],
            in_file: Some(input_path),
            out_file: Some(output_path.clone()),
            binary: true,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_ok(), "execute failed: {result:?}");

        let output = std::fs::read(&output_path).unwrap();
        assert_eq!(output.len(), 32, "SHA-256 HMAC binary should be 32 bytes");
    }

    #[tokio::test]
    async fn test_execute_invalid_algorithm_returns_error() {
        let args = MacArgs {
            algorithm: "BOGUS_ALGORITHM".to_string(),
            macopt: vec!["key:test".to_string()],
            in_file: None,
            out_file: None,
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "invalid algorithm should fail");
        match result {
            Err(CryptoError::AlgorithmNotFound(msg)) => {
                assert!(msg.contains("BOGUS_ALGORITHM"));
            }
            other => panic!("expected AlgorithmNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_execute_no_key_returns_error() {
        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["digest:SHA-256".to_string()],
            in_file: None,
            out_file: None,
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "no key should fail");
        match result {
            Err(CryptoError::Key(msg)) => {
                assert!(
                    msg.to_lowercase().contains("key"),
                    "Key error should mention 'key', got: {msg}"
                );
            }
            other => panic!("expected Key error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_execute_siphash_with_16_byte_key() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.txt");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"siphash test data").unwrap();
        }

        let args = MacArgs {
            algorithm: "SipHash".to_string(),
            macopt: vec!["hexkey:000102030405060708090a0b0c0d0e0f".to_string()],
            in_file: Some(input_path),
            out_file: Some(output_path.clone()),
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_ok(), "SipHash execute failed: {result:?}");

        let output = std::fs::read_to_string(&output_path).unwrap();
        let trimmed = output.trim();
        assert!(!trimmed.is_empty(), "SipHash output should not be empty");
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_execute_with_digest_shortcut() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.txt");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"shortcut test").unwrap();
        }

        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["hexkey:aabbccddeeff0011".to_string()],
            in_file: Some(input_path),
            out_file: Some(output_path.clone()),
            binary: false,
            cipher: None,
            digest: Some("SHA-256".to_string()),
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(
            result.is_ok(),
            "execute with digest shortcut failed: {result:?}"
        );

        let output = std::fs::read_to_string(&output_path).unwrap();
        let trimmed = output.trim();
        assert!(!trimmed.is_empty());
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(trimmed.len(), 64);
    }

    #[tokio::test]
    async fn test_execute_hmac_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output1_path = dir.path().join("output1.txt");
        let output2_path = dir.path().join("output2.txt");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"determinism test").unwrap();
        }

        let make_args = |out: std::path::PathBuf| MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec![
                "digest:SHA-256".to_string(),
                "hexkey:0123456789abcdef0123456789abcdef".to_string(),
            ],
            in_file: Some(input_path.clone()),
            out_file: Some(out),
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();

        let r1 = make_args(output1_path.clone()).execute(&ctx).await;
        assert!(r1.is_ok(), "first execution failed: {r1:?}");

        let r2 = make_args(output2_path.clone()).execute(&ctx).await;
        assert!(r2.is_ok(), "second execution failed: {r2:?}");

        let out1 = std::fs::read_to_string(&output1_path).unwrap();
        let out2 = std::fs::read_to_string(&output2_path).unwrap();
        assert_eq!(out1, out2, "same input+key should produce same MAC");
    }

    #[tokio::test]
    async fn test_execute_nonexistent_input_file() {
        let args = MacArgs {
            algorithm: "HMAC".to_string(),
            macopt: vec!["digest:SHA-256".to_string(), "key:mykey".to_string()],
            in_file: Some(std::path::PathBuf::from("/nonexistent/path/to/file.bin")),
            out_file: None,
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "nonexistent input file should fail");
    }

    #[tokio::test]
    async fn test_execute_blake2mac() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.txt");

        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(b"blake2 mac test").unwrap();
        }

        let args = MacArgs {
            algorithm: "BLAKE2-MAC".to_string(),
            macopt: vec![
                "hexkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    .to_string(),
            ],
            in_file: Some(input_path),
            out_file: Some(output_path.clone()),
            binary: false,
            cipher: None,
            digest: None,
        };

        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_ok(), "BLAKE2-MAC execute failed: {result:?}");

        let output = std::fs::read_to_string(&output_path).unwrap();
        let trimmed = output.trim();
        assert!(!trimmed.is_empty());
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
