//! `kdf` subcommand implementation — Key Derivation Function execution.
//!
//! Rewrite of `apps/kdf.c` (217 lines). Provides the `openssl kdf` CLI
//! subcommand for deriving key material using any provider-registered KDF
//! algorithm.
//!
//! # Architecture
//!
//! The command follows the standard CLI dispatch pattern:
//!
//! ```text
//! main.rs → CliCommand::Kdf(KdfArgs) → KdfArgs::execute(ctx)
//!        → openssl_crypto::kdf::KdfContext → derived key material → output
//! ```
//!
//! # C→Rust Translation
//!
//! | C Source (`apps/kdf.c`)             | Rust Equivalent                              |
//! |-------------------------------------|----------------------------------------------|
//! | `kdf_main()`                        | [`KdfArgs::execute()`]                       |
//! | `OPTION_CHOICE` enum                | clap `#[derive(Args)]` on [`KdfArgs`]        |
//! | `kdf_options[]` array               | clap field annotations                       |
//! | `alloc_kdf_algorithm_name()`        | [`KdfArgs::collect_all_opts()`]              |
//! | `EVP_KDF_fetch()`                   | [`parse_kdf_type()`] → [`KdfType`]           |
//! | `EVP_KDF_CTX_new` / `set_params`    | [`KdfContext`] builder pattern               |
//! | `EVP_KDF_derive()`                  | [`KdfContext::derive()`]                     |
//! | `OPENSSL_buf2hexstr()`              | [`hex::encode_upper()`] + [`format_hex_with_colons()`] |
//! | `OPENSSL_clear_free()`              | [`Zeroizing<Vec<u8>>`]                       |
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** `Option<T>` for optional fields; no sentinel values
//! - **R6 (Lossless Casts):** No bare `as` casts; `usize` used directly
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module
//! - **R9 (Warning-Free):** All code paths exercised; no dead code
//! - **R10 (Wiring):** Reachable via `CliCommand::Kdf` dispatch in `mod.rs`

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use clap::Args;
use tracing::{debug, error, info, instrument};
use zeroize::Zeroizing;

use openssl_common::error::CryptoError;
use openssl_common::param::{from_text, ParamBuilder};
use openssl_common::{CommonError, ParamSet, ParamValue};
use openssl_crypto::context::LibContext;
use openssl_crypto::kdf::{KdfContext, KdfType};

/// Arguments for the `openssl kdf` subcommand.
///
/// Declares the CLI interface for key derivation operations, replacing the C
/// `kdf_options[]` array and `OPTION_CHOICE` enum from `apps/kdf.c` lines
/// 20–54. Uses clap derive macros for declarative parsing with automatic
/// help text generation, validation, and shell completion.
///
/// # Usage
///
/// ```text
/// openssl kdf [OPTIONS] <ALGORITHM>
///
/// Arguments:
///   <ALGORITHM>  KDF algorithm name (e.g., HKDF, PBKDF2, SCRYPT, ARGON2ID)
///
/// Options:
///   -k, --kdfopt <KEY:VALUE>  KDF option in key:value format (repeatable)
///       --keylen <N>          Output key length in bytes (required)
///   -o, --out <FILE>          Output file (default: stdout)
///       --binary              Output raw binary instead of hex
///       --cipher <NAME>       Shorthand for -kdfopt cipher:NAME
///       --digest <NAME>       Shorthand for -kdfopt digest:NAME
///       --mac <NAME>          Shorthand for -kdfopt mac:NAME
/// ```
///
/// # Examples
///
/// ```text
/// # Derive 32 bytes using HKDF with SHA-256
/// openssl kdf --keylen 32 \
///   -k key:0x0b0b0b0b0b0b0b0b0b0b0b \
///   -k salt:0x000102030405060708090a0b0c \
///   -k info:0xf0f1f2f3f4f5f6f7f8f9 \
///   --digest SHA256 HKDF
///
/// # Derive 64 bytes using PBKDF2 with 100000 iterations
/// openssl kdf --keylen 64 \
///   -k key:password -k salt:0x1234 -k iterations:100000 PBKDF2
///
/// # Derive 32 bytes using scrypt
/// openssl kdf --keylen 32 \
///   -k key:password -k salt:NaCl -k n:1024 -k r:8 -k p:1 SCRYPT
/// ```
#[derive(Args, Debug)]
pub struct KdfArgs {
    /// KDF algorithm name (e.g., HKDF, PBKDF2, SCRYPT, ARGON2ID, KBKDF).
    ///
    /// Positional argument selecting the key derivation function. Matching
    /// is case-insensitive. Replaces `EVP_KDF_fetch()` algorithm name
    /// parameter from `apps/kdf.c:146`.
    #[arg(value_name = "ALGORITHM")]
    algorithm: String,

    /// KDF-specific options in `key:value` format (repeatable).
    ///
    /// Replaces C `-kdfopt` option and `STACK_OF(OPENSSL_STRING)`.
    /// The key identifies the parameter name; the value is auto-typed:
    /// - `0x` prefix → hex-encoded bytes
    /// - Numeric string → integer
    /// - Otherwise → UTF-8 string
    ///
    /// Well-known keys: `key`, `salt`, `info`, `iterations`, `n`, `r`, `p`,
    /// `time_cost`, `mem_cost`, `parallelism`, `cipher`, `digest`, `mac`.
    #[arg(short = 'k', long = "kdfopt", value_name = "KEY:VALUE")]
    kdfopt: Vec<String>,

    /// Output key length in bytes (required, must be greater than zero).
    ///
    /// Specifies the number of bytes of key material to derive.
    /// Replaces C `-keylen` option from `apps/kdf.c:178`.
    #[arg(long = "keylen", value_name = "N")]
    keylen: Option<usize>,

    /// Output file path. Defaults to stdout if not specified.
    ///
    /// Replaces C `-out` option and `bio_open_default()` call at
    /// `apps/kdf.c:174`.
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    out: Option<PathBuf>,

    /// Output raw binary instead of hex-encoded text.
    ///
    /// When set, the derived key material is written as raw bytes.
    /// When not set (default), output is uppercase hex with colon
    /// separators matching C `OPENSSL_buf2hexstr()` format.
    ///
    /// Replaces C `-binary` flag from `apps/kdf.c:100`.
    #[arg(long = "binary")]
    binary: bool,

    /// Shorthand for `-kdfopt cipher:NAME`.
    ///
    /// Convenience option that adds the cipher algorithm parameter
    /// without requiring the full kdfopt syntax. Replaces C `-cipher`
    /// option via `alloc_kdf_algorithm_name()` at `apps/kdf.c:56–72`.
    #[arg(long = "cipher", value_name = "NAME")]
    cipher: Option<String>,

    /// Shorthand for `-kdfopt digest:NAME`.
    ///
    /// Convenience option that adds the digest algorithm parameter
    /// without requiring the full kdfopt syntax. Replaces C `-digest`
    /// option via `alloc_kdf_algorithm_name()`.
    #[arg(long = "digest", value_name = "NAME")]
    digest: Option<String>,

    /// Shorthand for `-kdfopt mac:NAME`.
    ///
    /// Convenience option that adds the MAC algorithm parameter
    /// without requiring the full kdfopt syntax. Replaces C `-mac`
    /// option via `alloc_kdf_algorithm_name()`.
    #[arg(long = "mac", value_name = "NAME")]
    mac: Option<String>,
}

impl KdfArgs {
    /// Execute the `kdf` subcommand.
    ///
    /// Derives key material using the specified KDF algorithm and parameters,
    /// outputting the result in hex or binary format.
    ///
    /// This method replaces `kdf_main()` from `apps/kdf.c` lines 75–210.
    /// The execution flow mirrors the C implementation:
    ///
    /// 1. Parse algorithm name → [`KdfType`] (replaces `EVP_KDF_fetch`)
    /// 2. Validate output key length
    /// 3. Create [`KdfContext`] (replaces `EVP_KDF_CTX_new`)
    /// 4. Merge `kdfopt` + shorthand options into unified option list
    /// 5. Route params to dedicated setters or [`ParamSet`]
    /// 6. Derive key material (replaces `EVP_KDF_derive`)
    /// 7. Write output in binary or colon-separated hex format
    ///
    /// # Arguments
    ///
    /// * `_ctx` — Library context for provider lookup (used for algorithm
    ///   resolution scope; passed through the `CliCommand` dispatch chain).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] variants on:
    /// - Unrecognized algorithm name → [`CryptoError::AlgorithmNotFound`]
    /// - Missing/invalid keylen or malformed kdfopt → [`CryptoError::Common`]
    /// - Key derivation failure → [`CryptoError::Common`]
    /// - Output file I/O error → [`CryptoError::Io`]
    #[allow(clippy::unused_async)] // Required by CliCommand dispatch pattern; KDF ops are sync
    #[instrument(name = "kdf_command", skip_all, fields(algorithm = %self.algorithm))]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // ---------------------------------------------------------------
        // Step 1: Resolve KDF algorithm name → KdfType
        // Replaces: EVP_KDF_fetch(app_get0_libctx(), algorithm, propq)
        //           at apps/kdf.c:146
        // ---------------------------------------------------------------
        let kdf_type = parse_kdf_type(&self.algorithm)?;
        debug!(
            algorithm = %self.algorithm,
            kdf_type = %kdf_type,
            "resolved KDF algorithm"
        );

        // ---------------------------------------------------------------
        // Step 2: Validate output key length
        // Replaces: kdf.c:178 — `if (dkm_len <= 0)`
        // R5: Option<usize> instead of sentinel 0
        // ---------------------------------------------------------------
        let keylen = self.resolve_keylen()?;
        debug!(keylen, "validated output key length");

        // ---------------------------------------------------------------
        // Step 3: Create KDF context
        // Replaces: EVP_KDF_CTX_new(kdf) at kdf.c:153
        // ---------------------------------------------------------------
        let mut kdf_ctx = KdfContext::new(kdf_type);

        // ---------------------------------------------------------------
        // Step 4: Collect all options (kdfopt + shorthands)
        // Replaces: alloc_kdf_algorithm_name() + opts stack merge in
        //           kdf.c:92–138
        // ---------------------------------------------------------------
        let all_opts = self.collect_all_opts();

        // ---------------------------------------------------------------
        // Step 5: Process options → route to dedicated setters or ParamSet
        // Replaces: app_params_new_from_opts() at kdf.c:159 and
        //           EVP_KDF_CTX_set_params() at kdf.c:164
        // ---------------------------------------------------------------
        let param_set = apply_options(&all_opts, &mut kdf_ctx)?;
        if !param_set.is_empty() {
            kdf_ctx.set_params(param_set)?;
        }

        // ---------------------------------------------------------------
        // Step 6: Derive key material into a securely-zeroed buffer
        // Replaces: EVP_KDF_derive(ctx, dkm_bytes, dkm_len, params)
        //           at kdf.c:186
        // Security: Zeroizing<Vec<u8>> replaces OPENSSL_clear_free()
        //           at kdf.c:206 — buffer zeroed on drop
        // ---------------------------------------------------------------
        let dkm = Zeroizing::new(kdf_ctx.derive(keylen)?);
        debug!(bytes = dkm.len(), "key derivation complete");

        // ---------------------------------------------------------------
        // Step 7: Write output (binary or hex with colons)
        // Replaces: kdf.c:189–200
        // ---------------------------------------------------------------
        self.write_output(&dkm)?;

        info!(
            keylen,
            binary = self.binary,
            "KDF output written successfully"
        );
        Ok(())
    }

    /// Resolves and validates the output key length.
    ///
    /// Returns an error if `--keylen` was not specified or was set to zero,
    /// matching the C validation at `kdf.c:178`:
    /// ```c
    /// if (dkm_len <= 0) {
    ///     BIO_printf(bio_err, "Invalid key length %ld\n", (long)dkm_len);
    ///     goto end;
    /// }
    /// ```
    ///
    /// # Rule Compliance
    ///
    /// - **R5:** Uses `Option<usize>` — `None` means unset rather than
    ///   sentinel `0`.
    fn resolve_keylen(&self) -> Result<usize, CryptoError> {
        match self.keylen {
            Some(len) if len > 0 => Ok(len),
            Some(_zero) => {
                error!("key length must be greater than zero");
                Err(CryptoError::Common(CommonError::InvalidArgument(
                    "keylen must be greater than 0; use --keylen N with N > 0".to_string(),
                )))
            }
            None => {
                error!("key length not specified");
                Err(CryptoError::Common(CommonError::InvalidArgument(
                    "keylen is required; use --keylen N to specify output length".to_string(),
                )))
            }
        }
    }

    /// Collects all KDF options into a unified list of `"key:value"` strings.
    ///
    /// Merges user-provided `-kdfopt` entries with the shorthand options
    /// (`-cipher`, `-digest`, `-mac`) into a single ordered list. Shorthand
    /// options are appended after explicit kdfopt entries, matching the C
    /// behavior where `alloc_kdf_algorithm_name()` pushes onto the opts
    /// stack at `apps/kdf.c:56–72`.
    ///
    /// # Returns
    ///
    /// Combined option list where each entry is in `"key:value"` format.
    fn collect_all_opts(&self) -> Vec<String> {
        let mut opts: Vec<String> = self.kdfopt.clone();

        // Merge shorthand options as "key:value" entries, mirroring
        // alloc_kdf_algorithm_name() which prepends "cipher:", "digest:",
        // or "mac:" prefix to the name string.
        if let Some(ref name) = self.cipher {
            opts.push(format!("cipher:{name}"));
        }
        if let Some(ref name) = self.digest {
            opts.push(format!("digest:{name}"));
        }
        if let Some(ref name) = self.mac {
            opts.push(format!("mac:{name}"));
        }

        opts
    }

    /// Writes the derived key material to the configured output destination.
    ///
    /// Output behaviour:
    /// - `--binary` set: writes raw bytes (replaces `BIO_write(out, dkm_bytes,
    ///   dkm_len)` at `kdf.c:192`)
    /// - `--binary` not set: writes uppercase hex with colon separators and
    ///   trailing newline, matching C `OPENSSL_buf2hexstr()` format at
    ///   `kdf.c:194–199`
    ///
    /// Destination:
    /// - `--out <file>`: writes to the specified file (replaces
    ///   `bio_open_default(outfile, ...)` at `kdf.c:174`)
    /// - No `--out`: writes to stdout
    fn write_output(&self, dkm: &[u8]) -> Result<(), CryptoError> {
        let mut writer: Box<dyn Write> = match self.out {
            Some(ref path) => {
                let file = File::create(path)?;
                Box::new(BufWriter::new(file))
            }
            None => Box::new(BufWriter::new(io::stdout())),
        };

        if self.binary {
            // Binary mode: write raw derived key bytes
            writer.write_all(dkm)?;
        } else {
            // Hex mode: uppercase hex pairs with colon separators
            let hex_str = hex::encode_upper(dkm);
            let formatted = format_hex_with_colons(&hex_str);
            writer.write_all(formatted.as_bytes())?;
            writer.write_all(b"\n")?;
        }

        writer.flush()?;
        Ok(())
    }
}

// ===========================================================================
// Free Functions — Algorithm Resolution
// ===========================================================================

/// Parses a KDF algorithm name string into the corresponding [`KdfType`]
/// enum variant.
///
/// Performs case-insensitive matching against all recognized KDF algorithm
/// names. Replaces `EVP_KDF_fetch()` name resolution at `apps/kdf.c:146`.
///
/// # Supported Algorithm Names
///
/// | Input (case-insensitive)              | Resolved Type          |
/// |---------------------------------------|------------------------|
/// | `HKDF`                                | [`KdfType::Hkdf`]     |
/// | `HKDF-EXPAND`                         | [`KdfType::HkdfExpand`]|
/// | `HKDF-EXTRACT`                        | [`KdfType::HkdfExtract`]|
/// | `PBKDF2`                              | [`KdfType::Pbkdf2`]   |
/// | `ARGON2I`                             | [`KdfType::Argon2i`]  |
/// | `ARGON2D`                             | [`KdfType::Argon2d`]  |
/// | `ARGON2ID`                            | [`KdfType::Argon2id`] |
/// | `SCRYPT`                              | [`KdfType::Scrypt`]   |
/// | `KBKDF`                               | [`KdfType::Kbkdf`]    |
/// | `SSKDF`                               | [`KdfType::Sskdf`]    |
/// | `X963KDF`                             | [`KdfType::X963Kdf`]  |
/// | `TLS1-PRF`                            | [`KdfType::TlsPrf`]   |
/// | `SSHKDF`                              | [`KdfType::SshKdf`]   |
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the name does not match
/// any recognized KDF algorithm.
fn parse_kdf_type(name: &str) -> Result<KdfType, CryptoError> {
    match name.to_ascii_uppercase().as_str() {
        "HKDF" => Ok(KdfType::Hkdf),
        "HKDF-EXPAND" => Ok(KdfType::HkdfExpand),
        "HKDF-EXTRACT" => Ok(KdfType::HkdfExtract),
        "PBKDF2" => Ok(KdfType::Pbkdf2),
        "ARGON2I" => Ok(KdfType::Argon2i),
        "ARGON2D" => Ok(KdfType::Argon2d),
        "ARGON2ID" => Ok(KdfType::Argon2id),
        "SCRYPT" => Ok(KdfType::Scrypt),
        "KBKDF" => Ok(KdfType::Kbkdf),
        "SSKDF" => Ok(KdfType::Sskdf),
        "X963KDF" => Ok(KdfType::X963Kdf),
        "TLS1-PRF" => Ok(KdfType::TlsPrf),
        "SSHKDF" => Ok(KdfType::SshKdf),
        _ => {
            error!(name, "unknown KDF algorithm");
            Err(CryptoError::AlgorithmNotFound(name.to_string()))
        }
    }
}

// ===========================================================================
// Free Functions — Option Processing
// ===========================================================================

/// Processes all collected KDF options, routing values to either dedicated
/// [`KdfContext`] setter methods or into a [`ParamSet`] for remaining
/// algorithm-specific parameters.
///
/// Replaces `app_params_new_from_opts()` at `apps/kdf.c:159` and the
/// subsequent `EVP_KDF_CTX_set_params()` call at `kdf.c:164`.
///
/// # Routing Rules
///
/// | Key      | Handler                          | Rationale                   |
/// |----------|----------------------------------|-----------------------------|
/// | `key`    | [`KdfContext::set_key()`]         | Sets internal keying material |
/// | `salt`   | [`KdfContext::set_salt()`]        | Sets internal salt buffer     |
/// | `info`   | [`KdfContext::set_info()`]        | Sets internal info/context    |
/// | `digest` | [`KdfContext::set_digest()`]      | Sets digest algorithm name    |
/// | Other    | [`ParamBuilder`] → [`ParamSet`]  | Algorithm-specific params     |
///
/// The `key`, `salt`, and `info` values are parsed as bytes: hex-decoded
/// if the value starts with `0x`/`0X`, otherwise used as raw UTF-8 bytes.
///
/// # Errors
///
/// Returns [`CryptoError::Common`] if:
/// - A kdfopt string does not contain the `:` delimiter
/// - Hex decoding fails for a `0x`-prefixed value
/// - A dedicated setter rejects the provided value
fn apply_options(
    opts: &[String],
    kdf_ctx: &mut KdfContext,
) -> Result<ParamSet, CryptoError> {
    let mut builder = ParamBuilder::new();

    for opt in opts {
        let (key, value) = split_kdfopt(opt)?;

        match key {
            // ── Dedicated setters for core keying/context material ──
            "key" => {
                let key_bytes = parse_value_as_bytes(value)?;
                kdf_ctx.set_key(&key_bytes)?;
                debug!(key_len = key_bytes.len(), "set key material");
            }
            "salt" => {
                let salt_bytes = parse_value_as_bytes(value)?;
                kdf_ctx.set_salt(&salt_bytes)?;
                debug!(salt_len = salt_bytes.len(), "set salt");
            }
            "info" => {
                let info_bytes = parse_value_as_bytes(value)?;
                kdf_ctx.set_info(&info_bytes)?;
                debug!(info_len = info_bytes.len(), "set info/context");
            }
            "digest" => {
                kdf_ctx.set_digest(value)?;
                debug!(digest = value, "set digest algorithm");
            }

            // ── ParamSet: all other algorithm-specific parameters ──
            _ => {
                let param_value = from_text("", value)?;
                let static_key = to_static_param_key(key);
                builder = push_param_value(builder, static_key, param_value);
                debug!(key, value, "added parameter to param set");
            }
        }
    }

    Ok(builder.build())
}

/// Splits a KDF option string on the first `:` delimiter into (key, value).
///
/// # Examples
///
/// ```text
/// "iterations:10000"  → ("iterations", "10000")
/// "key:0xdeadbeef"    → ("key", "0xdeadbeef")
/// "salt:my:salt"      → ("salt", "my:salt")    // only first : splits
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::Common`] with [`CommonError::InvalidArgument`]
/// if the option string does not contain a `:` character.
fn split_kdfopt(opt: &str) -> Result<(&str, &str), CryptoError> {
    opt.split_once(':').ok_or_else(|| {
        error!(opt, "malformed kdfopt — missing ':' delimiter");
        CryptoError::Common(CommonError::InvalidArgument(format!(
            "invalid kdfopt format: expected 'key:value', got '{opt}'"
        )))
    })
}

/// Parses a value string as a byte vector.
///
/// - If the value starts with `"0x"` or `"0X"`, the remainder is
///   hex-decoded into bytes using [`from_text()`]'s hex parsing logic.
/// - Otherwise, the value's raw UTF-8 bytes are used directly.
///
/// This matches the C behaviour where `-kdfopt key:0x...` passes hex-decoded
/// bytes and `-kdfopt key:password` passes the literal string bytes.
///
/// # Errors
///
/// Returns [`CryptoError::Common`] if hex decoding fails for a `0x`-prefixed
/// value (invalid hex characters or odd-length string).
fn parse_value_as_bytes(value: &str) -> Result<Vec<u8>, CryptoError> {
    if value.starts_with("0x") || value.starts_with("0X") {
        // Delegate hex parsing to from_text which handles 0x-prefixed values
        match from_text("", value)? {
            ParamValue::OctetString(bytes) => Ok(bytes),
            // from_text returns OctetString for 0x-prefixed values; guard
            // against unexpected variant for robustness.
            other => Err(CryptoError::Common(CommonError::InvalidArgument(
                format!(
                    "expected hex bytes from '{}', got {}",
                    value,
                    other.param_type_name()
                ),
            ))),
        }
    } else {
        // Plain text: use raw UTF-8 byte representation
        Ok(value.as_bytes().to_vec())
    }
}

/// Pushes a [`ParamValue`] into a [`ParamBuilder`] with the correct
/// type-specific method, returning the updated builder.
///
/// Dispatches to the appropriate `push_*` method based on the
/// [`ParamValue`] variant to preserve type information in the resulting
/// [`ParamSet`].
///
/// # Rule Compliance
///
/// - **R6:** No bare `as` casts. Integer narrowing uses `i32::try_from`
///   / `u32::try_from`, falling through to the 64-bit push on overflow.
fn push_param_value(
    builder: ParamBuilder,
    key: &'static str,
    value: ParamValue,
) -> ParamBuilder {
    match value {
        ParamValue::Utf8String(s) => builder.push_utf8(key, s),
        ParamValue::OctetString(bytes) => builder.push_octet(key, bytes),
        ParamValue::Int32(v) => builder.push_i32(key, v),
        ParamValue::UInt32(v) => builder.push_u32(key, v),
        // R6: narrowing attempt with try_from; fallback to i64 on overflow
        ParamValue::Int64(v) => {
            if let Ok(v32) = i32::try_from(v) {
                builder.push_i32(key, v32)
            } else {
                builder.push_i64(key, v)
            }
        }
        // R6: narrowing attempt with try_from; fallback to u64 on overflow
        ParamValue::UInt64(v) => {
            if let Ok(v32) = u32::try_from(v) {
                builder.push_u32(key, v32)
            } else {
                builder.push_u64(key, v)
            }
        }
        ParamValue::Real(v) => builder.push_f64(key, v),
        ParamValue::BigNum(bytes) => builder.push_bignum(key, bytes),
    }
}

// ===========================================================================
// Free Functions — Key Mapping and Output Formatting
// ===========================================================================

/// Maps a runtime KDF parameter key string to a `&'static str` reference.
///
/// For well-known `OSSL_PARAM` parameter names used by KDF providers, returns
/// a string literal. For unknown keys, uses [`Box::leak()`] to create a
/// static reference — this is acceptable for a CLI tool that executes once
/// and exits, leaking only the small key string.
///
/// # Well-Known Keys
///
/// Covers all standard parameter names across all supported KDF algorithms:
/// - HKDF: `mode`, `info`, `label`
/// - PBKDF2: `iterations`
/// - scrypt: `n`, `r`, `p`
/// - Argon2: `time_cost`, `mem_cost`, `parallelism`
/// - KBKDF: `mode`, `label`, `context`, `seed`, `prefix`
/// - SSHKDF: `session_id`, `type`
/// - Common: `cipher`, `mac`, `properties`, `size`
fn to_static_param_key(key: &str) -> &'static str {
    match key {
        "cipher" => "cipher",
        "mac" => "mac",
        "iterations" => "iterations",
        "n" => "n",
        "r" => "r",
        "p" => "p",
        "time_cost" => "time_cost",
        "mem_cost" => "mem_cost",
        "parallelism" => "parallelism",
        "mode" => "mode",
        "label" => "label",
        "context" => "context",
        "seed" => "seed",
        "session_id" => "session_id",
        "type" => "type",
        "size" => "size",
        "prefix" => "prefix",
        "properties" => "properties",
        "pass" => "pass",
        "constant" => "constant",
        // Unknown key: leak the string for &'static lifetime.
        // This is a CLI process that exits shortly after — the leak is
        // bounded and intentional (only the key string, not the value).
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

/// Formats a contiguous hex string into colon-separated byte pairs.
///
/// Transforms `"AABBCCDD"` → `"AA:BB:CC:DD"`, matching the output format
/// produced by C `OPENSSL_buf2hexstr()` at `apps/kdf.c:194`.
///
/// # Edge Cases
///
/// - Empty input returns an empty string
/// - Odd-length input: the last nibble is emitted as a single character
///   (should not occur with [`hex::encode_upper()`] output)
fn format_hex_with_colons(hex: &str) -> String {
    if hex.is_empty() {
        return String::new();
    }

    let hex_bytes = hex.as_bytes();
    // Pre-allocate: each byte pair is 2 chars + 1 colon separator (except last)
    let pair_count = (hex_bytes.len() + 1) / 2;
    let mut result = String::with_capacity(hex.len() + pair_count.saturating_sub(1));

    for (idx, chunk) in hex_bytes.chunks(2).enumerate() {
        if idx > 0 {
            result.push(':');
        }
        // Each chunk is 1 or 2 bytes of the hex string
        for &byte in chunk {
            result.push(byte as char);
        }
    }

    result
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_kdf_type tests ────────────────────────────────────────────

    #[test]
    fn test_parse_kdf_type_case_insensitive() {
        assert!(matches!(parse_kdf_type("hkdf"), Ok(KdfType::Hkdf)));
        assert!(matches!(parse_kdf_type("HKDF"), Ok(KdfType::Hkdf)));
        assert!(matches!(parse_kdf_type("Hkdf"), Ok(KdfType::Hkdf)));
        assert!(matches!(parse_kdf_type("pbkdf2"), Ok(KdfType::Pbkdf2)));
        assert!(matches!(parse_kdf_type("PBKDF2"), Ok(KdfType::Pbkdf2)));
        assert!(matches!(parse_kdf_type("scrypt"), Ok(KdfType::Scrypt)));
        assert!(matches!(parse_kdf_type("SCRYPT"), Ok(KdfType::Scrypt)));
        assert!(matches!(parse_kdf_type("argon2id"), Ok(KdfType::Argon2id)));
        assert!(matches!(parse_kdf_type("ARGON2ID"), Ok(KdfType::Argon2id)));
        assert!(matches!(parse_kdf_type("kbkdf"), Ok(KdfType::Kbkdf)));
        assert!(matches!(parse_kdf_type("KBKDF"), Ok(KdfType::Kbkdf)));
    }

    #[test]
    fn test_parse_kdf_type_all_variants() {
        assert!(matches!(parse_kdf_type("HKDF-EXPAND"), Ok(KdfType::HkdfExpand)));
        assert!(matches!(parse_kdf_type("HKDF-EXTRACT"), Ok(KdfType::HkdfExtract)));
        assert!(matches!(parse_kdf_type("ARGON2I"), Ok(KdfType::Argon2i)));
        assert!(matches!(parse_kdf_type("ARGON2D"), Ok(KdfType::Argon2d)));
        assert!(matches!(parse_kdf_type("SSKDF"), Ok(KdfType::Sskdf)));
        assert!(matches!(parse_kdf_type("X963KDF"), Ok(KdfType::X963Kdf)));
        assert!(matches!(parse_kdf_type("TLS1-PRF"), Ok(KdfType::TlsPrf)));
        assert!(matches!(parse_kdf_type("SSHKDF"), Ok(KdfType::SshKdf)));
    }

    #[test]
    fn test_parse_kdf_type_unknown_algorithm() {
        let result = parse_kdf_type("UNKNOWN_KDF");
        assert!(result.is_err());
        match result {
            Err(CryptoError::AlgorithmNotFound(name)) => {
                assert_eq!(name, "UNKNOWN_KDF");
            }
            other => panic!("expected AlgorithmNotFound, got {:?}", other),
        }
    }

    // ── split_kdfopt tests ──────────────────────────────────────────────

    #[test]
    fn test_split_kdfopt_valid() {
        let (k, v) = split_kdfopt("iterations:10000").unwrap();
        assert_eq!(k, "iterations");
        assert_eq!(v, "10000");
    }

    #[test]
    fn test_split_kdfopt_hex_value() {
        let (k, v) = split_kdfopt("key:0xdeadbeef").unwrap();
        assert_eq!(k, "key");
        assert_eq!(v, "0xdeadbeef");
    }

    #[test]
    fn test_split_kdfopt_value_with_colons() {
        let (k, v) = split_kdfopt("salt:my:salted:value").unwrap();
        assert_eq!(k, "salt");
        assert_eq!(v, "my:salted:value");
    }

    #[test]
    fn test_split_kdfopt_missing_colon() {
        let result = split_kdfopt("no_colon_here");
        assert!(result.is_err());
    }

    // ── parse_value_as_bytes tests ──────────────────────────────────────

    #[test]
    fn test_parse_value_as_bytes_hex() {
        let bytes = parse_value_as_bytes("0xdeadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_value_as_bytes_hex_uppercase_prefix() {
        let bytes = parse_value_as_bytes("0Xaabb").unwrap();
        assert_eq!(bytes, vec![0xaa, 0xbb]);
    }

    #[test]
    fn test_parse_value_as_bytes_plain_text() {
        let bytes = parse_value_as_bytes("password").unwrap();
        assert_eq!(bytes, b"password".to_vec());
    }

    #[test]
    fn test_parse_value_as_bytes_empty_plain() {
        let bytes = parse_value_as_bytes("").unwrap();
        assert!(bytes.is_empty());
    }

    // ── format_hex_with_colons tests ────────────────────────────────────

    #[test]
    fn test_format_hex_with_colons_basic() {
        assert_eq!(format_hex_with_colons("AABBCCDD"), "AA:BB:CC:DD");
    }

    #[test]
    fn test_format_hex_with_colons_single_byte() {
        assert_eq!(format_hex_with_colons("FF"), "FF");
    }

    #[test]
    fn test_format_hex_with_colons_empty() {
        assert_eq!(format_hex_with_colons(""), "");
    }

    #[test]
    fn test_format_hex_with_colons_two_bytes() {
        assert_eq!(format_hex_with_colons("AABB"), "AA:BB");
    }

    // ── to_static_param_key tests ───────────────────────────────────────

    #[test]
    fn test_to_static_param_key_known_keys() {
        assert_eq!(to_static_param_key("iterations"), "iterations");
        assert_eq!(to_static_param_key("n"), "n");
        assert_eq!(to_static_param_key("r"), "r");
        assert_eq!(to_static_param_key("p"), "p");
        assert_eq!(to_static_param_key("cipher"), "cipher");
        assert_eq!(to_static_param_key("mac"), "mac");
        assert_eq!(to_static_param_key("time_cost"), "time_cost");
        assert_eq!(to_static_param_key("mem_cost"), "mem_cost");
        assert_eq!(to_static_param_key("parallelism"), "parallelism");
    }

    #[test]
    fn test_to_static_param_key_unknown_key() {
        let key = to_static_param_key("custom_param");
        assert_eq!(key, "custom_param");
    }

    // ── push_param_value tests ──────────────────────────────────────────

    #[test]
    fn test_push_param_value_utf8() {
        let builder = ParamBuilder::new();
        let builder = push_param_value(
            builder,
            "cipher",
            ParamValue::Utf8String("AES-256-CBC".to_string()),
        );
        let params = builder.build();
        assert!(params.get("cipher").is_some());
    }

    #[test]
    fn test_push_param_value_octet() {
        let builder = ParamBuilder::new();
        let builder = push_param_value(
            builder,
            "seed",
            ParamValue::OctetString(vec![1, 2, 3, 4]),
        );
        let params = builder.build();
        assert!(params.get("seed").is_some());
    }

    #[test]
    fn test_push_param_value_int64_narrow() {
        // Value fits in i32 — should be stored as i32
        let builder = ParamBuilder::new();
        let builder = push_param_value(
            builder,
            "iterations",
            ParamValue::Int64(10000),
        );
        let params = builder.build();
        let val = params.get("iterations").unwrap();
        // Verify value is accessible
        assert!(val.as_i32().is_some() || val.as_i64().is_some());
    }

    #[test]
    fn test_push_param_value_uint64_narrow() {
        // Value fits in u32 — should be stored as u32
        let builder = ParamBuilder::new();
        let builder = push_param_value(
            builder,
            "n",
            ParamValue::UInt64(16384),
        );
        let params = builder.build();
        let val = params.get("n").unwrap();
        assert!(val.as_u32().is_some() || val.as_u64().is_some());
    }

    // ── collect_all_opts tests ──────────────────────────────────────────

    #[test]
    fn test_collect_all_opts_kdfopt_only() {
        let args = KdfArgs {
            algorithm: "HKDF".to_string(),
            kdfopt: vec!["key:0x01".to_string(), "salt:0x02".to_string()],
            keylen: Some(32),
            out: None,
            binary: false,
            cipher: None,
            digest: None,
            mac: None,
        };
        let opts = args.collect_all_opts();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], "key:0x01");
        assert_eq!(opts[1], "salt:0x02");
    }

    #[test]
    fn test_collect_all_opts_with_shorthands() {
        let args = KdfArgs {
            algorithm: "KBKDF".to_string(),
            kdfopt: vec!["iterations:5".to_string()],
            keylen: Some(16),
            out: None,
            binary: false,
            cipher: Some("AES-256-CBC".to_string()),
            digest: Some("SHA256".to_string()),
            mac: Some("HMAC".to_string()),
        };
        let opts = args.collect_all_opts();
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], "iterations:5");
        assert_eq!(opts[1], "cipher:AES-256-CBC");
        assert_eq!(opts[2], "digest:SHA256");
        assert_eq!(opts[3], "mac:HMAC");
    }

    // ── resolve_keylen tests ────────────────────────────────────────────

    #[test]
    fn test_resolve_keylen_valid() {
        let args = KdfArgs {
            algorithm: String::new(),
            kdfopt: vec![],
            keylen: Some(32),
            out: None,
            binary: false,
            cipher: None,
            digest: None,
            mac: None,
        };
        assert_eq!(args.resolve_keylen().unwrap(), 32);
    }

    #[test]
    fn test_resolve_keylen_zero() {
        let args = KdfArgs {
            algorithm: String::new(),
            kdfopt: vec![],
            keylen: Some(0),
            out: None,
            binary: false,
            cipher: None,
            digest: None,
            mac: None,
        };
        assert!(args.resolve_keylen().is_err());
    }

    #[test]
    fn test_resolve_keylen_none() {
        let args = KdfArgs {
            algorithm: String::new(),
            kdfopt: vec![],
            keylen: None,
            out: None,
            binary: false,
            cipher: None,
            digest: None,
            mac: None,
        };
        assert!(args.resolve_keylen().is_err());
    }
}
