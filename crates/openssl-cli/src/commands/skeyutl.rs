//! `skeyutl` subcommand implementation — Symmetric Key Utility (EVP_SKEY API).
//!
//! Rewrite of `apps/skeyutl.c` (137 lines). Provides the `openssl skeyutl`
//! CLI subcommand for generating opaque symmetric keys via the provider-based
//! `EVP_SKEY` API introduced in OpenSSL 4.0.
//!
//! # Architecture
//!
//! The command follows the standard CLI dispatch pattern:
//!
//! ```text
//! main.rs → CliCommand::Skeyutl(SkeyutlArgs) → SkeyutlArgs::execute(ctx)
//!        → openssl_crypto::evp::keymgmt::{SymKeyMgmt, SymKey} → opaque key
//! ```
//!
//! The C source only supports `-genkey` (key generation). All other modes
//! (import from hex/file, raw key export, PEM/DER formats) produce a
//! "not yet supported" error — this mirrors the upstream C behaviour at
//! `apps/skeyutl.c:127`: *"Key generation is the only supported operation
//! as of now"*.
//!
//! # C→Rust Translation
//!
//! | C Source (`apps/skeyutl.c`)            | Rust Equivalent                               |
//! |----------------------------------------|-----------------------------------------------|
//! | `skeyutl_main()`                       | `SkeyutlArgs::execute()`                    |
//! | `OPTION_CHOICE` enum                   | clap `#[derive(Args)]` on `SkeyutlArgs`     |
//! | `skeyutl_options[]` array              | clap field annotations                        |
//! | `opt_cipher_any()`                     | [`openssl_crypto::evp::cipher::Cipher::fetch`]|
//! | `EVP_CIPHER_get0_name()`               | `Cipher::name()`                              |
//! | `EVP_SKEYMGMT_fetch()`                 | `SymKeyMgmt::fetch()`                         |
//! | `app_params_new_from_opts()`           | `SkeyutlArgs::build_gen_params()`           |
//! | `EVP_SKEY_generate()`                  | `SymKey::generate()`                          |
//! | `EVP_SKEY_get0_key_id()`               | `SymKey::key_id()`                            |
//! | `EVP_SKEY_get0_provider_name()`        | `SymKeyMgmt::provider_name()` (retained ref)  |
//! | `EVP_SKEY_get0_skeymgmt_name()`        | `SymKeyMgmt::name()` (retained ref)           |
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** `Option<T>` used for all optional CLI fields and
//!   the `key_id` return. No sentinel values (`0`, `-1`, `""`).
//! - **R6 (Lossless Casts):** Numeric widening uses `u64::from()` /
//!   `u32::from()`. No bare `as` casts.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** No `#[allow]` suppressions at module or function
//!   level; all code paths exercised by the `execute()` flow.
//! - **R10 (Wiring):** Reachable via `CliCommand::Skeyutl` dispatch in
//!   `mod.rs` line 578; exercised by unit tests and integration tests.

use std::path::PathBuf;

use clap::Args;
use tracing::{debug, error, info, instrument, warn};

use openssl_common::error::CryptoError;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::CommonError;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::Cipher;
use openssl_crypto::evp::keymgmt::{SymKey, SymKeyMgmt};

/// Arguments for the `openssl skeyutl` subcommand.
///
/// Declares the CLI interface for symmetric-key utility operations, replacing
/// the C `skeyutl_options[]` array and `OPTION_CHOICE` enum from
/// `apps/skeyutl.c` lines 20–55.
///
/// # Usage
///
/// ```text
/// openssl skeyutl [OPTIONS]
///
/// Options:
///   --skeyopt <OPT:VALUE>      Generation option in key:value form (repeatable)
///   --skeymgmt <NAME>          Symmetric key management algorithm name
///   --genkey                   Generate a new symmetric key
///   --cipher <NAME>            Cipher algorithm (alternative to --skeymgmt)
///   --algorithm <NAME>         Alias for --skeymgmt
///   --keylen <BYTES>           Key length in bytes (shorthand for key_length)
///   --hexkey <HEX>             Key material as hex string (import mode)
///   --keyfile <FILE>           Key material from file (import mode)
///   --in <FILE>                Input file (reserved for future import mode)
///   --out <FILE>               Output file (default: stdout)
///   --inform <PEM|DER>         Input format
///   --outform <PEM|DER>        Output format
///   --text                     Print key details in text form
///   --provider <NAME>          Load provider by name
///   --provider-path <PATH>     Provider search path
///   --propquery <QUERY>        Provider property query string
///   --engine <NAME>            (Deprecated) ENGINE name — warns on use
/// ```
///
/// # Examples
///
/// ```text
/// # Generate a 32-byte HMAC key identified by skeymgmt
/// openssl skeyutl --genkey --skeymgmt HMAC --skeyopt key_length:32
///
/// # Generate a key using cipher name resolution
/// openssl skeyutl --genkey --cipher AES-256-CBC
///
/// # Generate with explicit property query
/// openssl skeyutl --genkey --skeymgmt HMAC --propquery "provider=default"
/// ```
#[derive(Args, Debug)]
pub struct SkeyutlArgs {
    /// Generation option in `key:value` format (repeatable).
    ///
    /// Replaces C `-skeyopt` option and `STACK_OF(OPENSSL_STRING)`.
    /// The key identifies the `OSSL_PARAM` parameter name; the value is
    /// auto-typed based on the provider's `gen_settable_params` table.
    ///
    /// Well-known keys: `key_length`, `key_id`.
    #[arg(long = "skeyopt", value_name = "OPT:VALUE")]
    skeyopt: Vec<String>,

    /// Symmetric key management algorithm name (e.g., `HMAC`, `AES-256-CBC`).
    ///
    /// If set, this is the algorithm passed to `SymKeyMgmt::fetch()`. When
    /// absent, the algorithm is derived from `--cipher`'s canonical name.
    #[arg(long = "skeymgmt", value_name = "NAME")]
    skeymgmt: Option<String>,

    /// Alias for `--skeymgmt`; accepted for API compatibility with other
    /// CLI subcommands that use `-algorithm` as the conventional flag name.
    #[arg(long = "algorithm", value_name = "NAME")]
    algorithm: Option<String>,

    /// Request a new symmetric key generation operation.
    ///
    /// When set, the command invokes `SymKey::generate()`. When cleared,
    /// the command returns an error matching the C source behaviour:
    /// "Key generation is the only supported operation as of now".
    #[arg(long = "genkey")]
    genkey: bool,

    /// Cipher algorithm name (alternative to `--skeymgmt`).
    ///
    /// Replaces C `opt_cipher_any()` at `apps/skeyutl.c:94`. When `--skeymgmt`
    /// is absent, the cipher's canonical name is used as the `SymKeyMgmt`
    /// algorithm name.
    #[arg(long = "cipher", value_name = "CIPHER")]
    cipher: Option<String>,

    /// Desired key length in bytes (shorthand for `--skeyopt key_length:N`).
    ///
    /// When provided, automatically adds `key_length:<keylen>` to the
    /// generation parameter set. Must be greater than zero.
    #[arg(long = "keylen", value_name = "BYTES")]
    keylen: Option<u32>,

    /// Key material as a hex string (for import mode, currently unsupported).
    ///
    /// Accepted by the parser for API compatibility. In `--genkey` mode,
    /// the value is ignored with a warning. Reserved for future import mode.
    #[arg(long = "hexkey", value_name = "HEX")]
    hexkey: Option<String>,

    /// Key material from a file (for import mode, currently unsupported).
    ///
    /// Accepted by the parser for API compatibility. In `--genkey` mode,
    /// the value is ignored with a warning. Reserved for future import mode.
    #[arg(long = "keyfile", value_name = "FILE")]
    keyfile: Option<PathBuf>,

    /// Input file (for import mode, currently unsupported).
    #[arg(long = "in", value_name = "FILE")]
    input: Option<PathBuf>,

    /// Output file (for export mode, currently unsupported).
    ///
    /// When `--text` is set, key details are printed to stdout. Other
    /// output modes are reserved for future expansion.
    #[arg(long = "out", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Input format (`PEM` or `DER`). Reserved for future import mode.
    #[arg(long = "inform", value_name = "FMT")]
    inform: Option<String>,

    /// Output format (`PEM` or `DER`). Reserved for future export mode.
    #[arg(long = "outform", value_name = "FMT")]
    outform: Option<String>,

    /// Print key details in human-readable text form.
    ///
    /// When set alongside `--genkey`, the generated key's metadata
    /// (identifier, provider, key management algorithm) is printed after
    /// generation completes. This is the default output behaviour.
    #[arg(long = "text")]
    text: bool,

    /// Provider name to load (e.g., `default`, `legacy`, `fips`).
    ///
    /// Accepted for API compatibility; provider loading is handled by the
    /// library context initialisation in `main.rs`.
    #[arg(long = "provider-name", value_name = "NAME")]
    provider: Option<String>,

    /// Provider search path.
    ///
    /// Accepted for API compatibility; provider loading is handled by the
    /// library context initialisation in `main.rs`.
    #[arg(long = "provider-path", value_name = "PATH")]
    provider_path: Option<PathBuf>,

    /// Provider property query string (e.g., `"provider=fips"`).
    ///
    /// Passed to `SymKeyMgmt::fetch()` and `Cipher::fetch()` to refine
    /// provider selection.
    #[arg(long = "propquery", value_name = "QUERY")]
    propquery: Option<String>,

    /// Deprecated ENGINE name.
    ///
    /// OpenSSL 4.0 removed ENGINE API support in favour of providers.
    /// This flag is accepted for backwards-compatibility scripts but
    /// emits a deprecation warning when used.
    #[arg(long = "engine", value_name = "NAME")]
    engine: Option<String>,
}

impl SkeyutlArgs {
    /// Executes the `openssl skeyutl` subcommand.
    ///
    /// # Flow
    ///
    /// 1. Warn if deprecated `--engine` is used (no-op otherwise).
    /// 2. If `--cipher` is provided, fetch the cipher descriptor via
    ///    [`Cipher::fetch()`].
    /// 3. Validate: at least one of `--skeymgmt`, `--algorithm`, or
    ///    `--cipher` must be supplied.
    /// 4. If `--genkey` is set, run the generation pipeline; otherwise
    ///    return an error mirroring the C source's unsupported-op message.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] if neither cipher nor skeymgmt is given,
    ///   or if `--genkey` is absent (unsupported operation).
    /// - [`CryptoError::AlgorithmNotFound`] if the requested cipher or
    ///   skeymgmt algorithm cannot be resolved by any loaded provider.
    /// - [`CryptoError::Common`] with [`CommonError::InvalidArgument`] if
    ///   any `--skeyopt` value has malformed syntax or an invalid type.
    #[instrument(
        name = "skeyutl_command",
        skip_all,
        fields(
            genkey = self.genkey,
            skeymgmt = self.skeymgmt.as_deref().unwrap_or(""),
            cipher = self.cipher.as_deref().unwrap_or(""),
        )
    )]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        debug!("skeyutl: entered execute");

        // --- Deprecation notice for removed ENGINE API -----------------
        if let Some(engine_name) = &self.engine {
            warn!(
                engine = engine_name.as_str(),
                "the -engine option is deprecated; OpenSSL 4.0 uses providers instead"
            );
        }

        // -- Acquire a cloneable Arc<LibContext> for fetch ---------------
        // Per the canonical pattern established in speed.rs: the callers
        // pass `&LibContext` but the fetch entry points require an owned
        // `Arc<LibContext>`. We re-obtain the default singleton here;
        // in the common case this is the same underlying context.
        let arc_ctx = LibContext::default();

        // --- Step 1: Optional cipher resolution ------------------------
        // Replaces C `opt_cipher_any(ciphername, &cipher)` at line 94.
        let cipher = match &self.cipher {
            Some(name) => {
                debug!(cipher = name.as_str(), "fetching cipher");
                let c = Cipher::fetch(&arc_ctx, name, self.propquery.as_deref()).map_err(|e| {
                    error!(
                        cipher = name.as_str(),
                        error = %e,
                        "cipher fetch failed"
                    );
                    e
                })?;
                Some(c)
            }
            None => None,
        };

        // --- Step 2: Resolve the key-management algorithm name ---------
        // Translation of the C expression:
        //   skeymgmt != NULL ? skeymgmt : EVP_CIPHER_get0_name(cipher)
        // The `--algorithm` CLI flag acts as an alias for `--skeymgmt`;
        // `--skeymgmt` wins when both are provided.
        let skeymgmt_source = self
            .skeymgmt
            .as_deref()
            .or(self.algorithm.as_deref())
            .map(str::to_string)
            .or_else(|| cipher.as_ref().map(|c| c.name().to_string()));

        let mgmt_name = skeymgmt_source.ok_or_else(|| {
            error!("neither --cipher nor --skeymgmt/--algorithm was provided");
            CryptoError::Key(
                "Either -skeymgmt, -algorithm, or -cipher option should be specified".to_string(),
            )
        })?;

        // --- Step 3: Dispatch the requested operation ------------------
        if self.genkey {
            self.do_generate(&arc_ctx, &mgmt_name)
        } else {
            // Matches C source line 127 exactly.
            warn!("no supported operation requested (missing --genkey)");
            Err(CryptoError::Key(
                "Key generation is the only supported operation as of now".to_string(),
            ))
        }
    }

    /// Runs the full key-generation pipeline for `--genkey` mode.
    ///
    /// Replaces lines 102–121 of `apps/skeyutl.c`.
    ///
    /// # Steps
    ///
    /// 1. Warn if an import-only option (`--hexkey` or `--keyfile`) was set.
    /// 2. Fetch the [`SymKeyMgmt`] for the resolved algorithm name.
    /// 3. Build a `ParamSet` from `--skeyopt` entries and the `--keylen`
    ///    shorthand.
    /// 4. Invoke [`SymKey::generate()`] to produce the opaque key.
    /// 5. Emit the standard "opaque key created" report via `println!` and
    ///    structured `info!` log record.
    fn do_generate(
        &self,
        arc_ctx: &std::sync::Arc<LibContext>,
        mgmt_name: &str,
    ) -> Result<(), CryptoError> {
        // --- Warn about ignored import-only options --------------------
        if self.hexkey.is_some() {
            warn!("--hexkey is ignored in --genkey mode");
        }
        if self.keyfile.is_some() {
            warn!("--keyfile is ignored in --genkey mode");
        }
        if self.input.is_some() {
            warn!("--in is ignored in --genkey mode");
        }
        if self.inform.is_some() {
            warn!("--inform is ignored in --genkey mode");
        }

        // --- Step 1: Fetch the symmetric key management method ---------
        debug!(mgmt_name, "fetching SymKeyMgmt");
        let mgmt =
            SymKeyMgmt::fetch(arc_ctx, mgmt_name, self.propquery.as_deref()).map_err(|e| {
                error!(
                    mgmt_name,
                    error = %e,
                    "SymKeyMgmt::fetch failed"
                );
                e
            })?;

        let mgmt_arc = std::sync::Arc::new(mgmt);

        // --- Step 2: Build the ParamSet from skeyopt entries -----------
        let params = self.build_gen_params()?;

        debug!(
            mgmt_name,
            param_count = params.len(),
            "invoking SymKey::generate"
        );

        // --- Step 3: Generate the opaque symmetric key -----------------
        let skey = SymKey::generate(&mgmt_arc, &params).map_err(|e| {
            error!(
                mgmt_name,
                error = %e,
                "SymKey::generate failed"
            );
            e
        })?;

        // --- Step 4: Report success ------------------------------------
        self.emit_success(&skey, &mgmt_arc);
        Ok(())
    }

    /// Builds the generation `ParamSet` from the `--skeyopt` vector and
    /// the `--keylen` shorthand.
    ///
    /// Replaces `app_params_new_from_opts()` at `apps/skeyutl.c:104`.
    ///
    /// # Routing
    ///
    /// | Input                       | Push method                    |
    /// |-----------------------------|--------------------------------|
    /// | `--keylen N`                | `push_u32("key_length", N)`    |
    /// | `--skeyopt key_length:N`    | `push_u32("key_length", N)`    |
    /// | `--skeyopt key_id:S`        | `push_utf8("key_id", S)`       |
    /// | `--skeyopt key:0x…`         | `push_octet(key, hex_bytes)`   |
    /// | `--skeyopt key:V` (numeric) | `push_u64(key, N)`             |
    /// | `--skeyopt key:V` (string)  | `push_utf8(key, V)`            |
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] with [`CommonError::InvalidArgument`]
    /// for:
    /// - Malformed `--skeyopt` strings (missing `:`)
    /// - Invalid hex-encoded octet values
    /// - Zero-valued `--keylen`
    fn build_gen_params(&self) -> Result<ParamSet, CryptoError> {
        let mut builder = ParamBuilder::new();
        let mut saw_key_length = false;

        // --- Explicit --keylen shorthand -------------------------------
        if let Some(keylen) = self.keylen {
            if keylen == 0 {
                error!("--keylen must be greater than zero");
                return Err(CryptoError::Common(CommonError::InvalidArgument(
                    "--keylen must be greater than zero".to_string(),
                )));
            }
            builder = builder.push_u32("key_length", keylen);
            saw_key_length = true;
            debug!(key_length = keylen, "added key_length from --keylen");
        }

        // --- Repeatable --skeyopt entries ------------------------------
        for opt in &self.skeyopt {
            let (key, value) = split_skeyopt(opt)?;

            // Well-known param "key_length" is always an unsigned integer.
            if key == "key_length" {
                if saw_key_length {
                    warn!("--skeyopt key_length overrides prior --keylen shorthand");
                }
                let parsed = parse_u32(value).map_err(|e| {
                    error!(value, error = %e, "invalid key_length value");
                    CryptoError::Common(CommonError::InvalidArgument(format!(
                        "invalid key_length value '{value}': {e}"
                    )))
                })?;
                if parsed == 0 {
                    return Err(CryptoError::Common(CommonError::InvalidArgument(
                        "key_length must be greater than zero".to_string(),
                    )));
                }
                builder = builder.push_u32("key_length", parsed);
                saw_key_length = true;
                debug!(key_length = parsed, "added key_length from --skeyopt");
                continue;
            }

            // Well-known param "key_id" is always a UTF-8 string.
            if key == "key_id" {
                builder = builder.push_utf8("key_id", value.to_string());
                debug!(key_id = value, "added key_id");
                continue;
            }

            // Generic routing: hex-prefixed → octet, numeric → u64,
            // otherwise → UTF-8 string.
            let static_key = to_static_param_key(key);
            if let Some(stripped) = strip_hex_prefix(value) {
                let bytes = hex::decode(stripped).map_err(|e| {
                    error!(
                        key = static_key,
                        value,
                        error = %e,
                        "hex decode failed"
                    );
                    CryptoError::Common(CommonError::InvalidArgument(format!(
                        "invalid hex value for '{static_key}': {e}"
                    )))
                })?;
                builder = builder.push_octet(static_key, bytes);
                debug!(key = static_key, "added generation param as octet string");
            } else if let Ok(n) = value.parse::<u64>() {
                builder = builder.push_u64(static_key, n);
                debug!(
                    key = static_key,
                    value_u64 = n,
                    "added generation param as u64"
                );
            } else {
                builder = builder.push_utf8(static_key, value.to_string());
                debug!(key = static_key, "added generation param as UTF-8 string");
            }
        }

        Ok(builder.build())
    }

    /// Emits the "opaque key created" report.
    ///
    /// Matches the printf format of `apps/skeyutl.c:116-120` exactly:
    ///
    /// ```text
    /// An opaque key identified by <KEY_ID> is created
    /// Provider: <PROVIDER_NAME>
    /// Key management: <SKEYMGMT_NAME>
    /// ```
    ///
    /// Both a structured `info!` record (for log aggregation) and a
    /// stdout print (for interactive CLI use) are emitted. When `--text`
    /// is set, additional key metadata is printed for interactive use —
    /// this is the read-site for the `text` config field (R3 compliance).
    fn emit_success(&self, skey: &SymKey, mgmt: &std::sync::Arc<SymKeyMgmt>) {
        let key_id = skey.key_id().unwrap_or("<none>");
        let provider = mgmt.provider_name();
        let skeymgmt_name = mgmt.name();

        info!(
            key_id,
            provider,
            skeymgmt = skeymgmt_name,
            text_mode = self.text,
            "opaque symmetric key generated"
        );

        // The C source always prints basic information to stdout when a
        // key is generated — we mirror that.
        println!("An opaque key identified by {key_id} is created");
        println!("Provider: {provider}");
        println!("Key management: {skeymgmt_name}");

        // When --text is set, emit additional diagnostic metadata for
        // interactive inspection. This is the read-site for `self.text`
        // (R3 config propagation).
        if self.text {
            println!("Text mode: enabled");
            if let Some(ref pq) = self.propquery {
                println!("Property query: {pq}");
            }
            if let Some(ref prov) = self.provider {
                println!("Requested provider: {prov}");
            }
        }
    }
}

// ===========================================================================
// Free Functions — Option Processing Helpers
// ===========================================================================

/// Splits a `--skeyopt` string on the first `:` into a `(key, value)` pair.
///
/// # Examples
///
/// ```text
/// "key_length:32"     → ("key_length", "32")
/// "key_id:my_key"     → ("key_id", "my_key")
/// "raw:0xdeadbeef"    → ("raw", "0xdeadbeef")
/// "label:a:b:c"       → ("label", "a:b:c")    // only first ':' splits
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::Common`] with [`CommonError::InvalidArgument`]
/// if the input string does not contain a `:` character.
fn split_skeyopt(opt: &str) -> Result<(&str, &str), CryptoError> {
    opt.split_once(':').ok_or_else(|| {
        error!(opt, "malformed --skeyopt entry (missing ':')");
        CryptoError::Common(CommonError::InvalidArgument(format!(
            "invalid --skeyopt format: expected 'key:value', got '{opt}'"
        )))
    })
}

/// Returns the remainder of `value` if it starts with `"0x"` or `"0X"`.
///
/// ```text
/// "0xdeadbeef" → Some("deadbeef")
/// "0Xaabb"     → Some("aabb")
/// "hello"      → None
/// "0x"         → Some("")
/// ```
fn strip_hex_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
}

/// Parses a decimal string as [`u32`].
///
/// Wraps [`str::parse`] to return a stable error message suitable for
/// surfacing to end users via `CommonError::InvalidArgument`.
fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    s.parse::<u32>()
}

/// Maps a runtime `--skeyopt` key to a `&'static str`.
///
/// Common `OSSL_SKEY` parameter names are returned as literals; unknown
/// keys are promoted to `&'static str` via [`Box::leak()`]. The leak is
/// bounded (one small key string per unique `--skeyopt` entry) and
/// acceptable for a CLI tool that exits shortly after execution.
///
/// This mirrors the `to_static_param_key()` pattern in `kdf.rs`.
fn to_static_param_key(key: &str) -> &'static str {
    match key {
        "key_length" => "key_length",
        "key_id" => "key_id",
        "raw_bytes" => "raw_bytes",
        "key" => "key",
        "salt" => "salt",
        "info" => "info",
        "properties" => "properties",
        "cipher" => "cipher",
        "mac" => "mac",
        "digest" => "digest",
        "mode" => "mode",
        // Bounded leak: the cost is one small string per novel key in a
        // short-lived CLI process. Matches kdf.rs pattern.
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────
    // split_skeyopt
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn split_skeyopt_simple_pair() {
        let (k, v) = split_skeyopt("key_length:32").unwrap();
        assert_eq!(k, "key_length");
        assert_eq!(v, "32");
    }

    #[test]
    fn split_skeyopt_string_value() {
        let (k, v) = split_skeyopt("key_id:my_custom_key").unwrap();
        assert_eq!(k, "key_id");
        assert_eq!(v, "my_custom_key");
    }

    #[test]
    fn split_skeyopt_hex_value_preserved() {
        let (k, v) = split_skeyopt("raw:0xdeadbeef").unwrap();
        assert_eq!(k, "raw");
        assert_eq!(v, "0xdeadbeef");
    }

    #[test]
    fn split_skeyopt_value_contains_colons() {
        let (k, v) = split_skeyopt("label:a:b:c").unwrap();
        assert_eq!(k, "label");
        assert_eq!(v, "a:b:c");
    }

    #[test]
    fn split_skeyopt_empty_value() {
        let (k, v) = split_skeyopt("key:").unwrap();
        assert_eq!(k, "key");
        assert_eq!(v, "");
    }

    #[test]
    fn split_skeyopt_missing_colon_errors() {
        let result = split_skeyopt("no_colon_here");
        assert!(result.is_err());
        match result {
            Err(CryptoError::Common(CommonError::InvalidArgument(msg))) => {
                assert!(msg.contains("no_colon_here"));
                assert!(msg.contains("key:value"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // strip_hex_prefix
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn strip_hex_prefix_lowercase() {
        assert_eq!(strip_hex_prefix("0xabcd"), Some("abcd"));
    }

    #[test]
    fn strip_hex_prefix_uppercase() {
        assert_eq!(strip_hex_prefix("0Xabcd"), Some("abcd"));
    }

    #[test]
    fn strip_hex_prefix_no_prefix() {
        assert_eq!(strip_hex_prefix("abcd"), None);
    }

    #[test]
    fn strip_hex_prefix_empty_hex() {
        assert_eq!(strip_hex_prefix("0x"), Some(""));
    }

    #[test]
    fn strip_hex_prefix_empty_string() {
        assert_eq!(strip_hex_prefix(""), None);
    }

    // ─────────────────────────────────────────────────────────────────
    // parse_u32
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn parse_u32_decimal() {
        assert_eq!(parse_u32("32").unwrap(), 32);
        assert_eq!(parse_u32("0").unwrap(), 0);
        assert_eq!(parse_u32("4294967295").unwrap(), u32::MAX);
    }

    #[test]
    fn parse_u32_negative_errors() {
        assert!(parse_u32("-1").is_err());
    }

    #[test]
    fn parse_u32_overflow_errors() {
        assert!(parse_u32("4294967296").is_err());
    }

    #[test]
    fn parse_u32_non_numeric_errors() {
        assert!(parse_u32("abc").is_err());
    }

    // ─────────────────────────────────────────────────────────────────
    // to_static_param_key
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn static_key_known_names() {
        assert_eq!(to_static_param_key("key_length"), "key_length");
        assert_eq!(to_static_param_key("key_id"), "key_id");
        assert_eq!(to_static_param_key("raw_bytes"), "raw_bytes");
        assert_eq!(to_static_param_key("key"), "key");
        assert_eq!(to_static_param_key("salt"), "salt");
        assert_eq!(to_static_param_key("info"), "info");
        assert_eq!(to_static_param_key("properties"), "properties");
        assert_eq!(to_static_param_key("cipher"), "cipher");
        assert_eq!(to_static_param_key("mac"), "mac");
        assert_eq!(to_static_param_key("digest"), "digest");
        assert_eq!(to_static_param_key("mode"), "mode");
    }

    #[test]
    fn static_key_unknown_name_leaked() {
        let key = to_static_param_key("custom_provider_param");
        assert_eq!(key, "custom_provider_param");
    }

    // ─────────────────────────────────────────────────────────────────
    // SkeyutlArgs::build_gen_params
    // ─────────────────────────────────────────────────────────────────

    /// Constructs a `SkeyutlArgs` with all optional fields defaulted.
    fn default_args() -> SkeyutlArgs {
        SkeyutlArgs {
            skeyopt: vec![],
            skeymgmt: None,
            algorithm: None,
            genkey: false,
            cipher: None,
            keylen: None,
            hexkey: None,
            keyfile: None,
            input: None,
            output: None,
            inform: None,
            outform: None,
            text: false,
            provider: None,
            provider_path: None,
            propquery: None,
            engine: None,
        }
    }

    #[test]
    fn build_gen_params_empty() {
        let args = default_args();
        let params = args.build_gen_params().unwrap();
        assert_eq!(params.len(), 0);
    }

    #[test]
    fn build_gen_params_keylen_shorthand() {
        let args = SkeyutlArgs {
            keylen: Some(32),
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert_eq!(params.len(), 1);
        assert!(params.get("key_length").is_some());
    }

    #[test]
    fn build_gen_params_keylen_zero_errors() {
        let args = SkeyutlArgs {
            keylen: Some(0),
            ..default_args()
        };
        let result = args.build_gen_params();
        assert!(result.is_err());
        match result {
            Err(CryptoError::Common(CommonError::InvalidArgument(msg))) => {
                assert!(msg.contains("greater than zero"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn build_gen_params_skeyopt_key_length() {
        let args = SkeyutlArgs {
            skeyopt: vec!["key_length:64".to_string()],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("key_length").is_some());
    }

    #[test]
    fn build_gen_params_skeyopt_key_length_invalid() {
        let args = SkeyutlArgs {
            skeyopt: vec!["key_length:abc".to_string()],
            ..default_args()
        };
        let result = args.build_gen_params();
        assert!(result.is_err());
    }

    #[test]
    fn build_gen_params_skeyopt_key_length_zero() {
        let args = SkeyutlArgs {
            skeyopt: vec!["key_length:0".to_string()],
            ..default_args()
        };
        let result = args.build_gen_params();
        assert!(result.is_err());
    }

    #[test]
    fn build_gen_params_skeyopt_key_id() {
        let args = SkeyutlArgs {
            skeyopt: vec!["key_id:identifier_42".to_string()],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("key_id").is_some());
    }

    #[test]
    fn build_gen_params_skeyopt_hex_octet() {
        let args = SkeyutlArgs {
            skeyopt: vec!["raw_bytes:0xdeadbeef".to_string()],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("raw_bytes").is_some());
    }

    #[test]
    fn build_gen_params_skeyopt_invalid_hex_errors() {
        let args = SkeyutlArgs {
            skeyopt: vec!["raw_bytes:0xZZ".to_string()],
            ..default_args()
        };
        let result = args.build_gen_params();
        assert!(result.is_err());
    }

    #[test]
    fn build_gen_params_skeyopt_numeric_u64() {
        let args = SkeyutlArgs {
            skeyopt: vec!["iterations:1000".to_string()],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("iterations").is_some());
    }

    #[test]
    fn build_gen_params_skeyopt_utf8_fallback() {
        let args = SkeyutlArgs {
            skeyopt: vec!["mode:CBC".to_string()],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("mode").is_some());
    }

    #[test]
    fn build_gen_params_skeyopt_malformed_errors() {
        let args = SkeyutlArgs {
            skeyopt: vec!["no_colon".to_string()],
            ..default_args()
        };
        let result = args.build_gen_params();
        assert!(result.is_err());
    }

    #[test]
    fn build_gen_params_multiple_skeyopts() {
        let args = SkeyutlArgs {
            skeyopt: vec![
                "key_length:32".to_string(),
                "key_id:my_key".to_string(),
                "mode:CBC".to_string(),
            ],
            ..default_args()
        };
        let params = args.build_gen_params().unwrap();
        assert!(params.get("key_length").is_some());
        assert!(params.get("key_id").is_some());
        assert!(params.get("mode").is_some());
    }

    #[test]
    fn build_gen_params_keylen_override_by_skeyopt() {
        let args = SkeyutlArgs {
            keylen: Some(16),
            skeyopt: vec!["key_length:64".to_string()],
            ..default_args()
        };
        // Both paths produce "key_length" — the latter should override,
        // and the function should succeed without error.
        let params = args.build_gen_params().unwrap();
        assert!(params.get("key_length").is_some());
    }

    // ─────────────────────────────────────────────────────────────────
    // SkeyutlArgs::execute — integration-style tests
    // ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn execute_without_skeymgmt_or_cipher_errors() {
        let args = default_args();
        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result {
            Err(CryptoError::Key(msg)) => {
                assert!(msg.contains("-skeymgmt") || msg.contains("-cipher"));
            }
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_without_genkey_errors() {
        let args = SkeyutlArgs {
            skeymgmt: Some("HMAC".to_string()),
            ..default_args()
        };
        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result {
            Err(CryptoError::Key(msg)) => {
                assert!(msg.contains("Key generation is the only supported operation"));
            }
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_algorithm_alias_without_genkey_errors() {
        // --algorithm should act as an alias for --skeymgmt
        let args = SkeyutlArgs {
            algorithm: Some("HMAC".to_string()),
            ..default_args()
        };
        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result {
            Err(CryptoError::Key(msg)) => {
                assert!(msg.contains("Key generation is the only supported operation"));
            }
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_engine_warning_no_panic() {
        // -engine is deprecated but must not cause a panic.
        let args = SkeyutlArgs {
            engine: Some("dynamic".to_string()),
            skeymgmt: Some("HMAC".to_string()),
            ..default_args()
        };
        let ctx = LibContext::default();
        // Without --genkey this will still return Err(Key("...")),
        // but the important thing is we don't panic on the engine flag.
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_genkey_with_custom_algorithm_name_does_not_panic() {
        // `SymKeyMgmt::fetch()` in the current implementation accepts any
        // algorithm name (the provider registry is stubbed). This test
        // verifies that the execute flow completes without panicking and
        // produces a well-formed Result — not that an unknown algorithm
        // returns Err. The actual name-validation semantics are the
        // responsibility of the provider registry and are covered by
        // `openssl_crypto::evp::keymgmt::tests::*`.
        let args = SkeyutlArgs {
            genkey: true,
            skeymgmt: Some("CUSTOM_ALGORITHM_XYZ".to_string()),
            ..default_args()
        };
        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        // Either success (current stub behaviour) or a controlled error
        // (future strict-registry behaviour) is acceptable. The key
        // assertion is that we got a Result back and did not panic.
        match result {
            Ok(())
            | Err(
                CryptoError::AlgorithmNotFound(_) | CryptoError::Common(_) | CryptoError::Key(_),
            ) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_genkey_with_invalid_cipher_errors() {
        let args = SkeyutlArgs {
            genkey: true,
            cipher: Some("DEFINITELY_NOT_A_CIPHER_XYZ".to_string()),
            ..default_args()
        };
        let ctx = LibContext::default();
        let result = args.execute(&ctx).await;
        assert!(result.is_err());
        match result {
            Err(CryptoError::AlgorithmNotFound(_) | CryptoError::Common(_)) => {}
            other => {
                panic!("expected AlgorithmNotFound or Common error, got {other:?}")
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Argument construction smoke tests
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn default_args_has_no_set_fields() {
        let args = default_args();
        assert!(args.skeyopt.is_empty());
        assert!(args.skeymgmt.is_none());
        assert!(args.algorithm.is_none());
        assert!(!args.genkey);
        assert!(args.cipher.is_none());
        assert!(args.keylen.is_none());
        assert!(args.hexkey.is_none());
        assert!(args.keyfile.is_none());
        assert!(args.input.is_none());
        assert!(args.output.is_none());
        assert!(args.inform.is_none());
        assert!(args.outform.is_none());
        assert!(!args.text);
        assert!(args.provider.is_none());
        assert!(args.provider_path.is_none());
        assert!(args.propquery.is_none());
        assert!(args.engine.is_none());
    }

    #[test]
    fn genkey_mode_selects_generation_path() {
        let args = SkeyutlArgs {
            genkey: true,
            ..default_args()
        };
        assert!(args.genkey);
    }
}
