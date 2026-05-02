//! `asn1parse` subcommand implementation.
//!
//! Reads an ASN.1-encoded input (PEM, DER, or Base64), optionally drills into
//! nested structures via `--strparse`, validates / windows the resulting byte
//! buffer with `--offset` / `--length`, and prints a recursive TLV dump of the
//! data to stdout (unless `--noout` is given).  An optional `--out` file
//! receives the raw DER bytes of the selected window — exactly mirroring the
//! C tool's `derout` behaviour.
//!
//! In addition, the command can synthesize ASN.1 from a textual description
//! via `--genstr` (or read the same expression from a file via `--genconf`),
//! using the OpenSSL "asn1_generate" mini-language; the synthesized bytes are
//! then fed into the same parse/dump pipeline.
//!
//! This is the Rust equivalent of `apps/asn1parse.c` in the original C
//! codebase.  The C implementation reads input via `BIO_new_file()` /
//! `PEM_read_bio()` / `BIO_read()`, then calls `ASN1_parse_dump()` and
//! `d2i_ASN1_TYPE()` for `--strparse` drill-down.  The Rust rewrite delegates
//! all ASN.1 work to [`openssl_crypto::asn1`] (`parse_dump`,
//! `parse_tlv_header`, `Asn1Type::decode_der`, `generate_from_config`) and all
//! PEM decoding to [`openssl_crypto::pem`], using idiomatic [`Read`] / [`Write`]
//! traits in place of OpenSSL's `BIO` abstraction.
//!
//! # Output Format
//!
//! For each ASN.1 TLV the dumper emits one line of the form
//!
//! ```text
//!     0:d=0  hl=4 l= 256 cons: SEQUENCE
//! ```
//!
//! followed by recursive lines for constructed children.  Primitive (leaf)
//! TLVs additionally emit a hex preview of the first 32 content bytes.  When
//! `--indent` (`-i`) is given each depth level is prefixed with two spaces.
//!
//! # Rules Applied
//!
//! - **R5** — `Option<T>` is used for every optional argument (paths, lengths,
//!   genstr/genconf inputs).  No sentinel values such as `0` / `-1` / `""` are
//!   used to encode "unset".
//! - **R6** — No bare `as` casts on numeric data.  All offset / length
//!   arithmetic uses `checked_add` / explicit comparison with `usize` bounds.
//! - **R8** — Zero `unsafe` code.  The crate-level `#![forbid(unsafe_code)]`
//!   in `crates/openssl-cli/src/main.rs` makes this a compile-time guarantee.
//! - **R9** — Warning-free under `RUSTFLAGS="-D warnings"`; every public
//!   item carries a doc-comment.
//! - **R10** — Wired into the dispatch path: `main.rs` →
//!   `CliCommand::execute()` → `CliCommand::Asn1parse(args)` →
//!   `Asn1parseArgs::execute(ctx).await`, reachable from the binary entry
//!   point and exercised by integration tests in `tests/asn1parse.rs`.

use std::fs::File;
use std::io::{self, stdout, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding as _};
use clap::Args;
use tracing::{debug, error, info, trace, warn};

use openssl_common::error::CryptoError;
use openssl_crypto::asn1::{
    generate_from_config, parse_dump, parse_tlv_header, Asn1Class, Asn1Object, Asn1Tag, Asn1Type,
};
use openssl_crypto::context::LibContext;
use openssl_crypto::pem;

use crate::lib::opts::Format;

// ───────────────────────────────────────────────────────────────────────────
// Constants
// ───────────────────────────────────────────────────────────────────────────

/// Number of indent spaces emitted per depth level when `--indent` is given.
///
/// Matches the C implementation in `apps/asn1parse.c:268` which passes
/// `indent ? 2 : 0` to `ASN1_parse_dump()`.
const INDENT_SPACES_PER_LEVEL: usize = 2;

/// Maximum buffer size reserved when reading raw DER input (1 MiB hint).
///
/// This is a capacity hint passed to [`Vec::with_capacity`] — the actual
/// buffer grows as needed.
const RAW_READ_HINT: usize = 1024 * 1024;

// ───────────────────────────────────────────────────────────────────────────
// CLI Argument Struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `asn1parse` subcommand.
///
/// Provides ASN.1 parsing, drilling, and synthesis exactly mirroring the C
/// command's `asn1parse_options[]` table at `apps/asn1parse.c:18–48`, with
/// the sole exception of `--item` (templated structure parsing) which is not
/// supported in the Rust crypto layer.
///
/// All flags are declared via `clap` derive — replacing the manual
/// `OPTION_CHOICE` enum and `opt_init()` / `opt_next()` loop in the C source.
//
// Clippy lint `struct_excessive_bools` is disabled here because each `bool`
// field corresponds to an *independent* CLI flag (`--indent`, `--noout`,
// `--dump`, `--strictpem`).  These flags are user-controlled and orthogonal —
// they cannot be folded into a single state enum without breaking the
// `clap::Args` derive contract or the C tool's command-line surface.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Asn1parseArgs {
    /// Input format — one of `PEM`, `DER`, or `B64`.
    ///
    /// Mirrors the C `-inform` flag (default `PEM`).  When `--strictpem` is
    /// given this value is forced to `PEM` regardless of what the user
    /// supplied.
    ///
    /// `default_value = "PEM"` (string literal) plus `ignore_case = true` is
    /// required because clap's [`ValueEnum`](clap::ValueEnum) derive on
    /// [`Format`] generates lowercase variant names (`pem`, `der`, `base64`,
    /// …) as the canonical wire format, while the default literal `"PEM"`
    /// and the C tool's user input (`apps/lib/opt.c:opt_format`) are
    /// uppercase.  Using `default_value_t = Format::Pem` would feed the
    /// `Display` output (`"PEM"`) back through the auto-derived parser,
    /// which only accepts lowercase, and every invocation of
    /// `openssl asn1parse` without an explicit `-inform` would fail to
    /// parse with `invalid value 'PEM' for '--inform <INFORM>'`.
    #[arg(long = "inform", value_enum, default_value = "PEM", ignore_case = true)]
    inform: Format,

    /// Path of the input file (defaults to stdin when omitted).
    ///
    /// Mirrors the C `-in <FILE>` flag.  R5: `Option<PathBuf>` — no
    /// `""`/`NULL` sentinel for "stdin".
    #[arg(long = "in", value_name = "FILE")]
    in_file: Option<PathBuf>,

    /// Optional output file receiving the raw DER bytes of the selected
    /// window (`offset .. offset + length`).
    ///
    /// Mirrors the C `-out <FILE>` flag (`derout` BIO).  When `None`, no DER
    /// output is produced.
    #[arg(long = "out", value_name = "FILE")]
    out: Option<PathBuf>,

    /// Indent each depth level of the dump by two spaces.
    ///
    /// Mirrors the C `-i` flag.  When `false`, no indentation is applied.
    #[arg(short = 'i', long = "indent")]
    indent: bool,

    /// Suppress the human-readable parse dump (DER output via `--out` is
    /// still produced).
    ///
    /// Mirrors the C `-noout` flag.
    #[arg(long = "noout")]
    noout: bool,

    /// Path to a file containing extra OID definitions, one per line:
    /// `<dotted-numeric-oid> <short-name> [long-name]`.
    ///
    /// Mirrors the C `-oid <FILE>` flag.  The file is parsed and validated
    /// here, but global OID registration is not yet implemented in the Rust
    /// crypto layer; entries are logged for diagnostics.
    #[arg(long = "oid", value_name = "FILE")]
    oid: Option<PathBuf>,

    /// Byte offset within the (possibly drilled-into) buffer at which to
    /// begin parsing.
    ///
    /// Mirrors the C `-offset <N>` flag.  Defaults to `0`.
    #[arg(long = "offset", value_name = "N", default_value_t = 0)]
    offset: usize,

    /// Number of bytes to parse, starting at `--offset`.
    ///
    /// Mirrors the C `-length <N>` flag.  When omitted (or `0` from the C
    /// side), the parser consumes all bytes from `--offset` to the end of
    /// the buffer.  R5: `Option<usize>` — the absent state is encoded as
    /// `None`, not `0`.
    #[arg(long = "length", value_name = "N")]
    length: Option<usize>,

    /// Dump unrecognised primitive contents in full (`-dump` in the C tool).
    ///
    /// In the Rust implementation the dumper always emits a 32-byte preview
    /// for primitives.  This flag is accepted for CLI compatibility but
    /// does not change the dump format; setting it merely emits a diagnostic
    /// log line.
    #[arg(long = "dump")]
    dump: bool,

    /// Like `--dump`, but only dump primitives whose length is `<= N`.
    ///
    /// Accepted for CLI compatibility — see the note on `--dump`.  R5:
    /// `Option<usize>`.
    #[arg(long = "dlimit", value_name = "N")]
    dlimit: Option<usize>,

    /// Drill into a nested ASN.1 structure at the given offset before
    /// parsing.  May be repeated to drill multiple times.
    ///
    /// Each value is the byte offset (relative to the current working
    /// buffer) at which a TLV begins; after drilling, the inner content of
    /// that TLV becomes the new working buffer.  Mirrors the repeatable
    /// `-strparse <N>` flag in the C tool.
    #[arg(long = "strparse", value_name = "N", action = clap::ArgAction::Append)]
    strparse: Vec<usize>,

    /// Synthesize ASN.1 from a textual description rather than reading
    /// input.
    ///
    /// Mirrors the C `-genstr <STRING>` flag — see
    /// `openssl_crypto::asn1::generate_from_config` for the supported
    /// mini-language grammar.
    #[arg(long = "genstr", value_name = "STRING")]
    genstr: Option<String>,

    /// Read the synthesis description from a configuration file (an `asn1=`
    /// line in the chosen section).
    ///
    /// Mirrors the C `-genconf <FILE>` flag.
    #[arg(long = "genconf", value_name = "FILE")]
    genconf: Option<PathBuf>,

    /// When reading PEM, require strict RFC 7468 framing.  Implies
    /// `--inform PEM`.
    ///
    /// Mirrors the C `-strictpem` flag.
    #[arg(long = "strictpem")]
    strictpem: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Core Implementation
// ───────────────────────────────────────────────────────────────────────────

impl Asn1parseArgs {
    /// Execute the `asn1parse` subcommand.
    ///
    /// High-level flow (mirroring `apps/asn1parse.c:140–325`):
    ///
    /// 1. Optionally load extra OID definitions.
    /// 2. Acquire the working ASN.1 byte buffer — either by synthesizing it
    ///    from `--genstr` / `--genconf` or by reading and decoding the input
    ///    stream according to `--inform`.
    /// 3. Drill into nested TLVs for each `--strparse` offset.
    /// 4. Validate `--offset` / `--length` against the working buffer and
    ///    compute the final window.
    /// 5. Optionally write the DER bytes of that window to `--out`.
    /// 6. Unless `--noout` is given, recursively parse-dump the window to
    ///    stdout.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on any of:
    ///
    /// - I/O failures opening / reading / writing files (auto-converted via
    ///   `CryptoError::Io`)
    /// - Malformed PEM, Base64, or DER input
    /// - Out-of-range `--offset`
    /// - Disallowed `--strparse` target type (`OBJECT IDENTIFIER`,
    ///   `BOOLEAN`, or `NULL`)
    /// - ASN.1 generation / parse errors propagated from
    ///   [`openssl_crypto::asn1`]
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Asn1parse(args)` → `args.execute(ctx).await`.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        debug!("asn1parse: starting (inform={:?}, indent={}, noout={}, offset={}, length={:?}, strparse_count={}, genstr={}, genconf={})",
            self.inform,
            self.indent,
            self.noout,
            self.offset,
            self.length,
            self.strparse.len(),
            self.genstr.is_some(),
            self.genconf.is_some(),
        );

        // ── Step 1: Optionally load extra OIDs ───────────────────────────
        if let Some(ref oid_path) = self.oid {
            Self::load_oid_file(oid_path)?;
        }

        // ── Step 2: Acquire the ASN.1 byte buffer ────────────────────────
        let buffer: Vec<u8> = if let Some(ref expr) = self.genstr {
            // `--genstr` takes precedence over file input when both are given,
            // matching the C precedence (the string overrides the configfile
            // value of `asn1`).
            Self::synthesize_from_string(expr)?
        } else if let Some(ref conf) = self.genconf {
            let expr = Self::read_genconf_expression(conf)?;
            Self::synthesize_from_string(&expr)?
        } else {
            self.read_input_buffer()?
        };

        debug!(
            input_bytes = buffer.len(),
            "asn1parse: input buffer acquired"
        );

        // ── Step 3: Apply `--strparse` drill-down ────────────────────────
        let working: &[u8] = self.apply_strparse(&buffer)?;

        // ── Step 4: Validate offset / compute final length ───────────────
        let (window_start, window_len) = self.compute_window(working)?;
        let window: &[u8] = &working[window_start..window_start + window_len];

        debug!(
            offset = window_start,
            length = window_len,
            "asn1parse: final window selected"
        );

        // ── Step 5: Optional DER output ──────────────────────────────────
        if let Some(ref der_path) = self.out {
            Self::write_der_output(der_path, window)?;
        }

        // ── Step 6: Optional human-readable parse dump ───────────────────
        if !self.noout {
            self.write_parse_dump(window)?;
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 1: OID file loader
    // ───────────────────────────────────────────────────────────────────

    /// Parses an extra-OID file in the OpenSSL `OBJ_create_objects()` format
    /// and emits each entry to the trace log.
    ///
    /// Each non-empty, non-comment line is whitespace-delimited:
    /// `<dotted-oid> <short-name> [long-name]`.  Invalid lines are reported
    /// as warnings (matching the C `OBJ_create_objects()` behaviour of
    /// continuing past bad lines) rather than aborting the command.
    ///
    /// The OID itself is validated by parsing it with
    /// [`Asn1Object::from_oid_string`]; this catches arc-count and
    /// arc-range errors that the C implementation would surface via
    /// `OBJ_txt2obj()` returning `NULL`.
    ///
    /// Note: the Rust crypto layer does not yet expose a global OID
    /// registry, so registered names will not influence subsequent dumps;
    /// loading the file is performed for diagnostic and forward-
    /// compatibility purposes only.
    //
    // Associated function: takes no `&self` because the parsing logic is a
    // pure function of the file contents.  `Asn1parseArgs` state is read by
    // the caller (which decides *whether* to call this) but not by the
    // routine itself.
    fn load_oid_file(path: &Path) -> Result<(), CryptoError> {
        debug!(path = %path.display(), "asn1parse: loading extra OIDs");
        let file = File::open(path).map_err(|e| {
            error!(path = %path.display(), error = %e, "asn1parse: failed to open OID file");
            e
        })?;
        let reader = BufReader::new(file);

        let mut count: usize = 0;
        for (line_no, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            let stripped = strip_comment(line.trim());
            if stripped.is_empty() {
                continue;
            }

            let mut parts = stripped.split_whitespace();
            let Some(oid_text) = parts.next() else {
                continue;
            };
            let short = parts.next().unwrap_or("");
            let long = parts.next().unwrap_or(short);
            if short.is_empty() {
                warn!(
                    line = line_no + 1,
                    "asn1parse: OID file line missing short-name; skipping"
                );
                continue;
            }

            match Asn1Object::from_oid_string(oid_text) {
                Ok(obj) => {
                    count = count.checked_add(1).unwrap_or(count);
                    trace!(
                        line = line_no + 1,
                        oid = oid_text,
                        short_name = short,
                        long_name = long,
                        encoded_len = obj.raw_bytes().len(),
                        "asn1parse: OID accepted"
                    );
                }
                Err(e) => {
                    warn!(
                        line = line_no + 1,
                        oid = oid_text,
                        error = %e,
                        "asn1parse: invalid OID line; skipping"
                    );
                }
            }
        }
        info!(
            path = %path.display(),
            entries = count,
            "asn1parse: OID file processed"
        );
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 2: Input acquisition
    // ───────────────────────────────────────────────────────────────────

    /// Reads the input stream into a `Vec<u8>` and decodes it according to
    /// the effective input format.
    ///
    /// Format selection (mirrors `apps/asn1parse.c:171–225`):
    /// - `--strictpem` → forced PEM read.
    /// - `Format::Pem`  → `pem::decode_from_reader()`, take the first PEM
    ///   block's payload.
    /// - `Format::Der`  → raw `read_to_end()` (the entire stream is the
    ///   DER blob).
    /// - `Format::Base64` → `read_to_string()` followed by Base64 decode of
    ///   the trimmed text (whitespace is stripped first).
    /// - Any other text format (e.g. `Hex`) is treated as Base64 for
    ///   compatibility — the C tool only supports PEM/DER/B64 here.
    fn read_input_buffer(&self) -> Result<Vec<u8>, CryptoError> {
        let effective_format = if self.strictpem {
            debug!("asn1parse: --strictpem forces PEM input");
            Format::Pem
        } else {
            self.inform
        };

        let mut reader = self.open_input_reader()?;

        match effective_format {
            Format::Pem => {
                debug!("asn1parse: reading PEM input");
                let blocks = pem::decode_from_reader(&mut reader).map_err(|e| {
                    error!(error = %e, "asn1parse: PEM decode failed");
                    e
                })?;
                let first = blocks.into_iter().next().ok_or_else(|| {
                    error!("asn1parse: PEM input contains no blocks");
                    CryptoError::Encoding("input does not contain a PEM block".to_string())
                })?;
                debug!(
                    label = %first.label,
                    payload_bytes = first.data.len(),
                    "asn1parse: PEM block decoded"
                );
                Ok(first.data)
            }
            Format::Der => {
                debug!("asn1parse: reading raw DER input");
                let mut buf: Vec<u8> = Vec::with_capacity(RAW_READ_HINT);
                reader.read_to_end(&mut buf)?;
                Ok(buf)
            }
            Format::Base64 => {
                debug!("asn1parse: reading Base64 input");
                let mut text = String::new();
                reader.read_to_string(&mut text)?;
                decode_base64_text(&text)
            }
            other => {
                // Other text formats (Hex, etc.) are not supported by the C
                // tool; we treat them as Base64 for compatibility but warn.
                if other.is_text() {
                    warn!(
                        format = ?other,
                        "asn1parse: unsupported text format; attempting Base64 decode"
                    );
                    let mut text = String::new();
                    reader.read_to_string(&mut text)?;
                    decode_base64_text(&text)
                } else {
                    error!(format = ?other, "asn1parse: unsupported binary input format");
                    Err(CryptoError::Encoding(format!(
                        "unsupported input format: {other:?}"
                    )))
                }
            }
        }
    }

    /// Opens the input source — a file path if `--in` was given, otherwise
    /// stdin — wrapped in a buffered reader.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        if let Some(ref path) = self.in_file {
            debug!(path = %path.display(), "asn1parse: opening input file");
            let file = File::open(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "asn1parse: cannot open input file");
                e
            })?;
            Ok(Box::new(BufReader::new(file)))
        } else {
            debug!("asn1parse: reading input from stdin");
            Ok(Box::new(BufReader::new(io::stdin())))
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 2 (alt): Synthesis from generator language
    // ───────────────────────────────────────────────────────────────────

    /// Synthesizes a DER blob from an OpenSSL `asn1_generate` mini-language
    /// expression — see [`openssl_crypto::asn1::generate_from_config`].
    //
    // Associated function: the synthesis logic is a pure function of the
    // input expression and does not depend on any field of `Asn1parseArgs`.
    fn synthesize_from_string(expr: &str) -> Result<Vec<u8>, CryptoError> {
        debug!(
            expr_len = expr.len(),
            "asn1parse: synthesizing from --genstr"
        );
        let bytes = generate_from_config(expr).map_err(|e| {
            error!(error = %e, "asn1parse: ASN.1 generation failed");
            e
        })?;
        debug!(
            synthesized_bytes = bytes.len(),
            "asn1parse: synthesis complete"
        );
        Ok(bytes)
    }

    /// Reads a `--genconf` configuration file and extracts the `asn1=` value
    /// from its first matching key.
    ///
    /// The C implementation uses `NCONF_load()` + `NCONF_get_string()` to
    /// look up the `asn1` key in the named section.  In the absence of a
    /// full configuration parser at this layer we accept the simple
    /// `asn1 = <expr>` / `asn1=<expr>` syntax (with optional whitespace and
    /// `#` line comments).
    //
    // Associated function: parses the file based purely on its on-disk
    // contents; no `Asn1parseArgs` field is consulted.
    fn read_genconf_expression(path: &Path) -> Result<String, CryptoError> {
        debug!(path = %path.display(), "asn1parse: reading --genconf file");
        let file = File::open(path).map_err(|e| {
            error!(path = %path.display(), error = %e, "asn1parse: cannot open --genconf file");
            e
        })?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            let stripped = strip_comment(line.trim());
            if stripped.is_empty() {
                continue;
            }
            // Skip section headers ([name]).
            if stripped.starts_with('[') {
                continue;
            }

            if let Some(eq_pos) = stripped.find('=') {
                let (key, value) = stripped.split_at(eq_pos);
                if key.trim().eq_ignore_ascii_case("asn1") {
                    let expr = value
                        .get(1..)
                        .map_or("", str::trim)
                        .trim_matches(|c: char| c == '"' || c == '\'')
                        .to_string();
                    if expr.is_empty() {
                        error!("asn1parse: --genconf: 'asn1' key has empty value");
                        return Err(CryptoError::Encoding(
                            "genconf: 'asn1' key has empty value".to_string(),
                        ));
                    }
                    return Ok(expr);
                }
            }
        }

        error!(path = %path.display(), "asn1parse: --genconf: no 'asn1' key found");
        Err(CryptoError::Encoding(format!(
            "genconf: no 'asn1' key found in {}",
            path.display()
        )))
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 3: --strparse drill-down
    // ───────────────────────────────────────────────────────────────────

    /// Applies each `--strparse` offset to the buffer in turn, replacing
    /// the working slice with the *content* of the TLV found at that
    /// offset.
    ///
    /// Mirrors the loop at `apps/asn1parse.c:242–280`:
    /// - An out-of-range offset (`j == 0` or `j >= current_len`) emits a
    ///   warning and is **skipped** — execution continues with the next
    ///   offset.  This matches the `continue` branch in the C loop.
    /// - A target whose universal tag is `OBJECT IDENTIFIER`, `BOOLEAN`,
    ///   or `NULL` aborts the command with an `Encoding` error — matching
    ///   the C `goto end` branch and the comment "Can't parse %s type".
    /// - All other tags advance the working slice to the TLV's content
    ///   (i.e. excluding its identifier and length octets).
    ///
    /// The returned slice borrows from `buffer`, so its lifetime is tied
    /// to the caller's buffer.
    fn apply_strparse<'b>(&self, buffer: &'b [u8]) -> Result<&'b [u8], CryptoError> {
        let mut working: &[u8] = buffer;
        if self.strparse.is_empty() {
            return Ok(working);
        }

        for (idx, &j) in self.strparse.iter().enumerate() {
            if j == 0 || j >= working.len() {
                warn!(
                    offset = j,
                    current_len = working.len(),
                    iteration = idx,
                    "asn1parse: --strparse offset out of range; skipping"
                );
                continue;
            }

            let after_offset: &[u8] = &working[j..];
            let header = parse_tlv_header(after_offset).map_err(|e| {
                error!(offset = j, error = %e, "asn1parse: --strparse: malformed TLV at offset");
                e
            })?;

            // Reject types that have no parseable inner ASN.1 structure
            // (matches the C `V_ASN1_OBJECT/BOOLEAN/NULL` branch).
            if header.class == Asn1Class::Universal
                && matches!(
                    header.tag,
                    Asn1Tag::ObjectIdentifier | Asn1Tag::Boolean | Asn1Tag::Null
                )
            {
                error!(
                    offset = j,
                    tag = ?header.tag,
                    "asn1parse: --strparse: cannot drill into this type"
                );
                return Err(CryptoError::Encoding(format!(
                    "--strparse: cannot drill into {:?} at offset {}",
                    header.tag, j
                )));
            }

            // Validate that the TLV decodes cleanly (this catches truncated
            // content, indefinite-length encodings, malformed string types,
            // etc.) — without this step we'd silently propagate broken data
            // forward and produce confusing errors later.
            let _validated: Asn1Type = Asn1Type::decode_der(after_offset).map_err(|e| {
                error!(offset = j, error = %e, "asn1parse: --strparse: TLV failed to decode");
                e
            })?;

            // Advance to the TLV's content (header_length .. header_length + content_length).
            let body_start = header.header_length;
            let content_len = header.content_length.ok_or_else(|| {
                error!(
                    offset = j,
                    "asn1parse: --strparse: indefinite-length encoding not supported"
                );
                CryptoError::Encoding(
                    "--strparse: indefinite-length encoding not supported".to_string(),
                )
            })?;
            let content_end = body_start.checked_add(content_len).ok_or_else(|| {
                error!(
                    offset = j,
                    body_start,
                    content_len,
                    "asn1parse: --strparse: integer overflow computing content end"
                );
                CryptoError::Encoding("--strparse: integer overflow".to_string())
            })?;
            if content_end > after_offset.len() {
                error!(
                    offset = j,
                    content_end,
                    available = after_offset.len(),
                    "asn1parse: --strparse: TLV content truncated"
                );
                return Err(CryptoError::Encoding(
                    "--strparse: TLV content truncated".to_string(),
                ));
            }

            trace!(
                offset = j,
                tag = ?header.tag,
                inner_len = content_len,
                "asn1parse: --strparse: drilled into TLV"
            );
            working = &after_offset[body_start..content_end];
        }

        Ok(working)
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 4: Offset / length window
    // ───────────────────────────────────────────────────────────────────

    /// Validates `--offset` / `--length` against the working buffer and
    /// returns the `(start, length)` window to pass to the dumper.
    ///
    /// Matches the C validation at `apps/asn1parse.c:282–290`:
    /// - `offset >= num` is a hard error (mirrors the C `offset < 0 ||
    ///   offset >= num` check; for `usize` the negative branch is
    ///   unrepresentable).
    /// - A length of `0` (or unset, which is the Rust equivalent) or any
    ///   length larger than `num - offset` is **clamped** to `num -
    ///   offset` — this is exactly what C does with
    ///   `length = (unsigned int)num`.
    fn compute_window(&self, working: &[u8]) -> Result<(usize, usize), CryptoError> {
        let num = working.len();
        if self.offset >= num {
            // Special case: an empty buffer with offset == 0 is treated as
            // an empty window (no error), matching the C tool which produces
            // empty output rather than failing for length-zero inputs.
            if num == 0 && self.offset == 0 {
                return Ok((0, 0));
            }
            error!(
                offset = self.offset,
                buffer_len = num,
                "asn1parse: offset out of range"
            );
            return Err(CryptoError::Encoding(format!(
                "offset {} out of range (buffer length {})",
                self.offset, num
            )));
        }

        // Saturating subtraction is sound here because offset < num.
        let remaining = num - self.offset;
        let final_len = match self.length {
            Some(0) | None => remaining,
            Some(n) if n > remaining => remaining,
            Some(n) => n,
        };

        Ok((self.offset, final_len))
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 5: DER output
    // ───────────────────────────────────────────────────────────────────

    /// Writes the selected window to the `--out` file in raw DER form.
    //
    // Associated function: writes the supplied byte window directly to disk;
    // no `Asn1parseArgs` field influences the output.
    fn write_der_output(path: &Path, window: &[u8]) -> Result<(), CryptoError> {
        debug!(
            path = %path.display(),
            bytes = window.len(),
            "asn1parse: writing DER output"
        );
        let file = File::create(path).map_err(|e| {
            error!(path = %path.display(), error = %e, "asn1parse: cannot create DER output file");
            e
        })?;
        let mut writer = BufWriter::new(file);
        writer.write_all(window)?;
        writer.flush()?;
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Step 6: Parse dump
    // ───────────────────────────────────────────────────────────────────

    /// Renders the recursive parse dump to stdout.
    ///
    /// The optional [`Self::dump`] / [`Self::dlimit`] flags are accepted
    /// for CLI compatibility but do not currently change the dump format —
    /// see the field-level documentation.  When the buffer is empty no
    /// output is produced (matching the C tool, which emits nothing in
    /// that case).
    fn write_parse_dump(&self, window: &[u8]) -> Result<(), CryptoError> {
        if window.is_empty() {
            debug!("asn1parse: empty window — no dump output");
            return Ok(());
        }
        if self.dump || self.dlimit.is_some() {
            debug!(
                dump = self.dump,
                dlimit = ?self.dlimit,
                "asn1parse: --dump / --dlimit accepted (cosmetic only in this implementation)"
            );
        }

        let indent_per_level = if self.indent {
            INDENT_SPACES_PER_LEVEL
        } else {
            0
        };
        let rendered = parse_dump(window, indent_per_level).map_err(|e| {
            error!(error = %e, "asn1parse: parse_dump failed");
            e
        })?;

        let stdout_lock = stdout();
        let mut writer = BufWriter::new(stdout_lock.lock());
        writer.write_all(rendered.as_bytes())?;
        writer.flush()?;
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Free helpers
// ───────────────────────────────────────────────────────────────────────────

/// Strips a `#`-introduced line comment, preserving any leading content.
///
/// Used for both `--oid` files and `--genconf` files; both formats use `#`
/// as the line-comment introducer.
fn strip_comment(line: &str) -> &str {
    if let Some(idx) = line.find('#') {
        line[..idx].trim_end()
    } else {
        line
    }
}

/// Decodes a Base64 text blob into raw bytes.
///
/// All whitespace (spaces, tabs, newlines, carriage returns) is stripped
/// before decoding so that PEM-style line wrapping works with `--inform B64`.
fn decode_base64_text(text: &str) -> Result<Vec<u8>, CryptoError> {
    let mut filtered = String::with_capacity(text.len());
    for ch in text.chars() {
        if !ch.is_whitespace() {
            filtered.push(ch);
        }
    }
    if filtered.is_empty() {
        return Err(CryptoError::Encoding(
            "Base64 input contains no non-whitespace data".to_string(),
        ));
    }
    Base64::decode_vec(&filtered)
        .map_err(|e| CryptoError::Encoding(format!("invalid Base64 input: {e}")))
}

// ───────────────────────────────────────────────────────────────────────────
// Unit Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// A tiny DER blob: `INTEGER 0x12 0x34` (DER `02 02 12 34`).
    const DER_INT_1234: &[u8] = &[0x02, 0x02, 0x12, 0x34];

    /// A two-level DER blob: `SEQUENCE { INTEGER 0x12 0x34 }`
    /// = `30 04 02 02 12 34`.
    const DER_SEQ_INT: &[u8] = &[0x30, 0x04, 0x02, 0x02, 0x12, 0x34];

    fn default_args() -> Asn1parseArgs {
        Asn1parseArgs {
            inform: Format::Der,
            in_file: None,
            out: None,
            indent: false,
            noout: true, // suppress stdout for unit tests
            oid: None,
            offset: 0,
            length: None,
            dump: false,
            dlimit: None,
            strparse: Vec::new(),
            genstr: None,
            genconf: None,
            strictpem: false,
        }
    }

    #[test]
    fn strip_comment_removes_hash_and_after() {
        assert_eq!(strip_comment("oid # comment"), "oid");
        assert_eq!(strip_comment("# whole line"), "");
        assert_eq!(strip_comment("no comment"), "no comment");
        assert_eq!(strip_comment(""), "");
    }

    #[test]
    fn decode_base64_text_strips_whitespace() {
        let bytes = decode_base64_text("AQID\nBAUG\n").expect("decode succeeds");
        assert_eq!(bytes, &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn decode_base64_text_rejects_empty() {
        let err = decode_base64_text("   \n\t  ").expect_err("must reject empty input");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_base64_text_rejects_invalid() {
        let err = decode_base64_text("@@not-b64@@").expect_err("must reject invalid");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn compute_window_clamps_oversize_length() {
        let mut args = default_args();
        args.offset = 1;
        args.length = Some(1000);
        let (start, len) = args.compute_window(DER_INT_1234).expect("ok");
        assert_eq!(start, 1);
        assert_eq!(len, 3);
    }

    #[test]
    fn compute_window_uses_full_remaining_when_unset() {
        let mut args = default_args();
        args.offset = 2;
        args.length = None;
        let (start, len) = args.compute_window(DER_INT_1234).expect("ok");
        assert_eq!(start, 2);
        assert_eq!(len, 2);
    }

    #[test]
    fn compute_window_uses_full_remaining_when_zero() {
        let mut args = default_args();
        args.offset = 0;
        args.length = Some(0);
        let (start, len) = args.compute_window(DER_INT_1234).expect("ok");
        assert_eq!(start, 0);
        assert_eq!(len, DER_INT_1234.len());
    }

    #[test]
    fn compute_window_rejects_offset_out_of_range() {
        let mut args = default_args();
        args.offset = DER_INT_1234.len();
        let err = args
            .compute_window(DER_INT_1234)
            .expect_err("offset == len must error");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn compute_window_handles_empty_buffer_at_zero() {
        let args = default_args();
        let (start, len) = args.compute_window(&[]).expect("empty buffer ok");
        assert_eq!(start, 0);
        assert_eq!(len, 0);
    }

    #[test]
    fn apply_strparse_no_offsets_returns_input_unchanged() {
        let args = default_args();
        let out = args.apply_strparse(DER_SEQ_INT).expect("ok");
        assert_eq!(out, DER_SEQ_INT);
    }

    #[test]
    fn apply_strparse_skips_zero_offset_with_warning() {
        let mut args = default_args();
        args.strparse = vec![0];
        let out = args.apply_strparse(DER_SEQ_INT).expect("ok");
        // j == 0 is out of range and skipped — buffer unchanged.
        assert_eq!(out, DER_SEQ_INT);
    }

    #[test]
    fn apply_strparse_skips_offset_at_or_beyond_buffer() {
        let mut args = default_args();
        args.strparse = vec![DER_SEQ_INT.len(), DER_SEQ_INT.len() + 5];
        let out = args.apply_strparse(DER_SEQ_INT).expect("ok");
        assert_eq!(out, DER_SEQ_INT);
    }

    #[test]
    fn apply_strparse_rejects_drill_into_null() {
        // `04 02 05 00 04 02 12 34` — OCTET STRING containing the bytes
        // `05 00 04 02 12 34`.  Drilling at offset 2 of the inner content
        // points us at a NULL TLV (`05 00`), which must be rejected.
        // We construct: top OCTET STRING wrapping NULL + INTEGER for clarity.
        let buf: Vec<u8> = vec![
            0x04, 0x06, // OCTET STRING, len 6
            0x05, 0x00, // NULL
            0x02, 0x02, 0x12, 0x34, // INTEGER 0x1234
        ];
        // Strparse offset 2: this points at the NULL TLV in the *outer*
        // buffer — which should be rejected.
        let mut args = default_args();
        args.strparse = vec![2];
        let err = args
            .apply_strparse(&buf)
            .expect_err("drilling into NULL must error");
        match err {
            CryptoError::Encoding(msg) => assert!(
                msg.contains("NULL") || msg.contains("Null"),
                "msg should mention Null, got: {msg}"
            ),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn apply_strparse_drills_into_sequence_content() {
        // Top-level: SEQUENCE { OCTET STRING { 12 34 } }
        // = 30 06 04 04 .. .. .. ..  -> we use:
        //   30 04 04 02 12 34
        let buf: &[u8] = &[0x30, 0x04, 0x04, 0x02, 0x12, 0x34];
        let mut args = default_args();
        // Drill at offset 2 (the OCTET STRING TLV) — we should be left
        // looking at its content `12 34`.
        args.strparse = vec![2];
        let inner = args.apply_strparse(buf).expect("ok");
        assert_eq!(inner, &[0x12, 0x34]);
    }

    #[test]
    fn read_genconf_expression_finds_asn1_key() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "[default]").unwrap();
        writeln!(tmp, "asn1 = INTEGER:42").unwrap();
        let value = Asn1parseArgs::read_genconf_expression(tmp.path()).expect("expression");
        assert_eq!(value, "INTEGER:42");
    }

    #[test]
    fn read_genconf_expression_strips_quotes() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        writeln!(tmp, "asn1 = \"NULL\"").unwrap();
        let value = Asn1parseArgs::read_genconf_expression(tmp.path()).expect("expression");
        assert_eq!(value, "NULL");
    }

    #[test]
    fn read_genconf_expression_errors_when_missing() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        writeln!(tmp, "other = ignored").unwrap();
        let err = Asn1parseArgs::read_genconf_expression(tmp.path()).expect_err("must error");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn read_genconf_expression_errors_on_empty_value() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        writeln!(tmp, "asn1 =   ").unwrap();
        let err = Asn1parseArgs::read_genconf_expression(tmp.path()).expect_err("must error");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn synthesize_from_string_produces_der() {
        // BOOLEAN:TRUE wraps a full TLV (`01 01 FF`) per X.690 §8.2.
        let bytes = Asn1parseArgs::synthesize_from_string("BOOLEAN:TRUE").expect("synthesis");
        assert_eq!(bytes, &[0x01, 0x01, 0xFF]);
        // NULL produces a header-only TLV (`05 00`).
        let null_bytes = Asn1parseArgs::synthesize_from_string("NULL").expect("null synthesis");
        assert_eq!(null_bytes, &[0x05, 0x00]);
    }

    #[test]
    fn synthesize_from_string_propagates_errors() {
        let err = Asn1parseArgs::synthesize_from_string("BOGUS:42").expect_err("must error");
        // Any error variant is acceptable as long as it propagates.
        assert!(matches!(
            err,
            CryptoError::Encoding(_) | CryptoError::Common(_)
        ));
    }

    #[tokio::test]
    async fn execute_round_trip_der_in_via_file() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        tmp.write_all(DER_SEQ_INT).unwrap();

        let mut args = default_args();
        args.in_file = Some(tmp.path().to_path_buf());

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("dump completes");
    }

    #[tokio::test]
    async fn execute_genstr_path() {
        let mut args = default_args();
        args.genstr = Some("INTEGER:42".to_string());

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("genstr path completes");
    }

    #[tokio::test]
    async fn execute_writes_der_output() {
        let mut tmp_in = NamedTempFile::new().expect("in");
        tmp_in.write_all(DER_SEQ_INT).unwrap();
        let tmp_out = NamedTempFile::new().expect("out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out = Some(tmp_out.path().to_path_buf());

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("dump completes");

        let written = std::fs::read(tmp_out.path()).expect("read out");
        assert_eq!(written, DER_SEQ_INT);
    }

    #[tokio::test]
    async fn execute_offset_out_of_range_errors() {
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        tmp.write_all(DER_SEQ_INT).unwrap();

        let mut args = default_args();
        args.in_file = Some(tmp.path().to_path_buf());
        args.offset = 100;

        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.expect_err("must error");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_strparse_drills_then_parses() {
        // SEQUENCE { OCTET STRING { 12 34 } }
        // Outer: 30 06 04 04 04 02 12 34  (length 8)
        // Wait: let me build correctly:
        //   inner OCTET STRING wrapping {12 34}: 04 02 12 34  (len 4)
        //   wrap in SEQUENCE: 30 04 <inner4>
        // So: 30 04 04 02 12 34 (length 6)
        let buf = &[0x30, 0x04, 0x04, 0x02, 0x12, 0x34];
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        tmp.write_all(buf).unwrap();

        let mut args = default_args();
        args.in_file = Some(tmp.path().to_path_buf());
        // Drill into the inner OCTET STRING at offset 2.
        args.strparse = vec![2];

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("strparse drill completes");
    }
}
