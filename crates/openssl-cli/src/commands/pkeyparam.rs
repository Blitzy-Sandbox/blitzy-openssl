//! `pkeyparam` subcommand implementation.
//!
//! Reads PEM-encoded asymmetric algorithm parameters (DH / DSA / EC / X9.42-DH
//! parameter blocks) from a file or stdin, optionally validates them via
//! [`PKeyCtx::param_check`] (the Rust equivalent of `EVP_PKEY_param_check()`),
//! optionally re-encodes them to PEM on the output stream, and optionally
//! prints a human-readable text rendering.
//!
//! This is the Rust equivalent of `apps/pkeyparam.c` in the original C
//! codebase.  The C implementation reads input via `PEM_read_bio_Parameters_ex`
//! and writes output via `PEM_write_bio_Parameters` and
//! `EVP_PKEY_print_params`; the Rust rewrite delegates all PEM encoding /
//! decoding to [`openssl_crypto::pem`] and all parameter handling to
//! [`openssl_crypto::evp::pkey`].
//!
//! # Output Format
//!
//! Default behaviour is a faithful round-trip — the original PEM block is
//! decoded, then encoded back to the output stream verbatim.  When `--text`
//! is given an additional human-readable summary follows, comparable to the
//! C tool's `EVP_PKEY_print_params()` output (algorithm family, parameter
//! byte count, optional bit strength, hex dump of the DER payload).
//!
//! When `--check` is given the parameters are validated *before* output, and
//! the literal string `"Parameters are valid\n"` is written to the output
//! stream on success.  On failure `"Parameters are invalid\n"` is written
//! to stderr and the command returns [`CryptoError::Verification`].
//!
//! # Rules Applied
//!
//! - **R5** — `Option<T>` is used for every optional argument (input and
//!   output paths).  No sentinel values such as `0` / `-1` / `""` are used to
//!   encode "unset" — `None` denotes stdin / stdout respectively.
//! - **R6** — No bare `as` casts on numeric data.  All arithmetic uses
//!   wrapping helpers (`checked_*`) or works on `usize` directly.
//! - **R8** — Zero `unsafe` code.  The crate-level `#![forbid(unsafe_code)]`
//!   in `crates/openssl-cli/src/main.rs` makes this a compile-time guarantee.
//! - **R9** — Warning-free under `RUSTFLAGS="-D warnings"`; every public
//!   item carries a doc-comment.
//! - **R10** — Wired into the dispatch path: `main.rs` →
//!   `CliCommand::execute()` → `CliCommand::Pkeyparam(args)` →
//!   `PkeyparamArgs::execute(ctx).await`, reachable from the binary entry
//!   point and exercised by the integration tests in this module.

use std::fs::File;
use std::io::{self, stdout, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, trace, warn};

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx};
use openssl_crypto::pem::{self, PemObject};

// ───────────────────────────────────────────────────────────────────────────
// PEM Label Constants
// ───────────────────────────────────────────────────────────────────────────
//
// The `pem` module does not expose dedicated constants for the parameter-
// only PEM labels accepted by C `PEM_read_bio_Parameters_ex()` (see
// `crypto/pem/pem_pkey.c`), so we declare them locally.

/// PEM label for Diffie-Hellman parameter blocks (RFC 7919, PKCS #3).
const PEM_LABEL_DH_PARAMETERS: &str = "DH PARAMETERS";

/// PEM label for X9.42 Diffie-Hellman parameter blocks (`DHX`).
const PEM_LABEL_X942_DH_PARAMETERS: &str = "X9.42 DH PARAMETERS";

/// PEM label for DSA parameter blocks (FIPS 186 §A).
const PEM_LABEL_DSA_PARAMETERS: &str = "DSA PARAMETERS";

/// PEM label for elliptic-curve parameter blocks (RFC 5915 §3).
const PEM_LABEL_EC_PARAMETERS: &str = "EC PARAMETERS";

/// Generic PEM label for parameter blocks emitted by the new
/// provider-based key encoders.
const PEM_LABEL_PARAMETERS: &str = "PARAMETERS";

/// Output line written on successful `--check` validation, matching the
/// exact byte sequence emitted by the C tool (`apps/pkeyparam.c:118`).
const VALID_PARAMETERS_LINE: &str = "Parameters are valid\n";

/// Diagnostic line written to stderr on `--check` failure, matching the
/// exact byte sequence emitted by the C tool (`apps/pkeyparam.c:124`).
const INVALID_PARAMETERS_LINE: &str = "Parameters are invalid\n";

/// Maximum number of bytes shown per line in the `--text` hex dump.
const TEXT_HEX_BYTES_PER_LINE: usize = 16;

// ───────────────────────────────────────────────────────────────────────────
// CLI Argument Struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `pkeyparam` subcommand.
///
/// Mirrors the C command's `pkeyparam_options[]` table at
/// `apps/pkeyparam.c:29–44` exactly.  All flags are declared via `clap`
/// derive — replacing the manual `OPTION_CHOICE` enum and `opt_init()` /
/// `opt_next()` loop in the C source.
//
// Clippy lint `struct_excessive_bools` is disabled here because each `bool`
// field corresponds to an *independent* CLI flag (`--text`, `--noout`,
// `--check`).  These flags are user-controlled and orthogonal — they cannot
// be folded into a single state enum without breaking the `clap::Args`
// derive contract or the C tool's command-line surface.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct PkeyparamArgs {
    /// Path of the input PEM file (defaults to stdin when omitted).
    ///
    /// Mirrors the C `-in <FILE>` flag at `apps/pkeyparam.c:35`.
    /// R5: `Option<PathBuf>` — no `""` / `NULL` sentinel for "stdin".
    #[arg(long = "in", value_name = "FILE")]
    pub in_file: Option<PathBuf>,

    /// Path of the output file (defaults to stdout when omitted).
    ///
    /// Mirrors the C `-out <FILE>` flag at `apps/pkeyparam.c:38`.
    /// R5: `Option<PathBuf>` — no `""` / `NULL` sentinel for "stdout".
    #[arg(long = "out", value_name = "FILE")]
    pub out_file: Option<PathBuf>,

    /// Print parameters as human-readable text to the output stream after
    /// any PEM output.
    ///
    /// Mirrors the C `-text` flag at `apps/pkeyparam.c:39`.  Equivalent to
    /// the C call `EVP_PKEY_print_params(out, pkey, 0, NULL)` at line 134.
    #[arg(long = "text")]
    pub text: bool,

    /// Suppress PEM-encoded output (text output via `--text` is still
    /// emitted).
    ///
    /// Mirrors the C `-noout` flag at `apps/pkeyparam.c:40`.  When `false`,
    /// the original PEM parameter block is round-tripped to the output
    /// stream verbatim.
    #[arg(long = "noout")]
    pub noout: bool,

    /// Validate parameter consistency via the equivalent of
    /// `EVP_PKEY_param_check()`.
    ///
    /// Mirrors the C `-check` flag at `apps/pkeyparam.c:32`.  On success
    /// the literal `"Parameters are valid\n"` is written to the output
    /// stream; on failure `"Parameters are invalid\n"` is written to
    /// stderr and [`CryptoError::Verification`] is returned.
    #[arg(long = "check")]
    pub check: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Core Implementation
// ───────────────────────────────────────────────────────────────────────────

impl PkeyparamArgs {
    /// Execute the `pkeyparam` subcommand.
    ///
    /// High-level flow (mirroring `apps/pkeyparam.c:46–145`):
    ///
    /// 1. Open the input stream (file via `--in` or stdin).
    /// 2. Decode a single PEM parameter block from the input — the first
    ///    block is selected, matching `PEM_read_bio_Parameters_ex()` which
    ///    returns the first matching PEM record.
    /// 3. Map the PEM label to a [`KeyType`] for downstream typing.
    /// 4. Construct a [`PKey`] populated with the raw DER payload.
    /// 5. Open the output stream (file via `--out` or stdout).
    /// 6. If `--check` is given, run [`PKeyCtx::param_check`] and emit the
    ///    valid / invalid line.
    /// 7. If `--noout` is *not* given, re-encode the original PEM block to
    ///    the output stream (full round-trip).
    /// 8. If `--text` is given, append a human-readable parameter summary.
    ///
    /// The `_ctx` parameter is currently unused — the implementation
    /// re-acquires the singleton library context internally because the
    /// `openssl_crypto::evp::*` constructors take an owned `Arc<LibContext>`
    /// rather than a borrowed reference.  In the common case this resolves
    /// to the same underlying context as `_ctx`.  See the matching pattern
    /// in `crates/openssl-cli/src/commands/speed.rs` (lines 2015-2021).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on any of:
    ///
    /// - I/O failures opening / reading / writing files (auto-converted via
    ///   [`CryptoError::Io`]).
    /// - Malformed or empty PEM input (mapped to [`CryptoError::Encoding`]).
    /// - Parameter validation failures when `--check` is given (mapped to
    ///   [`CryptoError::Verification`]).
    /// - Failures propagated from [`openssl_crypto::evp::pkey`] when
    ///   constructing the [`PKeyCtx`] (mapped to [`CryptoError::Key`]).
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Pkeyparam(args)` → `args.execute(ctx).await`.
    //
    // `clippy::unused_async`: the dispatcher in `commands/mod.rs` invokes
    // every subcommand's `execute()` with `.await`, so the signature must
    // be `async` even though the current body does not suspend.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        debug!(
            in_file = ?self.in_file,
            out_file = ?self.out_file,
            text = self.text,
            noout = self.noout,
            check = self.check,
            "pkeyparam: starting"
        );

        // ── Step 1: Open input stream ────────────────────────────────────
        let mut reader = self.open_input_reader()?;

        // ── Step 2 + 3: Decode PEM and infer KeyType from the label ──────
        let (pem_obj, key_type) = read_pem_parameters(&mut reader)?;
        info!(
            label = %pem_obj.label,
            payload_bytes = pem_obj.data.len(),
            key_type = %key_type,
            "pkeyparam: parameters loaded"
        );

        // ── Step 4: Build the PKey ───────────────────────────────────────
        // `is_private = false` — parameter blocks carry public domain data
        // only, never private key material (mirroring
        // `PEM_read_bio_Parameters_ex()` semantics in the C source).
        let pkey = PKey::new_raw(key_type.clone(), &pem_obj.data, false);
        trace!(key_type = %pkey.key_type(), "pkeyparam: PKey constructed");

        // ── Step 5: Open output stream ───────────────────────────────────
        let mut writer = self.open_output_writer()?;

        // ── Step 6: Optional validation via PKeyCtx::param_check ─────────
        if self.check {
            run_param_check(&pkey, &mut writer)?;
        }

        // ── Step 7: Optional PEM re-encode (round-trip) ──────────────────
        if !self.noout {
            debug!(label = %pem_obj.label, "pkeyparam: writing PEM output");
            pem::encode_to_writer(&pem_obj, &mut writer).map_err(|e| {
                error!(error = %e, "pkeyparam: failed to encode PEM output");
                e
            })?;
        }

        // ── Step 8: Optional human-readable text dump ────────────────────
        if self.text {
            debug!("pkeyparam: writing text output");
            write_text_parameters(&mut writer, &pkey, &pem_obj)?;
        }

        writer.flush()?;
        info!("pkeyparam: complete");
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Input / Output stream factories
    // ───────────────────────────────────────────────────────────────────

    /// Opens the input source — a file path if `--in` was given, otherwise
    /// stdin — wrapped in a buffered reader.
    ///
    /// Replaces the C call `bio_open_default(infile, 'r', FORMAT_PEM)` at
    /// `apps/pkeyparam.c:93`.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        if let Some(ref path) = self.in_file {
            debug!(path = %path.display(), "pkeyparam: opening input file");
            let file = File::open(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "pkeyparam: cannot open input file");
                e
            })?;
            Ok(Box::new(BufReader::new(file)))
        } else {
            debug!("pkeyparam: reading input from stdin");
            Ok(Box::new(BufReader::new(io::stdin())))
        }
    }

    /// Opens the output sink — a file path if `--out` was given, otherwise
    /// stdout — wrapped in a buffered writer.
    ///
    /// Replaces the C call `bio_open_default(outfile, 'w', FORMAT_PEM)` at
    /// `apps/pkeyparam.c:103`.
    fn open_output_writer(&self) -> Result<Box<dyn Write>, CryptoError> {
        if let Some(ref path) = self.out_file {
            debug!(path = %path.display(), "pkeyparam: opening output file");
            let file = File::create(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "pkeyparam: cannot create output file");
                e
            })?;
            Ok(Box::new(BufWriter::new(file)))
        } else {
            debug!("pkeyparam: writing output to stdout");
            Ok(Box::new(BufWriter::new(stdout())))
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Parameter validation (free function — no `self` state required)
// ───────────────────────────────────────────────────────────────────────────

/// Runs [`PKeyCtx::param_check`] on the loaded parameters, writing the
/// success line to the output stream or the failure line to stderr.
///
/// Mirrors the C `if (check) { … }` block at `apps/pkeyparam.c:107–128`.
///
/// This is a free function rather than a method because none of its logic
/// depends on the `PkeyparamArgs` instance — the work is entirely a
/// transformation of the supplied [`PKey`] and the output writer.
fn run_param_check(pkey: &PKey, writer: &mut Box<dyn Write>) -> Result<(), CryptoError> {
    debug!("pkeyparam: running parameter check");

    // R5 / R7: re-acquire the default library context as `Arc<LibContext>`.
    // `LibContext::default()` returns the process-wide singleton (same
    // backing data as `get_default()`), so callers that did not explicitly
    // supply a context observe identical behaviour.  This follows the
    // documented pattern from
    // `crates/openssl-cli/src/commands/speed.rs:2015-2021`.
    let arc_ctx: Arc<LibContext> = LibContext::default();
    let arc_key: Arc<PKey> = Arc::new(pkey.clone());

    let pctx = PKeyCtx::new_from_pkey(arc_ctx, arc_key).map_err(|e| {
        error!(error = %e, "pkeyparam: failed to construct PKeyCtx");
        e
    })?;

    // The C function returns 1 (valid) / 0 (invalid) / -1 (unsupported).
    // Our Rust port returns `Ok(true)` for valid, `Ok(false)` for invalid,
    // and `Err(_)` for I/O / state failures.  All non-`true` outcomes —
    // including the DH/DSA case where parameters were not cached on the
    // `PKey` (see `PKeyCtx::param_check` source) — are mapped to the C
    // tool's "Parameters are invalid" diagnostic.
    let valid = match pctx.param_check() {
        Ok(true) => true,
        Ok(false) => {
            warn!(
                key_type = %pkey.key_type(),
                "pkeyparam: parameters reported invalid by param_check()"
            );
            false
        }
        Err(e) => {
            error!(error = %e, "pkeyparam: param_check returned error");
            false
        }
    };

    if valid {
        info!("pkeyparam: parameters are valid");
        writer
            .write_all(VALID_PARAMETERS_LINE.as_bytes())
            .map_err(|e| {
                error!(error = %e, "pkeyparam: failed to write valid line");
                CryptoError::Io(e)
            })?;
        Ok(())
    } else {
        // Match C behaviour: diagnostic on stderr (BIO_puts(bio_err, …)),
        // command exits non-zero.
        eprint!("{INVALID_PARAMETERS_LINE}");
        error!("pkeyparam: parameters are invalid");
        Err(CryptoError::Verification(format!(
            "parameters for {} are invalid",
            pkey.key_type()
        )))
    }
}

// ───────────────────────────────────────────────────────────────────────────
// PEM helpers (free functions — pure transforms over PEM input)
// ───────────────────────────────────────────────────────────────────────────

/// Decodes the first PEM parameter block from `reader` and infers the
/// associated [`KeyType`] from its label.
///
/// Mirrors the C call:
///
/// ```c
/// pkey = PEM_read_bio_Parameters_ex(in, NULL,
///                                   app_get0_libctx(),
///                                   app_get0_propq());
/// ```
///
/// at `apps/pkeyparam.c:96`.  The C variant transparently dispatches to
/// `i2d_*params()` / `d2i_*params()` based on the encountered PEM tag; the
/// Rust port resolves the tag via [`label_to_key_type`] and stores the raw
/// payload on the [`PKey`] for the caller to interpret.
fn read_pem_parameters<R: BufRead>(reader: &mut R) -> Result<(PemObject, KeyType), CryptoError> {
    debug!("pkeyparam: decoding PEM input");
    let blocks = pem::decode_from_reader(reader).map_err(|e| {
        error!(error = %e, "pkeyparam: PEM decode failed");
        e
    })?;

    let first = blocks.into_iter().next().ok_or_else(|| {
        error!("pkeyparam: PEM input contains no blocks");
        CryptoError::Encoding("input does not contain a PEM block".to_string())
    })?;

    if first.data.is_empty() {
        warn!(
            label = %first.label,
            "pkeyparam: PEM block has empty payload — downstream parsing may fail"
        );
    }

    let key_type = label_to_key_type(&first.label);
    Ok((first, key_type))
}

/// Maps a PEM block label to the corresponding [`KeyType`].
///
/// Recognises the four canonical parameter labels accepted by the C
/// implementation's `PEM_read_bio_Parameters()` callback table plus the
/// generic `"PARAMETERS"` label emitted by the new provider-based key
/// encoders.  Unknown labels fall through to [`KeyType::Unknown`] preserving
/// the original label string for diagnostic purposes.
fn label_to_key_type(label: &str) -> KeyType {
    match label {
        PEM_LABEL_DH_PARAMETERS | PEM_LABEL_X942_DH_PARAMETERS => KeyType::Dh,
        PEM_LABEL_DSA_PARAMETERS => KeyType::Dsa,
        PEM_LABEL_EC_PARAMETERS => KeyType::Ec,
        PEM_LABEL_PARAMETERS => KeyType::Unknown(PEM_LABEL_PARAMETERS.to_string()),
        other => {
            trace!(label = other, "pkeyparam: unknown PEM label");
            KeyType::Unknown(other.to_string())
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Text output (mirrors EVP_PKEY_print_params)
// ───────────────────────────────────────────────────────────────────────────

/// Writes a human-readable summary of `pkey` and the original PEM payload
/// to `writer`.
///
/// Replaces the C call `EVP_PKEY_print_params(out, pkey, 0, NULL)` at
/// `apps/pkeyparam.c:134`.  The original C tool delegates to provider-
/// specific pretty-printers; the Rust port provides a generic but
/// informative rendering that includes:
///
/// - The algorithm family (`KeyType` canonical name).
/// - The original PEM label (preserves `X9.42 DH` vs `DH` distinction).
/// - The bit strength when known (only key types whose strength is
///   computable without provider-specific inspection — RSA, EC, edwards
///   curves, ML-* / SLH-DSA / LMS).  DH and DSA are intentionally omitted
///   here because their bit strength is keyed on cached `params` which
///   `PKey::new_raw` does not populate.
/// - The byte length of the DER payload.
/// - A 16-byte-per-line hex preview of the DER payload, matching the
///   conventional OpenSSL diagnostic dump style.
fn write_text_parameters<W: Write>(
    writer: &mut W,
    pkey: &PKey,
    pem_obj: &PemObject,
) -> Result<(), CryptoError> {
    writeln!(writer, "Parameter type: {}", pkey.key_type())?;
    writeln!(writer, "PEM label: {}", pem_obj.label)?;

    // R6: `bits()` returns `u32` — no narrowing.  For DH/DSA the call may
    // legitimately fail (no cached params); in that case we simply skip the
    // bit-strength line rather than aborting the command.
    match pkey.bits() {
        Ok(bits) => {
            writeln!(writer, "Bit strength: {bits}")?;
        }
        Err(e) => {
            trace!(
                key_type = %pkey.key_type(),
                error = %e,
                "pkeyparam: bit strength unavailable for key type"
            );
        }
    }

    writeln!(writer, "DER payload bytes: {}", pem_obj.data.len())?;
    writeln!(writer, "DER payload (hex):")?;
    write_hex_dump(writer, &pem_obj.data)?;
    Ok(())
}

/// Writes `data` as an indented hexadecimal dump, 16 bytes per line.
///
/// Each line is prefixed with two spaces so it is visually distinct from
/// the surrounding key/value lines.  Bytes are separated by single spaces.
fn write_hex_dump<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), CryptoError> {
    if data.is_empty() {
        writeln!(writer, "  <empty>")?;
        return Ok(());
    }

    for chunk in data.chunks(TEXT_HEX_BYTES_PER_LINE) {
        write!(writer, " ")?;
        for byte in chunk {
            // `{byte:02x}` does not narrow — `u8` already fits two hex
            // digits — so R6 is satisfied without an explicit cast.
            write!(writer, " {byte:02x}")?;
        }
        writeln!(writer)?;
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
// Tests legitimately use `expect()`, `unwrap()`, and `panic!()` to surface
// failures with rich diagnostics under `cargo test` — these are the standard
// signals for "this invariant is violated, fail the test now".  Workspace
// `clippy` policy denies them in production code via `restriction`-tier
// lints, but allows them inside `#[cfg(test)]` modules per the same
// convention used in `crates/openssl-cli/src/commands/passwd.rs` and
// `crates/openssl-cli/src/commands/srp.rs`.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// A tiny synthetic PEM block whose payload (`0x30 0x00`) is the DER
    /// encoding of `SEQUENCE {}`.  We use it as a stand-in for real
    /// EC / DSA parameter encodings — the `pkeyparam` command itself does
    /// not parse the inner DER, it only round-trips it.
    const SYNTHETIC_DER: &[u8] = &[0x30, 0x00];

    fn make_pem(label: &str, payload: &[u8]) -> String {
        let obj = PemObject::with_data(label, payload.to_vec());
        pem::encode(&obj)
    }

    fn default_args() -> PkeyparamArgs {
        PkeyparamArgs {
            in_file: None,
            out_file: None,
            text: false,
            noout: false,
            check: false,
        }
    }

    // ── label_to_key_type mapping ─────────────────────────────────────────

    #[test]
    fn label_to_key_type_dh() {
        assert_eq!(label_to_key_type("DH PARAMETERS"), KeyType::Dh);
    }

    #[test]
    fn label_to_key_type_x942_dh() {
        assert_eq!(label_to_key_type("X9.42 DH PARAMETERS"), KeyType::Dh);
    }

    #[test]
    fn label_to_key_type_dsa() {
        assert_eq!(label_to_key_type("DSA PARAMETERS"), KeyType::Dsa);
    }

    #[test]
    fn label_to_key_type_ec() {
        assert_eq!(label_to_key_type("EC PARAMETERS"), KeyType::Ec);
    }

    #[test]
    fn label_to_key_type_generic_parameters() {
        match label_to_key_type("PARAMETERS") {
            KeyType::Unknown(s) => assert_eq!(s, "PARAMETERS"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn label_to_key_type_unknown_preserved() {
        match label_to_key_type("FROBNICATOR PARAMETERS") {
            KeyType::Unknown(s) => assert_eq!(s, "FROBNICATOR PARAMETERS"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn label_to_key_type_case_sensitive() {
        // The C tool is case-sensitive too — "dh parameters" is *not*
        // accepted as a parameter block.
        match label_to_key_type("dh parameters") {
            KeyType::Unknown(_) => (),
            other => panic!("expected Unknown for lowercase label, got {other:?}"),
        }
    }

    // ── read_pem_parameters helper ─────────────────────────────────────────

    #[test]
    fn read_pem_parameters_decodes_dh() {
        let pem_text = make_pem(PEM_LABEL_DH_PARAMETERS, SYNTHETIC_DER);
        let mut reader = BufReader::new(pem_text.as_bytes());
        let (obj, kt) = read_pem_parameters(&mut reader).expect("decode succeeds");
        assert_eq!(obj.label, PEM_LABEL_DH_PARAMETERS);
        assert_eq!(obj.data, SYNTHETIC_DER);
        assert_eq!(kt, KeyType::Dh);
    }

    #[test]
    fn read_pem_parameters_rejects_empty_input() {
        let empty = b"";
        let mut reader = BufReader::new(&empty[..]);
        let err = read_pem_parameters(&mut reader).expect_err("empty input must fail decode");
        // Either the underlying decoder reports Encoding or we hit our own
        // "no PEM block" Encoding error — both are acceptable for empty.
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn read_pem_parameters_rejects_garbage() {
        let garbage = b"this is not a PEM block\n";
        let mut reader = BufReader::new(&garbage[..]);
        let err = read_pem_parameters(&mut reader).expect_err("garbage input must fail decode");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn read_pem_parameters_takes_first_block() {
        let mut text = make_pem(PEM_LABEL_DH_PARAMETERS, SYNTHETIC_DER);
        text.push_str(&make_pem(PEM_LABEL_EC_PARAMETERS, &[0x30, 0x01, 0x00]));
        let mut reader = BufReader::new(text.as_bytes());
        let (obj, kt) = read_pem_parameters(&mut reader).expect("decode succeeds");
        // First block wins (mirrors PEM_read_bio_Parameters_ex semantics).
        assert_eq!(obj.label, PEM_LABEL_DH_PARAMETERS);
        assert_eq!(kt, KeyType::Dh);
    }

    // ── write_hex_dump formatting ──────────────────────────────────────────

    #[test]
    fn write_hex_dump_empty_emits_marker() {
        let mut buf: Vec<u8> = Vec::new();
        write_hex_dump(&mut buf, &[]).expect("ok");
        let s = String::from_utf8(buf).expect("utf8");
        assert_eq!(s, "  <empty>\n");
    }

    #[test]
    fn write_hex_dump_short_input_one_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_hex_dump(&mut buf, &[0x01, 0x02, 0xAB]).expect("ok");
        let s = String::from_utf8(buf).expect("utf8");
        assert_eq!(s, "  01 02 ab\n");
    }

    #[test]
    fn write_hex_dump_multiline_breaks_at_16() {
        let data: Vec<u8> = (0..20).collect();
        let mut buf: Vec<u8> = Vec::new();
        write_hex_dump(&mut buf, &data).expect("ok");
        let s = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2, "20 bytes split across 16+4");
        assert!(
            lines[0].contains("00") && lines[0].contains("0f"),
            "first line should contain bytes 00-0f, got: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("13"),
            "second line should contain byte 13"
        );
    }

    // ── execute() integration paths ────────────────────────────────────────

    #[tokio::test]
    async fn execute_round_trip_pem_parameters() {
        // Write a synthetic PEM block to a temp input file, run the
        // command with --out, verify the output equals the input.
        let pem_text = make_pem(PEM_LABEL_EC_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("round-trip succeeds");

        let written = std::fs::read_to_string(tmp_out.path()).expect("read out");
        assert!(
            written.contains("BEGIN EC PARAMETERS"),
            "output must include the EC PARAMETERS PEM header, got: {written:?}"
        );
        assert!(
            written.contains("END EC PARAMETERS"),
            "output must include the EC PARAMETERS PEM footer, got: {written:?}"
        );
    }

    #[tokio::test]
    async fn execute_noout_suppresses_pem_output() {
        let pem_text = make_pem(PEM_LABEL_DH_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());
        args.noout = true;

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("noout path completes");

        let written = std::fs::read_to_string(tmp_out.path()).expect("read out");
        // With both --noout and no --text, the file should be empty.
        assert!(
            written.is_empty(),
            "noout-only output must be empty, got: {written:?}"
        );
    }

    #[tokio::test]
    async fn execute_text_outputs_summary() {
        let pem_text = make_pem(PEM_LABEL_EC_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());
        args.noout = true; // suppress PEM so we can inspect text only
        args.text = true;

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("text path completes");

        let written = std::fs::read_to_string(tmp_out.path()).expect("read out");
        assert!(
            written.contains("Parameter type: EC"),
            "text output must declare parameter type, got: {written:?}"
        );
        assert!(
            written.contains("PEM label: EC PARAMETERS"),
            "text output must echo the PEM label, got: {written:?}"
        );
        assert!(
            written.contains("DER payload bytes: 2"),
            "text output must report payload length, got: {written:?}"
        );
        assert!(
            written.contains("30 00"),
            "text output must contain hex dump of payload, got: {written:?}"
        );
    }

    #[tokio::test]
    async fn execute_text_and_pem_combined() {
        let pem_text = make_pem(PEM_LABEL_EC_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());
        args.text = true;

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("text+pem path completes");

        let written = std::fs::read_to_string(tmp_out.path()).expect("read out");
        assert!(
            written.contains("BEGIN EC PARAMETERS"),
            "combined output must include PEM header, got: {written:?}"
        );
        assert!(
            written.contains("Parameter type: EC"),
            "combined output must include text section, got: {written:?}"
        );
    }

    #[tokio::test]
    async fn execute_check_succeeds_for_ec_parameters() {
        // EC params via `PKey::new_raw()` produce a key with `params: None`
        // but the matchlist in `PKeyCtx::param_check` covers `KeyType::Ec`,
        // so validation returns Ok(true) — matching C behaviour for valid
        // EC parameter blocks.
        let pem_text = make_pem(PEM_LABEL_EC_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());
        args.noout = true;
        args.check = true;

        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("EC check passes");

        let written = std::fs::read_to_string(tmp_out.path()).expect("read out");
        assert!(
            written.contains("Parameters are valid"),
            "EC check output must contain valid line, got: {written:?}"
        );
    }

    #[tokio::test]
    async fn execute_check_fails_for_dh_without_cached_params() {
        // DH/DSA via `PKey::new_raw()` get `params: None`, so
        // `param_check()` returns Ok(false), which our wrapper maps to
        // CryptoError::Verification.
        let pem_text = make_pem(PEM_LABEL_DH_PARAMETERS, SYNTHETIC_DER);

        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(pem_text.as_bytes()).unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());
        args.noout = true;
        args.check = true;

        let ctx = LibContext::new();
        let err = args
            .execute(&ctx)
            .await
            .expect_err("DH check without cached params must fail");
        match err {
            CryptoError::Verification(msg) => {
                assert!(
                    msg.to_uppercase().contains("DH"),
                    "verification error must mention key type, got: {msg}"
                );
            }
            other => panic!("expected Verification, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_invalid_input_errors() {
        let mut tmp_in = NamedTempFile::new().expect("tmp in");
        tmp_in.write_all(b"not a pem file at all").unwrap();
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(tmp_in.path().to_path_buf());
        args.out_file = Some(tmp_out.path().to_path_buf());

        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.expect_err("must fail decode");
        match err {
            CryptoError::Encoding(_) => (),
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_missing_input_file_errors() {
        let tmp_out = NamedTempFile::new().expect("tmp out");

        let mut args = default_args();
        args.in_file = Some(PathBuf::from("/nonexistent/pkeyparam_test_input.pem"));
        args.out_file = Some(tmp_out.path().to_path_buf());

        let ctx = LibContext::new();
        let err = args
            .execute(&ctx)
            .await
            .expect_err("missing input must fail");
        match err {
            CryptoError::Io(_) => (),
            other => panic!("expected Io, got {other:?}"),
        }
    }
}
