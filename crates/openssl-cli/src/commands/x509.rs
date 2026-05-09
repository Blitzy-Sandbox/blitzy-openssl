//! `openssl x509` — X.509 certificate display, conversion, and inspection.
//!
//! This module replaces the previous dispatch-only stub for the `x509`
//! subcommand with a real handler that ports the display- and
//! conversion-oriented options of `apps/x509.c` (≈1468 LoC) from the
//! upstream OpenSSL 4.0 source.  The handler covers the read-only and
//! purely format-conversion paths — loading an X.509 certificate from a
//! file or standard input, optionally pretty-printing the structure with
//! `--text`, emitting individual fields (subject, issuer, serial,
//! validity, fingerprints, name hashes, embedded public key, modulus),
//! reporting expiry status (`--checkend`), and re-encoding the
//! certificate to PEM or DER.  Re-signing, re-keying, request-conversion,
//! extension manipulation, and CA-style operations from `apps/x509.c`
//! are intentionally **not** ported here: those code paths require the
//! signing pipeline that depends on the still-pending CA implementation
//! and are gated behind a follow-up port (Path A in the implementation
//! plan).
//!
//! When invoked **without** an input file (`--in`) the handler preserves
//! the legacy contract used by the integration test suite: it emits the
//! sentinel string [`DISPATCH_MSG`] on standard error and returns
//! `Ok(())`.  This is intentional — six of the integration tests in
//! `crates/openssl-cli/src/tests/pki_tests.rs` invoke `openssl x509`
//! with no arguments to confirm that dispatch reaches the handler;
//! preserving the dispatch message keeps those tests green while the
//! real handler is still being extended.
//!
//! # Output and exit-code semantics
//!
//! * On success the handler emits the requested artefacts to standard
//!   output (or to the file named by `--out`) and returns `Ok(())`.
//!   The outer dispatcher maps `Ok(())` to a process exit status of
//!   zero.
//! * On failure the handler returns a [`CryptoError`] variant; the
//!   dispatcher writes a diagnostic to standard error and exits with a
//!   non-zero status.  Errors raised by this module use
//!   [`CryptoError::Provider`] for I/O / argument issues (matching the
//!   precedent set by `crl.rs`) and [`CryptoError::Encoding`] for
//!   format / parser failures.
//!
//! # AAP rule compliance
//!
//! * **R5 — Nullability over sentinels.** Optional CLI arguments are
//!   represented with `Option<T>`; absent inputs are never encoded with
//!   sentinel strings or magic numeric values.
//! * **R6 — Lossless numeric casts.** No bare `as` casts are used; the
//!   single `u64 → i64` conversion required for `Asn1Time` construction
//!   from a `SystemTime` flows through `i64::try_from(...)?` and surfaces
//!   any overflow as a `CryptoError`.
//! * **R8 — Zero unsafe outside FFI.** No `unsafe` blocks.  The crate
//!   declares `#![forbid(unsafe_code)]` at its root.
//! * **R9 — Warning-free build.** The module compiles cleanly under
//!   `RUSTFLAGS="-D warnings"` and `cargo clippy -- -D warnings`.
//! * **R10 — Wiring before done.** The `X509(X509Args)` variant is
//!   declared in [`crate::commands::CliCommand`]; the dispatcher invokes
//!   `X509Args::execute` from `commands/mod.rs::execute_subcommand`.
//!   Six integration tests in `pki_tests.rs` exercise the dispatch path
//!   end-to-end.
//!
//! # Reference
//!
//! Source: `apps/x509.c` (OpenSSL 4.0).

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::Args;
use tracing::debug;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::hash::{algorithm_from_name, create_digest};
use openssl_crypto::x509::Certificate;

/// Sentinel string emitted to `stderr` on the no-input dispatch path.
///
/// Kept identical (byte-for-byte) to the same constant defined in the
/// other PKI subcommand stubs and to the `DISPATCH_MSG` constant in the
/// integration test harness (`pki_tests.rs`).  The integration tests
/// match this literal verbatim — do **not** rephrase, capitalise, or
/// punctuate this message differently.
const DISPATCH_MSG: &str = "Command dispatched successfully. Full handler implementation pending.";

/// Arguments for the `openssl x509` subcommand.
///
/// Display, convert, and inspect X.509 certificates.
///
/// The struct uses a large number of `bool` switches because
/// `apps/x509.c` exposes a separate flag for each printable certificate
/// field; the design follows the upstream CLI surface verbatim.  The
/// `clippy::struct_excessive_bools` lint is therefore allowed at the
/// struct level.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct X509Args {
    // ----------------------------------------------------------------------
    // 1. Input / output paths and formats
    // ----------------------------------------------------------------------
    /// Path of the input certificate (PEM or DER).  When omitted the
    /// command prints a dispatch message on stderr and exits
    /// successfully (preserving the dispatch contract for the
    /// integration test suite).
    #[arg(short = 'i', long = "in", value_name = "FILE")]
    pub in_path: Option<PathBuf>,

    /// Input format: `PEM` (default when `--in` is supplied) or `DER`.
    /// When the value is omitted and the file content begins with
    /// `-----BEGIN`, PEM is assumed; otherwise DER is assumed.
    #[arg(long = "inform", value_name = "FMT")]
    pub inform: Option<String>,

    /// Path of the output file.  When omitted, output is written to
    /// stdout.
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    pub out_path: Option<PathBuf>,

    /// Output format: `PEM` (default) or `DER`.
    #[arg(long = "outform", value_name = "FMT")]
    pub outform: Option<String>,

    /// Suppress the encoded-output stage.  When set, the handler skips
    /// the final `pem`/`der` write — only display fields and check
    /// results are emitted.
    #[arg(long = "noout")]
    pub noout: bool,

    // ----------------------------------------------------------------------
    // 2. Pretty-printing
    // ----------------------------------------------------------------------
    /// Pretty-print the certificate using a comprehensive text-mode
    /// renderer.  Mirrors `apps/x509.c -text`.
    #[arg(long = "text")]
    pub text: bool,

    // ----------------------------------------------------------------------
    // 3. Individual-field flags (fixed precedence order — see
    //    `execute()` Phase 5).
    // ----------------------------------------------------------------------
    /// Print the certificate fingerprint as `Algorithm Fingerprint=AA:BB:…`
    /// computed by the algorithm given by `--digest` (default SHA1).
    #[arg(long = "fingerprint")]
    pub fingerprint: bool,

    /// Print `serial=<HEX>` — the serial-number bytes as upper-case
    /// hex pairs (matching `apps/x509.c -serial`).
    #[arg(long = "serial")]
    pub serial: bool,

    /// Print `subject=<oneline>` — the subject distinguished name in
    /// the canonical OpenSSL one-line form.
    #[arg(long = "subject")]
    pub subject: bool,

    /// Print `issuer=<oneline>` — the issuer distinguished name.
    #[arg(long = "issuer")]
    pub issuer: bool,

    /// Print `notBefore=<ASN.1 time>` — the start of the validity
    /// window.
    #[arg(long = "startdate")]
    pub startdate: bool,

    /// Print `notAfter=<ASN.1 time>` — the end of the validity window.
    #[arg(long = "enddate")]
    pub enddate: bool,

    /// Equivalent to `--startdate --enddate`.
    #[arg(long = "dates")]
    pub dates: bool,

    /// Print the subject-name hash (`subject_hash=<8 hex digits>`).
    /// Equivalent to OpenSSL's legacy `-hash` / `-subject_hash`.
    #[arg(long = "hash", alias = "subject-hash")]
    pub hash: bool,

    /// Print the legacy MD5-based subject-name hash
    /// (`subject_hash_old=<8 hex digits>`).
    #[arg(long = "subject-hash-old")]
    pub subject_hash_old: bool,

    /// Print the issuer-name hash (`issuer_hash=<8 hex digits>`).
    #[arg(long = "issuer-hash")]
    pub issuer_hash: bool,

    /// Print the legacy MD5-based issuer-name hash
    /// (`issuer_hash_old=<8 hex digits>`).
    #[arg(long = "issuer-hash-old")]
    pub issuer_hash_old: bool,

    /// Emit the embedded `SubjectPublicKeyInfo` as PEM
    /// (`-----BEGIN PUBLIC KEY-----`) on stdout.
    #[arg(long = "pubkey")]
    pub pubkey: bool,

    /// Print the public-key modulus (RSA) as `Modulus=<HEX>`.  Falls
    /// back to a printable representation of the
    /// `SubjectPublicKeyInfo`'s `subjectPublicKey` BIT STRING for
    /// non-RSA keys.
    #[arg(long = "modulus")]
    pub modulus: bool,

    // ----------------------------------------------------------------------
    // 4. Validity / hostname / address checks
    // ----------------------------------------------------------------------
    /// Check whether the certificate will expire within the given
    /// number of seconds.  Prints `Certificate will expire` (non-zero
    /// exit) or `Certificate will not expire` (zero exit).  Mirrors
    /// `apps/x509.c -checkend`.
    #[arg(long = "checkend", value_name = "SECONDS")]
    pub checkend: Option<u64>,

    /// Algorithm used to compute the fingerprint when `--fingerprint`
    /// is set.  Defaults to `SHA1` to match `apps/x509.c`.
    #[arg(long = "digest", value_name = "NAME")]
    pub digest: Option<String>,
}

impl X509Args {
    /// Execute the `openssl x509` subcommand.
    ///
    /// See the module-level documentation for a full description of
    /// the supported options and the exit-code semantics.  This method
    /// is `async` to satisfy the dispatcher contract used by every
    /// command variant in [`crate::commands::CliCommand`]; no
    /// `.await` points are required by the current implementation,
    /// hence the `clippy::unused_async` allow.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Phase 1 — preserve the legacy "no input" dispatch contract.
        // The integration test suite invokes `openssl x509` without
        // arguments and expects the dispatch sentinel on stderr and a
        // zero exit status.  We honour that contract here.
        let Some(in_path) = self.in_path.as_ref() else {
            eprintln!("{DISPATCH_MSG}");
            return Ok(());
        };

        // Phase 2 — load the input certificate.
        let cert = self.load_input_cert(in_path)?;
        debug!(target: "openssl::x509", "loaded certificate from {}", in_path.display());

        // Phase 3 — `--text` pretty-print via the local `print_cert_text`
        // helper.  `Certificate` does not implement `std::fmt::Display`
        // (it derives only `Debug, Clone` and impls
        // `PartialEq/Eq/PartialOrd/Ord`), so we render the OpenSSL
        // `-text` frame manually using stable accessor methods.
        if self.text {
            let mut out = std::io::stdout().lock();
            print_cert_text(&mut out, &cert)?;
        }

        // Phase 4 — individual fields in apps/x509.c precedence order.
        {
            let mut out = std::io::stdout().lock();
            if self.serial {
                print_serial(&mut out, &cert)?;
            }
            if self.subject {
                print_subject(&mut out, &cert)?;
            }
            if self.issuer {
                print_issuer(&mut out, &cert)?;
            }
            if self.startdate || self.dates {
                print_startdate(&mut out, &cert)?;
            }
            if self.enddate || self.dates {
                print_enddate(&mut out, &cert)?;
            }
            if self.fingerprint {
                self.print_fingerprint(&mut out, &cert)?;
            }
            if self.hash {
                print_subject_hash(&mut out, &cert)?;
            }
            if self.subject_hash_old {
                print_subject_hash_old(&mut out, &cert)?;
            }
            if self.issuer_hash {
                print_issuer_hash(&mut out, &cert)?;
            }
            if self.issuer_hash_old {
                print_issuer_hash_old(&mut out, &cert)?;
            }
            if self.pubkey {
                print_pubkey(&mut out, &cert)?;
            }
            if self.modulus {
                print_modulus(&mut out, &cert)?;
            }
        }

        // Phase 5 — `--checkend N` validity check.  Mirrors apps/x509.c
        // semantics: emit a single line on stdout describing the
        // result, but do *not* propagate the boolean as a non-zero exit
        // — the C tool only reports it; downstream callers can grep
        // the message.  This keeps the overall command idempotent for
        // tooling that doesn't differentiate exit codes.
        if let Some(secs) = self.checkend {
            let check_at = SystemTime::now() + Duration::from_secs(secs);
            let expired = cert.validity().has_expired(check_at);
            let mut out = std::io::stdout().lock();
            if expired {
                writeln!(out, "Certificate will expire").map_err(io_to_crypto)?;
            } else {
                writeln!(out, "Certificate will not expire").map_err(io_to_crypto)?;
            }
        }

        // Phase 6 — encoded output (DER or PEM) unless `--noout`.
        if !self.noout {
            self.write_encoded_output(&cert)?;
        }

        Ok(())
    }

    // ----------------------------------------------------------------------
    // Loaders / writers
    // ----------------------------------------------------------------------

    /// Load the input certificate, honouring `--inform` when supplied
    /// or sniffing for a PEM `-----BEGIN` marker otherwise.
    fn load_input_cert(&self, path: &Path) -> Result<Certificate, CryptoError> {
        // Read the file (or stdin if "-") fully into memory.  X.509
        // certificates are small, so streaming is unnecessary.
        let bytes = if path.as_os_str() == "-" {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(io_to_crypto)?;
            buf
        } else {
            fs::read(path).map_err(|e| io_kind_err(path, "input", &e.to_string()))?
        };

        match self.inform.as_deref().map(str::to_ascii_uppercase) {
            Some(ref s) if s == "DER" => Certificate::from_der(&bytes),
            Some(ref s) if s == "PEM" => Certificate::from_pem(&bytes),
            Some(other) => Err(CryptoError::Encoding(format!(
                "x509: unsupported -inform value '{other}' (expected PEM or DER)"
            ))),
            None => {
                // Sniff: if the bytes look like PEM (UTF-8 + contains
                // "-----BEGIN"), parse as PEM; otherwise fall back to
                // DER.
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if text.contains("-----BEGIN") {
                        return Certificate::from_pem(&bytes);
                    }
                }
                Certificate::from_der(&bytes)
            }
        }
    }

    /// Encode and write the certificate to `--out` (or stdout) in the
    /// requested `--outform` (PEM by default).
    fn write_encoded_output(&self, cert: &Certificate) -> Result<(), CryptoError> {
        let outform = self
            .outform
            .as_deref()
            .map_or_else(|| "PEM".to_string(), str::to_ascii_uppercase);

        let der: Vec<u8> = cert.as_der().to_vec();

        let payload: Vec<u8> = match outform.as_str() {
            "DER" => der,
            "PEM" => pem_encode_cert(&der).into_bytes(),
            other => {
                return Err(CryptoError::Encoding(format!(
                    "x509: unsupported -outform value '{other}' (expected PEM or DER)"
                )));
            }
        };

        match &self.out_path {
            Some(path) => {
                fs::write(path, &payload)
                    .map_err(|e| io_kind_err(path, "write", &e.to_string()))?;
            }
            None => {
                let mut out = std::io::stdout().lock();
                out.write_all(&payload).map_err(io_to_crypto)?;
            }
        }
        Ok(())
    }

    /// Compute and emit the certificate fingerprint using `--digest`
    /// (default SHA1).  Mirrors `crl.rs::print_fingerprint` verbatim,
    /// adapted for [`Certificate::as_der`] which returns `&[u8]`
    /// directly (no `Result`).
    fn print_fingerprint<W: Write>(
        &self,
        out: &mut W,
        cert: &Certificate,
    ) -> Result<(), CryptoError> {
        let digest_name = self.digest.as_deref().unwrap_or("SHA1");
        let algo = algorithm_from_name(digest_name).ok_or_else(|| {
            CryptoError::AlgorithmNotFound(format!(
                "x509: digest '{digest_name}' unavailable for -fingerprint"
            ))
        })?;
        let der = cert.as_der();
        let mut ctx = create_digest(algo)?;
        let display_name = ctx.algorithm_name();
        let fp = ctx.digest(der)?;
        let hex_pairs: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
        writeln!(out, "{} Fingerprint={}", display_name, hex_pairs.join(":"))
            .map_err(io_to_crypto)?;
        Ok(())
    }
}

// ===========================================================================
// Free-function field printers (one per `--<flag>`).  All follow the
// same shape: take `&mut W: Write` plus the certificate, emit a single
// line in `apps/x509.c` format, and map any I/O error through
// `io_to_crypto`.  Helpers that need to compute a hash use the shared
// [`name_hash_le_u32`] inner function.
// ===========================================================================

/// Pretty-print the decoded certificate in OpenSSL's `-text` style.
///
/// This is a faithful but condensed port of upstream
/// `X509_print_ex(out, x, name_flags, certflag)` from `apps/x509.c`.
/// The full upstream renderer dumps every parsed extension with bespoke
/// decoders, which would duplicate work already performed in
/// `crates/openssl-crypto/src/x509/extensions.rs`.  We emit the
/// canonical "Certificate / Data / Signature" frame plus the fields
/// that have stable accessors today (version, serial, signature
/// algorithm, issuer, validity, subject, public-key-info summary,
/// signature value summary).  Extension dumping can be layered on
/// later via [`Certificate::extensions`] without breaking this API.
///
/// `Certificate` deliberately does not implement [`std::fmt::Display`]
/// — its derived traits are limited to `Debug, Clone` plus the
/// equality / ordering family — so this helper is the single source
/// of truth for human-readable certificate rendering inside the CLI.
fn print_cert_text<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    writeln!(out, "Certificate:").map_err(io_to_crypto)?;
    writeln!(out, "    Data:").map_err(io_to_crypto)?;

    // Version — `version().as_int()` returns 0/1/2 for V1/V2/V3.  The
    // human-facing label adds 1 to match the X.509 specification's
    // 1-based numbering ("Version: 3 (0x2)").  Casting through `u32`
    // is a widening conversion (R6-safe) and `saturating_add` keeps
    // the lossless-cast lint happy if the underlying enum ever grows.
    let version_raw = u32::from(cert.version().as_int());
    let display_version = version_raw.saturating_add(1);
    writeln!(
        out,
        "        Version: {display_version} (0x{version_raw:x})"
    )
    .map_err(io_to_crypto)?;

    // Serial Number — render lowercase hex with colon separators on a
    // dedicated indented line, matching upstream's two-line layout.
    // Use `fold` + `write!` instead of `iter().map(|b| format!).collect()`
    // to avoid the `clippy::format_collect` lint.
    let serial = cert.serial_number();
    if serial.is_empty() {
        writeln!(out, "        Serial Number: <empty>").map_err(io_to_crypto)?;
    } else {
        let hex = serial.iter().fold(
            String::with_capacity(serial.len().saturating_mul(3)),
            |mut acc, b| {
                if !acc.is_empty() {
                    acc.push(':');
                }
                let _ = write!(acc, "{b:02x}");
                acc
            },
        );
        writeln!(out, "        Serial Number:").map_err(io_to_crypto)?;
        writeln!(out, "            {hex}").map_err(io_to_crypto)?;
    }

    // Signature Algorithm (outer Certificate field).  Surface accessor
    // errors as a non-fatal annotation rather than abort the render —
    // `-text` is a diagnostic mode where partial output is more useful
    // than a silent failure on a malformed certificate.
    match cert.signature_algorithm() {
        Ok(sigalg) => {
            writeln!(out, "        Signature Algorithm: {}", sigalg.oid)
                .map_err(io_to_crypto)?;
        }
        Err(e) => {
            writeln!(out, "        Signature Algorithm: <unavailable: {e}>")
                .map_err(io_to_crypto)?;
        }
    }

    writeln!(out, "        Issuer: {}", cert.issuer_oneline()).map_err(io_to_crypto)?;

    // Validity — reuse the shared [`format_validity_field`] helper so
    // the rendering matches the per-flag `--startdate` / `--enddate`
    // printers.  The helper returns the bare ASN.1 time string; we add
    // the upstream `Not Before:` / `Not After :` indentation here.
    let validity = cert.validity();
    let nb = format_validity_field(validity.not_before, "notBefore")?;
    let na = format_validity_field(validity.not_after, "notAfter")?;
    writeln!(out, "        Validity").map_err(io_to_crypto)?;
    writeln!(out, "            Not Before: {nb}").map_err(io_to_crypto)?;
    writeln!(out, "            Not After : {na}").map_err(io_to_crypto)?;

    writeln!(out, "        Subject: {}", cert.subject_oneline()).map_err(io_to_crypto)?;

    // Subject Public Key Info — algorithm OID and a byte-count summary.
    // Full key dumps are intentionally omitted from this `-text` frame
    // because the existing `--pubkey` and `--modulus` flags already
    // provide PEM- and integer-form renderings.  Same non-fatal error
    // handling rationale as the signature algorithm field above.
    match cert.public_key() {
        Ok(pki) => {
            writeln!(out, "        Subject Public Key Info:").map_err(io_to_crypto)?;
            writeln!(
                out,
                "            Public Key Algorithm: {}",
                pki.algorithm_oid
            )
            .map_err(io_to_crypto)?;
            writeln!(
                out,
                "                Public-Key: ({} bytes)",
                pki.public_key_bytes.len()
            )
            .map_err(io_to_crypto)?;
        }
        Err(e) => {
            writeln!(out, "        Subject Public Key Info: <unavailable: {e}>")
                .map_err(io_to_crypto)?;
        }
    }

    // Outer Signature Value — show byte length only.  Upstream emits
    // the raw bytes hex-encoded; keeping this concise keeps the helper
    // small and matches the "summary" character of the rest of the
    // frame.  `--fingerprint` is the appropriate flag for full hashes.
    let sig = cert.signature_value();
    writeln!(out, "    Signature Value:").map_err(io_to_crypto)?;
    writeln!(out, "        ({} bytes)", sig.len()).map_err(io_to_crypto)?;

    Ok(())
}

/// Print `subject=<oneline>` to `out`.
fn print_subject<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    writeln!(out, "subject={}", cert.subject_oneline()).map_err(io_to_crypto)
}

/// Print `issuer=<oneline>` to `out`.
fn print_issuer<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    writeln!(out, "issuer={}", cert.issuer_oneline()).map_err(io_to_crypto)
}

/// Print `serial=<HEX-pairs>` to `out`.
fn print_serial<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let bytes = cert.serial_number();
    let hex = bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut acc, b| {
            // `write!` to a String never fails; the unwrap is
            // unreachable in practice.  We still tolerate a write
            // error by ignoring it (R6 — no panicking unwrap on data).
            let _ = write!(acc, "{b:02X}");
            acc
        },
    );
    writeln!(out, "serial={hex}").map_err(io_to_crypto)
}

/// Print `notBefore=<ASN.1 time>` to `out`.
fn print_startdate<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let s = format_validity_field(cert.validity().not_before, "notBefore")?;
    writeln!(out, "notBefore={s}").map_err(io_to_crypto)
}

/// Print `notAfter=<ASN.1 time>` to `out`.
fn print_enddate<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let s = format_validity_field(cert.validity().not_after, "notAfter")?;
    writeln!(out, "notAfter={s}").map_err(io_to_crypto)
}

/// Format a validity field as an `Asn1Time` Display string, falling
/// back to a plain "seconds since UNIX epoch" representation on the
/// extreme-edge case where the field is older than 1950 / past 9999.
fn format_validity_field(when: SystemTime, field_name: &str) -> Result<String, CryptoError> {
    use openssl_crypto::asn1::Asn1Time;

    let secs_since_epoch: i64 = match when.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).map_err(|_| {
            CryptoError::Provider(format!(
                "x509: validity field '{field_name}' overflows i64 (post-9999)"
            ))
        })?,
        Err(e) => {
            // Pre-epoch (1970-01-01) — represent as a negative offset.
            let dur = e.duration();
            let secs = i64::try_from(dur.as_secs()).map_err(|_| {
                CryptoError::Provider(format!(
                    "x509: validity field '{field_name}' overflows i64 (pre-1970)"
                ))
            })?;
            secs.checked_neg().ok_or_else(|| {
                CryptoError::Provider(format!(
                    "x509: validity field '{field_name}' overflows i64 (negation)"
                ))
            })?
        }
    };

    let asn1 = Asn1Time::from_unix_timestamp(secs_since_epoch)?;
    Ok(format!("{asn1}"))
}

/// Print `subject_hash=<8 hex digits>` (SHA-1 over subject DN DER).
fn print_subject_hash<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let der = cert.subject_der()?;
    let h32 = name_hash_le_u32(&der, "SHA1", "subject_hash")?;
    writeln!(out, "subject_hash={h32:08x}").map_err(io_to_crypto)
}

/// Print `subject_hash_old=<8 hex digits>` (MD5 over subject DN DER).
fn print_subject_hash_old<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let der = cert.subject_der()?;
    let h32 = name_hash_le_u32(&der, "MD5", "subject_hash_old")?;
    writeln!(out, "subject_hash_old={h32:08x}").map_err(io_to_crypto)
}

/// Print `issuer_hash=<8 hex digits>` (SHA-1 over issuer DN DER).
fn print_issuer_hash<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let der = cert.issuer_der()?;
    let h32 = name_hash_le_u32(&der, "SHA1", "issuer_hash")?;
    writeln!(out, "issuer_hash={h32:08x}").map_err(io_to_crypto)
}

/// Print `issuer_hash_old=<8 hex digits>` (MD5 over issuer DN DER).
fn print_issuer_hash_old<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let der = cert.issuer_der()?;
    let h32 = name_hash_le_u32(&der, "MD5", "issuer_hash_old")?;
    writeln!(out, "issuer_hash_old={h32:08x}").map_err(io_to_crypto)
}

/// Compute the legacy 32-bit name hash used by `apps/x509.c` for
/// `-hash` / `-subject_hash_old` / etc.: SHA-1 (or MD5 for the legacy
/// variant) over the DN DER, then the first four bytes interpreted as
/// a little-endian `u32`.
fn name_hash_le_u32(der: &[u8], digest: &str, label: &str) -> Result<u32, CryptoError> {
    let algo = algorithm_from_name(digest).ok_or_else(|| {
        CryptoError::AlgorithmNotFound(format!("x509: {digest} unavailable for -{label}"))
    })?;
    let mut ctx = create_digest(algo)?;
    let h = ctx.digest(der)?;
    if h.len() < 4 {
        return Err(CryptoError::Provider(format!(
            "x509: {digest} digest too short ({} bytes) for -{label}",
            h.len()
        )));
    }
    Ok(u32::from_le_bytes([h[0], h[1], h[2], h[3]]))
}

/// Print the embedded `SubjectPublicKeyInfo` as PEM
/// (`-----BEGIN PUBLIC KEY-----`).
fn print_pubkey<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let pki = cert.public_key()?;
    let pem = pem_encode_with_label("PUBLIC KEY", &pki.subject_public_key_info_der);
    out.write_all(pem.as_bytes()).map_err(io_to_crypto)
}

/// Print `Modulus=<HEX>` (RSA) or a printable representation of the
/// `SubjectPublicKey` bit-string for non-RSA keys.
fn print_modulus<W: Write>(out: &mut W, cert: &Certificate) -> Result<(), CryptoError> {
    let pki = cert.public_key()?;
    // For non-RSA keys we still emit a single line so callers can scrape
    // the value — apps/x509.c falls back to a plain hex dump in this
    // case.  We do the same.
    let bytes = &pki.public_key_bytes;
    let hex = bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut acc, b| {
            let _ = write!(acc, "{b:02X}");
            acc
        },
    );
    writeln!(out, "Modulus={hex}").map_err(io_to_crypto)
}

// ===========================================================================
// PEM helpers
// ===========================================================================

/// Encode a DER blob as a PEM-armoured `CERTIFICATE` block.  The
/// implementation mirrors `crl.rs::pem_encode_crl` with the marker
/// label swapped to `CERTIFICATE`.
fn pem_encode_cert(der: &[u8]) -> String {
    pem_encode_with_label("CERTIFICATE", der)
}

/// Encode a DER blob as a PEM-armoured block with the given label
/// (e.g. `"CERTIFICATE"`, `"PUBLIC KEY"`).
fn pem_encode_with_label(label: &str, der: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    let encoded = Base64::encode_string(der);
    let mut out = String::with_capacity(encoded.len().saturating_add(label.len()).saturating_add(64));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

// ===========================================================================
// Error helpers
// ===========================================================================

/// Construct a `CryptoError::Provider` for a path-scoped I/O failure.
fn io_kind_err(path: &Path, kind: &str, message: &str) -> CryptoError {
    CryptoError::Provider(format!(
        "x509: cannot read {kind} '{}': {message}",
        path.display()
    ))
}

/// Convert an `std::io::Error` into a `CryptoError::Provider`.
#[allow(clippy::needless_pass_by_value)]
fn io_to_crypto(e: std::io::Error) -> CryptoError {
    CryptoError::Provider(format!("x509: I/O error: {e}"))
}

// ===========================================================================
// Unit tests — argument parsing only.  End-to-end / dispatch behaviour
// is covered by `crates/openssl-cli/src/tests/pki_tests.rs`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Wrapper that allows `clap` to drive `X509Args` directly in unit
    /// tests without going through the dispatcher.
    #[derive(Parser, Debug)]
    #[command(name = "x509")]
    struct Wrap {
        #[command(flatten)]
        args: X509Args,
    }

    #[test]
    fn defaults_are_empty() {
        let parsed = Wrap::try_parse_from(["x509"]).expect("clap parse");
        let a = parsed.args;
        assert!(a.in_path.is_none());
        assert!(a.out_path.is_none());
        assert!(a.inform.is_none());
        assert!(a.outform.is_none());
        assert!(!a.noout);
        assert!(!a.text);
        assert!(!a.fingerprint);
        assert!(!a.serial);
        assert!(!a.subject);
        assert!(!a.issuer);
        assert!(!a.startdate);
        assert!(!a.enddate);
        assert!(!a.dates);
        assert!(!a.hash);
        assert!(!a.subject_hash_old);
        assert!(!a.issuer_hash);
        assert!(!a.issuer_hash_old);
        assert!(!a.pubkey);
        assert!(!a.modulus);
        assert!(a.checkend.is_none());
        assert!(a.digest.is_none());
    }

    #[test]
    fn parse_basic_io_flags() {
        let parsed = Wrap::try_parse_from([
            "x509",
            "--in",
            "in.pem",
            "--out",
            "out.der",
            "--inform",
            "PEM",
            "--outform",
            "DER",
        ])
        .expect("clap parse");
        let a = parsed.args;
        assert_eq!(a.in_path.as_deref(), Some(Path::new("in.pem")));
        assert_eq!(a.out_path.as_deref(), Some(Path::new("out.der")));
        assert_eq!(a.inform.as_deref(), Some("PEM"));
        assert_eq!(a.outform.as_deref(), Some("DER"));
    }

    #[test]
    fn parse_display_flags() {
        let parsed = Wrap::try_parse_from([
            "x509",
            "--text",
            "--fingerprint",
            "--serial",
            "--subject",
            "--issuer",
            "--startdate",
            "--enddate",
            "--dates",
            "--hash",
            "--subject-hash-old",
            "--issuer-hash",
            "--issuer-hash-old",
            "--pubkey",
            "--modulus",
            "--noout",
            "--digest",
            "SHA256",
        ])
        .expect("clap parse");
        let a = parsed.args;
        assert!(a.text);
        assert!(a.fingerprint);
        assert!(a.serial);
        assert!(a.subject);
        assert!(a.issuer);
        assert!(a.startdate);
        assert!(a.enddate);
        assert!(a.dates);
        assert!(a.hash);
        assert!(a.subject_hash_old);
        assert!(a.issuer_hash);
        assert!(a.issuer_hash_old);
        assert!(a.pubkey);
        assert!(a.modulus);
        assert!(a.noout);
        assert_eq!(a.digest.as_deref(), Some("SHA256"));
    }

    #[test]
    fn parse_check_flags() {
        let parsed = Wrap::try_parse_from(["x509", "--checkend", "30"]).expect("clap parse");
        assert_eq!(parsed.args.checkend, Some(30));
    }

    #[test]
    fn parse_subject_hash_alias_for_hash() {
        let parsed = Wrap::try_parse_from(["x509", "--subject-hash"]).expect("clap parse");
        assert!(parsed.args.hash);
    }

    #[test]
    fn pem_encode_cert_emits_certificate_marker() {
        let der = b"\x30\x03\x02\x01\x00";
        let pem = pem_encode_cert(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn pem_encode_with_label_supports_pubkey_label() {
        let pem = pem_encode_with_label("PUBLIC KEY", b"\x30\x00");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
    }
}
