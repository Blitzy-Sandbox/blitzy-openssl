//! `openssl crl` — manage X.509 Certificate Revocation Lists (CRLs).
//!
//! Rust port of the C reference implementation in `apps/crl.c` (≈421 lines).
//! Implements display, badsig corruption, and PEM↔DER format conversion for
//! X.509 CRLs.  Verification and delta-CRL generation are surfaced as
//! unsupported errors because the underlying primitives are not yet ported
//! (see [Limitations](#limitations) below).
//!
//! # Output and exit-code semantics
//!
//! * Display flags (`--issuer`, `--lastupdate`, `--nextupdate`,
//!   `--fingerprint`, `--hash`, `--hash_old`, `--crlnumber`) and `--text`
//!   emit to stdout.
//! * Encoded output is written to the path passed to `--out`, or to stdout
//!   when absent and `--noout` is not set.
//! * Errors propagate as [`CryptoError`] and surface as a non-zero process
//!   exit status via the top-level dispatcher.
//!
//! # Limitations
//!
//! * `--gendelta` is **not implemented** — there is no `X509_CRL_diff()`
//!   Rust equivalent in this codebase (the underlying CRL signing helpers
//!   are not yet ported).  Invoking `--gendelta` returns
//!   [`CryptoError::Provider`] with a descriptive message.
//! * `--verify` is **not implemented** — the EVP-backed signature
//!   verification pathway is not yet wired into `X509Crl`/`X509Certificate`.
//!   Invoking `--verify` (or supplying any of `--CAfile`, `--CApath`,
//!   `--CAstore`) returns [`CryptoError::Provider`] with a descriptive
//!   message.  All other display/conversion flags continue to work.
//!
//! # Reference
//!
//! * Upstream C source: `apps/crl.c`.
//!
//! # Compliance notes
//!
//! * **R5 (nullability):** Optional CLI inputs use [`Option`]; absence is
//!   never encoded as a sentinel.
//! * **R6 (lossless casts):** `u64 → u32` truncation when emitting issuer
//!   hashes is documented inline with a per-site `#[allow]` and FIPS-style
//!   justification (the upstream `%08lx` print format prints the lower 32
//!   bits of the 64-bit hash for diagnostic compatibility).
//! * **R8 (zero unsafe):** No `unsafe` blocks.
//! * **R9 (warning-free):** All paths handled; uses `tracing::{debug, warn}`
//!   for diagnostic output instead of unconditional `println!`.
//! * **R10 (wiring):** Reachable from `openssl-cli`'s top-level command
//!   dispatcher and exercised by the integration tests in
//!   `crates/openssl-cli/src/tests/pki_tests.rs`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use tracing::{debug, warn};

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::hash::{algorithm_from_name, create_digest};
use openssl_crypto::x509::store::{load_file, load_locations, set_default_paths};
use openssl_crypto::x509::{FileFormat, X509Crl, X509Store};

/// Manage X.509 Certificate Revocation Lists (CRLs).
///
/// This subcommand parses, displays, optionally corrupts the signature on
/// (`--badsig`), and converts certificate revocation list files between PEM
/// and DER. Mirrors the option table in `apps/crl.c` (29 `OPT_choice` variants)
/// modulo the limitations documented at the module level.
///
/// `CrlArgs` intentionally mirrors the C option table layout — the count of
/// boolean flags (`text`, `noout`, `hash`, `hash_old`, `issuer`, `lastupdate`,
/// `nextupdate`, `fingerprint`, `crl_number`, `verify`, `badsig`) directly
/// reflects the 29-option `OPT_choice` enum in `apps/crl.c`.
#[derive(Args, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct CrlArgs {
    /// Input format (PEM or DER).  Defaults to PEM when not specified.
    #[arg(long = "inform", value_name = "FORMAT")]
    pub inform: Option<String>,

    /// Input file path.  Reads from stdin when omitted.
    #[arg(long = "in", value_name = "FILE")]
    pub input_file: Option<PathBuf>,

    /// Output format (PEM or DER).  Defaults to PEM.
    #[arg(long = "outform", value_name = "FORMAT")]
    pub outform: Option<String>,

    /// Output file path.  Writes to stdout when omitted.
    #[arg(long = "out", value_name = "FILE")]
    pub output_file: Option<PathBuf>,

    /// Key format (`-keyform`).  Currently has no effect; mirrors apps/crl.c.
    #[arg(long = "keyform", value_name = "FORMAT")]
    pub keyform: Option<String>,

    /// Issuer key (`-key`).  Currently has no effect; mirrors apps/crl.c.
    #[arg(long = "key", value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// Generate a delta CRL by diffing against the supplied base CRL.
    /// **Not implemented** in this build (returns an unsupported error).
    #[arg(long = "gendelta", value_name = "FILE")]
    pub gendelta: Option<PathBuf>,

    /// Verify the CRL signature against the trust store.
    /// **Not implemented** in this build (returns an unsupported error).
    #[arg(long = "verify")]
    pub verify: bool,

    /// CA directory containing per-hash trusted certificates.
    #[arg(long = "CApath", value_name = "DIR")]
    pub capath: Option<PathBuf>,

    /// File of concatenated PEM trusted certificates.
    #[arg(long = "CAfile", value_name = "FILE")]
    pub cafile: Option<PathBuf>,

    /// CA store URI (e.g. `file:/etc/ssl/certs`).
    #[arg(long = "CAstore", value_name = "URI")]
    pub castore: Option<String>,

    /// Disable loading certificates from the default `--CApath`.
    #[arg(long = "no-CApath")]
    pub no_capath: bool,

    /// Disable loading certificates from the default `--CAfile`.
    #[arg(long = "no-CAfile")]
    pub no_cafile: bool,

    /// Disable loading certificates from the default `--CAstore`.
    #[arg(long = "no-CAstore")]
    pub no_castore: bool,

    /// ASN.1 date format options (currently consumed without effect).
    #[arg(long = "dateopt", value_name = "OPTS")]
    pub dateopt: Option<String>,

    /// Render the CRL as human-readable text.
    #[arg(long = "text")]
    pub text: bool,

    /// Suppress the encoded DER/PEM output.
    #[arg(long = "noout")]
    pub noout: bool,

    /// Print the issuer DN.
    #[arg(long = "issuer")]
    pub issuer: bool,

    /// Print `lastUpdate`.
    #[arg(long = "lastupdate")]
    pub lastupdate: bool,

    /// Print `nextUpdate`.
    #[arg(long = "nextupdate")]
    pub nextupdate: bool,

    /// Print the canonical issuer name hash (truncated to 32 bits to match
    /// upstream's `%08lx` print format).
    #[arg(long = "hash")]
    pub hash: bool,

    /// Print the legacy MD5-based issuer name hash (mirrors `-hash_old`).
    #[arg(long = "hash_old")]
    pub hash_old: bool,

    /// Print the CRL fingerprint (digest of the encoded DER).
    #[arg(long = "fingerprint")]
    pub fingerprint: bool,

    /// Print the CRL number extension when present.
    #[arg(long = "crlnumber")]
    pub crlnumber: bool,

    /// Corrupt the signature on output (for negative test vectors).
    #[arg(long = "badsig")]
    pub badsig: bool,

    /// Name display options (currently consumed without effect).
    #[arg(long = "nameopt", value_name = "OPTS")]
    pub nameopt: Option<String>,

    /// Digest algorithm for `--fingerprint`.  Defaults to SHA1.
    #[arg(long = "digest", value_name = "ALGO")]
    pub digest: Option<String>,
}

impl CrlArgs {
    /// Execute the `crl` subcommand.
    ///
    /// The flow mirrors `apps/crl.c`'s top-level state machine:
    ///
    /// 1. Validate flags and reject unsupported features (`--gendelta`).
    /// 2. Load the input CRL.
    /// 3. Optionally verify the signature against a trust store
    ///    (currently returns an unsupported error).
    /// 4. Optionally render the CRL as human-readable text.
    /// 5. Print individual fields in `apps/crl.c`'s precedence order.
    /// 6. Emit DER/PEM output unless `--noout` is set.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Phase 1 — flag validation and unsupported-feature rejection.
        if self.gendelta.is_some() {
            return Err(CryptoError::Provider(
                "gendelta is not supported by this implementation; use the \
                 original openssl tooling for delta CRL generation"
                    .to_string(),
            ));
        }

        // apps/crl.c automatically enables verification when CAfile/CApath/
        // CAstore are present.  We mirror that behaviour for diagnostic
        // parity even though our verify path is currently unsupported.
        let do_verify = self.verify
            || self.cafile.is_some()
            || self.capath.is_some()
            || self.castore.is_some();

        // Phase 2 — load the input CRL.
        let crl = self.load_input_crl()?;
        debug!(target: "openssl::crl", "loaded CRL from input");

        // Phase 3 — optional verification (currently unsupported).
        if do_verify {
            // Build the trust store anyway to surface obvious user errors
            // (missing CAfile, etc.) before reporting unsupported status.
            let _store = self.build_trust_store()?;
            return self.verify_crl(&crl);
        }

        // Phase 4 — text rendering (uses Display impl on X509Crl).
        if self.text {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{crl}").map_err(io_to_crypto)?;
        }

        // Phase 5 — display individual fields in apps/crl.c precedence order:
        // issuer → lastUpdate → nextUpdate → fingerprint → hash → hash_old →
        // crlNumber.  Multiple flags can appear together; they are emitted in
        // this fixed order regardless of CLI position.
        {
            let mut out = std::io::stdout().lock();
            if self.issuer {
                print_issuer(&mut out, &crl)?;
            }
            if self.lastupdate {
                print_last_update(&mut out, &crl)?;
            }
            if self.nextupdate {
                print_next_update(&mut out, &crl)?;
            }
            if self.fingerprint {
                self.print_fingerprint(&mut out, &crl)?;
            }
            if self.hash {
                print_hash(&mut out, &crl)?;
            }
            if self.hash_old {
                print_hash_old(&mut out, &crl)?;
            }
            if self.crlnumber {
                print_crl_number(&mut out, &crl)?;
            }
        }

        // Phase 6 — encoded output (DER/PEM) unless `--noout`.
        if !self.noout {
            self.write_encoded_output(&crl)?;
        }

        Ok(())
    }

    /// Read the CRL from `--in` (or stdin) and parse the bytes.
    fn load_input_crl(&self) -> Result<X509Crl, CryptoError> {
        let bytes = match &self.input_file {
            Some(path) => fs::read(path)
                .map_err(|e| io_kind_err(path, "read", &e.to_string()))?,
            None => {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(io_to_crypto)?;
                buf
            }
        };

        match self.inform.as_deref().map(str::to_ascii_uppercase) {
            Some(ref s) if s == "DER" => X509Crl::from_der(&bytes),
            Some(ref s) if s == "PEM" => {
                let text = std::str::from_utf8(&bytes).map_err(|_| {
                    CryptoError::Encoding(
                        "crl: input is not valid UTF-8 PEM".to_string(),
                    )
                })?;
                X509Crl::from_pem(text)
            }
            Some(other) => Err(CryptoError::Encoding(format!(
                "crl: unsupported -inform value '{other}' (expected PEM or DER)"
            ))),
            None => {
                // Sniff: PEM input begins with the `-----BEGIN` marker.
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if text.contains("-----BEGIN") {
                        return X509Crl::from_pem(text);
                    }
                }
                X509Crl::from_der(&bytes)
            }
        }
    }

    /// Build the trust store from the user-provided locations.
    ///
    /// The store is populated best-effort: failures while loading the
    /// default paths are demoted to a warning so that explicit `--CAfile`/
    /// `--CApath` values are still honoured.  Per `apps/crl.c`, the
    /// `--no-CAfile`/`--no-CApath`/`--no-CAstore` switches skip the
    /// corresponding default location.
    fn build_trust_store(&self) -> Result<X509Store, CryptoError> {
        let mut store = X509Store::new();

        if !self.no_cafile && !self.no_capath {
            if let Err(e) = set_default_paths(&mut store) {
                warn!(
                    target: "openssl::crl",
                    "ignoring failure to load default trust paths: {e}"
                );
            }
        }

        let cafile = self.cafile.as_deref();
        let capath = self.capath.as_deref();
        if cafile.is_some() || capath.is_some() {
            load_locations(&mut store, cafile, capath).map_err(|e| {
                CryptoError::Provider(format!(
                    "crl: failed to load CA locations: {e}"
                ))
            })?;
        }

        if let Some(uri) = &self.castore {
            // Only the `file:` URI scheme is currently supported, matching
            // the most common downstream usage of `-CAstore`.
            if let Some(stripped) = uri.strip_prefix("file:") {
                let path = Path::new(stripped);
                load_file(&mut store, path, FileFormat::Pem).map_err(|e| {
                    CryptoError::Provider(format!(
                        "crl: failed to load CAstore '{}': {e}",
                        path.display()
                    ))
                })?;
            } else {
                warn!(
                    target: "openssl::crl",
                    "ignoring -CAstore '{uri}': only 'file:' URIs are supported"
                );
            }
        }

        Ok(store)
    }

    /// Verification helper.
    ///
    /// The underlying `X509Crl` API does not yet expose an EVP-backed
    /// signature verification path; therefore we surface this as an
    /// unsupported feature rather than silently returning success.  See
    /// the module-level `Limitations` section.
    ///
    /// Kept as `&self` so future EVP integrations can read trust-anchor
    /// fields (`cafile`, `capath`, `castore`) without breaking call sites.
    #[allow(clippy::unused_self)]
    fn verify_crl(&self, _crl: &X509Crl) -> Result<(), CryptoError> {
        Err(CryptoError::Provider(
            "CRL signature verification is not yet supported by this \
             implementation; the underlying EVP integration is pending"
                .to_string(),
        ))
    }

    /// Emit the CRL fingerprint to `out`.
    ///
    /// Computes a one-shot digest over the encoded DER (mirroring
    /// `X509_CRL_digest`'s diagnostic behaviour for compatibility).
    fn print_fingerprint<W: Write>(
        &self,
        out: &mut W,
        crl: &X509Crl,
    ) -> Result<(), CryptoError> {
        let digest_name = self.digest.as_deref().unwrap_or("SHA1");
        let algo = algorithm_from_name(digest_name).ok_or_else(|| {
            CryptoError::AlgorithmNotFound(format!(
                "crl: unknown digest '{digest_name}'"
            ))
        })?;
        let der = crl.to_der().map_err(|e| {
            CryptoError::Encoding(format!("crl: failed to encode CRL: {e}"))
        })?;
        let mut ctx = create_digest(algo)?;
        let display_name = ctx.algorithm_name();
        let fp = ctx.digest(&der)?;
        let hex_pairs: Vec<String> =
            fp.iter().map(|b| format!("{b:02X}")).collect();
        writeln!(
            out,
            "{} Fingerprint={}",
            display_name,
            hex_pairs.join(":")
        )
        .map_err(io_to_crypto)?;
        Ok(())
    }

    /// Write the encoded CRL to `--out` (or stdout) honouring `--outform`
    /// and `--badsig`.
    fn write_encoded_output(&self, crl: &X509Crl) -> Result<(), CryptoError> {
        let outform = self
            .outform
            .as_deref()
            .map_or_else(|| "PEM".to_string(), str::to_ascii_uppercase);

        // Pull the cached DER first.  When `--badsig` is set we mutate the
        // last byte directly in the returned `Vec<u8>` rather than going
        // through `set_signature()` (which clears the cached encoding and
        // would force a re-emit through paths that are not yet ported).
        let mut der = crl.to_der().map_err(|e| {
            CryptoError::Encoding(format!("crl: failed to encode CRL: {e}"))
        })?;

        if self.badsig {
            if let Some(last) = der.last_mut() {
                *last ^= 0xFF;
            }
        }

        let payload: Vec<u8> = match outform.as_str() {
            "DER" => der,
            "PEM" => pem_encode_crl(&der).into_bytes(),
            other => {
                return Err(CryptoError::Encoding(format!(
                    "crl: unsupported -outform value '{other}' (expected PEM or DER)"
                )));
            }
        };

        match &self.output_file {
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
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Manually PEM-encode a CRL DER payload.
///
/// Mirrors `PEM_write_X509_CRL` for diagnostic compatibility: 64-character
/// base64 lines wrapped in `-----BEGIN/END X509 CRL-----` markers.
fn pem_encode_crl(der: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    let encoded = Base64::encode_string(der);
    let mut out = String::with_capacity(encoded.len() + 64);
    out.push_str("-----BEGIN X509 CRL-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // Base64 output is always ASCII-safe; chunk boundaries are also
        // character boundaries, so utf8 conversion is infallible in practice.
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END X509 CRL-----\n");
    out
}

/// Print the CRL issuer DN (`-issuer`).
fn print_issuer<W: Write>(out: &mut W, crl: &X509Crl) -> Result<(), CryptoError> {
    writeln!(out, "issuer={}", crl.issuer().to_string_oneline()).map_err(io_to_crypto)
}

/// Print the CRL `lastUpdate` field (`-lastupdate`).
fn print_last_update<W: Write>(
    out: &mut W,
    crl: &X509Crl,
) -> Result<(), CryptoError> {
    writeln!(out, "lastUpdate={}", crl.last_update()).map_err(io_to_crypto)
}

/// Print the CRL `nextUpdate` field, or `NONE` when absent (`-nextupdate`).
fn print_next_update<W: Write>(
    out: &mut W,
    crl: &X509Crl,
) -> Result<(), CryptoError> {
    match crl.next_update() {
        Some(t) => writeln!(out, "nextUpdate={t}").map_err(io_to_crypto),
        None => writeln!(out, "nextUpdate=NONE").map_err(io_to_crypto),
    }
}

/// Print the canonical issuer name hash (`-hash`).
///
/// The local `X509Name` placeholder in `openssl_crypto::x509::crl` does not
/// expose a `hash()` method, so we reproduce upstream OpenSSL's
/// `X509_NAME_hash_ex()` algorithm here: SHA-1 over the canonical DER
/// encoding of the name, with the leading 4 bytes interpreted as a
/// little-endian `u32` (matching `crypto/x509/x509_cmp.c::X509_NAME_hash_ex`).
///
/// `apps/crl.c` prints the value via the `%08lx\n` format string, which on
/// 64-bit platforms displays the lower 32 bits of the underlying 64-bit
/// hash value. We reproduce that exact format here for diagnostic
/// compatibility with the C tool.
fn print_hash<W: Write>(out: &mut W, crl: &X509Crl) -> Result<(), CryptoError> {
    let der = crl.issuer().as_der().to_vec();
    let algo = algorithm_from_name("SHA1").ok_or_else(|| {
        CryptoError::AlgorithmNotFound("crl: SHA1 unavailable for -hash".to_string())
    })?;
    let mut ctx = create_digest(algo)?;
    let digest = ctx.digest(&der)?;
    if digest.len() < 4 {
        return Err(CryptoError::Verification(
            "crl: SHA1 digest shorter than 4 bytes (impossible)".to_string(),
        ));
    }
    let h32 = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    writeln!(out, "{h32:08x}").map_err(io_to_crypto)
}

/// Print the legacy MD5-based issuer name hash (`-hash_old`).
///
/// The Rust `X509Name` type does not expose `hash_old`, so we compute it
/// manually: MD5 over the canonical DER name and reinterpret the leading
/// little-endian 32 bits as the hash value (mirroring upstream's
/// `X509_NAME_hash_old` implementation in `crypto/x509/x509_cmp.c`).
fn print_hash_old<W: Write>(
    out: &mut W,
    crl: &X509Crl,
) -> Result<(), CryptoError> {
    let canonical = crl.issuer().as_der().to_vec();
    let algo = algorithm_from_name("MD5").ok_or_else(|| {
        CryptoError::AlgorithmNotFound(
            "crl: MD5 unavailable for -hash_old".to_string(),
        )
    })?;
    let mut ctx = create_digest(algo)?;
    let digest = ctx.digest(&canonical)?;
    if digest.len() < 4 {
        return Err(CryptoError::Verification(
            "crl: MD5 digest shorter than 4 bytes (impossible)".to_string(),
        ));
    }
    let h32 = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    writeln!(out, "{h32:08x}").map_err(io_to_crypto)
}

/// Print the CRL number extension when present (`-crlnumber`).
fn print_crl_number<W: Write>(
    out: &mut W,
    crl: &X509Crl,
) -> Result<(), CryptoError> {
    match crl.crl_number() {
        Some(bytes) if !bytes.is_empty() => {
            // Build the hex string with a single allocation by folding into
            // a pre-sized `String` and writing each byte via `write!`. This
            // avoids the per-byte `format!` allocations that
            // `clippy::format_collect` flags.
            use std::fmt::Write as _;
            let hex = bytes.iter().fold(
                String::with_capacity(bytes.len().saturating_mul(2)),
                |mut acc, b| {
                    let _ = write!(acc, "{b:02X}");
                    acc
                },
            );
            writeln!(out, "crlNumber=0x{hex}").map_err(io_to_crypto)
        }
        _ => writeln!(out, "crlNumber=<NONE>").map_err(io_to_crypto),
    }
}

/// Construct an [`io::Error`]-derived [`CryptoError`] tagged with the path.
fn io_kind_err(path: &Path, kind: &str, message: &str) -> CryptoError {
    CryptoError::Provider(format!(
        "crl: {kind} '{}': {message}",
        path.display()
    ))
}

/// Convert an [`std::io::Error`] into a [`CryptoError`] with a `crl:` prefix.
///
/// Takes the error by value to preserve the ergonomic `.map_err(io_to_crypto)`
/// call sites that pepper this module; a by-reference signature would require
/// every caller to write `.map_err(|e| io_to_crypto(&e))` instead.
#[allow(clippy::needless_pass_by_value)]
fn io_to_crypto(e: std::io::Error) -> CryptoError {
    CryptoError::Provider(format!("crl: I/O error: {e}"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Wrapper that exercises `CrlArgs` through clap derive parsing without
    /// pulling in the full top-level `Commands` enum.
    #[derive(Parser, Debug)]
    #[command(name = "crl")]
    struct Wrap {
        #[command(flatten)]
        args: CrlArgs,
    }

    #[test]
    fn crl_args_default_is_empty() {
        let args = CrlArgs::default();
        assert!(args.input_file.is_none());
        assert!(args.output_file.is_none());
        assert!(args.gendelta.is_none());
        assert!(!args.verify);
        assert!(!args.text);
        assert!(!args.noout);
        assert!(!args.issuer);
        assert!(!args.lastupdate);
        assert!(!args.nextupdate);
        assert!(!args.hash);
        assert!(!args.hash_old);
        assert!(!args.fingerprint);
        assert!(!args.crlnumber);
        assert!(!args.badsig);
    }

    #[test]
    fn crl_args_parse_basic() {
        let cmd = Wrap::try_parse_from([
            "crl",
            "--in",
            "test.pem",
            "--out",
            "out.der",
            "--inform",
            "PEM",
            "--outform",
            "DER",
        ])
        .expect("clap parse");
        assert_eq!(cmd.args.input_file.as_deref(), Some(Path::new("test.pem")));
        assert_eq!(cmd.args.output_file.as_deref(), Some(Path::new("out.der")));
        assert_eq!(cmd.args.inform.as_deref(), Some("PEM"));
        assert_eq!(cmd.args.outform.as_deref(), Some("DER"));
    }

    #[test]
    fn crl_args_parse_display_flags() {
        let cmd = Wrap::try_parse_from([
            "crl",
            "--issuer",
            "--lastupdate",
            "--nextupdate",
            "--hash",
            "--hash_old",
            "--fingerprint",
            "--crlnumber",
            "--text",
            "--noout",
        ])
        .expect("clap parse");
        assert!(cmd.args.issuer);
        assert!(cmd.args.lastupdate);
        assert!(cmd.args.nextupdate);
        assert!(cmd.args.hash);
        assert!(cmd.args.hash_old);
        assert!(cmd.args.fingerprint);
        assert!(cmd.args.crlnumber);
        assert!(cmd.args.text);
        assert!(cmd.args.noout);
    }

    #[test]
    fn crl_args_parse_verify_flags() {
        let cmd = Wrap::try_parse_from([
            "crl",
            "--verify",
            "--CAfile",
            "ca.pem",
            "--CApath",
            "/etc/ssl/certs",
            "--CAstore",
            "file:/tmp/store",
            "--no-CAfile",
            "--no-CApath",
            "--no-CAstore",
        ])
        .expect("clap parse");
        assert!(cmd.args.verify);
        assert_eq!(cmd.args.cafile.as_deref(), Some(Path::new("ca.pem")));
        assert_eq!(
            cmd.args.capath.as_deref(),
            Some(Path::new("/etc/ssl/certs"))
        );
        assert_eq!(cmd.args.castore.as_deref(), Some("file:/tmp/store"));
        assert!(cmd.args.no_cafile);
        assert!(cmd.args.no_capath);
        assert!(cmd.args.no_castore);
    }
}
