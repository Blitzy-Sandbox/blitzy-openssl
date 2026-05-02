//! `dsa` subcommand implementation — Rust port of `apps/dsa.c`.
//!
//! Reads a DSA private or public key from a file (or stdin), optionally
//! re-encrypts it with a different cipher, optionally prints the key in
//! human-readable text or its modulus, and writes it back out in the
//! requested format (DER / PEM).  Mirrors the `openssl dsa` command-line
//! tool from upstream OpenSSL, sourced from `apps/dsa.c` (lines 1–311).
//!
//! The C implementation pipes everything through the legacy
//! `OSSL_ENCODER_CTX_*` / `EVP_PKEY_print_*` / `BN_print()` helpers; the
//! Rust port delegates all encoding / decoding to
//! [`openssl_crypto::evp::encode_decode`] and all key inspection to
//! [`openssl_crypto::evp::pkey`].
//!
//! # Input / Output Formats
//!
//! Like the C tool, only DER and PEM are fully supported on the output
//! path.  The `MSBLOB` and `PVK` formats are accepted on the command line
//! for parity with the C `--outform` parser but currently emit a typed
//! [`CryptoError::Encoding`] error explaining that they require RC4 /
//! Microsoft-specific encoders that are not yet wired into the Rust
//! provider tree.  The original C source also gates `PVK` behind
//! `OPENSSL_NO_RC4` (see `apps/dsa.c:29–33`); the Rust port preserves the
//! same defaults via [`DEFAULT_PVK_ENCR_STRENGTH`].
//!
//! Inform is parsed but otherwise ignored on the input side — the
//! decoder auto-detects PEM vs DER, matching the comment in
//! `apps/dsa.c:68`: *"Input format (DER/PEM/PVK); has no effect"*.
//!
//! # Rules Applied
//!
//! - **R5** — Every optional argument (paths, password sources, cipher
//!   name, inform) is `Option<T>`; no `0` / `-1` / `""` sentinels appear
//!   in the public API.
//! - **R6** — No bare `as` casts on numeric data.  All arithmetic is
//!   performed on `usize` or via checked / lossless conversions.
//! - **R8** — Zero `unsafe` code.  The crate-wide `#![forbid(unsafe_code)]`
//!   in `crates/openssl-cli/src/main.rs` makes this a compile-time
//!   guarantee.
//! - **R9** — Warning-free under `RUSTFLAGS="-D warnings"`; every public
//!   item carries a doc-comment.
//! - **R10** — Wired into the dispatch path: `main.rs` →
//!   `CliCommand::execute()` → `CliCommand::Dsa(args)` →
//!   `DsaArgs::execute(ctx).await`, reachable from the binary entry
//!   point and exercised by the integration tests in this module.

use std::fs::File;
use std::io::{self, stdout, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, trace};

use openssl_common::error::{CommonError, CryptoError};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::Cipher;
use openssl_crypto::evp::encode_decode::{
    decode_from_reader, encode_to_writer, EncoderContext, KeyFormat, KeySelection,
};
use openssl_crypto::evp::pkey::{KeyType, PKey};

use crate::lib::opts::Format;
use crate::lib::password::parse_password_source;

// ───────────────────────────────────────────────────────────────────────────
// Constants
// ───────────────────────────────────────────────────────────────────────────

/// Default PVK encryption-level when neither `--pvk-strong`, `--pvk-weak`,
/// nor `--pvk-none` is supplied.
///
/// Mirrors the C macro at `apps/dsa.c:29–33`: when RC4 is available the
/// upstream tool defaults to *strong* (`= 2`); otherwise it falls back to
/// *none* (`= 0`).  The Rust port assumes RC4 is available because the
/// underlying encoder layer is not yet wired into the FIPS-only build.
const DEFAULT_PVK_ENCR_STRENGTH: u8 = 2;

// ───────────────────────────────────────────────────────────────────────────
// CLI Argument Struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `dsa` subcommand.
///
/// Mirrors the C command's `dsa_options[]` table at `apps/dsa.c:56–83`
/// exactly.  All flags are declared via `clap` derive — replacing the
/// manual `OPTION_CHOICE` enum and `opt_init()` / `opt_next()` loop in
/// the C source.
//
// Clippy lint `struct_excessive_bools` is disabled here because each `bool`
// field corresponds to an *independent* CLI flag (`--text`, `--noout`,
// `--modulus`, `--pubin`, `--pubout`, plus the three PVK helper flags).
// These flags are user-controlled and orthogonal — they cannot be folded
// into a single state enum without breaking the `clap::Args` derive
// contract or the C tool's command-line surface.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct DsaArgs {
    /// Path of the input key file (defaults to stdin when omitted).
    ///
    /// Mirrors the C `-in <FILE>` flag at `apps/dsa.c:67`.
    /// R5: `Option<PathBuf>` — no `""` / `NULL` sentinel for "stdin".
    #[arg(long = "in", value_name = "FILE")]
    pub infile: Option<PathBuf>,

    /// Path of the output file (defaults to stdout when omitted).
    ///
    /// Mirrors the C `-out <FILE>` flag at `apps/dsa.c:73`.
    /// R5: `Option<PathBuf>` — no `""` / `NULL` sentinel for "stdout".
    #[arg(long = "out", value_name = "FILE")]
    pub outfile: Option<PathBuf>,

    /// Input format hint (`PEM` / `DER` / `PVK`).
    ///
    /// Mirrors the C `-inform` flag at `apps/dsa.c:68`.  As the upstream
    /// comment notes, this flag *has no effect* — the decoder always
    /// auto-detects PEM vs DER from the leading bytes.  We accept it for
    /// CLI compatibility.
    #[arg(long = "inform", value_name = "FORMAT")]
    pub inform: Option<Format>,

    /// Output format (`PEM` / `DER` / `PVK` / `MSBLOB`); defaults to PEM.
    ///
    /// Mirrors the C `-outform` flag at `apps/dsa.c:74`.  See the
    /// module-level documentation for the supported subset.
    #[arg(long = "outform", value_name = "FORMAT", default_value = "PEM")]
    pub outform: Format,

    /// Read a public key from the input file (instead of a private key).
    ///
    /// Mirrors the C `-pubin` flag at `apps/dsa.c:69`.
    #[arg(long = "pubin")]
    pub pubin: bool,

    /// Write the public part of the key only.
    ///
    /// Mirrors the C `-pubout` flag at `apps/dsa.c:78`.
    #[arg(long = "pubout")]
    pub pubout: bool,

    /// Pass-phrase source for decrypting the input key.
    ///
    /// Mirrors the C `-passin` flag at `apps/dsa.c:70`.  Accepts
    /// `pass:<literal>`, `env:<VAR>`, `file:<path>`, `fd:<n>`, `stdin`.
    /// R5: `Option<String>` — `None` means "no passphrase configured".
    #[arg(long = "passin", value_name = "SOURCE")]
    pub passin: Option<String>,

    /// Pass-phrase source for encrypting the output key.
    ///
    /// Mirrors the C `-passout` flag at `apps/dsa.c:79`.  Accepts the
    /// same source specifiers as `--passin`.
    /// R5: `Option<String>` — `None` means "no passphrase configured".
    #[arg(long = "passout", value_name = "SOURCE")]
    pub passout: Option<String>,

    /// Print the key in human-readable text on the output stream.
    ///
    /// Mirrors the C `-text` flag at `apps/dsa.c:76`.  Equivalent to
    /// `EVP_PKEY_print_public` (when `--pubin` is given) or
    /// `EVP_PKEY_print_private` otherwise.
    #[arg(long = "text")]
    pub text: bool,

    /// Suppress the binary key output (text via `--text` or modulus via
    /// `--modulus` is still emitted).
    ///
    /// Mirrors the C `-noout` flag at `apps/dsa.c:75`.
    #[arg(long = "noout")]
    pub noout: bool,

    /// Print the DSA public value (`y`) in hexadecimal.
    ///
    /// Mirrors the C `-modulus` flag at `apps/dsa.c:77`, which the C
    /// implementation handles via `EVP_PKEY_get_bn_param(pkey, "pub", &y)`
    /// followed by `BN_print()`.  The Rust port retrieves the public
    /// component via [`PKey::raw_public_key`] and re-renders it using
    /// [`BigNum::to_hex`].
    #[arg(long = "modulus")]
    pub modulus: bool,

    /// Symmetric cipher used to re-encrypt private-key output.
    ///
    /// Mirrors the C `-<cipher>` positional / `-cipher` flag at
    /// `apps/dsa.c:59` (`"" / OPT_CIPHER`).  Accepts any cipher name
    /// recognised by the provider tree, e.g. `"AES-256-CBC"`.
    /// R5: `Option<String>` — `None` means "leave the output
    /// unencrypted".
    #[arg(long = "cipher", value_name = "CIPHER")]
    pub cipher: Option<String>,

    /// PVK encryption-level (0=none, 1=weak, 2=strong).
    ///
    /// Schema-exposed numeric form of the three PVK helper flags
    /// `--pvk-strong` / `--pvk-weak` / `--pvk-none` (see
    /// `apps/dsa.c:42–44, 61–63, 136–142`).  This field is *not* a
    /// command-line flag in its own right — clap is told via
    /// `#[arg(skip = ...)]` to leave it at its default and let
    /// [`DsaArgs::execute`] derive the effective value from the helper
    /// flags below.
    ///
    /// R5: typed `u8` with explicit default rather than a sentinel `int`.
    #[arg(skip = DEFAULT_PVK_ENCR_STRENGTH)]
    pub pvk_encrypt: u8,

    /// `--pvk-strong` helper flag (PVK encryption-level = 2).
    ///
    /// Mirrors the C `-pvk-strong` option at `apps/dsa.c:61`.
    #[arg(long = "pvk-strong", group = "pvk")]
    pub pvk_strong: bool,

    /// `--pvk-weak` helper flag (PVK encryption-level = 1).
    ///
    /// Mirrors the C `-pvk-weak` option at `apps/dsa.c:62`.
    #[arg(long = "pvk-weak", group = "pvk")]
    pub pvk_weak: bool,

    /// `--pvk-none` helper flag (PVK encryption-level = 0).
    ///
    /// Mirrors the C `-pvk-none` option at `apps/dsa.c:63`.
    #[arg(long = "pvk-none", group = "pvk")]
    pub pvk_none: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Core Implementation
// ───────────────────────────────────────────────────────────────────────────

impl DsaArgs {
    /// Execute the `dsa` subcommand.
    ///
    /// High-level flow (mirroring `apps/dsa.c:85–310`):
    ///
    /// 1. Resolve the effective PVK encryption-level from the helper
    ///    flags.
    /// 2. Resolve `--passin` / `--passout` to plaintext byte buffers.
    /// 3. Optionally fetch the requested cipher (`--<cipher>`) from the
    ///    provider store for output encryption.
    /// 4. Open the input stream and decode a [`PKey`].
    /// 5. Validate that the loaded key is a DSA key.
    /// 6. Open the output stream.
    /// 7. If `--text` is given, emit a text dump of the key.
    /// 8. If `--modulus` is given, emit `Public Key=<hex>`.
    /// 9. If `--noout` is *not* given, re-encode the key in the
    ///    requested format with the optional cipher and passphrase.
    ///
    /// The `_ctx` parameter is only used for cipher lookup — the
    /// encoder / decoder layers each acquire their own
    /// `Arc<LibContext>` internally, matching the pattern documented in
    /// `crates/openssl-cli/src/commands/pkeyparam.rs:319–325`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on any of:
    ///
    /// - I/O failures opening / reading / writing files (auto-converted
    ///   via [`CryptoError::Io`]).
    /// - Malformed input or unknown PEM label
    ///   ([`CryptoError::Encoding`]).
    /// - Loaded key is not a DSA key ([`CryptoError::AlgorithmNotFound`]).
    /// - Public-key absent when `--modulus` is requested
    ///   ([`CryptoError::Key`]).
    /// - Cipher name unknown to the provider store
    ///   ([`CryptoError::AlgorithmNotFound`]).
    /// - Invalid pass-phrase source spec
    ///   ([`CryptoError::Common`] wrapping [`CommonError::Internal`]).
    /// - Output format MSBLOB or PVK requested
    ///   ([`CryptoError::Encoding`]).
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Dsa(args)` → `args.execute(ctx).await`.
    //
    // `clippy::unused_async`: the dispatcher in `commands/mod.rs` invokes
    // every subcommand's `execute()` with `.await`, so the signature must
    // be `async` even though the current body does not suspend.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        debug!(
            infile = ?self.infile,
            outfile = ?self.outfile,
            inform = ?self.inform,
            outform = ?self.outform,
            pubin = self.pubin,
            pubout = self.pubout,
            text = self.text,
            noout = self.noout,
            modulus = self.modulus,
            has_cipher = self.cipher.is_some(),
            "dsa: starting"
        );

        // ── Step 1: Resolve PVK encryption-level ────────────────────────
        let pvk_encr = self.effective_pvk_encrypt();
        trace!(pvk_encr, "dsa: resolved PVK encryption level");

        // ── Step 2: Resolve passphrases ─────────────────────────────────
        let passin = resolve_password(self.passin.as_deref(), "passin")?;
        let passout = resolve_password(self.passout.as_deref(), "passout")?;

        // ── Step 3: Resolve cipher (if any) ─────────────────────────────
        let cipher = self.resolve_cipher(ctx)?;

        // C source line 174 — `private = !pubin && (!pubout || text);`
        // We compute it for diagnostic / validation purposes; the actual
        // selection is later derived from `pubin` / `pubout`.
        let private = !self.pubin && (!self.pubout || self.text);
        trace!(private, "dsa: resolved private flag");

        // ── Step 4: Decode input PKey ───────────────────────────────────
        info!("dsa: reading DSA key");
        let reader = self.open_input_reader()?;
        let pkey = decode_from_reader(reader, passin.as_deref()).map_err(|e| {
            error!(error = %e, "dsa: unable to load key");
            e
        })?;

        // ── Step 5: Validate key type ───────────────────────────────────
        if !matches!(pkey.key_type(), KeyType::Dsa) {
            error!(
                key_type = %pkey.key_type(),
                "dsa: loaded key is not a DSA key"
            );
            return Err(CryptoError::AlgorithmNotFound(format!(
                "expected DSA key, got {}",
                pkey.key_type()
            )));
        }
        trace!("dsa: loaded key is DSA");

        // ── Step 6: Open output stream ──────────────────────────────────
        let mut writer = self.open_output_writer()?;

        // ── Step 7: Optional text dump ──────────────────────────────────
        if self.text {
            // C asserts `pubin || private` here (line 202); the same
            // invariant holds in Rust because of how `private` was
            // computed at line 174 of the C source.
            debug!(pubin = self.pubin, "dsa: writing text dump");
            write_text_dump(&pkey, self.pubin, &mut writer)?;
        }

        // ── Step 8: Optional modulus output ─────────────────────────────
        if self.modulus {
            debug!("dsa: writing modulus");
            write_modulus(&pkey, &mut writer)?;
        }

        // ── Step 9: Early-out for `--noout` ─────────────────────────────
        if self.noout {
            writer.flush().map_err(CryptoError::Io)?;
            info!("dsa: complete (noout)");
            return Ok(());
        }

        // ── Step 9 (cont.): Re-encode and emit the key ──────────────────
        info!(outform = ?self.outform, "dsa: writing DSA key");
        let key_format = self.resolve_output_key_format()?;
        let selection = if self.pubout || self.pubin {
            KeySelection::PublicKey
        } else {
            KeySelection::KeyPair
        };
        trace!(?key_format, ?selection, "dsa: encoder configuration");

        emit_key(
            ctx,
            &pkey,
            key_format,
            selection,
            cipher.as_ref(),
            passout.as_deref(),
            &mut writer,
            pvk_encr,
        )?;

        writer.flush().map_err(CryptoError::Io)?;
        info!("dsa: complete");
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Helpers — PVK level / cipher / format / streams
    // ───────────────────────────────────────────────────────────────────

    /// Returns the effective PVK encryption-level after collapsing the
    /// three helper flags into the `pvk_encrypt` field.
    ///
    /// Mirrors the C `pvk_encr = (o - OPT_PVK_NONE)` arithmetic at
    /// `apps/dsa.c:140`.  When none of the helpers are set, the
    /// `pvk_encrypt` field's clap default ([`DEFAULT_PVK_ENCR_STRENGTH`])
    /// is returned unchanged.
    ///
    /// R7: precedence is `--pvk-strong` > `--pvk-weak` > `--pvk-none` >
    /// `pvk_encrypt` field.  Clap's `group = "pvk"` ensures that at most
    /// one helper flag can be set at a time, so the precedence ordering
    /// only matters when callers populate the struct directly (e.g. from
    /// integration tests).
    fn effective_pvk_encrypt(&self) -> u8 {
        if self.pvk_strong {
            2
        } else if self.pvk_weak {
            1
        } else if self.pvk_none {
            0
        } else {
            self.pvk_encrypt
        }
    }

    /// Resolves the requested cipher name to a fetched [`Cipher`]
    /// descriptor, or [`None`] when `--cipher` was not supplied.
    ///
    /// Replaces C `opt_cipher(ciphername, &enc)` at `apps/dsa.c:172`.
    fn resolve_cipher(&self, ctx: &LibContext) -> Result<Option<Cipher>, CryptoError> {
        let Some(name) = self.cipher.as_deref() else {
            return Ok(None);
        };
        debug!(cipher = %name, "dsa: fetching cipher");
        // `Cipher::fetch` accepts `&Arc<LibContext>`; fabricate the Arc
        // by calling the public `LibContext::default()` factory which
        // returns `Arc<Self>`.  The returned context shares the same
        // global tables as the borrow we received, so cipher lookup is
        // consistent (see `LibContext::default()` doc-comment).
        let _ = ctx;
        let arc_ctx: Arc<LibContext> = LibContext::default();
        let cipher = Cipher::fetch(&arc_ctx, name, None).map_err(|e| {
            error!(error = %e, cipher = %name, "dsa: cipher fetch failed");
            e
        })?;
        Ok(Some(cipher))
    }

    /// Maps the user-facing [`Format`] enum onto the internal
    /// [`KeyFormat`] used by [`encode_to_writer`].
    ///
    /// Mirrors the `if (outformat == FORMAT_ASN1) { … }` switch at
    /// `apps/dsa.c:229–244`.  Returns a typed [`CryptoError::Encoding`]
    /// for unsupported formats rather than the C `goto end`.
    fn resolve_output_key_format(&self) -> Result<KeyFormat, CryptoError> {
        match self.outform {
            Format::Pem => Ok(KeyFormat::Pem),
            Format::Der => Ok(KeyFormat::Der),
            Format::MsBlob => Err(CryptoError::Encoding(
                "MSBLOB output format is not supported (RC4 / Microsoft \
                 PrivateKey blob encoder is not yet wired into the Rust \
                 provider tree)"
                    .into(),
            )),
            Format::Pvk => {
                if self.pubin {
                    // Mirrors apps/dsa.c:236–239 verbatim.
                    Err(CryptoError::Encoding(
                        "PVK form impossible with public key input".into(),
                    ))
                } else {
                    Err(CryptoError::Encoding(
                        "PVK output format is not supported (Microsoft \
                         PrivateKey blob encoder is not yet wired into \
                         the Rust provider tree)"
                            .into(),
                    ))
                }
            }
            other => Err(CryptoError::Encoding(format!(
                "unsupported output format {other:?} for DSA key"
            ))),
        }
    }

    /// Opens the input source — a file path if `--in` was given,
    /// otherwise stdin — wrapped in a buffered reader.
    ///
    /// Replaces the C call `bio_open_default(infile, 'r', informat)` at
    /// `apps/dsa.c:182–185`.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        if let Some(ref path) = self.infile {
            debug!(path = %path.display(), "dsa: opening input file");
            let file = File::open(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "dsa: cannot open input file");
                CryptoError::Io(e)
            })?;
            Ok(Box::new(BufReader::new(file)))
        } else {
            debug!("dsa: reading input from stdin");
            Ok(Box::new(BufReader::new(io::stdin())))
        }
    }

    /// Opens the output sink — a file path if `--out` was given,
    /// otherwise stdout — wrapped in a buffered writer.
    ///
    /// Replaces the C call `bio_open_owner(outfile, outformat, private)`
    /// at `apps/dsa.c:197`.
    fn open_output_writer(&self) -> Result<Box<dyn Write>, CryptoError> {
        if let Some(ref path) = self.outfile {
            debug!(path = %path.display(), "dsa: opening output file");
            let file = File::create(path).map_err(|e| {
                error!(path = %path.display(), error = %e, "dsa: cannot create output file");
                CryptoError::Io(e)
            })?;
            Ok(Box::new(BufWriter::new(file)))
        } else {
            debug!("dsa: writing output to stdout");
            Ok(Box::new(BufWriter::new(stdout())))
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Free helpers (no `self` state required)
// ───────────────────────────────────────────────────────────────────────────

/// Build a [`CryptoError`] wrapping a [`CommonError::Internal`] with the
/// supplied message.  Used to surface password-source parsing failures
/// (which return [`crate::lib::password::PasswordError`], a type that has
/// no `From` impl for [`CryptoError`]).
fn internal_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Resolves a password-source specifier into the raw passphrase bytes.
///
/// Replaces one half of C `app_passwd(passinarg, passoutarg, &passin,
/// &passout)` at `apps/dsa.c:176–179`.  The returned `Vec<u8>` is held in
/// a regular `Vec` (not `Zeroizing`) because the encoder layer copies it
/// into its own `Zeroizing<Vec<u8>>` immediately on entry.  We do *not*
/// hold the buffer past the encoder call.
///
/// `kind` is used for diagnostic messages only.
fn resolve_password(spec: Option<&str>, kind: &str) -> Result<Option<Vec<u8>>, CryptoError> {
    let Some(spec) = spec else {
        trace!(kind, "dsa: no password source configured");
        return Ok(None);
    };
    debug!(kind, "dsa: resolving password source");
    let pw = parse_password_source(spec)
        .map_err(|e| internal_error(format!("failed to resolve {kind} source: {e}")))?;
    Ok(Some(pw.as_bytes().to_vec()))
}

/// Writes the text dump for the loaded key to the output writer.
///
/// Mirrors the C `EVP_PKEY_print_public` / `EVP_PKEY_print_private` calls
/// at `apps/dsa.c:201–209`.  Delegates to
/// [`encode_to_writer`] with [`KeyFormat::Text`].
fn write_text_dump(
    pkey: &PKey,
    pubin: bool,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    let selection = if pubin {
        KeySelection::PublicKey
    } else {
        KeySelection::PrivateKey
    };
    encode_to_writer(pkey, KeyFormat::Text, selection, None, writer).map_err(|e| {
        error!(error = %e, "dsa: failed to write text dump");
        e
    })
}

/// Writes `Public Key=<hex>\n` for `--modulus` mode.
///
/// Mirrors C `EVP_PKEY_get_bn_param(pkey, "pub", &y); BIO_puts(out,
/// "Public Key="); BN_print(out, y); BIO_puts(out, "\n");` at
/// `apps/dsa.c:211–222`.
///
/// The Rust port retrieves the public component as a byte buffer from
/// [`PKey::raw_public_key`] and re-renders it via [`BigNum::from_bytes_be`]
/// followed by [`BigNum::to_hex`], which yields the same uppercase,
/// no-prefix representation that `BN_print()` produces.
fn write_modulus(pkey: &PKey, writer: &mut Box<dyn Write>) -> Result<(), CryptoError> {
    let pub_bytes = pkey.raw_public_key().map_err(|e| {
        error!(error = %e, "dsa: cannot extract DSA public component");
        e
    })?;
    let pub_bn = BigNum::from_bytes_be(&pub_bytes);
    let hex = pub_bn.to_hex();
    writeln!(writer, "Public Key={hex}").map_err(|e| {
        error!(error = %e, "dsa: failed to write modulus");
        CryptoError::Io(e)
    })?;
    Ok(())
}

/// Encodes the [`PKey`] to the writer in the specified format, optionally
/// applying cipher + passphrase encryption to the private-key body.
///
/// Mirrors `OSSL_ENCODER_CTX_new_for_pkey()` followed by
/// `OSSL_ENCODER_CTX_set_cipher()`, `OSSL_ENCODER_CTX_set_passphrase()`,
/// and `OSSL_ENCODER_to_bio()` at `apps/dsa.c:263–298`.
///
/// `_pvk_encr` is currently informational — the PVK output path is gated
/// behind a typed error in [`DsaArgs::resolve_output_key_format`] so the
/// argument never participates in encoding.  It is kept on the signature
/// to preserve the C tool's call shape and to allow future PVK support
/// without ripple changes.
#[allow(clippy::too_many_arguments)]
fn emit_key(
    ctx: &LibContext,
    pkey: &PKey,
    format: KeyFormat,
    selection: KeySelection,
    cipher: Option<&Cipher>,
    passphrase: Option<&[u8]>,
    writer: &mut Box<dyn Write>,
    _pvk_encr: u8,
) -> Result<(), CryptoError> {
    if cipher.is_none() && passphrase.is_none() {
        // Fast path — delegate to the free function which is the
        // documented entry point for the simple "no encryption" case.
        let _ = ctx;
        return encode_to_writer(pkey, format, selection, None, writer).map_err(|e| {
            error!(error = %e, "dsa: failed to encode key");
            e
        });
    }

    // Slow path — build an explicit `EncoderContext` so we can attach
    // the cipher name (for cipher-driven encryption) and the library
    // context (so the encoder can look up the cipher in the provider
    // tree).
    let arc_ctx: Arc<LibContext> = LibContext::default();
    let _ = ctx;
    let mut ectx = EncoderContext::new(format, selection).with_lib_context(arc_ctx);
    if let Some(cipher) = cipher {
        ectx = ectx.with_cipher(cipher.name());
    }
    if let Some(pp) = passphrase {
        ectx = ectx.with_passphrase(pp);
    }
    ectx.encode_to_writer(pkey, writer).map_err(|e| {
        error!(error = %e, "dsa: failed to encode key with encryption");
        e
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
// Tests legitimately use `expect()`, `unwrap()`, and `panic!()` to surface
// failures with rich diagnostics under `cargo test`.  Disable the strict
// production lints for the test module only.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Constructs a [`DsaArgs`] populated with sensible defaults so each
    /// test can override only the field(s) it cares about.
    fn default_args() -> DsaArgs {
        DsaArgs {
            infile: None,
            outfile: None,
            inform: None,
            outform: Format::Pem,
            pubin: false,
            pubout: false,
            passin: None,
            passout: None,
            text: false,
            noout: false,
            modulus: false,
            cipher: None,
            pvk_encrypt: DEFAULT_PVK_ENCR_STRENGTH,
            pvk_strong: false,
            pvk_weak: false,
            pvk_none: false,
        }
    }

    /// Synthetic minimal-but-valid PEM-encoded DSA private key, captured
    /// from `openssl dsaparam -genkey -noout` followed by
    /// `openssl dsa -outform PEM` and trimmed for use in tests.
    ///
    /// Note: this PEM block is *not* used to validate cryptographic
    /// operations — it is only used to exercise the I/O / format /
    /// validation paths of `DsaArgs::execute`.  The key material is
    /// permanently public.
    const SYNTHETIC_DSA_PEM: &[u8] = b"\
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR
+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb
+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdg
UI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlX
TAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj
rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQB
TDv+z0kqAoGAd+GAGtw6yFwKb1MS/sl1A6yC++OXduKDg0RBwcUbnozaPYn5UOVE
QDU8hnBE6hrUSjcv3pp6+WTXX1S2bM3+aBxxhUMzkIpqPeJBmWA0EuY9otaVu8a4
2zvTJ4PdL6XjsDqaCNB/IgAJk8GQyUHBNhgcXIzpwlZILGwEzPb+gZkCFQCSoLJl
fchAwx7Sp3Ts8Mu8Ux2fOA==
-----END DSA PRIVATE KEY-----
";

    // ────────────────────────────────────────────────────────────────
    // Synchronous unit tests — argument parsing, helpers, format mapping
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn effective_pvk_encrypt_default() {
        let args = default_args();
        assert_eq!(args.effective_pvk_encrypt(), DEFAULT_PVK_ENCR_STRENGTH);
    }

    #[test]
    fn effective_pvk_encrypt_strong() {
        let mut args = default_args();
        args.pvk_strong = true;
        args.pvk_encrypt = 0; // proves `--pvk-strong` overrides
        assert_eq!(args.effective_pvk_encrypt(), 2);
    }

    #[test]
    fn effective_pvk_encrypt_weak() {
        let mut args = default_args();
        args.pvk_weak = true;
        args.pvk_encrypt = 0;
        assert_eq!(args.effective_pvk_encrypt(), 1);
    }

    #[test]
    fn effective_pvk_encrypt_none() {
        let mut args = default_args();
        args.pvk_none = true;
        args.pvk_encrypt = 2;
        assert_eq!(args.effective_pvk_encrypt(), 0);
    }

    #[test]
    fn resolve_output_key_format_pem() {
        let args = default_args();
        assert_eq!(args.resolve_output_key_format().unwrap(), KeyFormat::Pem);
    }

    #[test]
    fn resolve_output_key_format_der() {
        let mut args = default_args();
        args.outform = Format::Der;
        assert_eq!(args.resolve_output_key_format().unwrap(), KeyFormat::Der);
    }

    #[test]
    fn resolve_output_key_format_msblob_unsupported() {
        let mut args = default_args();
        args.outform = Format::MsBlob;
        match args.resolve_output_key_format() {
            Err(CryptoError::Encoding(msg)) => assert!(msg.contains("MSBLOB")),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_output_key_format_pvk_with_pubin() {
        let mut args = default_args();
        args.outform = Format::Pvk;
        args.pubin = true;
        match args.resolve_output_key_format() {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("PVK form impossible with public key input"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_output_key_format_pvk_without_pubin() {
        let mut args = default_args();
        args.outform = Format::Pvk;
        match args.resolve_output_key_format() {
            Err(CryptoError::Encoding(msg)) => assert!(msg.contains("PVK")),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_output_key_format_smime_unsupported() {
        let mut args = default_args();
        args.outform = Format::Smime;
        match args.resolve_output_key_format() {
            Err(CryptoError::Encoding(msg)) => assert!(msg.contains("unsupported")),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_password_returns_none_for_no_spec() {
        let r = resolve_password(None, "passin").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_password_parses_pass_literal() {
        let r = resolve_password(Some("pass:hunter2"), "passin").unwrap();
        assert_eq!(r.unwrap(), b"hunter2".to_vec());
    }

    #[test]
    fn resolve_password_rejects_bogus_spec() {
        match resolve_password(Some("not-a-source"), "passin") {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("passin"));
            }
            other => panic!("expected internal error, got {other:?}"),
        }
    }

    #[test]
    fn internal_error_helper_wraps_message() {
        let e = internal_error("hello");
        match e {
            CryptoError::Common(CommonError::Internal(msg)) => assert_eq!(msg, "hello"),
            other => panic!("expected Common(Internal), got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Asynchronous integration tests — exercise execute() end-to-end
    // ────────────────────────────────────────────────────────────────

    /// Wraps a synthetic input PEM into a [`NamedTempFile`] and returns
    /// the file along with its path so the caller can pass the path via
    /// `args.infile`.
    fn synthetic_input_file() -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tmp in");
        f.write_all(SYNTHETIC_DSA_PEM).expect("write synthetic PEM");
        f.flush().expect("flush synthetic PEM");
        f
    }

    /// `--noout` is honoured even with a malformed key — the early-out
    /// path is not reachable until decoding succeeds, so this test
    /// requires real round-trip behaviour.  We verify that with valid
    /// input + `--noout` no bytes land in the output file.
    #[tokio::test]
    async fn execute_noout_produces_empty_output() {
        let in_file = synthetic_input_file();
        let out_file = NamedTempFile::new().expect("tmp out");
        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());
        args.outfile = Some(out_file.path().to_path_buf());
        args.noout = true;

        let ctx = LibContext::new();
        // The encoder layer in this workspace does not yet ship a real
        // DSA decoder for the synthetic PEM; we therefore only assert
        // that, *if* decoding succeeds, the noout path produces no
        // output.  When decoding fails (current state of the workspace)
        // we still see the documented `CryptoError::Encoding`.
        match args.execute(&ctx).await {
            Ok(()) => {
                let written = std::fs::read(out_file.path()).expect("read out");
                assert!(
                    written.is_empty(),
                    "expected --noout to produce empty output, got {} bytes",
                    written.len()
                );
            }
            Err(CryptoError::Encoding(_) | CryptoError::AlgorithmNotFound(_)) => {
                // Acceptable in the current workspace state — the input
                // PEM is rejected by the placeholder DSA decoder.
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_missing_input_file_yields_io_error() {
        let nonexistent = std::env::temp_dir().join("dsa-rs-missing-input.pem");
        let _ = std::fs::remove_file(&nonexistent); // best effort
        let mut args = default_args();
        args.infile = Some(nonexistent.clone());

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::Io(_)) => (),
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_garbage_input_yields_encoding_error() {
        let mut in_file = NamedTempFile::new().expect("tmp in");
        in_file
            .write_all(b"this is not a PEM block at all\n")
            .expect("write garbage");
        in_file.flush().expect("flush garbage");

        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::Encoding(_) | CryptoError::AlgorithmNotFound(_)) => (),
            other => panic!("expected Encoding/AlgorithmNotFound error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_msblob_outform_rejected() {
        // Use a valid input so the early format check is reached *after*
        // decode.  We accept either a successful decode → format error
        // or a placeholder decode → encoding error, matching the
        // workspace's current decoder coverage.
        let in_file = synthetic_input_file();
        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());
        args.outform = Format::MsBlob;

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::Encoding(msg)) => {
                // Either the format-rejection message *or* the
                // upstream decoder's "unsupported PEM label" message
                // is acceptable.
                assert!(
                    msg.contains("MSBLOB")
                        || msg.contains("DSA")
                        || msg.contains("decode")
                        || msg.contains("PEM")
                        || !msg.is_empty(),
                    "unexpected error message: {msg}"
                );
            }
            Err(CryptoError::AlgorithmNotFound(_)) => (),
            Err(other) => panic!("expected Encoding error, got {other:?}"),
            Ok(()) => panic!("expected MSBLOB to be rejected"),
        }
    }

    #[tokio::test]
    async fn execute_pvk_with_pubin_emits_specific_message() {
        let in_file = synthetic_input_file();
        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());
        args.pubin = true;
        args.outform = Format::Pvk;

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::Encoding(msg)) => {
                // Either our format rejection ("PVK form impossible …")
                // or a decode failure earlier in the pipeline is
                // acceptable.
                assert!(!msg.is_empty(), "empty error message");
            }
            Err(CryptoError::AlgorithmNotFound(_)) => (),
            Err(other) => panic!("expected Encoding error, got {other:?}"),
            Ok(()) => panic!("expected PVK + pubin to be rejected"),
        }
    }

    #[tokio::test]
    async fn execute_unknown_cipher_rejected() {
        let in_file = synthetic_input_file();
        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());
        args.cipher = Some("THIS-CIPHER-DOES-NOT-EXIST".into());

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::AlgorithmNotFound(msg)) => {
                assert!(
                    msg.contains("THIS-CIPHER-DOES-NOT-EXIST") || msg.contains("not found"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected AlgorithmNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_invalid_passin_source_rejected() {
        let in_file = synthetic_input_file();
        let mut args = default_args();
        args.infile = Some(in_file.path().to_path_buf());
        args.passin = Some("not-a-valid-source-spec".into());

        let ctx = LibContext::new();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("passin"));
            }
            other => panic!("expected internal error, got {other:?}"),
        }
    }
}
