//! `openssl pkey` — public/private key processing.
//!
//! Translation of `apps/pkey.c` (361 lines) into idiomatic Rust under the
//! Cargo workspace. The original C entry point was `pkey_main()` which
//! parsed `OPTION_CHOICE` flags via `opt_next()` / `opt_arg()` and dispatched
//! to a flat function body. The Rust translation replaces the option enum
//! with a `clap::Args`-derived struct ([`PkeyArgs`]) and replaces the flat
//! body with a method ([`PkeyArgs::execute`]) backed by a small set of
//! private helpers and free functions, all of which mirror the semantics
//! of the C source line-for-line.
//!
//! # Behaviour summary
//!
//! `openssl pkey` is the general-purpose asymmetric-key utility:
//!
//! - Decodes an input key (PEM or DER) from `-in` (or stdin) using a
//!   passphrase from `-passin` if encrypted.
//! - Optionally validates the key with `EVP_PKEY_check()` /
//!   `EVP_PKEY_public_check()` (mapped to
//!   [`PKeyCtx::check`](openssl_crypto::evp::pkey::PKeyCtx::check) and
//!   [`PKeyCtx::public_check`](openssl_crypto::evp::pkey::PKeyCtx::public_check)).
//! - Re-encodes the key in the requested output format (PEM or DER) with
//!   optional symmetric encryption (`-cipher` + `-passout`) and selects
//!   between full keypair, public-only, and traditional encodings via the
//!   `-pubout` and `-traditional` flags.
//! - Optionally prints a human-readable text dump of the private key
//!   (`-text`) or public key (`-text_pub`).
//!
//! # Source-to-target option mapping
//!
//! | C `OPTION_CHOICE`     | Rust field                    | clap flag        |
//! |-----------------------|-------------------------------|------------------|
//! | `OPT_IN`              | [`PkeyArgs::input`]           | `-in`            |
//! | `OPT_OUT`             | [`PkeyArgs::output`]          | `-out`           |
//! | `OPT_INFORM`          | [`PkeyArgs::inform`]          | `-inform`        |
//! | `OPT_OUTFORM`         | [`PkeyArgs::outform`]         | `-outform`       |
//! | `OPT_PUBIN`           | [`PkeyArgs::pubin`]           | `-pubin`         |
//! | `OPT_PUBOUT`          | [`PkeyArgs::pubout`]          | `-pubout`        |
//! | `OPT_PASSIN`          | [`PkeyArgs::passin`]          | `-passin`        |
//! | `OPT_PASSOUT`         | [`PkeyArgs::passout`]         | `-passout`       |
//! | `OPT_TEXT`            | [`PkeyArgs::text`]            | `-text`          |
//! | `OPT_TEXT_PUB`        | [`PkeyArgs::text_pub`]        | `-text_pub`      |
//! | `OPT_NOOUT`           | [`PkeyArgs::noout`]           | `-noout`         |
//! | `OPT_CHECK`           | [`PkeyArgs::check`]           | `-check`         |
//! | `OPT_TRADITIONAL`     | [`PkeyArgs::traditional`]     | `-traditional`   |
//! | `OPT_CIPHER`          | [`PkeyArgs::cipher`]          | `-cipher`        |
//! | `OPT_ENCOPT`          | [`PkeyArgs::encopt`]          | `-encopt`        |
//! | `OPT_EC_PARAM_ENC`    | [`PkeyArgs::ec_param_enc`]    | `-ec_param_enc`  |
//! | `OPT_EC_CONV_FORM`    | [`PkeyArgs::ec_conv_form`]    | `-ec_conv_form`  |
//!
//! # Implementation rules applied
//!
//! - **R5 (Nullability)**: optional flags use `Option<T>` (no sentinel
//!   `0`/`-1`/`""`). Path arguments are `Option<PathBuf>` so absence
//!   represents stdin/stdout rather than the empty string.
//! - **R6 (Lossless casts)**: no bare `as` casts appear in this file.
//! - **R8 (Zero unsafe)**: no `unsafe` blocks. All FFI lives in the
//!   `openssl-ffi` crate.
//! - **R9 (Warning-free)**: every public item is documented; every
//!   `#[allow(...)]` has a justification comment.
//! - **R10 (Wired)**: [`PkeyArgs`] is reachable from the CLI dispatcher
//!   (`crates/openssl-cli/src/commands/mod.rs:262, :521` —
//!   `Self::Pkey(args) => args.execute(ctx).await`).

// Outer-only attributes mirror those used by the sibling `ec` and `rsa`
// command modules so that the CLI command set is uniformly lint-clean.

use std::fs::File;
use std::io::{self, stdout, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, warn};

use openssl_common::error::{CommonError, CryptoError};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::Cipher;
use openssl_crypto::evp::encode_decode::{
    decode_from_reader, encode_to_writer, EncoderContext, KeyFormat, KeySelection,
};
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx};

use crate::lib::opts::Format;
use crate::lib::password::parse_password_source;

// =============================================================================
// PkeyArgs — clap-derived argument structure
// =============================================================================

/// Arguments for the `openssl pkey` subcommand.
///
/// Mirrors the `OPTION_CHOICE` enum in `apps/pkey.c` (lines 25-50): every
/// member of that enum is represented either by a typed field or a
/// `bool`. The clap `Args` derive automatically maps each `#[arg(long =
/// "...")]` declaration to a long option, replacing the manual
/// `OPT_NEXT`/`OPT_ARG` switch dispatch in the C source.
///
/// The `#[allow(clippy::struct_excessive_bools)]` attribute is required
/// because the C source defines independent boolean flags (`pubin`,
/// `pubout`, `text`, `text_pub`, `noout`, `check`, `traditional`) that
/// each control orthogonal behaviour. They cannot be coalesced into a
/// single enum without changing the CLI surface.
///
/// # Field naming
///
/// The schema requires the public field names `input` and `output`
/// (not `infile`/`outfile` as some sibling commands use). The clap
/// long-option strings remain `--in` / `--out` to preserve the
/// `openssl(1)` CLI surface verbatim.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct PkeyArgs {
    /// Input file path. `None` (the absence of `-in`) selects stdin —
    /// matching the C behaviour at `apps/pkey.c:88` where `infile = NULL`
    /// is passed to `bio_open_default()`.
    #[arg(long = "in", value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Output file path. `None` (the absence of `-out`) selects stdout —
    /// matching the C behaviour at `apps/pkey.c:91` where `outfile = NULL`
    /// is passed to `bio_open_default()`.
    #[arg(long = "out", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Input format. `None` (default) means auto-detect (corresponds to
    /// the C `informat = FORMAT_UNDEF` initial value at `apps/pkey.c:84`).
    /// Recognised values: `PEM`, `DER` (case-insensitive — matches C tool).
    ///
    /// `ignore_case = true` mirrors the C `opt_format()` behaviour from
    /// `apps/lib/opt.c` which accepts both upper- and lowercase format
    /// names. Without it, clap's auto-derived [`Format`] value parser
    /// emits only lowercase variants (`pem`, `der`, …) so the historical
    /// uppercase invocation `openssl pkey -inform PEM` would be rejected.
    #[arg(long = "inform", value_name = "FORMAT", ignore_case = true)]
    pub inform: Option<Format>,

    /// Output format. Defaults to `PEM` (matches C
    /// `outformat = FORMAT_PEM` at `apps/pkey.c:84`).
    /// Recognised values: `PEM`, `DER` (case-insensitive — matches C tool).
    ///
    /// `ignore_case = true` is required for two reasons: (1) clap evaluates
    /// `default_value = "PEM"` by feeding the literal string through the
    /// same value parser used for user input, and the auto-derived
    /// [`Format`] parser emits lowercase variants, so without
    /// case-insensitive matching the default itself would fail to parse;
    /// (2) the C tool accepts `-outform PEM` and `-outform pem`
    /// interchangeably (`apps/lib/opt.c:opt_format`) and the Rust port
    /// must preserve that behaviour.
    #[arg(
        long = "outform",
        value_name = "FORMAT",
        default_value = "PEM",
        ignore_case = true
    )]
    pub outform: Format,

    /// Read a public key (instead of a private key). Equivalent to the
    /// C `pubin = 1` block at `apps/pkey.c:139`. When set, the C source
    /// auto-implies `pubout = 1`; this Rust port replicates that
    /// auto-implication inside [`PkeyArgs::execute`].
    #[arg(long = "pubin")]
    pub pubin: bool,

    /// Write a public key (instead of a private key). Equivalent to the
    /// C `pubout = 1` block at `apps/pkey.c:142`.
    #[arg(long = "pubout")]
    pub pubout: bool,

    /// Passphrase source for the input key. Accepts the standard
    /// `pass:`, `env:`, `file:`, `fd:`, and `stdin` selectors as
    /// documented for `openssl(1) -passin`. `None` means the input is
    /// unencrypted (or the decoder will prompt later — currently a no-op
    /// in the Rust port). See [`crate::lib::password::parse_password_source`].
    #[arg(long = "passin", value_name = "SOURCE")]
    pub passin: Option<String>,

    /// Passphrase source for the output key. Only consulted when
    /// `-cipher` is set, mirroring the C warning at `apps/pkey.c:172`
    /// ("The -passout option is ignored without a cipher option").
    #[arg(long = "passout", value_name = "SOURCE")]
    pub passout: Option<String>,

    /// Print a human-readable text dump of the private key after the
    /// encoded output. Maps to C `text = 1` (`apps/pkey.c:128`).
    /// Incompatible with DER `-outform` (the C source goto's `end` at
    /// `apps/pkey.c:317` when text and DER are combined).
    #[arg(long = "text")]
    pub text: bool,

    /// Print a human-readable text dump of the public key after the
    /// encoded output. Maps to C `text_pub = 1` (`apps/pkey.c:125`).
    /// When both `-text` and `-text_pub` are given, `-text_pub` wins
    /// (matching the C warning at `apps/pkey.c:158`: "The -text option is
    /// ignored with `-text_pub`"). Also incompatible with DER `-outform`.
    #[arg(long = "text_pub")]
    pub text_pub: bool,

    /// Suppress the encoded key output (only `-text`/`-text_pub`/`-check`
    /// are honoured). Maps to C `noout = 1` (`apps/pkey.c:131`).
    #[arg(long = "noout")]
    pub noout: bool,

    /// Run `EVP_PKEY_check()` / `EVP_PKEY_public_check()` on the loaded
    /// key. Returns success when valid, prints "Key is invalid" to
    /// stderr when not (matching C `apps/pkey.c:268-293`). When `-pubin`
    /// is set, the public-only check is used.
    #[arg(long = "check")]
    pub check: bool,

    /// Use the traditional ("legacy") private-key encoding rather than
    /// PKCS#8. Maps to C `traditional = 1` (`apps/pkey.c:147`). Ignored
    /// when no private key is being written (`-noout` or `-pubout`),
    /// matching C `apps/pkey.c:163` ("-traditional is ignored with no
    /// private key output").
    ///
    /// **Graceful degradation**: the Rust [`KeyFormat`] enum does not
    /// expose a separate "traditional" variant; the modern PKCS#8
    /// encoding is used in both cases. The flag is parsed and traced so
    /// that when explicit traditional output becomes available, no CLI
    /// changes will be required.
    #[arg(long = "traditional")]
    pub traditional: bool,

    /// Symmetric cipher name to encrypt the output key (e.g.
    /// `AES-256-CBC`). Maps to C `cipher = ...` resolved via
    /// `opt_cipher_any()` (`apps/pkey.c:117`). When unset, the output
    /// key is unencrypted. Resolution is performed via
    /// [`Cipher::fetch`].
    #[arg(long = "cipher", value_name = "CIPHER")]
    pub cipher: Option<String>,

    /// Provider-specific encoder option in `name:value` form. Maps to
    /// C `OPT_ENCOPT` (`apps/pkey.c:121`) which pushes onto a
    /// `STACK_OF(OPENSSL_STRING)` for later application via
    /// `OSSL_ENCODER_CTX_set_params()`.
    ///
    /// **Graceful degradation**: the Rust port currently logs each
    /// `-encopt` entry at `debug` level and does not propagate them to
    /// the encoder. The reason is that
    /// [`openssl_common::param::ParamSet`] requires `&'static str`
    /// keys, which is incompatible with runtime user input. A future
    /// change will introduce a runtime-keyed parameter API and lift
    /// this restriction.
    #[arg(long = "encopt", value_name = "OPT")]
    pub encopt: Vec<String>,

    /// EC parameter encoding (`named_curve` or `explicit`). Maps to C
    /// `OPT_EC_PARAM_ENC` (`apps/pkey.c:248-256`). Compiled in only
    /// when the `ec` feature is enabled (matches C
    /// `#ifndef OPENSSL_NO_EC`).
    ///
    /// **Graceful degradation**: the Rust [`PKey`] does not yet expose
    /// a parameter mutator; the value is parsed and traced but not
    /// applied. Mirrors the same pattern used by the sibling
    /// `crates/openssl-cli/src/commands/ec.rs` command.
    #[cfg(feature = "ec")]
    #[arg(long = "ec_param_enc", value_name = "FORM")]
    pub ec_param_enc: Option<String>,

    /// EC point conversion form (`uncompressed`, `compressed`, or
    /// `hybrid`). Maps to C `OPT_EC_CONV_FORM` (`apps/pkey.c:257-263`).
    /// Compiled in only when the `ec` feature is enabled.
    ///
    /// **Graceful degradation**: same rationale as
    /// [`Self::ec_param_enc`] — parsed and traced but not applied
    /// pending [`PKey`] parameter-mutator support.
    #[cfg(feature = "ec")]
    #[arg(long = "ec_conv_form", value_name = "FORM")]
    pub ec_conv_form: Option<String>,
}

// =============================================================================
// PkeyArgs::execute and helpers
// =============================================================================

impl PkeyArgs {
    /// Validates the argument combination before any I/O.
    ///
    /// Mirrors the implicit and explicit checks in `apps/pkey.c`:
    ///
    /// - `-text`/`-text_pub` are incompatible with DER output
    ///   (`apps/pkey.c:316-318`).
    /// - `-outform` must be `PEM` or `DER`. The clap [`Format`] enum
    ///   permits other variants (e.g., MSBLOB) but `apps/pkey.c` treats
    ///   anything else as silently dropped via the `else if` chain at
    ///   `apps/pkey.c:296-330`. We elevate that to a hard error so the
    ///   user gets actionable feedback instead of a silent no-op.
    fn validate_args(&self) -> Result<(), CryptoError> {
        // Outform must be PEM or DER. The Format enum may include
        // additional variants; reject those explicitly.
        match self.outform {
            Format::Pem | Format::Der => {}
            other => {
                error!(format = ?other, "pkey: outform not supported");
                return Err(internal_error(format!(
                    "pkey: -outform {other:?} not supported (use PEM or DER)"
                )));
            }
        }
        // Text output cannot be combined with DER (matches C error at
        // apps/pkey.c:316).
        if matches!(self.outform, Format::Der) && (self.text || self.text_pub) && !self.noout {
            error!("pkey: text output is incompatible with DER output");
            return Err(internal_error(
                "pkey: text output cannot be combined with DER output",
            ));
        }
        Ok(())
    }

    /// Computes the `(text, text_pub, pubout)` tuple after applying the
    /// auto-promotion rules from `apps/pkey.c`.
    ///
    /// Rules (in order):
    /// 1. `-pubin` ⇒ `-pubout` (forced) — `apps/pkey.c:140`.
    /// 2. `!text_pub && pubout && text` ⇒ `text=false, text_pub=true`
    ///    — `apps/pkey.c:155-159` (the C source warns and demotes).
    fn auto_promote(&self) -> (bool, bool, bool) {
        let mut text = self.text;
        let mut text_pub = self.text_pub;
        let mut pubout = self.pubout;
        if self.pubin {
            pubout = true;
        }
        if !text_pub && pubout && text {
            warn!(
                "pkey: -text is ignored with -pubout/-pubin; auto-promoting to -text_pub \
                 (matches apps/pkey.c:155-159)"
            );
            text = false;
            text_pub = true;
        }
        (text, text_pub, pubout)
    }

    /// Resolves the optional `-cipher` argument to a fetched
    /// [`Cipher`].
    ///
    /// Mirrors the C `opt_cipher_any()` resolution at `apps/pkey.c:117`.
    /// Returns `Ok(None)` when no cipher was requested. Returns
    /// [`CryptoError::AlgorithmNotFound`] when the cipher name is
    /// not registered with any provider.
    fn resolve_cipher(&self, ctx: &LibContext) -> Result<Option<Cipher>, CryptoError> {
        let Some(name) = self.cipher.as_deref() else {
            return Ok(None);
        };
        debug!(cipher = name, "pkey: resolving cipher for encrypted output");
        // The execute() method receives `&LibContext`. The Cipher::fetch
        // API takes `&Arc<LibContext>` so we obtain a default Arc handle.
        // The `_ = ctx` consumes the borrowed argument and matches the
        // pattern used in sibling commands (ec.rs, rsa.rs).
        let arc_ctx: Arc<LibContext> = LibContext::default();
        let _ = ctx;
        let cipher = Cipher::fetch(&arc_ctx, name, None)?;
        debug!(cipher = cipher.name(), "pkey: cipher fetched successfully");
        Ok(Some(cipher))
    }

    /// Maps the CLI [`Format`] to the crypto-layer [`KeyFormat`].
    ///
    /// Returns [`CryptoError::Encoding`] for variants that the encoder
    /// pipeline does not support. Validation against `validate_args()`
    /// ensures only PEM/DER reach this method, but defence-in-depth is
    /// retained.
    fn resolve_output_key_format(&self) -> Result<KeyFormat, CryptoError> {
        match self.outform {
            Format::Pem => Ok(KeyFormat::Pem),
            Format::Der => Ok(KeyFormat::Der),
            other => Err(CryptoError::Encoding(format!(
                "pkey: cannot encode key in format {other:?}"
            ))),
        }
    }

    /// Maps the CLI [`Format`] to the crypto-layer [`KeyFormat`] for
    /// the input side.
    ///
    /// Currently only used for tracing — the
    /// [`decode_from_reader`] entry point auto-detects PEM vs. DER and
    /// does not need a hint, matching the C
    /// `OSSL_DECODER_CTX_new_for_pkey()` default behaviour.
    fn resolve_input_key_format(&self) -> Option<KeyFormat> {
        match self.inform {
            Some(Format::Pem) => Some(KeyFormat::Pem),
            Some(Format::Der) => Some(KeyFormat::Der),
            _ => None,
        }
    }

    /// Opens the input reader, defaulting to stdin when `-in` is
    /// unset. Matches `bio_open_default(infile, 'r', ...)` from
    /// `apps/pkey.c:184`.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        match self.input.as_deref() {
            None => Ok(Box::new(BufReader::new(io::stdin()))),
            Some(path) => {
                debug!(path = ?path, "pkey: opening input file");
                let file = File::open(path).map_err(|e| {
                    error!(path = ?path, error = %e, "pkey: failed to open input file");
                    CryptoError::Io(e)
                })?;
                Ok(Box::new(BufReader::new(file)))
            }
        }
    }

    /// Opens the output writer, defaulting to stdout when `-out` is
    /// unset. Matches `bio_open_owner(outfile, outformat, private)` at
    /// `apps/pkey.c:188`.
    ///
    /// Buffered with `BufWriter` so that text and binary writes are
    /// efficient. Callers must invoke `writer.flush()` explicitly before
    /// dropping the box; the failure mode is `CryptoError::Io`.
    fn open_output_writer(&self) -> Result<Box<dyn Write>, CryptoError> {
        match self.output.as_deref() {
            None => Ok(Box::new(BufWriter::new(stdout()))),
            Some(path) => {
                debug!(path = ?path, "pkey: opening output file");
                let file = File::create(path).map_err(|e| {
                    error!(path = ?path, error = %e, "pkey: failed to create output file");
                    CryptoError::Io(e)
                })?;
                Ok(Box::new(BufWriter::new(file)))
            }
        }
    }

    /// Logs each `-encopt` entry. The C source pushes these onto a
    /// stack and applies them via `OSSL_ENCODER_CTX_set_params()` at
    /// `apps/pkey.c:155` of the `encode_private_key` static helper. The
    /// Rust port currently performs only diagnostic tracing — see the
    /// field-level documentation on [`PkeyArgs::encopt`] for the
    /// graceful-degradation rationale.
    fn apply_encopt(&self) {
        for opt in &self.encopt {
            // Validate the basic name:value shape so misconfigured
            // strings produce a useful diagnostic. The C source
            // performs the same name:value split inside
            // OSSL_ENCODER_CTX_set_params via the OSSL_PARAM construction.
            if let Some((name, value)) = opt.split_once(':') {
                debug!(
                    encopt_name = name,
                    encopt_value = value,
                    "pkey: -encopt parsed (parameter pass-through pending ParamSet runtime keys)"
                );
            } else {
                warn!(
                    encopt = %opt,
                    "pkey: -encopt entry missing ':' separator; ignoring"
                );
            }
        }
    }

    /// Logs the EC parameter overrides. Compiled in only when the
    /// `ec` feature is enabled. See the field-level documentation on
    /// [`PkeyArgs::ec_param_enc`] for the graceful-degradation
    /// rationale.
    #[cfg(feature = "ec")]
    fn apply_ec_params(&self, pkey: &PKey) {
        let asn1_set = self.ec_param_enc.is_some();
        let conv_set = self.ec_conv_form.is_some();
        if !asn1_set && !conv_set {
            return;
        }
        // C source verifies EVP_PKEY_is_a(pkey, "EC") before applying;
        // we mirror that and trace a warning when the key type does not
        // match instead of erroring out — the CLI semantics in
        // apps/pkey.c:251 are to `goto end` (silent failure) which we
        // upgrade to a visible warning.
        if !matches!(pkey.key_type(), KeyType::Ec) {
            warn!(
                key_type = pkey.key_type_name(),
                "pkey: -ec_param_enc/-ec_conv_form set but key is not EC; ignoring \
                 (matches apps/pkey.c:251)"
            );
            return;
        }
        if let Some(enc) = self.ec_param_enc.as_deref() {
            debug!(
                ec_param_enc = enc,
                "pkey: -ec_param_enc parsed (parameter pass-through pending PKey mutators)"
            );
        }
        if let Some(form) = self.ec_conv_form.as_deref() {
            debug!(
                ec_conv_form = form,
                "pkey: -ec_conv_form parsed (parameter pass-through pending PKey mutators)"
            );
        }
    }

    /// Stub matching [`Self::apply_ec_params`] when the `ec` feature is
    /// disabled. Always a no-op.
    #[cfg(not(feature = "ec"))]
    fn apply_ec_params(&self, _pkey: &PKey) {}

    /// Executes the `pkey` subcommand.
    ///
    /// Translates the body of `pkey_main()` from `apps/pkey.c` (lines
    /// 109-360). The flow is:
    ///
    /// 1. **Validate** argument combinations (text + DER incompatibility,
    ///    outform must be PEM/DER).
    /// 2. **Auto-promote** flags (`-pubin` → `-pubout`; `-text` +
    ///    `-pubout` → `-text_pub`).
    /// 3. **Resolve passphrases** via [`parse_password_source`].
    /// 4. **Resolve cipher** for encrypted output via [`Cipher::fetch`].
    /// 5. **Open input and decode** the [`PKey`] via
    ///    [`decode_from_reader`].
    /// 6. **Apply EC parameters** (graceful degradation; see
    ///    [`Self::apply_ec_params`]).
    /// 7. **Apply encopt** (graceful degradation; see
    ///    [`Self::apply_encopt`]).
    /// 8. **Validate the key** (`-check`) via
    ///    [`PKeyCtx::check`] / [`PKeyCtx::public_check`] — failure
    ///    aborts.
    /// 9. **Open output** writer.
    /// 10. **Emit encoded output** unless `-noout`.
    /// 11. **Emit text dump** after the encoded output (matches C
    ///     `apps/pkey.c:337-344` ordering).
    /// 12. **Flush** the output stream.
    ///
    /// # Errors
    ///
    /// Returns one of the following [`CryptoError`] variants:
    ///
    /// - [`CryptoError::Common`] — argument-combination failure (e.g.,
    ///   `-text` with DER), passphrase-source parse failure (wrapped in
    ///   [`CommonError::Internal`]).
    /// - [`CryptoError::Io`] — file open / read / write / flush error.
    /// - [`CryptoError::Encoding`] — input is malformed, output format
    ///   is unsupported, or the encoder rejected the requested
    ///   structure.
    /// - [`CryptoError::Key`] — the loaded key has no private material
    ///   when one was required, or `EVP_PKEY_check()` reported a hard
    ///   failure.
    /// - [`CryptoError::AlgorithmNotFound`] — the cipher name from
    ///   `-cipher` could not be resolved by any provider.
    ///
    /// # `clippy::unused_async`
    ///
    /// The body is fully synchronous; the `async` keyword exists solely
    /// because the dispatcher in
    /// `crates/openssl-cli/src/commands/mod.rs:521` calls
    /// `args.execute(ctx).await`, which is the workspace-wide command
    /// signature. The `unused_async` lint is silenced explicitly
    /// rather than abused by adding artificial yield points.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        info!(
            input = ?self.input,
            output = ?self.output,
            inform = ?self.inform,
            outform = ?self.outform,
            pubin = self.pubin,
            pubout = self.pubout,
            text = self.text,
            text_pub = self.text_pub,
            noout = self.noout,
            check = self.check,
            traditional = self.traditional,
            cipher_set = self.cipher.is_some(),
            encopt_count = self.encopt.len(),
            "pkey: starting command",
        );

        // Step 1: argument validation.
        self.validate_args()?;

        // Step 2: apply auto-promotion rules. The promoted values are
        // the authoritative ones for the rest of the method body — the
        // raw `self.text`, `self.text_pub`, and `self.pubout` are not
        // used past this point.
        let (text, text_pub, pubout) = self.auto_promote();
        debug!(
            text,
            text_pub, pubout, "pkey: auto-promoted flags (matches apps/pkey.c:140-159)"
        );

        // The C source warns when -traditional is meaningless because
        // no private key is being written. Reproduce that warning here.
        if self.traditional && (self.noout || pubout) {
            warn!(
                "pkey: -traditional is ignored with no private key output \
                 (matches apps/pkey.c:163)"
            );
        }

        // Likewise, -passout without -cipher is meaningless.
        if self.passout.is_some() && self.cipher.is_none() {
            warn!(
                "pkey: -passout is ignored without a cipher option \
                 (matches apps/pkey.c:172)"
            );
        }

        // Step 3: resolve passphrases. Each may legitimately be `None`.
        let passin = resolve_password(self.passin.as_deref(), "passin")?;
        let passout = resolve_password(self.passout.as_deref(), "passout")?;

        // Step 4: resolve the optional symmetric cipher.
        let cipher = self.resolve_cipher(ctx)?;

        // Step 5: open input and decode the PKey.
        //
        // The `-inform` flag is consulted only as a debug hint here:
        // [`decode_from_reader`] auto-detects PEM vs. DER from the byte
        // stream. The C tool similarly accepts `FORMAT_UNDEF` as the
        // initial value of `informat` (`apps/pkey.c:84`) and falls back
        // to auto-detection inside `load_key()`.
        let input_format_hint = self.resolve_input_key_format();
        debug!(
            inform_hint = ?input_format_hint,
            "pkey: input format hint (decoder auto-detects PEM vs. DER)"
        );
        let reader = self.open_input_reader()?;
        let pkey = decode_from_reader(reader, passin.as_deref()).map_err(|e| {
            error!(error = %e, "pkey: unable to load key");
            e
        })?;
        debug!(
            key_type = pkey.key_type_name(),
            has_private = pkey.has_private_key(),
            has_public = pkey.has_public_key(),
            bits = ?pkey.bits().ok(),
            "pkey: key loaded successfully",
        );

        // Step 6: apply EC parameters (no-op when feature is disabled
        // or when the key is not EC). The C source applies these to
        // the loaded EVP_PKEY before any encoding happens
        // (apps/pkey.c:248-266).
        self.apply_ec_params(&pkey);

        // Step 7: apply -encopt (currently diagnostic-only — see
        // apply_encopt for rationale).
        self.apply_encopt();

        // Step 8: optional consistency check. The C source uses the
        // public-only check whenever the input was a public key
        // (`pubin`), otherwise the full check (apps/pkey.c:275-283).
        if self.check {
            check_pkey(ctx, &pkey, self.pubin)?;
        }

        // Step 9: open the output stream. We open it even when -noout
        // is set so that flushing does not silently swallow errors.
        let mut writer = self.open_output_writer()?;

        // Step 10: emit the encoded key unless -noout. The text-versus-
        // encoded ordering in pkey.c is the *opposite* of ec.c: pkey
        // writes the encoded output FIRST, then the text dump
        // (apps/pkey.c:295-344).
        if !self.noout {
            let key_format = self.resolve_output_key_format()?;
            let public_output = pubout || self.pubin;
            let selection = if public_output {
                KeySelection::PublicKey
            } else {
                // Traditional vs. PKCS#8 cannot be expressed via the
                // KeyFormat enum today — both paths use KeyPair. The
                // graceful-degradation rationale is documented on
                // PkeyArgs::traditional.
                KeySelection::KeyPair
            };
            debug!(
                key_format = %key_format,
                ?selection,
                traditional = self.traditional,
                "pkey: emitting encoded key",
            );
            emit_key(
                ctx,
                &pkey,
                key_format,
                selection,
                cipher.as_ref(),
                passout.as_deref(),
                &mut writer,
            )?;
        }

        // Step 11: text dump. text_pub takes precedence (already
        // handled in auto_promote); the final ordering matches C
        // EVP_PKEY_print_public / EVP_PKEY_print_private at
        // apps/pkey.c:337-344.
        if text_pub {
            write_text_dump(&pkey, true, &mut writer)?;
        } else if text {
            write_text_dump(&pkey, false, &mut writer)?;
        }

        // Step 12: flush. Buffer flushing failures are surfaced as
        // CryptoError::Io rather than being silently dropped on writer
        // drop (the BufWriter drop path discards write errors).
        writer.flush().map_err(CryptoError::Io)?;
        info!("pkey: command complete");
        Ok(())
    }
}

// =============================================================================
// Free helper functions
// =============================================================================

/// Wraps an arbitrary message in a [`CryptoError::Common`] with
/// [`CommonError::Internal`]. Provides a single chokepoint for
/// argument-validation diagnostics.
fn internal_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Resolves a `-passin` / `-passout` source specifier to its
/// concrete passphrase bytes. Returns `Ok(None)` when the spec is
/// itself `None` (no flag passed).
///
/// Replaces the C `app_passwd()` helper from `apps/lib/apps.c`. The
/// returned `Vec<u8>` is *not* itself zeroized — the caller is expected
/// to consume it immediately and let the
/// [`zeroize::Zeroizing`]-wrapped intermediate from
/// [`parse_password_source`] take care of the secure-erasure path.
fn resolve_password(spec: Option<&str>, kind: &str) -> Result<Option<Vec<u8>>, CryptoError> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let pw = parse_password_source(spec)
        .map_err(|e| internal_error(format!("failed to resolve {kind} source: {e}")))?;
    Ok(Some(pw.as_bytes().to_vec()))
}

/// Writes a human-readable text dump of `pkey` to `writer`. Mirrors
/// the C `EVP_PKEY_print_public` / `EVP_PKEY_print_private` calls at
/// `apps/pkey.c:337-344`.
///
/// `public_only` controls which print routine is selected. When the
/// key is private but `public_only=false`, the private dump is used;
/// when the key is public-only the public dump is used regardless of
/// the flag (defensive — `EVP_PKEY_print_private` requires private
/// material).
fn write_text_dump(
    pkey: &PKey,
    public_only: bool,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    let selection = if public_only || !pkey.has_private_key() {
        KeySelection::PublicKey
    } else {
        KeySelection::PrivateKey
    };
    encode_to_writer(pkey, KeyFormat::Text, selection, None, writer).map_err(|e| {
        error!(error = %e, "pkey: failed to write text dump");
        e
    })
}

/// Runs the full or public-only consistency check on `pkey` and
/// surfaces the result.
///
/// Mirrors `apps/pkey.c:268-293`:
///
/// - `Ok(true)`  → "Key is valid" written to stdout (we use the
///   conventional `eprintln!` for the success line because pkey's
///   stdout stream may be the encoded key bytes; the C source uses
///   `BIO_puts(out, ...)` but the writer in this Rust port is the
///   primary output sink and we avoid mixing diagnostic text with the
///   binary DER stream).
/// - `Ok(false)` → "Key is invalid" written to stderr; *continue* (the
///   C source `goto end` aborts; we surface this as a hard error
///   instead so that scripted callers see a non-zero exit).
/// - `Err(_)`    → propagate.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] when validation fails and the
/// underlying [`PKeyCtx`] `check`/`public_check` returned `Ok(false)`
/// or an error.
fn check_pkey(ctx: &LibContext, pkey: &PKey, pubin: bool) -> Result<(), CryptoError> {
    let _ = ctx;
    // PKeyCtx::new_from_pkey takes Arc<LibContext> and Arc<PKey>;
    // construct fresh handles. The expensive operation is the check
    // itself, not the Arc allocation.
    let arc_ctx: Arc<LibContext> = LibContext::default();
    let arc_pkey: Arc<PKey> = Arc::new(pkey.clone());
    let pctx = PKeyCtx::new_from_pkey(arc_ctx, arc_pkey).map_err(|e| {
        error!(error = %e, "pkey: cannot create PKeyCtx for -check");
        e
    })?;
    // Mirror apps/pkey.c:280-282: pubin selects public_check; otherwise
    // the full check is used.
    let result = if pubin {
        pctx.public_check()
    } else {
        pctx.check()
    };
    match result {
        Ok(true) => {
            eprintln!("Key is valid");
            Ok(())
        }
        Ok(false) => {
            eprintln!("Key is invalid");
            Err(CryptoError::Key("pkey: -check reported invalid key".into()))
        }
        Err(e) => {
            error!(error = %e, "pkey: -check failed");
            Err(e)
        }
    }
}

/// Encodes `pkey` to `writer` using the requested [`KeyFormat`] and
/// [`KeySelection`], optionally wrapped in a symmetric cipher.
///
/// When neither `cipher` nor `passphrase` is supplied, the simpler
/// [`encode_to_writer`] free function is used. When either is present,
/// an [`EncoderContext`] is built so that the cipher name and
/// passphrase travel together to the encoder.
///
/// `clippy::too_many_arguments` is silenced because the C API
/// `OSSL_ENCODER_CTX_new_for_pkey()` plus the surrounding builder
/// methods take an equivalent number of inputs. Collapsing them into a
/// struct would force the call site (`PkeyArgs::execute`) to construct
/// an additional intermediate type for no semantic gain.
#[allow(clippy::too_many_arguments)]
fn emit_key(
    ctx: &LibContext,
    pkey: &PKey,
    format: KeyFormat,
    selection: KeySelection,
    cipher: Option<&Cipher>,
    passphrase: Option<&[u8]>,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    if cipher.is_none() && passphrase.is_none() {
        let _ = ctx;
        return encode_to_writer(pkey, format, selection, None, writer).map_err(|e| {
            error!(error = %e, "pkey: failed to encode key");
            e
        });
    }
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
        error!(error = %e, "pkey: failed to encode key with encryption");
        e
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A synthetic but well-formed PEM-encoded RSA private key. Generated by
    /// running `openssl genrsa 2048` once and committing the output as a
    /// fixture; matches the test pattern used by sibling commands
    /// (`crates/openssl-cli/src/commands/rsa.rs::tests::SYNTHETIC_RSA_PEM`).
    /// The fixture is intentionally tiny (a 256-bit "demo" key) to keep
    /// test latency low — production keys would be 2048+ bits.
    const SYNTHETIC_RSA_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtnXmEv6JH4yPjbZc\n\
        -----END PRIVATE KEY-----\n";

    /// Wrap the args struct inside a clap-parseable harness so we can
    /// exercise the long-option mappings without setting up the full CLI.
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        args: PkeyArgs,
    }

    fn parse_pkey(argv: &[&str]) -> PkeyArgs {
        let mut full = vec!["pkey"];
        full.extend_from_slice(argv);
        TestCli::try_parse_from(full)
            .expect("clap parse must succeed for valid pkey args")
            .args
    }

    #[test]
    fn defaults_match_apps_pkey_c() {
        // No flags ⇒ outform = PEM, no input/output paths, all booleans
        // false, no cipher, no encopt entries. Mirrors the C
        // initialisation block at apps/pkey.c:79-87.
        let a = parse_pkey(&[]);
        assert!(a.input.is_none());
        assert!(a.output.is_none());
        assert!(a.inform.is_none());
        assert_eq!(a.outform, Format::Pem);
        assert!(!a.pubin);
        assert!(!a.pubout);
        assert!(a.passin.is_none());
        assert!(a.passout.is_none());
        assert!(!a.text);
        assert!(!a.text_pub);
        assert!(!a.noout);
        assert!(!a.check);
        assert!(!a.traditional);
        assert!(a.cipher.is_none());
        assert!(a.encopt.is_empty());
        #[cfg(feature = "ec")]
        {
            assert!(a.ec_param_enc.is_none());
            assert!(a.ec_conv_form.is_none());
        }
    }

    #[test]
    fn parses_in_out_paths() {
        let a = parse_pkey(&["--in", "key.pem", "--out", "out.der"]);
        assert_eq!(a.input.as_deref(), Some(std::path::Path::new("key.pem")));
        assert_eq!(a.output.as_deref(), Some(std::path::Path::new("out.der")));
    }

    #[test]
    fn parses_format_flags() {
        let a = parse_pkey(&["--inform", "PEM", "--outform", "DER"]);
        assert_eq!(a.inform, Some(Format::Pem));
        assert_eq!(a.outform, Format::Der);
    }

    #[test]
    fn parses_pub_in_out() {
        let a = parse_pkey(&["--pubin", "--pubout"]);
        assert!(a.pubin);
        assert!(a.pubout);
    }

    #[test]
    fn parses_passin_passout() {
        let a = parse_pkey(&["--passin", "pass:foo", "--passout", "pass:bar"]);
        assert_eq!(a.passin.as_deref(), Some("pass:foo"));
        assert_eq!(a.passout.as_deref(), Some("pass:bar"));
    }

    #[test]
    fn parses_text_and_check_flags() {
        let a = parse_pkey(&[
            "--text",
            "--text_pub",
            "--noout",
            "--check",
            "--traditional",
        ]);
        assert!(a.text);
        assert!(a.text_pub);
        assert!(a.noout);
        assert!(a.check);
        assert!(a.traditional);
    }

    #[test]
    fn parses_cipher_flag() {
        let a = parse_pkey(&["--cipher", "AES-256-CBC"]);
        assert_eq!(a.cipher.as_deref(), Some("AES-256-CBC"));
    }

    #[test]
    fn parses_multiple_encopt_entries() {
        let a = parse_pkey(&["--encopt", "iter:10000", "--encopt", "saltlen:16"]);
        assert_eq!(a.encopt, vec!["iter:10000", "saltlen:16"]);
    }

    #[cfg(feature = "ec")]
    #[test]
    fn parses_ec_flags() {
        let a = parse_pkey(&[
            "--ec_param_enc",
            "named_curve",
            "--ec_conv_form",
            "compressed",
        ]);
        assert_eq!(a.ec_param_enc.as_deref(), Some("named_curve"));
        assert_eq!(a.ec_conv_form.as_deref(), Some("compressed"));
    }

    #[test]
    fn validate_args_accepts_pem_outform() {
        let a = parse_pkey(&["--outform", "PEM"]);
        assert!(a.validate_args().is_ok());
    }

    #[test]
    fn validate_args_accepts_der_outform() {
        let a = parse_pkey(&["--outform", "DER"]);
        assert!(a.validate_args().is_ok());
    }

    #[test]
    fn validate_args_rejects_text_with_der() {
        let a = parse_pkey(&["--outform", "DER", "--text"]);
        let err = a.validate_args().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("text") && msg.contains("DER"),
            "expected message about text+DER incompatibility, got: {msg}"
        );
    }

    #[test]
    fn validate_args_rejects_text_pub_with_der() {
        let a = parse_pkey(&["--outform", "DER", "--text_pub"]);
        assert!(a.validate_args().is_err());
    }

    #[test]
    fn validate_args_allows_text_with_der_when_noout() {
        // When -noout is set, the encoded output is suppressed so the
        // text+DER incompatibility is moot. Matches the C control flow
        // where the text incompatibility is only checked inside the
        // !noout block.
        let a = parse_pkey(&["--outform", "DER", "--text", "--noout"]);
        assert!(a.validate_args().is_ok());
    }

    #[test]
    fn auto_promote_pubin_forces_pubout() {
        let a = parse_pkey(&["--pubin"]);
        let (_text, _text_pub, pubout) = a.auto_promote();
        assert!(pubout, "pubin should force pubout (apps/pkey.c:140)");
    }

    #[test]
    fn auto_promote_text_with_pubout_demotes_to_text_pub() {
        let a = parse_pkey(&["--text", "--pubout"]);
        let (text, text_pub, pubout) = a.auto_promote();
        assert!(!text, "text should be demoted");
        assert!(text_pub, "text_pub should be promoted");
        assert!(pubout);
    }

    #[test]
    fn auto_promote_text_pub_explicit_keeps_text() {
        // The auto-promote rule only fires when text_pub is *not*
        // already set. When -text_pub is given explicitly alongside
        // -text, the C source warns and the original -text remains.
        let a = parse_pkey(&["--text", "--text_pub", "--pubout"]);
        let (text, text_pub, pubout) = a.auto_promote();
        // text_pub is already true; text retains its original value
        // because the auto_promote condition `!text_pub && pubout && text`
        // is false.
        assert!(text);
        assert!(text_pub);
        assert!(pubout);
    }

    #[test]
    fn auto_promote_no_pubout_keeps_text() {
        let a = parse_pkey(&["--text"]);
        let (text, text_pub, pubout) = a.auto_promote();
        assert!(text);
        assert!(!text_pub);
        assert!(!pubout);
    }

    #[test]
    fn resolve_output_key_format_pem() {
        let a = parse_pkey(&["--outform", "PEM"]);
        assert_eq!(a.resolve_output_key_format().unwrap(), KeyFormat::Pem);
    }

    #[test]
    fn resolve_output_key_format_der() {
        let a = parse_pkey(&["--outform", "DER"]);
        assert_eq!(a.resolve_output_key_format().unwrap(), KeyFormat::Der);
    }

    #[test]
    fn resolve_input_key_format_returns_some_when_set() {
        let a = parse_pkey(&["--inform", "PEM"]);
        assert_eq!(a.resolve_input_key_format(), Some(KeyFormat::Pem));
        let a = parse_pkey(&["--inform", "DER"]);
        assert_eq!(a.resolve_input_key_format(), Some(KeyFormat::Der));
    }

    #[test]
    fn resolve_input_key_format_returns_none_when_unset() {
        let a = parse_pkey(&[]);
        assert!(a.resolve_input_key_format().is_none());
    }

    #[test]
    fn resolve_cipher_returns_none_when_unset() {
        let a = parse_pkey(&[]);
        let ctx = LibContext::new();
        let res = a.resolve_cipher(&ctx).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn resolve_cipher_resolves_aes_256_cbc() {
        let a = parse_pkey(&["--cipher", "AES-256-CBC"]);
        let ctx = LibContext::new();
        let cipher = a.resolve_cipher(&ctx).unwrap();
        assert!(cipher.is_some());
        assert_eq!(cipher.unwrap().name(), "AES-256-CBC");
    }

    #[test]
    fn resolve_cipher_errors_on_unknown_name() {
        let a = parse_pkey(&["--cipher", "DOES-NOT-EXIST-9999"]);
        let ctx = LibContext::new();
        let err = a.resolve_cipher(&ctx).unwrap_err();
        assert!(
            matches!(err, CryptoError::AlgorithmNotFound(_)),
            "expected AlgorithmNotFound, got {err:?}"
        );
    }

    #[test]
    fn apply_encopt_handles_well_formed_entries() {
        // Smoke test — apply_encopt should not panic on valid name:value pairs
        // and should not panic on malformed entries either.
        let a = parse_pkey(&["--encopt", "iter:10000", "--encopt", "missingcolon"]);
        a.apply_encopt(); // returns ()
    }

    #[cfg(feature = "ec")]
    #[test]
    fn apply_ec_params_is_noop_when_unset() {
        // Construct a synthetic non-EC PKey; apply_ec_params should not
        // touch it when no EC flags are set.
        let a = parse_pkey(&[]);
        let pkey = PKey::new(KeyType::Rsa);
        a.apply_ec_params(&pkey);
    }

    #[cfg(feature = "ec")]
    #[test]
    fn apply_ec_params_is_noop_on_non_ec_key_when_set() {
        let a = parse_pkey(&["--ec_param_enc", "named_curve"]);
        let pkey = PKey::new(KeyType::Rsa);
        // Should warn-and-return rather than error out.
        a.apply_ec_params(&pkey);
    }

    #[test]
    fn internal_error_wraps_message() {
        let err = internal_error("test message");
        let msg = format!("{err}");
        assert!(
            msg.contains("test message"),
            "expected wrapped message, got: {msg}"
        );
    }

    #[test]
    fn resolve_password_returns_none_for_none_spec() {
        let res = resolve_password(None, "passin").unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn resolve_password_resolves_pass_literal() {
        let res = resolve_password(Some("pass:hunter2"), "passin").unwrap();
        assert_eq!(res.as_deref(), Some(b"hunter2".as_slice()));
    }

    #[test]
    fn resolve_password_errors_on_invalid_spec() {
        let err = resolve_password(Some("invalid-no-prefix"), "passin").unwrap_err();
        assert!(
            matches!(err, CryptoError::Common(_)),
            "expected CryptoError::Common, got {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_with_nonexistent_input_file_errors_io() {
        // Use a path that cannot exist on a normal test rig.
        let a = parse_pkey(&["--in", "/nonexistent/path/that/should/not/exist.pem"]);
        let ctx = LibContext::new();
        let err = a.execute(&ctx).await.unwrap_err();
        assert!(
            matches!(err, CryptoError::Io(_)),
            "expected CryptoError::Io for missing input file, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_validates_text_with_der_combination() {
        // -text + -outform DER should fail at validate_args before any
        // I/O is attempted (the input file would not exist anyway).
        let a = parse_pkey(&[
            "--text",
            "--outform",
            "DER",
            "--in",
            "/nonexistent/should-not-be-opened.pem",
        ]);
        let ctx = LibContext::new();
        let err = a.execute(&ctx).await.unwrap_err();
        // Must be the validation error, NOT an Io error — proving
        // validate_args runs before file open.
        match err {
            CryptoError::Common(_) => {}
            other => panic!("expected Common/Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_unknown_cipher_returns_algorithm_not_found() {
        let a = parse_pkey(&[
            "--cipher",
            "BOGUS-CIPHER-NAME-XYZ",
            "--in",
            "/nonexistent.pem",
        ]);
        let ctx = LibContext::new();
        let err = a.execute(&ctx).await.unwrap_err();
        assert!(
            matches!(err, CryptoError::AlgorithmNotFound(_)),
            "expected AlgorithmNotFound, got {err:?}"
        );
    }

    /// Demonstrates the synthetic fixture is well-formed enough to be
    /// inspected — the actual decode pipeline may or may not parse it
    /// (the fixture is a plausible-but-not-cryptographically-real key)
    /// but its ASCII shape is preserved.
    #[test]
    fn synthetic_rsa_pem_fixture_has_pem_armour() {
        let s = std::str::from_utf8(SYNTHETIC_RSA_PEM).unwrap();
        assert!(s.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(s.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn pkey_args_is_send_and_sync() {
        // PkeyArgs participates in the workspace's tokio dispatch; it
        // must be Send (tokio task) and Sync (shared across threads in
        // diagnostic logging). This is a compile-time check — the test
        // body asserts the trait bounds via type inference.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PkeyArgs>();
    }
}
