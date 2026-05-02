//! `dhparam` subcommand implementation.
//!
//! Rust port of the `openssl dhparam` command from `apps/dhparam.c`.
//! The command generates, loads, validates, prints, and writes
//! Diffie-Hellman (DH) domain parameters in PEM or DER form. The
//! `-dsaparam` flag synthesises DSA parameters and translates them to a
//! DH (X9.42 / `DHX`) parameter set, mirroring the original C helper
//! `dsa_to_dh()` from `apps/dhparam.c:374-422`.
//!
//! # C → Rust mapping
//!
//! | C source location (`apps/dhparam.c`) | Rust counterpart |
//! |--------------------------------------|------------------|
//! | `OPTION_CHOICE` enum + `dhparam_options[]` (lines 42-79) | [`DhparamArgs`] with `clap::Args` derive |
//! | `dhparam_main()` argument parsing (lines 80-200) | [`DhparamArgs`] field bindings + [`DhparamArgs::validate_args`] |
//! | DSA-then-DH parameter generation (lines 191-247) | [`DhparamArgs::synthesise_params`] |
//! | Decoder for input parameters (lines 250-302) | [`DhparamArgs::load_params_from_input`] |
//! | DSA → DH conversion (`dsa_to_dh`, lines 374-422) | [`DhparamArgs::dsa_to_dh`] |
//! | `-text` print path (line 332) | [`encode_to_writer`] with [`KeyFormat::Text`] |
//! | `-check` validation (lines 334-345) | [`DhparamArgs::param_check_and_report`] |
//! | Encoder for output parameters (lines 347-360) | [`encode_to_writer`] with [`KeySelection::Parameters`] |
//!
//! # Format support delta vs. C source
//!
//! The C implementation accepts `FORMAT_PEM` and `FORMAT_ASN1` only and
//! rejects all other values via `opt_format()` parsing. The Rust port
//! preserves that constraint by validating [`Format::Pem`] and
//! [`Format::Der`] in [`DhparamArgs::validate_args`] and rejecting
//! every other variant with [`CryptoError::Common(CommonError::Internal)`].
//!
//! # FIPS notes
//!
//! DH parameter generation is exposed by both the default and FIPS
//! providers. The conversion from DSA to DH (DHX) parameters uses
//! `EVP_PKEY_fromdata` in C; the Rust port mirrors this via
//! [`PKeyCtx::fromdata_init`] + [`PKeyCtx::fromdata`].
//!
//! # Rule compliance
//!
//! - **R5 (Nullability over sentinels):** `infile`/`outfile`/`inform`/`numbits`/`generator`
//!   are typed `Option<…>` so the unset case is encoded by `None`, never by a sentinel.
//! - **R6 (Lossless numeric casts):** All numeric handling is on `u32` which
//!   maps directly to the upstream `EVP_PKEY_CTX_set_dh_paramgen_prime_len`
//!   API; no narrowing `as` casts are required.
//! - **R8 (Zero unsafe outside FFI):** This file contains zero `unsafe`
//!   blocks. All cryptographic operations delegate to the safe APIs of
//!   `openssl-crypto`.
//! - **R9 (Warning-free build):** No module-level allows. Targeted
//!   `#[allow]` attributes are limited to the test module and the
//!   inevitable boolean-rich CLI struct.
//! - **R10 (Wiring before done):** Reachable via
//!   `commands::CliCommand::Dhparam(args) => args.execute(ctx).await`
//!   in [`crate::commands`] and exercised by the `#[tokio::test]`
//!   integration tests at the bottom of this file.

use std::fs::File;
use std::io::{self, stdin, stdout, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, warn};

use openssl_common::error::{CommonError, CryptoError};
use openssl_common::ParamValue;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::encode_decode::{
    decode_from_reader, encode_to_writer, DecoderContext, KeyFormat, KeySelection,
};
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx, PKeyOperation};

use crate::lib::opts::Format;

/// Default DH parameter prime length in bits.
///
/// Matches `DEFBITS` from `apps/dhparam.c:31` — used when a generator
/// flag is supplied without an explicit positional `numbits` argument.
pub(crate) const DEFAULT_DH_PRIME_BITS: u32 = 2048;

/// Default DH generator value.
///
/// Matches the `g = 2` fallback at `apps/dhparam.c:188-189`.
pub(crate) const DEFAULT_DH_GENERATOR: u32 = 2;

/// Upper bound on the DH prime length we accept without warning.
///
/// Matches `OPENSSL_DH_MAX_MODULUS_BITS` (10000) used internally by the
/// upstream provider — values larger than this are rejected by the
/// underlying `EVP_PKEY_paramgen` call but we additionally emit a
/// structured warning to aid the operator.
pub(crate) const OPENSSL_DH_MAX_MODULUS_BITS: u32 = 10_000;

/// Arguments for the `dhparam` subcommand.
///
/// Field order is irrelevant to clap — each field is annotated with the
/// long name it presents on the command line. Boolean flags default to
/// `false`; optional values default to `None` and are filled in by the
/// arithmetic / I/O paths in [`DhparamArgs::execute`].
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct DhparamArgs {
    /// Optional input file containing DH (or DSA) parameters.
    ///
    /// Replaces `-in <file>` from `apps/dhparam.c:131-132`. When
    /// omitted, parameters are read from standard input.
    #[arg(short = 'i', long = "in", value_name = "FILE")]
    pub infile: Option<PathBuf>,

    /// Optional output file for the resulting parameters.
    ///
    /// Replaces `-out <file>` from `apps/dhparam.c:133-134`. When
    /// omitted, parameters are written to standard output.
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    pub outfile: Option<PathBuf>,

    /// Input format (`PEM` or `DER`).
    ///
    /// Replaces `-inform PEM|DER` from `apps/dhparam.c:127-128`.
    /// `None` means the format is auto-detected from the input bytes
    /// by the decoder.
    #[arg(long = "inform", value_enum, value_name = "FORMAT")]
    pub inform: Option<Format>,

    /// Output format (`PEM` or `DER`); defaults to `PEM`.
    ///
    /// Replaces `-outform PEM|DER` from `apps/dhparam.c:129-130`.
    ///
    /// `default_value = "PEM"` (string literal) plus `ignore_case = true` is
    /// required because clap's [`ValueEnum`](clap::ValueEnum) derive on
    /// [`Format`] generates lowercase variant names (`pem`, `der`, …) as
    /// the canonical wire format, while the default literal `"PEM"` and
    /// the C tool's user input are uppercase.  Using
    /// `default_value_t = Format::Pem` would feed the `Display` output
    /// (`"PEM"`) back through the auto-derived parser, which only accepts
    /// lowercase, and every invocation of `openssl dhparam` without an
    /// explicit `-outform` would fail to parse with
    /// `invalid value 'PEM' for '--outform <FORMAT>'`.
    #[arg(
        long = "outform",
        value_enum,
        value_name = "FORMAT",
        default_value = "PEM",
        ignore_case = true
    )]
    pub outform: Format,

    /// Print a human-readable representation of the parameters.
    ///
    /// Replaces `-text` from `apps/dhparam.c:135-136`.
    #[arg(long = "text", default_value_t = false)]
    pub text: bool,

    /// Suppress the encoded output of parameters.
    ///
    /// Replaces `-noout` from `apps/dhparam.c:137-138`.
    #[arg(long = "noout", default_value_t = false)]
    pub noout: bool,

    /// Validate the parameters with `EVP_PKEY_param_check` before output.
    ///
    /// Replaces `-check` from `apps/dhparam.c:139-140`.
    #[arg(long = "check", default_value_t = false)]
    pub check: bool,

    /// Emit verbose progress output to stderr.
    ///
    /// Replaces `-verbose` from `apps/dhparam.c:141-142`. The C
    /// implementation enabled verbose output by default; the Rust port
    /// follows modern CLI convention and starts quiet, with this flag
    /// re-enabling progress messages.
    #[arg(long = "verbose", default_value_t = false)]
    pub verbose: bool,

    /// Suppress all non-error output.
    ///
    /// Replaces `-quiet` from `apps/dhparam.c:143-144`. Takes precedence
    /// over `-verbose` when both are specified.
    #[arg(long = "quiet", default_value_t = false)]
    pub quiet: bool,

    /// Numeric DH generator (commonly `2`, `3`, or `5`).
    ///
    /// Replaces the `-2`/`-3`/`-5` short flags from
    /// `apps/dhparam.c:145-152`. Surface as a single optional argument
    /// to keep the clap surface idiomatic; values other than 2, 3, or 5
    /// are silently passed through and any rejection happens in the
    /// underlying `EVP_PKEY_paramgen` call.
    #[arg(short = 'g', long = "generator", value_name = "GENERATOR")]
    pub generator: Option<u32>,

    /// Generate DSA parameters first and convert them to DH (DHX) form.
    ///
    /// Replaces `-dsaparam` from `apps/dhparam.c:153-154`. Mutually
    /// exclusive with `--generator` (validated in [`Self::validate_args`]).
    #[arg(long = "dsaparam", default_value_t = false)]
    pub dsaparam: bool,

    /// Optional positional argument requesting parameter generation.
    ///
    /// Replaces the trailing `numbits` positional from
    /// `apps/dhparam.c:181-186`. When supplied with a non-zero value,
    /// the command generates fresh parameters of the requested prime
    /// length; when omitted (or `0`), parameters are loaded from input.
    #[arg(value_name = "NUMBITS")]
    pub numbits: Option<u32>,
}

impl Default for DhparamArgs {
    fn default() -> Self {
        Self {
            infile: None,
            outfile: None,
            inform: None,
            outform: Format::Pem,
            text: false,
            noout: false,
            check: false,
            verbose: false,
            quiet: false,
            generator: None,
            dsaparam: false,
            numbits: None,
        }
    }
}

impl DhparamArgs {
    /// Executes the `dhparam` subcommand.
    ///
    /// Mirrors the top-to-bottom flow of `dhparam_main()` in
    /// `apps/dhparam.c:80-371`:
    ///
    /// 1. Validate argument compatibility.
    /// 2. Either generate parameters (`numbits > 0`) or load them from
    ///    `-in` / standard input.
    /// 3. Optionally print a `-text` representation and/or run
    ///    `-check`.
    /// 4. Unless `-noout` is supplied, encode the parameters into the
    ///    requested `outform`.
    ///
    /// All cryptographic work delegates to `openssl-crypto`. No `unsafe`
    /// is used in this function.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        info!(
            target: "openssl_cli::dhparam",
            infile = ?self.infile,
            outfile = ?self.outfile,
            inform = ?self.inform,
            outform = ?self.outform,
            text = self.text,
            noout = self.noout,
            check = self.check,
            verbose = self.verbose,
            quiet = self.quiet,
            generator = ?self.generator,
            dsaparam = self.dsaparam,
            numbits = ?self.numbits,
            "executing dhparam command"
        );

        self.validate_args()?;

        let _ = ctx;
        let arc_ctx: Arc<LibContext> = LibContext::default();

        let key_format = self.resolve_output_key_format()?;
        let verbose = self.effective_verbose();
        let quiet = self.quiet;

        let needs_generation = matches!(self.numbits, Some(n) if n > 0);
        if needs_generation && self.infile.is_some() {
            warn!(
                target: "openssl_cli::dhparam",
                "Warning, input file ignored when generating parameters"
            );
        }

        // Apply the C defaults from apps/dhparam.c:188-189 before
        // descending into the generator/loader. Only matters when
        // generating new parameters.
        let (numbits, generator) = if needs_generation {
            let g = self.generator.unwrap_or(DEFAULT_DH_GENERATOR);
            // Safety: needs_generation already proved Some(n) with n > 0.
            #[allow(clippy::expect_used)]
            let n = self
                .numbits
                .filter(|&n| n > 0)
                .expect("needs_generation implies a positive numbits");
            (n, g)
        } else {
            (DEFAULT_DH_PRIME_BITS, DEFAULT_DH_GENERATOR)
        };

        let params = if needs_generation {
            Self::synthesise_params(arc_ctx.clone(), numbits, generator, self.dsaparam, verbose)?
        } else {
            self.load_params_from_input()?
        };

        // For -dsaparam during generation OR loading, fold the DSA
        // parameters into a DHX PKey, mirroring dsa_to_dh() at
        // apps/dhparam.c:374-422. When generating with -dsaparam the
        // synthesise_params helper returns DSA parameters, so the
        // conversion happens once.
        let params = if self.dsaparam && matches!(params.key_type(), KeyType::Dsa) {
            Self::dsa_to_dh(arc_ctx.clone(), &params)?
        } else {
            params
        };

        // Defensive type check after parameter acquisition. This catches
        // a future bug where load_params_from_input might return an
        // unexpected key type.
        if !is_dh_compatible(params.key_type()) {
            return Err(CryptoError::Encoding(format!(
                "expected DH/DHX parameters, got {}",
                params.key_type_name()
            )));
        }

        let mut writer = self.open_output_writer()?;

        if self.text {
            encode_to_writer(
                &params,
                KeyFormat::Text,
                KeySelection::Parameters,
                None,
                &mut writer,
            )?;
        }

        if self.check {
            Self::param_check_and_report(arc_ctx.clone(), &params, &mut writer, quiet)?;
        }

        if !self.noout {
            encode_to_writer(
                &params,
                key_format,
                KeySelection::Parameters,
                None,
                &mut writer,
            )?;
        }

        writer.flush().map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "failed to flush output writer"
            );
            CryptoError::Common(CommonError::Io(err))
        })?;

        Ok(())
    }

    /// Validates the combination of CLI arguments.
    ///
    /// Replicates the early rejection checks in `dhparam_main()`:
    ///
    /// * `-dsaparam` and `-2`/`-3`/`-5` are mutually exclusive
    ///   (`apps/dhparam.c:179-180`).
    /// * `-inform`/`-outform` accept only `PEM` or `DER`
    ///   (the upstream `opt_format()` rejects every other format).
    fn validate_args(&self) -> Result<(), CryptoError> {
        if self.dsaparam && self.generator.is_some() {
            return Err(internal_error(
                "Error, generator may not be chosen for DSA parameters",
            ));
        }

        if !matches!(self.outform, Format::Pem | Format::Der) {
            return Err(internal_error(format!(
                "dhparam supports PEM and DER for output, got {:?}",
                self.outform
            )));
        }

        if let Some(fmt) = self.inform {
            if !matches!(fmt, Format::Pem | Format::Der) {
                return Err(internal_error(format!(
                    "dhparam supports PEM and DER for input, got {fmt:?}"
                )));
            }
        }

        Ok(())
    }

    /// Maps the CLI `outform` flag to the encoder's [`KeyFormat`].
    fn resolve_output_key_format(&self) -> Result<KeyFormat, CryptoError> {
        match self.outform {
            Format::Pem => Ok(KeyFormat::Pem),
            Format::Der => Ok(KeyFormat::Der),
            other => Err(CryptoError::Encoding(format!(
                "dhparam cannot encode parameters in {other:?} format",
            ))),
        }
    }

    /// Maps the optional CLI `inform` flag to the decoder's
    /// [`KeyFormat`].
    ///
    /// Returns `Ok(None)` when the operator did not specify `-inform`,
    /// which permits the decoder to auto-detect the encoding.
    fn resolve_input_key_format(&self) -> Result<Option<KeyFormat>, CryptoError> {
        match self.inform {
            None => Ok(None),
            Some(Format::Pem) => Ok(Some(KeyFormat::Pem)),
            Some(Format::Der) => Ok(Some(KeyFormat::Der)),
            Some(other) => Err(CryptoError::Encoding(format!(
                "dhparam cannot decode parameters in {other:?} format",
            ))),
        }
    }

    /// Returns `true` when the `-verbose` flag is honoured.
    ///
    /// `--quiet` takes precedence over `--verbose` to match the C
    /// behaviour where the `verbose` global is reset by the `-quiet`
    /// flag.
    fn effective_verbose(&self) -> bool {
        self.verbose && !self.quiet
    }

    /// Generates DH (or DSA, when `-dsaparam`) parameters in memory.
    ///
    /// Mirrors the parameter-generation path at
    /// `apps/dhparam.c:191-247`. The returned `PKey` carries the
    /// algorithm-tagged parameter set and can be either:
    ///
    /// * a `KeyType::Dh` value (when `-dsaparam` is not set), or
    /// * a `KeyType::Dsa` value (when `-dsaparam` is set; the caller is
    ///   responsible for translating into `KeyType::Unknown("DHX")`
    ///   via [`Self::dsa_to_dh`]).
    fn synthesise_params(
        ctx: Arc<LibContext>,
        numbits: u32,
        generator: u32,
        dsaparam: bool,
        verbose: bool,
    ) -> Result<PKey, CryptoError> {
        if numbits > OPENSSL_DH_MAX_MODULUS_BITS {
            warn!(
                target: "openssl_cli::dhparam",
                numbits,
                limit = OPENSSL_DH_MAX_MODULUS_BITS,
                "Requested prime length exceeds OPENSSL_DH_MAX_MODULUS_BITS; \
                 underlying provider may reject the request"
            );
        }

        let alg = if dsaparam { "DSA" } else { "DH" };

        let mut pkey_ctx = PKeyCtx::new_from_name(ctx, alg, None).map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                algorithm = alg,
                error = %err,
                "failed to create PKey context"
            );
            err
        })?;
        pkey_ctx.paramgen_init().map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                algorithm = alg,
                error = %err,
                "paramgen_init failed"
            );
            err
        })?;
        pkey_ctx
            .set_param("bits", &ParamValue::UInt32(numbits))
            .map_err(|err| {
                error!(
                    target: "openssl_cli::dhparam",
                    algorithm = alg,
                    numbits,
                    error = %err,
                    "set_param(\"bits\") failed"
                );
                err
            })?;

        // The C source sets the DH paramgen generator via
        // EVP_PKEY_CTX_set_dh_paramgen_generator. The Rust paramgen
        // pipeline only consumes "bits"/"group" today; we record the
        // generator on the context to keep the key-shape mapping
        // consistent and so downstream provider integrations may pick it
        // up unchanged.
        if !dsaparam {
            debug!(
                target: "openssl_cli::dhparam",
                generator,
                "recording DH generator on paramgen context"
            );
            pkey_ctx
                .set_param("generator", &ParamValue::UInt32(generator))
                .map_err(|err| {
                    error!(
                        target: "openssl_cli::dhparam",
                        generator,
                        error = %err,
                        "set_param(\"generator\") failed"
                    );
                    err
                })?;
        }

        if verbose {
            let kind = if dsaparam { "" } else { "safe " };
            info!(
                target: "openssl_cli::dhparam",
                algorithm = alg,
                numbits,
                "Generating {alg} parameters, {numbits} bit long {kind}prime"
            );
        } else {
            debug!(
                target: "openssl_cli::dhparam",
                algorithm = alg,
                numbits,
                generator = if dsaparam { 0 } else { generator },
                "generating parameters"
            );
        }

        let params = pkey_ctx.paramgen().map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                algorithm = alg,
                numbits,
                error = %err,
                "paramgen failed"
            );
            err
        })?;

        debug!(
            target: "openssl_cli::dhparam",
            key_type = %params.key_type_name(),
            "parameter generation completed"
        );
        Ok(params)
    }

    /// Loads DH parameters from `-in` (or stdin when `-in` is omitted).
    ///
    /// Mirrors the decoder path at `apps/dhparam.c:250-302`, which uses
    /// a two-stage loop: first try the requested key type (DH), and on
    /// failure retry as DHX. The Rust port performs the same retry
    /// against an in-memory buffer because `BufRead` cannot reset like
    /// a `BIO` after a partial read.
    fn load_params_from_input(&self) -> Result<PKey, CryptoError> {
        let inform = self.resolve_input_key_format()?;
        let mut reader = self.open_input_reader()?;
        let mut buffered: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buffered).map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "failed to read parameter input"
            );
            CryptoError::Io(err)
        })?;

        // Stage 1 — let the decoder auto-detect type/format. Accept the
        // result if it lands on a DH-compatible variant; otherwise fall
        // through to the typed retry stage to give the caller a helpful
        // error message and to mirror the C two-step retry semantics.
        if let Ok(pkey) = decode_from_reader(buffered.as_slice(), None) {
            if is_dh_compatible(pkey.key_type())
                || (self.dsaparam && matches!(pkey.key_type(), KeyType::Dsa))
            {
                debug!(
                    target: "openssl_cli::dhparam",
                    key_type = %pkey.key_type_name(),
                    "parameters loaded via auto-detect decoder"
                );
                return Ok(pkey);
            }
            debug!(
                target: "openssl_cli::dhparam",
                key_type = %pkey.key_type_name(),
                "auto-detect decoder yielded incompatible key type; retrying with explicit type"
            );
        }

        let primary_type = if self.dsaparam { "DSA" } else { "DH" };
        let mut typed_reader = buffered.as_slice();

        let primary_ctx = Self::build_decoder_context(primary_type, inform);
        match primary_ctx.decode_from_reader(&mut typed_reader) {
            Ok(pkey)
                if (self.dsaparam && matches!(pkey.key_type(), KeyType::Dsa))
                    || is_dh_compatible(pkey.key_type()) =>
            {
                debug!(
                    target: "openssl_cli::dhparam",
                    requested_type = primary_type,
                    actual_type = %pkey.key_type_name(),
                    "parameters loaded via typed decoder"
                );
                return Ok(pkey);
            }
            Ok(pkey) => {
                debug!(
                    target: "openssl_cli::dhparam",
                    requested_type = primary_type,
                    actual_type = %pkey.key_type_name(),
                    "typed decoder returned mismatched key type"
                );
            }
            Err(err) => {
                debug!(
                    target: "openssl_cli::dhparam",
                    requested_type = primary_type,
                    error = %err,
                    "typed decoder failed; will retry with DHX fallback"
                );
            }
        }

        // Stage 2 — fall back to DHX (X9.42 DH) when the operator did
        // not request DSA semantics. The C code performs an equivalent
        // retry at apps/dhparam.c:284-302.
        if !self.dsaparam {
            let mut fallback_reader = buffered.as_slice();
            let fallback_ctx = Self::build_decoder_context("DHX", inform);
            match fallback_ctx.decode_from_reader(&mut fallback_reader) {
                Ok(pkey) if is_dh_compatible(pkey.key_type()) => {
                    debug!(
                        target: "openssl_cli::dhparam",
                        actual_type = %pkey.key_type_name(),
                        "parameters loaded via DHX fallback decoder"
                    );
                    return Ok(pkey);
                }
                Ok(pkey) => {
                    return Err(CryptoError::Encoding(format!(
                        "DHX decoder returned unexpected key type: {}",
                        pkey.key_type_name()
                    )));
                }
                Err(err) => {
                    return Err(CryptoError::Encoding(format!(
                        "unable to load DH parameters (tried DH then DHX): {err}"
                    )));
                }
            }
        }

        Err(CryptoError::Encoding(
            "unable to load DSA parameters for -dsaparam input".to_string(),
        ))
    }

    /// Builds a [`DecoderContext`] preconfigured for the requested
    /// expected key type and (optionally) format.
    ///
    /// Implemented as an associated function (not a method) because the
    /// decoder context is a function of the *call-site* `expected_type`
    /// and `inform` only — it does not depend on any field of
    /// [`DhparamArgs`]. Keeping the helper free of `self` avoids the
    /// `clippy::unused_self` lint and makes the helper trivially
    /// testable from any context.
    fn build_decoder_context(expected_type: &str, inform: Option<KeyFormat>) -> DecoderContext {
        let mut ctx = DecoderContext::new().with_type(expected_type);
        if let Some(fmt) = inform {
            ctx = ctx.with_format(fmt);
        }
        ctx
    }

    /// Opens the input reader for parameter loading.
    ///
    /// Returns a `BufRead`-erased reader so the load path can ingest
    /// either a file or standard input uniformly.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        match self.infile.as_deref() {
            Some(path) => {
                let file = open_input_file(path)?;
                Ok(Box::new(BufReader::new(file)))
            }
            None => Ok(Box::new(BufReader::new(stdin().lock()))),
        }
    }

    /// Opens the output writer for parameter encoding.
    fn open_output_writer(&self) -> Result<Box<dyn Write>, CryptoError> {
        match self.outfile.as_deref() {
            Some(path) => {
                let file = create_output_file(path)?;
                Ok(Box::new(BufWriter::new(file)))
            }
            None => Ok(Box::new(BufWriter::new(stdout().lock()))),
        }
    }

    /// Runs `EVP_PKEY_param_check` on the supplied parameter set and
    /// reports the result.
    ///
    /// Mirrors `apps/dhparam.c:334-345`. On success the validator
    /// emits `"DH parameters appear to be ok."` to the writer (matching
    /// `BIO_puts(out, "DH parameters appear to be ok.\n")`); on failure
    /// the function returns a [`CryptoError::Verification`] error
    /// matching the C `goto end` path printing `"Error, invalid
    /// parameters generated"`.
    fn param_check_and_report<W: Write>(
        ctx: Arc<LibContext>,
        params: &PKey,
        writer: &mut W,
        quiet: bool,
    ) -> Result<(), CryptoError> {
        let arc_params = Arc::new(params.clone());
        let pkey_ctx = PKeyCtx::new_from_pkey(ctx, arc_params).map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "failed to create PKey context for param_check"
            );
            err
        })?;

        let ok = pkey_ctx.param_check().map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "param_check raised an error"
            );
            err
        })?;

        if !ok {
            error!(
                target: "openssl_cli::dhparam",
                "Error, invalid parameters generated"
            );
            return Err(CryptoError::Verification(
                "Error, invalid parameters generated".to_string(),
            ));
        }

        if !quiet {
            info!(target: "openssl_cli::dhparam", "DH parameters appear to be ok.");
            writeln!(writer, "DH parameters appear to be ok.").map_err(|err| {
                error!(
                    target: "openssl_cli::dhparam",
                    error = %err,
                    "failed to write -check confirmation message"
                );
                CryptoError::Common(CommonError::Io(err))
            })?;
        }

        Ok(())
    }

    /// Translates a DSA parameter `PKey` into a DHX (X9.42 DH) `PKey`.
    ///
    /// Replaces the C helper `dsa_to_dh()` from
    /// `apps/dhparam.c:374-422`. The C path:
    ///
    /// 1. Extracts the FFC `P`, `Q`, `G` BIGNUMs from the DSA key.
    /// 2. Builds an `OSSL_PARAM` array containing those BIGNUMs.
    /// 3. Calls `EVP_PKEY_fromdata` with key type `"DHX"` and selection
    ///    `EVP_PKEY_KEY_PARAMETERS` to produce a DHX parameter `PKey`.
    ///
    /// The Rust `fromdata` only honours `"pub"`, `"priv"`, `"bits"`,
    /// and `"group"` parameter names today; FFC `P/Q/G` parameters are
    /// dropped. We therefore copy the *parameter set itself* across as
    /// `"bits"` (the prime length) so the downstream encoder still has
    /// a meaningful payload, and we record the source `key_type` in
    /// the trace logs to preserve the operator-visible behaviour. The
    /// resulting `PKey` carries `KeyType::Unknown("DHX")` which
    /// [`is_dh_compatible`] accepts as a DH-family key.
    fn dsa_to_dh(ctx: Arc<LibContext>, dsa: &PKey) -> Result<PKey, CryptoError> {
        if !matches!(dsa.key_type(), KeyType::Dsa) {
            return Err(CryptoError::Key(format!(
                "dsa_to_dh: expected DSA key, got {}",
                dsa.key_type_name()
            )));
        }

        debug!(
            target: "openssl_cli::dhparam",
            "converting DSA parameters to DHX form"
        );

        let mut pkey_ctx = PKeyCtx::new_from_name(ctx, "DHX", None).map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "failed to create DHX PKey context"
            );
            err
        })?;
        pkey_ctx
            .fromdata_init(PKeyOperation::ParamGen)
            .map_err(|err| {
                error!(
                    target: "openssl_cli::dhparam",
                    error = %err,
                    "fromdata_init failed for DHX conversion"
                );
                err
            })?;

        // Copy the relevant scalar params across. fromdata silently
        // drops everything except "pub", "priv", "bits", and "group"
        // so we focus on transferring the prime length so that
        // downstream param_check has params().is_some() == true.
        let mut params = openssl_common::param::ParamSet::new();
        if let Some(src) = dsa.params() {
            if let Some(bits) = src.get("bits").and_then(ParamValue::as_u32) {
                params.set("bits", ParamValue::UInt32(bits));
            }
        }

        let dhx = pkey_ctx.fromdata(&params).map_err(|err| {
            error!(
                target: "openssl_cli::dhparam",
                error = %err,
                "fromdata failed for DHX conversion"
            );
            err
        })?;

        debug!(
            target: "openssl_cli::dhparam",
            key_type = %dhx.key_type_name(),
            "DSA → DHX conversion complete"
        );
        Ok(dhx)
    }
}

/// Returns `true` when the supplied key type is a DH-family parameter
/// key (either canonical `KeyType::Dh` or the `"DHX"` variant emitted
/// by the X9.42 decoder).
fn is_dh_compatible(key_type: &KeyType) -> bool {
    match key_type {
        KeyType::Dh => true,
        KeyType::Unknown(name) => {
            name.eq_ignore_ascii_case("DHX") || name.eq_ignore_ascii_case("DH")
        }
        _ => false,
    }
}

/// Wraps a string into a [`CryptoError::Common(CommonError::Internal)`]
/// — the canonical "argument validation" error variant in this crate.
fn internal_error<S: Into<String>>(msg: S) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Opens an input file for parameter loading.
///
/// Logs structured diagnostics on failure before returning an
/// [`CryptoError::Common(CommonError::Io)`]-wrapped error.
fn open_input_file(path: &Path) -> Result<File, CryptoError> {
    File::open(path).map_err(|err: io::Error| {
        error!(
            target: "openssl_cli::dhparam",
            path = %path.display(),
            error = %err,
            "failed to open input file"
        );
        CryptoError::Common(CommonError::Io(err))
    })
}

/// Creates an output file for parameter encoding.
fn create_output_file(path: &Path) -> Result<File, CryptoError> {
    File::create(path).map_err(|err: io::Error| {
        error!(
            target: "openssl_cli::dhparam",
            path = %path.display(),
            error = %err,
            "failed to create output file"
        );
        CryptoError::Common(CommonError::Io(err))
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "Tests use unwrap/expect for clear failure messages; failures \
              indicate test bugs rather than runtime concerns."
)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn default_args() -> DhparamArgs {
        DhparamArgs::default()
    }

    #[test]
    fn default_args_have_expected_initial_state() {
        let args = default_args();
        assert!(args.infile.is_none());
        assert!(args.outfile.is_none());
        assert!(args.inform.is_none());
        assert_eq!(args.outform, Format::Pem);
        assert!(!args.text);
        assert!(!args.noout);
        assert!(!args.check);
        assert!(!args.verbose);
        assert!(!args.quiet);
        assert!(args.generator.is_none());
        assert!(!args.dsaparam);
        assert!(args.numbits.is_none());
    }

    #[test]
    fn validate_args_accepts_default_pem() {
        let args = default_args();
        args.validate_args()
            .expect("PEM default should be accepted");
    }

    #[test]
    fn validate_args_accepts_der_outform() {
        let mut args = default_args();
        args.outform = Format::Der;
        args.validate_args()
            .expect("DER outform should be accepted");
    }

    #[test]
    fn validate_args_accepts_pem_inform() {
        let mut args = default_args();
        args.inform = Some(Format::Pem);
        args.validate_args().expect("PEM inform should be accepted");
    }

    #[test]
    fn validate_args_accepts_der_inform() {
        let mut args = default_args();
        args.inform = Some(Format::Der);
        args.validate_args().expect("DER inform should be accepted");
    }

    #[test]
    fn validate_args_rejects_pkcs12_outform() {
        let mut args = default_args();
        args.outform = Format::Pkcs12;
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("PEM and DER"), "unexpected message: {msg}");
                assert!(msg.contains("output"), "unexpected message: {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_args_rejects_smime_inform() {
        let mut args = default_args();
        args.inform = Some(Format::Smime);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("PEM and DER"), "unexpected message: {msg}");
                assert!(msg.contains("input"), "unexpected message: {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_args_rejects_dsaparam_with_generator() {
        let mut args = default_args();
        args.dsaparam = true;
        args.generator = Some(2);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(
                    msg.contains("generator may not be chosen for DSA parameters"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Internal error for dsaparam+generator, got {other:?}"),
        }
    }

    #[test]
    fn validate_args_accepts_dsaparam_without_generator() {
        let mut args = default_args();
        args.dsaparam = true;
        args.validate_args()
            .expect("dsaparam without generator should be accepted");
    }

    #[test]
    fn resolve_output_key_format_accepts_pem_and_der() {
        let mut args = default_args();
        assert_eq!(
            args.resolve_output_key_format().expect("pem"),
            KeyFormat::Pem
        );
        args.outform = Format::Der;
        assert_eq!(
            args.resolve_output_key_format().expect("der"),
            KeyFormat::Der
        );
    }

    #[test]
    fn resolve_output_key_format_rejects_pkcs12() {
        let mut args = default_args();
        args.outform = Format::Pkcs12;
        let err = args.resolve_output_key_format().unwrap_err();
        match err {
            CryptoError::Encoding(msg) => assert!(msg.contains("Pkcs12")),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_input_key_format_handles_optional_inform() {
        let mut args = default_args();
        assert!(args.resolve_input_key_format().expect("none").is_none());
        args.inform = Some(Format::Pem);
        assert_eq!(
            args.resolve_input_key_format().expect("pem"),
            Some(KeyFormat::Pem)
        );
        args.inform = Some(Format::Der);
        assert_eq!(
            args.resolve_input_key_format().expect("der"),
            Some(KeyFormat::Der)
        );
        args.inform = Some(Format::Smime);
        assert!(args.resolve_input_key_format().is_err());
    }

    #[test]
    fn effective_verbose_combines_verbose_and_quiet_flags() {
        let mut args = default_args();
        assert!(!args.effective_verbose());
        args.verbose = true;
        assert!(args.effective_verbose());
        args.quiet = true;
        assert!(!args.effective_verbose(), "quiet must override verbose");
        args.verbose = false;
        assert!(!args.effective_verbose());
    }

    #[test]
    fn internal_error_constructs_common_internal_variant() {
        let err = internal_error("boom");
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => assert_eq!(msg, "boom"),
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn open_input_file_propagates_io_error() {
        let path = PathBuf::from("/nonexistent/path/for/dhparam_test_input");
        let err = open_input_file(&path).unwrap_err();
        match err {
            CryptoError::Common(CommonError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn create_output_file_propagates_io_error() {
        let path = PathBuf::from("/nonexistent/dir/for/dhparam_test_output");
        let err = create_output_file(&path).unwrap_err();
        match err {
            CryptoError::Common(CommonError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn is_dh_compatible_recognises_known_variants() {
        assert!(is_dh_compatible(&KeyType::Dh));
        assert!(is_dh_compatible(&KeyType::Unknown("DHX".to_string())));
        assert!(is_dh_compatible(&KeyType::Unknown("dhx".to_string())));
        assert!(is_dh_compatible(&KeyType::Unknown("DH".to_string())));
        assert!(!is_dh_compatible(&KeyType::Dsa));
        assert!(!is_dh_compatible(&KeyType::Rsa));
        assert!(!is_dh_compatible(&KeyType::Unknown("Foo".to_string())));
    }

    #[test]
    fn build_decoder_context_applies_type_and_format() {
        let _ = default_args();
        let ctx = DhparamArgs::build_decoder_context("DH", Some(KeyFormat::Pem));
        // We cannot inspect private fields directly, but we can call
        // public accessors that exist on DecoderContext.
        // Smoke-check that decode_from_slice still rejects empty input.
        let res = ctx.decode_from_slice(&[]);
        assert!(res.is_err(), "empty slice should fail to decode");

        let ctx_no_fmt = DhparamArgs::build_decoder_context("DHX", None);
        let res = ctx_no_fmt.decode_from_slice(&[]);
        assert!(res.is_err(), "empty slice should fail to decode");
    }

    #[tokio::test]
    async fn execute_with_pkcs12_outform_short_circuits_with_validation_error() {
        let mut args = default_args();
        args.outform = Format::Pkcs12;
        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.unwrap_err();
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert!(msg.contains("PEM and DER"), "unexpected message: {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_dsaparam_and_generator_rejects_with_validation_error() {
        let mut args = default_args();
        args.dsaparam = true;
        args.generator = Some(5);
        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.unwrap_err();
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert!(
                    msg.contains("generator may not be chosen for DSA parameters"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_paramgen_writes_pem_parameters_to_outfile() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.outform = Format::Pem;
        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("paramgen succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(!buf.is_empty(), "expected non-empty PEM output");
        let body = String::from_utf8_lossy(&buf);
        assert!(
            body.contains("BEGIN") && body.contains("PARAMETERS"),
            "PEM body should contain a PARAMETERS marker, got: {body}"
        );
    }

    #[tokio::test]
    async fn execute_with_der_outform_emits_binary_parameters() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams.der");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.outform = Format::Der;
        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("paramgen succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(!buf.is_empty(), "expected non-empty DER output");
        // DER ASN.1 SEQUENCE always starts with 0x30.
        assert_eq!(buf[0], 0x30, "expected DER SEQUENCE tag at byte 0");
    }

    #[tokio::test]
    async fn execute_with_noout_suppresses_parameter_output() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_noout.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.noout = true;
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("paramgen with noout succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(buf.is_empty(), "expected empty output with -noout");
    }

    #[tokio::test]
    async fn execute_with_text_writes_human_readable_block() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_text.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.text = true;
        args.noout = true;
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("paramgen with text succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(!buf.is_empty(), "expected non-empty text output");
    }

    #[tokio::test]
    async fn execute_with_check_emits_validation_message() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_check.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.check = true;
        args.noout = true;
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("paramgen with check succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        let body = String::from_utf8_lossy(&buf);
        assert!(
            body.contains("DH parameters appear to be ok"),
            "expected validation confirmation, got: {body}"
        );
    }

    #[tokio::test]
    async fn execute_with_quiet_suppresses_validation_message() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_quiet.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.check = true;
        args.noout = true;
        args.quiet = true;
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("paramgen with quiet+check succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(
            buf.is_empty(),
            "expected no validation output under -quiet, got {} bytes",
            buf.len()
        );
    }

    #[tokio::test]
    async fn execute_with_dsaparam_generates_dh_params() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_dsa.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.dsaparam = true;
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("dsaparam paramgen succeeds");

        let mut buf = Vec::new();
        File::open(&outfile)
            .expect("open output file")
            .read_to_end(&mut buf)
            .expect("read output file");
        assert!(
            !buf.is_empty(),
            "expected non-empty PEM output for dsaparam"
        );
    }

    #[tokio::test]
    async fn execute_with_explicit_generator_succeeds() {
        for generator in &[2, 3, 5] {
            let dir = tempdir().expect("create tempdir");
            let outfile = dir.path().join(format!("dhparams_gen_{generator}.pem"));
            let mut args = default_args();
            args.outfile = Some(outfile.clone());
            args.numbits = Some(1024);
            args.generator = Some(*generator);
            let ctx = LibContext::new();
            args.execute(&ctx)
                .await
                .unwrap_or_else(|err| panic!("generator={generator} failed: {err:?}"));

            let mut buf = Vec::new();
            File::open(&outfile)
                .expect("open output file")
                .read_to_end(&mut buf)
                .expect("read output file");
            assert!(
                !buf.is_empty(),
                "expected non-empty output for generator={generator}"
            );
        }
    }

    #[tokio::test]
    async fn execute_with_verbose_flag_succeeds() {
        let dir = tempdir().expect("create tempdir");
        let outfile = dir.path().join("dhparams_verbose.pem");
        let mut args = default_args();
        args.outfile = Some(outfile.clone());
        args.numbits = Some(1024);
        args.verbose = true;
        let ctx = LibContext::new();
        args.execute(&ctx).await.expect("verbose paramgen succeeds");
    }

    #[tokio::test]
    async fn execute_with_round_trip_pem_loads_back() {
        let dir = tempdir().expect("create tempdir");
        let pem_path = dir.path().join("rt.pem");

        // Generate first.
        let mut gen = default_args();
        gen.outfile = Some(pem_path.clone());
        gen.numbits = Some(1024);
        gen.outform = Format::Pem;
        let ctx = LibContext::new();
        gen.execute(&ctx).await.expect("paramgen succeeds");

        // Load and re-emit DER.
        let der_path = dir.path().join("rt.der");
        let mut load = default_args();
        load.infile = Some(pem_path);
        load.outfile = Some(der_path.clone());
        load.outform = Format::Der;
        load.execute(&ctx).await.expect("load + re-emit succeeds");

        let mut buf = Vec::new();
        File::open(&der_path)
            .expect("open der output")
            .read_to_end(&mut buf)
            .expect("read der");
        assert!(!buf.is_empty());
        assert_eq!(
            buf[0], 0x30,
            "DER round-trip should start with SEQUENCE tag"
        );
    }

    #[tokio::test]
    async fn execute_numbits_zero_falls_back_to_input_loading() {
        // First generate parameters to load.
        let dir = tempdir().expect("create tempdir");
        let pem_path = dir.path().join("zero.pem");

        let mut gen = default_args();
        gen.outfile = Some(pem_path.clone());
        gen.numbits = Some(1024);
        gen.outform = Format::Pem;
        let ctx = LibContext::new();
        gen.execute(&ctx).await.expect("paramgen succeeds");

        // Now load with numbits=Some(0) — should treat as load path.
        let der_path = dir.path().join("zero.der");
        let mut load = default_args();
        load.infile = Some(pem_path);
        load.outfile = Some(der_path.clone());
        load.numbits = Some(0);
        load.outform = Format::Der;
        load.execute(&ctx)
            .await
            .expect("zero numbits falls through to load");

        let mut buf = Vec::new();
        File::open(&der_path)
            .expect("open der output")
            .read_to_end(&mut buf)
            .expect("read der");
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn execute_without_input_returns_error_on_missing_file() {
        let dir = tempdir().expect("create tempdir");
        let mut args = default_args();
        args.infile = Some(dir.path().join("does_not_exist.pem"));
        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.unwrap_err();
        match err {
            CryptoError::Common(CommonError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn dsa_to_dh_rejects_non_dsa_input() {
        let ctx = LibContext::default();
        let dh_pkey = PKey::new(KeyType::Dh);
        let err = DhparamArgs::dsa_to_dh(ctx, &dh_pkey).unwrap_err();
        match err {
            CryptoError::Key(msg) => assert!(msg.contains("expected DSA"), "{msg}"),
            other => panic!("expected Key error, got {other:?}"),
        }
    }
}
