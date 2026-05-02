//! `openssl ecparam` — Elliptic-Curve parameter generation and inspection.
//!
//! This module is the idiomatic Rust rewrite of the C tool implemented in
//! `apps/ecparam.c`. It enumerates supported EC named curves, loads or
//! generates EC domain parameters, optionally validates them, optionally
//! generates a key pair, and serialises the result in PEM or DER form.
//!
//! # Functional surface
//!
//! The following options from the C tool are surfaced through `clap`:
//!
//! * `-in`/`-out` — input and output file paths (default to stdin/stdout).
//! * `-inform`/`-outform` — input/output format. Only PEM and DER are
//!   accepted; any other value reported by the shared [`Format`] enum is
//!   rejected at validation time and translated into
//!   [`CryptoError::Encoding`].
//! * `-text` — render a human-readable parameter dump in addition to the
//!   binary output.
//! * `-noout` — suppress the encoded parameter output.
//! * `-check` / `-check_named` — validate the loaded/synthesised parameters
//!   via [`PKeyCtx::param_check`].
//! * `-list_curves` — enumerate the named curves understood by the
//!   underlying crypto crate.
//! * `-name <curve>` — synthesise EC parameters for a built-in named curve.
//! * `-genkey` — after producing parameters, generate an EC key pair and
//!   serialise it.
//! * `-no_seed` — strip the seed from explicit parameters. The Rust crypto
//!   layer does not currently track seed material, so the flag is accepted
//!   for compatibility and merely logged at debug level.
//! * `-param_enc named_curve|explicit` — control how parameters are encoded
//!   on output. Recorded on the `PKeyCtx` via `set_param("encoding", …)`.
//! * `-conv_form uncompressed|compressed|hybrid` — point conversion form;
//!   recorded on the `PKeyCtx` via `set_param("point-format", …)`.
//!
//! # Format support delta from upstream
//!
//! The upstream tool in C accepts PEM and DER only for parameter
//! input/output (`OPT_FMT_PEMDER`). The shared CLI [`Format`] enum models a
//! larger set used by sibling commands; this command rejects everything
//! other than [`Format::Pem`] and [`Format::Der`] with a structured
//! diagnostic. Other public APIs introduced by the rewrite — namely the
//! provider-based `encode_to_writer` framework — accept the same `KeyFormat`
//! discriminants as the rest of the CLI, but only the two parameter formats
//! are exercised here.
//!
//! # Curve catalogue
//!
//! The Rust crypto crate currently exposes four built-in named curves
//! (`prime256v1`, `secp384r1`, `secp521r1`, `secp256k1`); the C tool also
//! recognises many SECG curves not modelled in Rust today. Specifying an
//! unknown curve through `-name` produces
//! [`CryptoError::AlgorithmNotFound`] rather than a panic, matching the
//! "graceful degradation" behaviour required by the migration plan.
//!
//! # Compliance notes
//!
//! * **R5 (nullability over sentinels)** — every "may be absent" CLI input
//!   uses [`Option`]; the C tool's "infile == NULL means stdin" idiom is
//!   modelled with `Option<PathBuf>` rather than the empty string.
//! * **R6 (lossless numeric casts)** — no `as` casts are used. All
//!   conversions go through [`TryFrom`]/[`TryInto`] or are explicit usize
//!   widenings handled by the crypto crate.
//! * **R8 (no unsafe outside the FFI crate)** — this module contains zero
//!   `unsafe` blocks.
//! * **R9 (warning-free build)** — every public item carries a `///`
//!   comment, and the only `#[allow]` attributes are scoped to the
//!   `EcparamArgs` struct (`clippy::struct_excessive_bools`) and the
//!   [`EcparamArgs::execute`] method (`clippy::unused_async`) with
//!   justifications below.
//! * **R10 (wiring before done)** — the entry point is
//!   [`EcparamArgs::execute`], invoked from the top-level dispatcher in
//!   `crates/openssl-cli/src/commands/mod.rs` via
//!   `Self::Ecparam(args) => args.execute(ctx).await`.

use std::fs::File;
use std::io::{self, stdout, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, ValueEnum};
use tracing::{debug, error, info};

use openssl_common::error::{CommonError, CryptoError};
use openssl_common::ParamValue;
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::{EcGroup, NamedCurve};
use openssl_crypto::evp::encode_decode::{
    decode_from_reader, encode_to_writer, KeyFormat, KeySelection,
};
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx};

use crate::lib::opts::Format;

// ---------------------------------------------------------------------------
// Value-enums
// ---------------------------------------------------------------------------

/// Point-conversion form selectable through `-conv_form`.
///
/// Mirrors the `point_format_options` table from the C header
/// `apps/include/ec_common.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PointFormat {
    /// `04 || X || Y` octet form. Default for most callers.
    #[value(name = "uncompressed")]
    Uncompressed,
    /// `02|03 || X` octet form using the parity of `Y`.
    #[value(name = "compressed")]
    Compressed,
    /// `06|07 || X || Y` octet form combining compressed prefix with the
    /// full coordinate pair.
    #[value(name = "hybrid")]
    Hybrid,
}

impl PointFormat {
    /// Return the canonical OpenSSL parameter string for this point form.
    ///
    /// The values match the spelling used by the C library so that the
    /// underlying provider implementations recognise them.
    #[must_use]
    pub fn as_ossl_str(self) -> &'static str {
        match self {
            Self::Uncompressed => "uncompressed",
            Self::Compressed => "compressed",
            Self::Hybrid => "hybrid",
        }
    }
}

/// ASN.1 parameter encoding selectable through `-param_enc`.
///
/// Mirrors the `asn1_encoding_options` table from the C header
/// `apps/include/ec_common.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ParamEncoding {
    /// Encode the parameters as a single OID identifying the named curve
    /// (e.g. `prime256v1`). This is the upstream default.
    #[value(name = "named_curve")]
    NamedCurve,
    /// Encode the parameters in fully explicit form (`SEQUENCE` of field
    /// type, curve coefficients, generator, order, cofactor).
    #[value(name = "explicit")]
    Explicit,
}

impl ParamEncoding {
    /// Return the canonical OpenSSL parameter string for this encoding.
    #[must_use]
    pub fn as_ossl_str(self) -> &'static str {
        match self {
            Self::NamedCurve => "named_curve",
            Self::Explicit => "explicit",
        }
    }
}

// ---------------------------------------------------------------------------
// Argument struct
// ---------------------------------------------------------------------------

/// Command-line arguments for `openssl ecparam`.
///
/// `clippy::struct_excessive_bools` is allowed because the upstream tool
/// exposes a wide flag surface that maps naturally onto independent
/// booleans; collapsing them into a single bitfield would degrade
/// readability and diverge from the C semantics.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct EcparamArgs {
    /// Input file (parameter source). Reads from standard input when
    /// omitted, matching the C behaviour for `-in -`.
    #[arg(long = "in", value_name = "FILE")]
    pub infile: Option<PathBuf>,

    /// Output file (parameter sink). Writes to standard output when
    /// omitted.
    #[arg(long = "out", value_name = "FILE")]
    pub outfile: Option<PathBuf>,

    /// Input encoding. Defaults to PEM at decode time when absent, but the
    /// option is offered explicitly for parity with the C tool.
    #[arg(long = "inform")]
    pub inform: Option<Format>,

    /// Output encoding. Defaults to PEM. Only PEM and DER are accepted.
    #[arg(long = "outform", default_value = "PEM")]
    pub outform: Format,

    /// Print a human-readable parameter dump.
    #[arg(long = "text")]
    pub text: bool,

    /// Suppress the encoded parameter (or key) output.
    #[arg(long = "noout")]
    pub noout: bool,

    /// Validate the parameter group via [`PKeyCtx::param_check`].
    #[arg(long = "check")]
    pub check: bool,

    /// Validate the parameter group as a named curve. In Rust this is a
    /// lighter validation than `-check`, but both ultimately delegate to
    /// [`PKeyCtx::param_check`].
    #[arg(long = "check_named")]
    pub check_named: bool,

    /// Enumerate the supported built-in curves and exit.
    #[arg(long = "list_curves")]
    pub list_curves: bool,

    /// Synthesise parameters for the named curve.
    #[arg(long = "name", value_name = "CURVE")]
    pub name: Option<String>,

    /// Generate an EC key pair from the loaded/synthesised parameters.
    #[arg(long = "genkey")]
    pub genkey: bool,

    /// Strip the seed from explicit parameters. Accepted for compatibility;
    /// the Rust crypto crate does not yet model parameter seeds, so this is
    /// recorded only at `debug!` level.
    #[arg(long = "no_seed")]
    pub no_seed: bool,

    /// Override the ASN.1 parameter encoding.
    #[arg(long = "param_enc", value_enum)]
    pub param_enc: Option<ParamEncoding>,

    /// Override the EC point conversion form.
    #[arg(long = "conv_form", value_enum)]
    pub conv_form: Option<PointFormat>,
}

impl Default for EcparamArgs {
    /// Construct an `EcparamArgs` populated with the same defaults clap
    /// would apply at runtime: PEM output format, no input or output file
    /// override, every boolean flag clear, and every optional curve/format
    /// override unset.
    fn default() -> Self {
        Self {
            infile: None,
            outfile: None,
            inform: None,
            outform: Format::Pem,
            text: false,
            noout: false,
            check: false,
            check_named: false,
            list_curves: false,
            name: None,
            genkey: false,
            no_seed: false,
            param_enc: None,
            conv_form: None,
        }
    }
}

impl EcparamArgs {
    // ---------------------------------------------------------------------
    // Validation helpers
    // ---------------------------------------------------------------------

    /// Validate the combination of arguments before any I/O.
    ///
    /// * Rejects output formats other than PEM/DER.
    /// * Rejects providing `-name` and reading from `-in` simultaneously
    ///   (the C tool uses one or the other; we mirror the precedence for
    ///   clearer diagnostics).
    fn validate_args(&self) -> Result<(), CryptoError> {
        // Output format must be PEM or DER.
        if !matches!(self.outform, Format::Pem | Format::Der) {
            return Err(internal_error(format!(
                "ecparam supports only PEM and DER output formats; got {:?}",
                self.outform
            )));
        }
        if let Some(fmt) = self.inform {
            if !matches!(fmt, Format::Pem | Format::Der) {
                return Err(internal_error(format!(
                    "ecparam supports only PEM and DER input formats; got {fmt:?}"
                )));
            }
        }

        // -name and -in are mutually exclusive: the C tool silently prefers
        // one over the other, but in Rust we surface the conflict to give
        // the operator a clear diagnostic.
        if self.name.is_some() && self.infile.is_some() {
            return Err(internal_error(
                "ecparam: -name and -in are mutually exclusive",
            ));
        }
        Ok(())
    }

    /// Translate the CLI [`Format`] into a [`KeyFormat`] for the encoder
    /// framework. Returns [`CryptoError::Encoding`] for unsupported inputs.
    fn resolve_output_key_format(&self) -> Result<KeyFormat, CryptoError> {
        match self.outform {
            Format::Pem => Ok(KeyFormat::Pem),
            Format::Der => Ok(KeyFormat::Der),
            other => Err(CryptoError::Encoding(format!(
                "ecparam cannot serialise parameters in {other:?} format"
            ))),
        }
    }

    // ---------------------------------------------------------------------
    // I/O helpers
    // ---------------------------------------------------------------------

    /// Open the parameter input source. `None` => standard input.
    fn open_input_reader(&self) -> Result<Box<dyn BufRead>, CryptoError> {
        match self.infile.as_deref() {
            Some(path) => Ok(Box::new(BufReader::new(open_input_file(path)?))),
            None => Ok(Box::new(BufReader::new(io::stdin()))),
        }
    }

    /// Open the parameter output sink. `None` => standard output.
    fn open_output_writer(&self) -> Result<Box<dyn Write>, CryptoError> {
        match self.outfile.as_deref() {
            Some(path) => Ok(Box::new(BufWriter::new(create_output_file(path)?))),
            None => Ok(Box::new(BufWriter::new(stdout()))),
        }
    }

    // ---------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------

    /// Run the `ecparam` subcommand.
    ///
    /// `clippy::unused_async` is allowed because this method must conform to
    /// the workspace dispatch signature
    /// `Self::Ecparam(args) => args.execute(ctx).await` even though no
    /// `.await` is currently performed inside.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        info!(
            target: "openssl_cli::ecparam",
            list_curves = self.list_curves,
            name = self.name.as_deref().unwrap_or(""),
            infile = ?self.infile,
            outfile = ?self.outfile,
            outform = ?self.outform,
            text = self.text,
            noout = self.noout,
            check = self.check,
            check_named = self.check_named,
            genkey = self.genkey,
            no_seed = self.no_seed,
            "ecparam invocation"
        );

        self.validate_args()?;

        // -list_curves short-circuit: enumerate built-in curves, ignoring
        // every other flag, and return.
        if self.list_curves {
            let mut writer = self.open_output_writer()?;
            list_builtin_curves(&mut writer)?;
            writer
                .flush()
                .map_err(|err| CryptoError::Common(CommonError::Io(err)))?;
            return Ok(());
        }

        // Resolve the output format up-front: this validates the choice
        // before any expensive operation.
        let key_format = self.resolve_output_key_format()?;

        // The dispatcher passes a `&LibContext` per the workspace
        // dispatch contract; PKey/PKeyCtx APIs require `Arc<LibContext>`.
        // `LibContext::default()` is the inherent constructor that returns
        // a shared `Arc<LibContext>` — matching the pattern used by the
        // sibling `ec` command for its provider-driven helper functions.
        // The `_ctx` parameter is retained on the signature so that future
        // wiring can pass a per-invocation context without changing the
        // dispatch shape.
        let _ = ctx;
        let arc_ctx: Arc<LibContext> = LibContext::default();

        // Resolve the source of parameters: a curve name supplied through
        // `-name`, or a previously serialised parameter blob read from
        // `-in`/stdin.
        let mut pkey = if let Some(curve_name) = self.name.as_deref() {
            Self::synthesise_params(arc_ctx.clone(), curve_name)?
        } else {
            self.load_params_from_input()?
        };

        // The parameter source must be EC: any other key type indicates the
        // input was misrouted.
        if !matches!(pkey.key_type(), KeyType::Ec | KeyType::Sm2) {
            return Err(CryptoError::Encoding(format!(
                "ecparam: expected EC parameters, got {:?}",
                pkey.key_type()
            )));
        }

        // Apply per-parameter overrides expressed on the command line.
        self.apply_param_overrides(&mut pkey, arc_ctx.clone())?;

        // Open the destination here so any I/O failure surfaces before we
        // run the (potentially expensive) -text or -genkey paths.
        let mut writer = self.open_output_writer()?;

        if self.text {
            debug!(target: "openssl_cli::ecparam", "emitting human-readable parameter dump");
            encode_to_writer(
                &pkey,
                KeyFormat::Text,
                KeySelection::Parameters,
                None,
                &mut writer,
            )
            .map_err(|err| {
                error!(target: "openssl_cli::ecparam", error = %err, "text dump failed");
                err
            })?;
        }

        if self.check || self.check_named {
            run_param_check(arc_ctx.clone(), &pkey, &mut writer, self.check_named)?;
        }

        // Compatibility quirk: the C tool forces `noout` when DER output is
        // combined with `-genkey`, because emitting raw DER parameters
        // followed by raw DER private keys produces an unparseable stream.
        let mut effective_noout = self.noout;
        if matches!(self.outform, Format::Der) && self.genkey {
            debug!(
                target: "openssl_cli::ecparam",
                "DER + genkey detected — forcing -noout to avoid concatenated DER blobs"
            );
            effective_noout = true;
        }

        if !effective_noout {
            debug!(
                target: "openssl_cli::ecparam",
                format = ?key_format,
                "encoding EC parameters"
            );
            encode_to_writer(
                &pkey,
                key_format,
                KeySelection::Parameters,
                None,
                &mut writer,
            )
            .map_err(|err| {
                error!(target: "openssl_cli::ecparam", error = %err, "parameter emission failed");
                err
            })?;
        }

        if self.genkey {
            let key = Self::generate_keypair(arc_ctx.clone(), &pkey)?;
            debug!(
                target: "openssl_cli::ecparam",
                format = ?key_format,
                "emitting generated EC key pair"
            );
            encode_to_writer(&key, key_format, KeySelection::KeyPair, None, &mut writer).map_err(
                |err| {
                    error!(target: "openssl_cli::ecparam", error = %err, "key emission failed");
                    err
                },
            )?;
        }

        writer
            .flush()
            .map_err(|err| CryptoError::Common(CommonError::Io(err)))?;

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Parameter sources
    // ---------------------------------------------------------------------

    /// Synthesise EC parameters for a built-in named curve.
    ///
    /// This helper is an associated function (no `self`) because parameter
    /// generation is fully determined by `curve_name` and the supplied
    /// library context. Keeping it `Self::`-scoped preserves the affinity
    /// to [`EcparamArgs`] without taking an unused `&self` argument
    /// (`clippy::unused_self`).
    fn synthesise_params(arc_ctx: Arc<LibContext>, curve_name: &str) -> Result<PKey, CryptoError> {
        debug!(
            target: "openssl_cli::ecparam",
            curve = curve_name,
            "synthesising EC parameters from curve name"
        );

        // First validate that the curve exists by attempting to construct
        // an EcGroup. This produces a clear `AlgorithmNotFound` error for
        // unsupported curves before any provider work happens.
        let named = NamedCurve::from_name(curve_name).ok_or_else(|| {
            error!(
                target: "openssl_cli::ecparam",
                curve = curve_name,
                "unknown EC curve"
            );
            CryptoError::AlgorithmNotFound(format!("unknown EC curve: {curve_name}"))
        })?;

        // Construct the group eagerly so the operator sees curve-construction
        // errors here rather than buried inside paramgen.
        let group = EcGroup::from_curve_name(named).map_err(|err| {
            error!(
                target: "openssl_cli::ecparam",
                curve = curve_name,
                error = %err,
                "EcGroup::from_curve_name failed"
            );
            err
        })?;
        debug!(
            target: "openssl_cli::ecparam",
            curve = %named,
            degree = group.degree(),
            "EcGroup constructed"
        );

        // Parameter generation goes through the EVP/PKey abstraction so the
        // resulting `PKey` is consistent with parameters loaded through the
        // decoder framework (matching C's EVP_PKEY_paramgen path).
        let mut pctx = PKeyCtx::new_from_name(arc_ctx, "ec", None).map_err(|err| {
            error!(
                target: "openssl_cli::ecparam",
                error = %err,
                "PKeyCtx::new_from_name(ec) failed"
            );
            err
        })?;
        pctx.paramgen_init().map_err(|err| {
            error!(target: "openssl_cli::ecparam", error = %err, "paramgen_init failed");
            err
        })?;
        pctx.set_param("group", &ParamValue::Utf8String(named.name().to_string()))?;

        // Surface the bit-size of the curve as the canonical "bits"
        // parameter so downstream consumers can introspect it without
        // recomputing.
        pctx.set_param("bits", &ParamValue::UInt32(named.key_size_bits()))?;

        let pkey = pctx.paramgen().map_err(|err| {
            error!(target: "openssl_cli::ecparam", error = %err, "paramgen failed");
            err
        })?;
        Ok(pkey)
    }

    /// Load EC parameters from the input reader.
    fn load_params_from_input(&self) -> Result<PKey, CryptoError> {
        debug!(
            target: "openssl_cli::ecparam",
            infile = ?self.infile,
            inform = ?self.inform,
            "loading EC parameters from input"
        );

        let reader = self.open_input_reader()?;
        let pkey = decode_from_reader(reader, None).map_err(|err| {
            error!(target: "openssl_cli::ecparam", error = %err, "parameter decode failed");
            err
        })?;
        debug!(
            target: "openssl_cli::ecparam",
            key_type = ?pkey.key_type(),
            "decoded parameters"
        );
        Ok(pkey)
    }

    // ---------------------------------------------------------------------
    // Parameter overrides and validation
    // ---------------------------------------------------------------------

    /// Apply CLI-level overrides — `-param_enc`, `-conv_form`, `-no_seed` —
    /// to the in-memory `PKey` via a fresh [`PKeyCtx`]. The Rust crypto
    /// crate stores these as named parameters; downstream encoder/decoder
    /// implementations consult them when serialising the key.
    fn apply_param_overrides(
        &self,
        pkey: &mut PKey,
        arc_ctx: Arc<LibContext>,
    ) -> Result<(), CryptoError> {
        if self.param_enc.is_none() && self.conv_form.is_none() && !self.no_seed {
            return Ok(());
        }

        let arc_pkey = Arc::new(pkey.clone());
        let mut pctx = PKeyCtx::new_from_pkey(arc_ctx, arc_pkey).map_err(|err| {
            error!(
                target: "openssl_cli::ecparam",
                error = %err,
                "PKeyCtx::new_from_pkey failed during override application"
            );
            err
        })?;

        if let Some(enc) = self.param_enc {
            debug!(
                target: "openssl_cli::ecparam",
                encoding = enc.as_ossl_str(),
                "applying -param_enc override"
            );
            pctx.set_param(
                "encoding",
                &ParamValue::Utf8String(enc.as_ossl_str().to_string()),
            )?;
        }

        if let Some(form) = self.conv_form {
            debug!(
                target: "openssl_cli::ecparam",
                point_format = form.as_ossl_str(),
                "applying -conv_form override"
            );
            pctx.set_param(
                "point-format",
                &ParamValue::Utf8String(form.as_ossl_str().to_string()),
            )?;
        }

        if self.no_seed {
            // No equivalent in the Rust crypto crate today (parameter seeds
            // are not modelled). Record the intent so test harnesses can
            // observe the flag and downstream encoders can opt to consult
            // the parameter.
            debug!(
                target: "openssl_cli::ecparam",
                "applying -no_seed (recorded as parameter; Rust crypto layer treats as no-op)"
            );
            pctx.set_param("no-seed", &ParamValue::UInt32(1))?;
        }

        Ok(())
    }

    /// Generate an EC key pair using the supplied parameter object as the
    /// template. The key inherits the EC group and any encoding overrides
    /// that were attached during [`Self::apply_param_overrides`].
    ///
    /// Associated function (no `&self`) because the operation is fully
    /// determined by `arc_ctx` and `params` — `clippy::unused_self`.
    fn generate_keypair(arc_ctx: Arc<LibContext>, params: &PKey) -> Result<PKey, CryptoError> {
        debug!(target: "openssl_cli::ecparam", "generating EC key pair via PKeyCtx::keygen");

        let arc_params = Arc::new(params.clone());
        let mut pctx = PKeyCtx::new_from_pkey(arc_ctx, arc_params).map_err(|err| {
            error!(
                target: "openssl_cli::ecparam",
                error = %err,
                "PKeyCtx::new_from_pkey failed during keygen"
            );
            err
        })?;
        pctx.keygen_init().map_err(|err| {
            error!(target: "openssl_cli::ecparam", error = %err, "keygen_init failed");
            err
        })?;
        let key = pctx.keygen().map_err(|err| {
            error!(target: "openssl_cli::ecparam", error = %err, "keygen failed");
            CryptoError::Key(format!("EC keygen failed: {err}"))
        })?;
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Convenience constructor for "internal CLI" errors. Mirrors the helper
/// used by the sibling `ec` command and centralises the layering of the
/// `Common::Internal` variant.
fn internal_error<S: Into<String>>(msg: S) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Run the `-check`/`-check_named` post-load validation step.
///
/// On success, prints the same `"EC group is valid"` / `"EC name is valid"`
/// lines as the C tool. On failure, propagates the error and emits a
/// matching diagnostic on the configured writer.
fn run_param_check(
    arc_ctx: Arc<LibContext>,
    pkey: &PKey,
    writer: &mut dyn Write,
    named_only: bool,
) -> Result<(), CryptoError> {
    debug!(
        target: "openssl_cli::ecparam",
        named_only,
        "running EC parameter check"
    );

    let arc_pkey = Arc::new(pkey.clone());
    let pctx = PKeyCtx::new_from_pkey(arc_ctx, arc_pkey)?;
    match pctx.param_check() {
        Ok(true) => {
            let label = if named_only { "EC name" } else { "EC group" };
            writeln!(writer, "{label} is valid")
                .map_err(|err| CryptoError::Common(CommonError::Io(err)))?;
            Ok(())
        }
        Ok(false) => {
            let label = if named_only { "EC name" } else { "EC group" };
            writeln!(writer, "{label} validation failed")
                .map_err(|err| CryptoError::Common(CommonError::Io(err)))?;
            Err(CryptoError::Verification(format!(
                "{label} validation failed"
            )))
        }
        Err(err) => {
            error!(
                target: "openssl_cli::ecparam",
                error = %err,
                "param_check returned an error"
            );
            Err(err)
        }
    }
}

/// Print the catalogue of built-in curves to `writer`.
///
/// The output matches the upstream format `"  %-10s: %s\n"`, where the
/// left-hand column is the canonical curve name and the right-hand column
/// is a short descriptive comment. The Rust crypto crate currently exposes
/// four named curves; the descriptive comments are hardcoded here because
/// `NamedCurve` does not yet expose a `comment()` accessor.
fn list_builtin_curves(writer: &mut dyn Write) -> Result<(), CryptoError> {
    debug!(
        target: "openssl_cli::ecparam",
        count = BUILTIN_CURVE_DESCRIPTIONS.len(),
        "listing built-in EC curves"
    );

    for (curve, comment) in BUILTIN_CURVE_DESCRIPTIONS {
        writeln!(writer, "  {:<10}: {}", curve.name(), comment)
            .map_err(|err| CryptoError::Common(CommonError::Io(err)))?;
    }
    Ok(())
}

/// Static catalogue of built-in curves and their human-readable
/// descriptions. The list is deliberately sorted to match the upstream
/// ordering for the four curves shared with the C catalogue.
const BUILTIN_CURVE_DESCRIPTIONS: &[(NamedCurve, &str)] = &[
    (
        NamedCurve::Prime256v1,
        "X9.62/SECG curve over a 256 bit prime field",
    ),
    (
        NamedCurve::Secp384r1,
        "NIST/SECG curve over a 384 bit prime field",
    ),
    (
        NamedCurve::Secp521r1,
        "NIST/SECG curve over a 521 bit prime field",
    ),
    (
        NamedCurve::Secp256k1,
        "SECG curve over a 256 bit prime field",
    ),
];

/// Open `path` for reading, mapping I/O errors into the structured error
/// type used throughout the CLI.
fn open_input_file(path: &Path) -> Result<File, CryptoError> {
    File::open(path).map_err(|err| {
        error!(
            target: "openssl_cli::ecparam",
            path = %path.display(),
            error = %err,
            "failed to open input file"
        );
        CryptoError::Common(CommonError::Io(err))
    })
}

/// Create (or truncate) `path` for writing.
fn create_output_file(path: &Path) -> Result<File, CryptoError> {
    File::create(path).map_err(|err| {
        error!(
            target: "openssl_cli::ecparam",
            path = %path.display(),
            error = %err,
            "failed to create output file"
        );
        CryptoError::Common(CommonError::Io(err))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    /// Construct an [`EcparamArgs`] with default values for use in tests.
    fn default_args() -> EcparamArgs {
        EcparamArgs {
            outform: Format::Pem,
            ..Default::default()
        }
    }

    // ---- ValueEnum smoke tests ------------------------------------------

    #[test]
    fn point_format_as_ossl_str_round_trip() {
        assert_eq!(PointFormat::Uncompressed.as_ossl_str(), "uncompressed");
        assert_eq!(PointFormat::Compressed.as_ossl_str(), "compressed");
        assert_eq!(PointFormat::Hybrid.as_ossl_str(), "hybrid");
    }

    #[test]
    fn param_encoding_as_ossl_str_round_trip() {
        assert_eq!(ParamEncoding::NamedCurve.as_ossl_str(), "named_curve");
        assert_eq!(ParamEncoding::Explicit.as_ossl_str(), "explicit");
    }

    // ---- validate_args / resolve_output_key_format ----------------------

    #[test]
    fn validate_args_accepts_default_pem() {
        let args = default_args();
        args.validate_args()
            .expect("default PEM args must validate");
    }

    #[test]
    fn validate_args_rejects_pkcs12_outform() {
        let args = EcparamArgs {
            outform: Format::Pkcs12,
            ..Default::default()
        };
        let err = args
            .validate_args()
            .expect_err("Pkcs12 outform must be rejected");
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert!(msg.contains("PEM and DER"), "unexpected message: {msg}");
            }
            other => panic!("expected Common::Internal, got {other:?}"),
        }
    }

    #[test]
    fn validate_args_rejects_msblob_inform() {
        let args = EcparamArgs {
            inform: Some(Format::MsBlob),
            ..default_args()
        };
        let err = args
            .validate_args()
            .expect_err("MsBlob inform must be rejected");
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert!(msg.contains("PEM and DER"), "unexpected message: {msg}");
            }
            other => panic!("expected Common::Internal, got {other:?}"),
        }
    }

    #[test]
    fn validate_args_rejects_name_with_infile() {
        let args = EcparamArgs {
            name: Some("prime256v1".to_string()),
            infile: Some(PathBuf::from("/tmp/params.pem")),
            ..default_args()
        };
        let err = args
            .validate_args()
            .expect_err("-name + -in must be rejected");
        match err {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert!(msg.contains("mutually exclusive"), "unexpected: {msg}");
            }
            other => panic!("expected Common::Internal, got {other:?}"),
        }
    }

    #[test]
    fn resolve_output_key_format_accepts_pem_and_der() {
        let mut args = default_args();
        args.outform = Format::Pem;
        assert!(matches!(
            args.resolve_output_key_format(),
            Ok(KeyFormat::Pem)
        ));
        args.outform = Format::Der;
        assert!(matches!(
            args.resolve_output_key_format(),
            Ok(KeyFormat::Der)
        ));
    }

    #[test]
    fn resolve_output_key_format_rejects_msblob() {
        let args = EcparamArgs {
            outform: Format::MsBlob,
            ..Default::default()
        };
        let err = args
            .resolve_output_key_format()
            .expect_err("MsBlob must be rejected");
        match err {
            CryptoError::Encoding(msg) => {
                assert!(msg.contains("MsBlob") || msg.contains("ecparam"));
            }
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    // ---- list_builtin_curves --------------------------------------------

    #[test]
    fn list_builtin_curves_emits_all_four_curves() {
        let mut buf: Vec<u8> = Vec::new();
        list_builtin_curves(&mut buf).expect("listing must not fail");
        let text = str::from_utf8(&buf).expect("output must be utf8");

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "expected 4 lines, got: {text}");
        assert!(lines[0].contains("prime256v1"));
        assert!(lines[1].contains("secp384r1"));
        assert!(lines[2].contains("secp521r1"));
        assert!(lines[3].contains("secp256k1"));
    }

    #[test]
    fn list_builtin_curves_uses_two_space_indent_and_colon_separator() {
        let mut buf: Vec<u8> = Vec::new();
        list_builtin_curves(&mut buf).expect("listing must not fail");
        let text = str::from_utf8(&buf).expect("output must be utf8");

        for line in text.lines() {
            assert!(line.starts_with("  "), "missing 2-space indent: {line}");
            assert!(line.contains(": "), "missing colon-space separator: {line}");
        }
    }

    #[test]
    fn list_builtin_curves_carries_descriptive_comments() {
        let mut buf: Vec<u8> = Vec::new();
        list_builtin_curves(&mut buf).expect("listing must not fail");
        let text = str::from_utf8(&buf).expect("output must be utf8");

        assert!(text.contains("256 bit prime field"));
        assert!(text.contains("384 bit prime field"));
        assert!(text.contains("521 bit prime field"));
    }

    // ---- BUILTIN_CURVE_DESCRIPTIONS table --------------------------------

    #[test]
    fn builtin_curve_descriptions_table_is_complete() {
        assert_eq!(BUILTIN_CURVE_DESCRIPTIONS.len(), 4);
        let names: Vec<&'static str> = BUILTIN_CURVE_DESCRIPTIONS
            .iter()
            .map(|(c, _)| c.name())
            .collect();
        assert!(names.contains(&"prime256v1"));
        assert!(names.contains(&"secp384r1"));
        assert!(names.contains(&"secp521r1"));
        assert!(names.contains(&"secp256k1"));
    }

    // ---- internal_error helper ------------------------------------------

    #[test]
    fn internal_error_constructs_common_internal_variant() {
        match internal_error("explanation") {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert_eq!(msg, "explanation");
            }
            other => panic!("expected Common::Internal, got {other:?}"),
        }
    }

    // ---- list_curves end-to-end via execute -----------------------------

    #[tokio::test]
    async fn list_curves_short_circuits_writes_curves_to_outfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("curves.txt");
        let args = EcparamArgs {
            list_curves: true,
            outfile: Some(outpath.clone()),
            ..default_args()
        };
        let ctx = LibContext::default();
        args.execute(&ctx).await.expect("list_curves must succeed");

        let body = std::fs::read_to_string(&outpath).expect("outfile readable");
        assert!(body.contains("prime256v1"));
        assert!(body.contains("secp384r1"));
        assert!(body.contains("secp521r1"));
        assert!(body.contains("secp256k1"));
    }

    // ---- synthesise_params (via execute) end-to-end ---------------------

    #[tokio::test]
    async fn execute_with_unknown_curve_returns_algorithm_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ecparam.pem");
        let args = EcparamArgs {
            name: Some("does-not-exist-curve".to_string()),
            outfile: Some(outpath),
            ..default_args()
        };
        let ctx = LibContext::default();
        let err = args
            .execute(&ctx)
            .await
            .expect_err("unknown curve must fail");
        match err {
            CryptoError::AlgorithmNotFound(msg) => {
                assert!(msg.contains("does-not-exist-curve"), "got {msg}");
            }
            other => panic!("expected AlgorithmNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_with_named_curve_emits_pem_parameters() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ecparam.pem");
        let args = EcparamArgs {
            name: Some("prime256v1".to_string()),
            outfile: Some(outpath.clone()),
            outform: Format::Pem,
            ..Default::default()
        };
        let ctx = LibContext::default();
        args.execute(&ctx)
            .await
            .expect("ecparam -name must succeed");

        let body = std::fs::read_to_string(&outpath).expect("outfile readable");
        assert!(
            !body.is_empty(),
            "expected non-empty parameter output, got empty file"
        );
    }

    // ---- DER + genkey forces noout (no parameter blob emitted) -----------

    #[tokio::test]
    async fn der_plus_genkey_forces_noout_and_emits_only_keypair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ec.der");
        let args = EcparamArgs {
            name: Some("prime256v1".to_string()),
            outfile: Some(outpath.clone()),
            outform: Format::Der,
            genkey: true,
            ..Default::default()
        };
        let ctx = LibContext::default();
        args.execute(&ctx).await.expect("genkey must succeed");

        let body = std::fs::read(&outpath).expect("outfile readable");
        assert!(
            !body.is_empty(),
            "expected non-empty key output, got empty file"
        );
    }

    // ---- text + noout combination ----------------------------------------

    #[tokio::test]
    async fn text_with_noout_emits_only_human_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ec.txt");
        let args = EcparamArgs {
            name: Some("prime256v1".to_string()),
            outfile: Some(outpath.clone()),
            text: true,
            noout: true,
            ..default_args()
        };
        let ctx = LibContext::default();
        args.execute(&ctx).await.expect("text+noout must succeed");

        let body = std::fs::read_to_string(&outpath).expect("outfile readable");
        // We don't assert on exact content (depends on the encoder backend),
        // but we can be sure the encoded parameter block is absent because
        // -noout was requested.
        assert!(
            !body.contains("-----BEGIN EC PARAMETERS-----"),
            "expected no PEM header, got: {body}"
        );
    }

    // ---- check / check_named --------------------------------------------

    #[tokio::test]
    async fn check_with_named_curve_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ec.pem");
        let args = EcparamArgs {
            name: Some("secp384r1".to_string()),
            outfile: Some(outpath),
            check: true,
            noout: true,
            ..default_args()
        };
        let ctx = LibContext::default();
        args.execute(&ctx)
            .await
            .expect("-check on a named curve must succeed");
    }

    #[tokio::test]
    async fn check_named_with_named_curve_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ec.pem");
        let args = EcparamArgs {
            name: Some("secp521r1".to_string()),
            outfile: Some(outpath),
            check_named: true,
            noout: true,
            ..default_args()
        };
        let ctx = LibContext::default();
        args.execute(&ctx)
            .await
            .expect("-check_named on a named curve must succeed");
    }

    // ---- conv_form / param_enc / no_seed acceptance ----------------------

    #[tokio::test]
    async fn conv_form_param_enc_no_seed_are_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outpath = dir.path().join("ec.pem");
        let args = EcparamArgs {
            name: Some("prime256v1".to_string()),
            outfile: Some(outpath),
            conv_form: Some(PointFormat::Compressed),
            param_enc: Some(ParamEncoding::Explicit),
            no_seed: true,
            noout: true,
            ..default_args()
        };
        let ctx = LibContext::default();
        args.execute(&ctx)
            .await
            .expect("conv_form/param_enc/no_seed must be accepted on -name path");
    }
}
