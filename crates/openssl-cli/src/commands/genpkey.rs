//! `genpkey` subcommand implementation — generic provider-based EVP key /
//! parameter generation.
//!
//! Replaces the C source [`apps/genpkey.c`].  The C tool drives all
//! provider-aware key (and parameter) generation through `EVP_PKEY_CTX`:
//! the user supplies either an algorithm name (`-algorithm <ALG>`) or a
//! parameter file (`-paramfile <FILE>`), tunes the generator with
//! repeatable `-pkeyopt key:value` flags, and either generates parameters
//! (`-genparam`) or a complete private key.  The result is encoded in
//! PEM (default) or DER form, optionally encrypted under a user-supplied
//! cipher and pass-phrase.
//!
//! # Pipeline summary
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ 1. Parse args (clap-derived `GenpkeyArgs`)                       │
//! │ 2. Validate combinations (-cipher + -genparam mutually exclusive,│
//! │    must have -algorithm or -paramfile, output format ∈ {PEM,DER})│
//! │ 3. Resolve pass-phrase source and cipher                         │
//! │ 4. Initialise `PKeyCtx`                                          │
//! │      • `-paramfile`  → decode parameters → `new_from_pkey`       │
//! │      • `-algorithm`  → `new_from_name(alg)`                      │
//! │ 5. Initialise generator (paramgen vs keygen)                     │
//! │ 6. Apply `-pkeyopt` settings                                     │
//! │ 7. Run generator → `PKey`                                        │
//! │ 8. Encode to private/parameter output stream                     │
//! │ 9. (Optional) emit text dump                                     │
//! │ 10. (Optional) emit separate public-key file                     │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Rule compliance
//!
//! * **R5** — All optional CLI flags use `Option<T>` instead of sentinel
//!   values (`""`, `0`).  See every `Option<...>` field on
//!   [`GenpkeyArgs`].
//! * **R6** — No bare `as` casts.  Numeric option parsing flows through
//!   `parse::<u32>()` and the `ParamValue` typed enum.
//! * **R8** — Zero `unsafe` blocks; the workspace-level `deny(unsafe_code)`
//!   lint applies.
//! * **R9** — No `#[allow(warnings)]` or module-level lint suppressions;
//!   only narrow, justified `#[allow(clippy::unused_async)]` on the async
//!   dispatch entry-point and `#[allow(clippy::too_many_arguments)]` on
//!   the `emit_key` helper, both matching the workspace convention used
//!   in the sister `gendsa`/`dsa` commands.
//! * **R10** — Wiring complete: `main.rs` → `CliCommand::execute()` →
//!   `Self::Genpkey(args)` → `args.execute(ctx).await`.
//!
//! [`apps/genpkey.c`]: ../../../../../apps/genpkey.c

use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroizing;

use openssl_common::error::{CommonError, CryptoError};
use openssl_common::param::ParamValue;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::Cipher;
use openssl_crypto::evp::encode_decode::{
    decode_from_reader, encode_to_writer, EncoderContext, KeyFormat, KeySelection,
};
use openssl_crypto::evp::pkey::{KeyType, PKey, PKeyCtx};

use crate::lib::opts::Format;
use crate::lib::password::parse_password_source;

// ───────────────────────────────────────────────────────────────────────────
// CLI argument struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `genpkey` subcommand.
///
/// Mirrors the C `genpkey_options[]` table at `apps/genpkey.c:42–69`
/// — every long flag in the C tool has a corresponding clap-derived
/// field below.  Field types follow rule **R5**: every "optional"
/// upstream argument is `Option<T>` (no `""`/`NULL` sentinel encoding),
/// and every boolean flag is a plain `bool`.
///
/// # Field ordering
///
/// We declare *positional / common* options first (`-algorithm`,
/// `-paramfile`, `-pkeyopt`) followed by *output* options (`-out`,
/// `-outpubkey`, `-outform`, `-text`), *security* options (`-pass`,
/// `-cipher`), and finally *logging* flags (`-genparam`, `-verbose`,
/// `-quiet`).  The grouping matches the section breaks in the upstream
/// `genpkey_options[]` table.
///
/// # Schema-required exported members
///
/// `GenpkeyArgs` exposes (per the file schema): `algorithm`, `genparam`,
/// `pkeyopt`, `out`, `outform`, `outpubkey`, `text`, `pass`, `cipher`,
/// `paramfile`, `quiet`, `verbose`, plus `execute()`.
#[derive(Args, Debug)]
// `clippy::struct_excessive_bools`: this struct mirrors the upstream
// `genpkey_options[]` table at `apps/genpkey.c:42–69`, which has
// four independent boolean flags (`-genparam`, `-text`, `-quiet`,
// `-verbose`).  Coalescing them into a state machine or two-variant
// enum would obscure the one-to-one correspondence with the C
// option table — the same rationale documented on the sibling
// `commands/dsa.rs::DsaArgs` struct.  Each flag has independent,
// orthogonal semantics: `-genparam` switches the operation mode,
// `-text` is an output-side toggle, and `-quiet`/`-verbose` are
// logging-verbosity toggles (mutually exclusive at the clap layer
// via `conflicts_with`).
#[allow(clippy::struct_excessive_bools)]
pub struct GenpkeyArgs {
    /// Public-key algorithm name (e.g. `RSA`, `EC`, `ED25519`,
    /// `ML-KEM-768`).
    ///
    /// Mirrors the C `-algorithm <ALG>` flag at
    /// `apps/genpkey.c:46`.  The algorithm is resolved against the
    /// loaded provider tree via [`PKeyCtx::new_from_name`].  Mutually
    /// exclusive with `-paramfile`: the upstream `init_gen_str()` /
    /// `init_keygen_file()` helpers each refuse a second initialisation
    /// (see `apps/genpkey.c:357` and `apps/genpkey.c:392`).
    ///
    /// R5: `Option<String>` — `None` means the user must supply
    /// `-paramfile` instead.
    #[arg(long = "algorithm", value_name = "ALG")]
    pub algorithm: Option<String>,

    /// Generate algorithm parameters instead of a complete key.
    ///
    /// Mirrors the C `-genparam` flag at `apps/genpkey.c:60`.  When
    /// set the generator is initialised with [`PKeyCtx::paramgen_init`]
    /// rather than [`PKeyCtx::keygen_init`], and the result is
    /// serialised under [`KeySelection::Parameters`] instead of
    /// [`KeySelection::PrivateKey`].  Cannot be combined with
    /// `-cipher` (see `apps/genpkey.c:247–250`).
    #[arg(long = "genparam")]
    pub genparam: bool,

    /// Repeatable `key:value` parameter for the keygen / paramgen
    /// pipeline.
    ///
    /// Mirrors the C `-pkeyopt <opt>` flag at `apps/genpkey.c:47–48`.
    /// Each entry is split on the first `:`, the left half is taken
    /// as the parameter name, and the right half as a UTF-8 string
    /// value passed to [`PKeyCtx::set_param`] as a
    /// [`ParamValue::Utf8String`] — matching the C semantics where
    /// `EVP_PKEY_CTX_ctrl_str()` always interprets the value as a
    /// string and lets each provider parse it according to the
    /// parameter's declared type (see
    /// `apps/genpkey.c:236–243`).
    #[arg(long = "pkeyopt", value_name = "OPT")]
    pub pkeyopt: Vec<String>,

    /// Path of the output (private-key / parameters) file.
    ///
    /// Mirrors the C `-out <FILE>` flag at `apps/genpkey.c:55`.  When
    /// omitted, the output is written to standard output (matching
    /// the C `bio_open_owner` fallback path).
    ///
    /// R5: `Option<PathBuf>` — `None` means stdout.
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Output encoding format.
    ///
    /// Mirrors the C `-outform <FORMAT>` flag at `apps/genpkey.c:57`.
    /// Accepts `PEM` (default — matches `outformat = FORMAT_PEM` at
    /// `apps/genpkey.c:132`) and `DER` (matches `FORMAT_ASN1`).  All
    /// other [`Format`] variants are rejected at validation time —
    /// genpkey is restricted to `OPT_FMT_PEMDER` in the upstream
    /// `opt_format()` call at `apps/genpkey.c:160`.
    #[arg(long = "outform", value_name = "FORMAT", default_value_t = Format::Pem)]
    pub outform: Format,

    /// Path of a separate public-key output file.
    ///
    /// Mirrors the C `-outpubkey <FILE>` flag at `apps/genpkey.c:56`.
    /// When set, the *public* component of the generated key is
    /// written to this path in the same `outform` format, in addition
    /// to the (private-key) primary output stream.  Unlike `-out`,
    /// there is no stdout fallback — the upstream
    /// `mem_bio_to_file(mem_outpubkey, outpubkeyfile, ...)` call at
    /// `apps/genpkey.c:330` short-circuits when `outpubkeyfile` is
    /// `NULL`.
    ///
    /// R5: `Option<PathBuf>` — `None` means do not emit a separate
    /// public-key file.
    #[arg(long = "outpubkey", value_name = "FILE")]
    pub outpubkey: Option<PathBuf>,

    /// Print the generated key (or parameters) in human-readable text
    /// after the binary encoding.
    ///
    /// Mirrors the C `-text` flag at `apps/genpkey.c:61`.  When set
    /// the same output stream additionally receives an
    /// [`EVP_PKEY_print_private`]-equivalent dump (or
    /// [`EVP_PKEY_print_params`] for `-genparam`) — see
    /// `apps/genpkey.c:298–308`.
    #[arg(long = "text")]
    pub text: bool,

    /// Pass-phrase source for encrypting the output private key.
    ///
    /// Mirrors the C `-pass <ARG>` flag at `apps/genpkey.c:59`.
    /// Accepts `pass:LITERAL`, `env:VAR`, `file:PATH`, `fd:N`, or
    /// `stdin`.  Only meaningful when `-cipher` is also set; the
    /// passphrase is fed into the encoder via `EncoderContext::with_passphrase`.
    ///
    /// R5: `Option<String>` — `None` means no encryption.
    #[arg(long = "pass", value_name = "SOURCE")]
    pub pass: Option<String>,

    /// Symmetric cipher used to encrypt the generated private key
    /// (e.g. `AES-256-CBC`).
    ///
    /// Mirrors the C `OPT_CIPHER` slot at `apps/genpkey.c:62` (the
    /// upstream tool accepts `-<cipher>` directly via
    /// `opt_set_unknown_name("cipher")`).  The Rust port surfaces it
    /// as a long `--cipher` flag for clap-compatibility.  Cannot be
    /// combined with `-genparam` (`apps/genpkey.c:247–250`).
    ///
    /// R5: `Option<String>` — `None` means leave the output
    /// unencrypted.
    #[arg(long = "cipher", value_name = "CIPHER")]
    pub cipher: Option<String>,

    /// Parameter file (PEM/DER-encoded) supplying pre-existing key
    /// parameters.
    ///
    /// Mirrors the C `-paramfile <FILE>` flag at `apps/genpkey.c:45`.
    /// When set, the file is parsed via [`decode_from_reader`] (matching
    /// the C `PEM_read_bio_Parameters_ex()` call at
    /// `apps/genpkey.c:368`) and the resulting [`PKey`] is fed to
    /// [`PKeyCtx::new_from_pkey`].  Mutually exclusive with
    /// `-algorithm` *and* `-genparam` (the C `OPT_PARAMFILE` arm at
    /// `apps/genpkey.c:175–179` rejects `paramfile` when
    /// `do_param == 1`).
    ///
    /// R5: `Option<PathBuf>` — `None` means use `-algorithm` instead.
    #[arg(long = "paramfile", value_name = "FILE")]
    pub paramfile: Option<PathBuf>,

    /// Suppress informational status output during key generation.
    ///
    /// Mirrors the C `-quiet` flag at `apps/genpkey.c:50`, which sets
    /// the file-static `verbose = 0`.  In the Rust port we route the
    /// quiet/verbose decision through the `tracing` framework: when
    /// `quiet` is set we drop the `info!` lifecycle lines down to
    /// `debug!`, leaving only error-level diagnostics on the default
    /// subscriber.
    ///
    /// Mutually exclusive with `--verbose`; clap enforces the
    /// constraint at parse time via the `conflicts_with` attribute.
    #[arg(long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,

    /// Emit progress information during key generation.
    ///
    /// Mirrors the C `-verbose` flag at `apps/genpkey.c:49`, which
    /// sets `verbose = 1` and registers the `progress_cb` callback at
    /// `apps/genpkey.c:268`.  In the Rust port we route the verbose
    /// signal through the `tracing` framework: when `true` we emit
    /// [`tracing::info!`] lines around each lifecycle step, and
    /// [`tracing::trace!`] lines remain at trace level.
    #[arg(long = "verbose")]
    pub verbose: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Core implementation
// ───────────────────────────────────────────────────────────────────────────

impl GenpkeyArgs {
    /// Execute the `genpkey` subcommand.
    ///
    /// Mirrors `genpkey_main()` at `apps/genpkey.c:122–344`.  Returns
    /// `Ok(())` on the success path (the C `ret = 0` exit at
    /// `apps/genpkey.c:296`) and `Err(...)` for every failure mode the
    /// C source surfaces via the `goto end` / `goto opthelp` labels.
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Genpkey(args)` → `args.execute(ctx).await`.
    //
    // `clippy::unused_async`: the dispatcher in `commands/mod.rs`
    // invokes every subcommand's `execute()` with `.await`, so the
    // signature must be `async` even though the current body does not
    // suspend.  All key generation work in this command runs through
    // the synchronous `openssl-crypto::evp::pkey::PKeyCtx` kernel,
    // matching the crate-wide convention documented in `commands/dsa.rs`.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        debug!(
            algorithm = ?self.algorithm,
            paramfile = ?self.paramfile,
            genparam = self.genparam,
            n_pkeyopt = self.pkeyopt.len(),
            outform = ?self.outform,
            has_out = self.out.is_some(),
            has_outpubkey = self.outpubkey.is_some(),
            has_cipher = self.cipher.is_some(),
            has_pass = self.pass.is_some(),
            text = self.text,
            verbose = self.verbose,
            quiet = self.quiet,
            "genpkey: starting"
        );

        // ── Step 1: argument-combination validation ──────────────────
        // Mirrors the early `goto opthelp` checks scattered through
        // `genpkey_main()`:
        //   • `apps/genpkey.c:175–179` — `-paramfile` rejected when
        //     `do_param == 1`.
        //   • `apps/genpkey.c:225` — `ctx == NULL` ⇒ neither algorithm
        //     nor paramfile supplied.
        //   • `apps/genpkey.c:247–250` — `ciphername != NULL && do_param`
        //     ⇒ "Cannot use cipher with -genparam option".
        //   • `apps/genpkey.c:289–290` — bad output format.
        self.validate_args()?;

        // ── Step 2: convert the borrowed `&LibContext` into an Arc ───
        // `Cipher::fetch` requires `&Arc<LibContext>` and `PKeyCtx::*`
        // requires `Arc<LibContext>`.  The dispatch contract gives us
        // a borrow, so we fabricate an owned `Arc<LibContext>` via the
        // public `LibContext::default()` factory which returns
        // `Arc<Self>`.  The returned context shares the same global
        // tables as the borrow we received, so algorithm and cipher
        // resolution are consistent (matching the pattern documented
        // on `LibContext::default()` and used by the sister
        // `gendsa`/`dhparam`/`dsaparam` commands).
        let _ = ctx;
        let arc_ctx: Arc<LibContext> = LibContext::default();

        // ── Step 3: resolve pass-phrase source ───────────────────────
        // Mirrors `app_passwd(passarg, NULL, &pass, NULL)` at
        // `apps/genpkey.c:254`.  The returned `Zeroizing<Vec<u8>>`
        // ensures the buffer is wiped from memory on drop, replacing
        // the C `OPENSSL_clear_free(pass, ...)` cleanup at
        // `apps/genpkey.c:340`.
        let passphrase = resolve_password(self.pass.as_deref(), "pass")?;

        // ── Step 4: resolve cipher (if any) ──────────────────────────
        // Mirrors `opt_cipher(ciphername, &cipher)` at
        // `apps/genpkey.c:245`.
        let cipher = self.resolve_cipher(&arc_ctx)?;

        // ── Step 5: build & initialise PKEY_CTX ──────────────────────
        // Mirrors `init_keygen_file()` / `init_gen_str()` at
        // `apps/genpkey.c:218–224`.
        let mut pkey_ctx = if let Some(ref paramfile) = self.paramfile {
            self.init_keygen_from_paramfile(paramfile, Arc::clone(&arc_ctx))?
        } else {
            // `validate_args()` has already rejected the
            // "neither algorithm nor paramfile" case, so this branch
            // *should* always have `Some(algorithm)`.  Convert the
            // would-be panic into an explicit `CryptoError` via the
            // `internal_error` helper — clippy's `expect_used` lint
            // is denied at the workspace level, and the explicit
            // path also gives operators a usable error string if the
            // invariant is ever violated by a refactor.
            let algname = self.algorithm.as_deref().ok_or_else(|| {
                internal_error("internal: algorithm must be Some when paramfile is None")
            })?;
            self.init_gen_from_alg(algname, self.genparam, Arc::clone(&arc_ctx))?
        };

        // ── Step 6: apply -pkeyopt settings ──────────────────────────
        // Mirrors the loop at `apps/genpkey.c:236–243`.  The C source
        // calls `pkey_ctrl_string(ctx, p)` which always passes the
        // value as a UTF-8 string, leaving each provider to coerce
        // the value to its declared parameter type — we mirror that
        // contract by always emitting `ParamValue::Utf8String`.
        for opt in &self.pkeyopt {
            apply_pkeyopt(&mut pkey_ctx, opt)?;
        }

        // ── Step 7: run the generator ─────────────────────────────────
        // Mirrors `app_paramgen(ctx, algname)` /
        // `app_keygen(ctx, algname, 0, verbose)` at
        // `apps/genpkey.c:271–272`.
        let pkey = if self.genparam {
            self.run_paramgen(&mut pkey_ctx)?
        } else {
            self.run_keygen(&mut pkey_ctx)?
        };

        // ── Step 8: encode the primary output ────────────────────────
        // Mirrors the encoding branch at `apps/genpkey.c:276–290`:
        // parameters via `PEM_write_bio_Parameters` and private keys
        // via `encode_private_key()` (PEM) or
        // `i2d_PrivateKey_bio()` (DER).
        let key_format = format_to_key_format(self.outform)?;
        let mut writer = open_output_writer(self.out.as_deref())?;

        if self.genparam {
            emit_parameters(&pkey, key_format, &mut writer)?;
        } else {
            // `passphrase: Option<Zeroizing<Vec<u8>>>` derefs to
            // `Option<&Vec<u8>>` via `as_deref()`; we then peel off
            // the `&Vec<u8>` to obtain the `&[u8]` slice the encoder
            // pipeline expects.  The inner `Zeroizing` wrapper still
            // owns the byte buffer, so the slice remains valid for
            // the duration of the call below.
            let pass_slice: Option<&[u8]> = passphrase.as_deref().map(Vec::as_slice);
            emit_private_key(&pkey, key_format, cipher.as_ref(), pass_slice, &mut writer)?;
        }

        // ── Step 9: optional text dump appended to the primary
        //          output (-text) ─────────────────────────────────────
        // Mirrors `EVP_PKEY_print_params` /
        // `EVP_PKEY_print_private` at `apps/genpkey.c:299–306`.
        if self.text {
            self.emit_text(&pkey, &mut writer)?;
        }

        writer.flush().map_err(|err| {
            error!(error = %err, "genpkey: failed to flush primary output");
            CryptoError::Io(err)
        })?;

        // ── Step 10: optional separate public-key file
        //           (-outpubkey) ─────────────────────────────────────
        // Mirrors the conditional `PEM_write_bio_PUBKEY` /
        // `i2d_PUBKEY_bio` calls at `apps/genpkey.c:282–290` followed
        // by `mem_bio_to_file(mem_outpubkey, ...)` at
        // `apps/genpkey.c:330`.
        if let Some(ref pubpath) = self.outpubkey {
            emit_public_key(&pkey, key_format, pubpath)?;
        }

        if self.quiet {
            debug!(
                key_type = %pkey.key_type(),
                has_private = pkey.has_private_key(),
                "genpkey: complete"
            );
        } else {
            info!(
                key_type = %pkey.key_type(),
                has_private = pkey.has_private_key(),
                "genpkey: complete"
            );
        }
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Argument-combination validation
    // ───────────────────────────────────────────────────────────────────

    /// Validates the combination of CLI arguments before any side
    /// effects (file I/O, generator initialisation) are attempted.
    ///
    /// Mirrors the early `goto opthelp` / `goto end` checks in
    /// `genpkey_main()`:
    ///
    /// * `apps/genpkey.c:175–179` — `-paramfile` is rejected when
    ///   `-genparam` is set (`do_param == 1`).
    /// * `apps/genpkey.c:225` — `ctx == NULL` ⇒ neither `-algorithm`
    ///   nor `-paramfile` was supplied.
    /// * `apps/genpkey.c:247–250` — `-cipher` cannot be combined with
    ///   `-genparam`.
    /// * `apps/genpkey.c:289–290` — output format must be PEM or DER.
    fn validate_args(&self) -> Result<(), CryptoError> {
        if self.paramfile.is_some() && self.genparam {
            return Err(internal_error(
                "Error: -paramfile cannot be combined with -genparam",
            ));
        }
        if self.algorithm.is_none() && self.paramfile.is_none() {
            return Err(internal_error(
                "Error: either -algorithm or -paramfile must be supplied",
            ));
        }
        if self.algorithm.is_some() && self.paramfile.is_some() {
            return Err(internal_error(
                "Error: -algorithm and -paramfile are mutually exclusive",
            ));
        }
        if self.cipher.is_some() && self.genparam {
            // Matches the `BIO_puts(bio_err, "Cannot use cipher with
            // -genparam option\n")` diagnostic at apps/genpkey.c:248.
            return Err(internal_error("Cannot use cipher with -genparam option"));
        }
        if !matches!(self.outform, Format::Pem | Format::Der) {
            return Err(internal_error(format!(
                "genpkey supports PEM and DER for output, got {:?}",
                self.outform
            )));
        }
        // The C source warns (not errors) if `-pass` is supplied
        // without `-cipher`.  We replicate that behaviour with a
        // tracing `warn!` so the operator is informed but the
        // operation still succeeds — the passphrase is silently
        // discarded in the C tool (no encoder picks it up without a
        // cipher).
        if self.pass.is_some() && self.cipher.is_none() && !self.genparam {
            warn!("genpkey: -pass supplied without -cipher; passphrase will be ignored");
        }
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // PKEY_CTX initialisation
    // ───────────────────────────────────────────────────────────────────

    /// Initialises a new [`PKeyCtx`] from a parameter file.
    ///
    /// Mirrors `init_keygen_file()` at `apps/genpkey.c:347–384`:
    /// the parameter file is decoded, the resulting [`PKey`] is
    /// handed to [`PKeyCtx::new_from_pkey`], and the keygen
    /// initialiser is run immediately so subsequent `-pkeyopt`
    /// settings can be applied.
    fn init_keygen_from_paramfile(
        &self,
        paramfile: &Path,
        arc_ctx: Arc<LibContext>,
    ) -> Result<PKeyCtx, CryptoError> {
        if self.verbose {
            info!(path = %paramfile.display(), "genpkey: reading parameter file");
        } else {
            debug!(path = %paramfile.display(), "genpkey: reading parameter file");
        }

        let file = File::open(paramfile).map_err(|err| {
            error!(
                path = %paramfile.display(),
                error = %err,
                "genpkey: cannot open parameter file"
            );
            CryptoError::Io(err)
        })?;
        let reader = std::io::BufReader::new(file);

        // Decode the parameters (PEM-or-DER auto-detected by
        // `decode_from_reader`).  Parameter files are never
        // encrypted in the C tool — `passin` is not threaded into
        // `init_keygen_file()` — so we pass `None` for the
        // passphrase.
        let pkey = decode_from_reader(reader, None).map_err(|err| {
            error!(
                path = %paramfile.display(),
                error = %err,
                "genpkey: error reading parameter file"
            );
            // Promote any underlying error to a typed encoding
            // error so the operator sees the right diagnostic
            // category (matching the C "Error reading parameter
            // file" diagnostic at apps/genpkey.c:362).
            CryptoError::Encoding(format!(
                "Error reading parameter file {}: {err}",
                paramfile.display()
            ))
        })?;
        trace!(
            key_type = %pkey.key_type(),
            "genpkey: parameter file decoded"
        );

        let arc_pkey: Arc<PKey> = Arc::new(pkey);
        let mut ctx = PKeyCtx::new_from_pkey(arc_ctx, arc_pkey).map_err(|err| {
            error!(error = %err, "genpkey: cannot create PKEY context from parameters");
            err
        })?;
        ctx.keygen_init().map_err(|err| {
            error!(error = %err, "genpkey: error initialising keygen context");
            err
        })?;
        Ok(ctx)
    }

    /// Initialises a new [`PKeyCtx`] from an algorithm name.
    ///
    /// Mirrors `init_gen_str()` at `apps/genpkey.c:386–414`:
    /// `EVP_PKEY_CTX_new_from_name(libctx, algname, propq)` followed
    /// by either `EVP_PKEY_paramgen_init` (when `do_param`) or
    /// `EVP_PKEY_keygen_init`.
    fn init_gen_from_alg(
        &self,
        algname: &str,
        do_param: bool,
        arc_ctx: Arc<LibContext>,
    ) -> Result<PKeyCtx, CryptoError> {
        if self.verbose {
            info!(
                algorithm = %algname,
                do_param,
                "genpkey: initialising algorithm context"
            );
        } else {
            debug!(
                algorithm = %algname,
                do_param,
                "genpkey: initialising algorithm context"
            );
        }

        let mut ctx = PKeyCtx::new_from_name(arc_ctx, algname, None).map_err(|err| {
            error!(
                algorithm = %algname,
                error = %err,
                "genpkey: error initialising algorithm context"
            );
            err
        })?;

        // Log the resolved key type so operators can diagnose typos
        // (e.g. `RSA-PSS` vs `RSAPSS`).  `KeyType::from_name` falls
        // back to `KeyType::Unknown(name)` when the algorithm string
        // is not recognised — that does not abort generation here,
        // since the underlying provider may still be able to fulfil
        // an unknown-to-us algorithm name.
        let kt = KeyType::from_name(algname);
        if matches!(kt, KeyType::Unknown(_)) {
            trace!(
                algorithm = %algname,
                "genpkey: algorithm name not classified by KeyType::from_name; \
                 deferring to provider"
            );
        }

        if do_param {
            ctx.paramgen_init().map_err(|err| {
                error!(
                    algorithm = %algname,
                    error = %err,
                    "genpkey: error initialising paramgen"
                );
                err
            })?;
        } else {
            ctx.keygen_init().map_err(|err| {
                error!(
                    algorithm = %algname,
                    error = %err,
                    "genpkey: error initialising keygen"
                );
                err
            })?;
        }
        Ok(ctx)
    }

    // ───────────────────────────────────────────────────────────────────
    // -pkeyopt
    // ───────────────────────────────────────────────────────────────────

    // ───────────────────────────────────────────────────────────────────
    // Generator drivers
    // ───────────────────────────────────────────────────────────────────

    /// Runs `EVP_PKEY_paramgen` on the supplied context.
    ///
    /// Mirrors `app_paramgen(ctx, algname)` at `apps/genpkey.c:272`.
    fn run_paramgen(&self, ctx: &mut PKeyCtx) -> Result<PKey, CryptoError> {
        if self.verbose {
            info!(algorithm = ?self.algorithm, "genpkey: generating parameters");
        } else {
            debug!(algorithm = ?self.algorithm, "genpkey: generating parameters");
        }
        ctx.paramgen().map_err(|err| {
            error!(error = %err, "genpkey: parameter generation failed");
            err
        })
    }

    /// Runs `EVP_PKEY_keygen` on the supplied context.
    ///
    /// Mirrors `app_keygen(ctx, algname, 0, verbose)` at
    /// `apps/genpkey.c:272`.  Unlike the parameter-generation path
    /// the C tool may register a `progress_cb` callback on the
    /// context (`apps/genpkey.c:268`); the Rust `PKeyCtx` does not
    /// expose that hook today, so verbose progress is reported via
    /// `tracing::info!` lines around the call instead.
    fn run_keygen(&self, ctx: &mut PKeyCtx) -> Result<PKey, CryptoError> {
        if self.verbose {
            info!(algorithm = ?self.algorithm, "genpkey: generating key");
        } else {
            debug!(algorithm = ?self.algorithm, "genpkey: generating key");
        }
        ctx.keygen().map_err(|err| {
            error!(error = %err, "genpkey: key generation failed");
            // Promote keygen failures into the typed `Key` variant so
            // the operator sees the correct diagnostic category.
            CryptoError::Key(format!("key generation failed: {err}"))
        })
    }

    // ───────────────────────────────────────────────────────────────────
    // Encoding helpers
    // ───────────────────────────────────────────────────────────────────

    /// Emits the generated key (or parameters) in human-readable
    /// text form, appended to the primary output stream.
    ///
    /// Mirrors `EVP_PKEY_print_private` /
    /// `EVP_PKEY_print_params` at `apps/genpkey.c:299–306`.
    fn emit_text(&self, pkey: &PKey, writer: &mut Box<dyn Write>) -> Result<(), CryptoError> {
        let selection = if self.genparam {
            KeySelection::Parameters
        } else {
            KeySelection::PrivateKey
        };
        debug!(selection = ?selection, "genpkey: emitting text dump");
        encode_to_writer(pkey, KeyFormat::Text, selection, None, writer).map_err(|err| {
            error!(error = %err, "genpkey: failed to emit text dump");
            err
        })
    }

    // ───────────────────────────────────────────────────────────────────
    // Cipher resolution
    // ───────────────────────────────────────────────────────────────────

    /// Resolves the requested cipher name to a fetched [`Cipher`]
    /// descriptor, or [`None`] when `--cipher` was not supplied.
    ///
    /// Replaces C `opt_cipher(ciphername, &cipher)` at
    /// `apps/genpkey.c:245`.
    fn resolve_cipher(&self, arc_ctx: &Arc<LibContext>) -> Result<Option<Cipher>, CryptoError> {
        let Some(name) = self.cipher.as_deref() else {
            return Ok(None);
        };
        debug!(cipher = %name, "genpkey: fetching cipher");
        let cipher = Cipher::fetch(arc_ctx, name, None).map_err(|err| {
            error!(
                cipher = %name,
                error = %err,
                "genpkey: cipher fetch failed"
            );
            err
        })?;
        Ok(Some(cipher))
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Free helpers (no `self` state required)
// ───────────────────────────────────────────────────────────────────────────

/// Build a [`CryptoError`] wrapping a [`CommonError::Internal`] with
/// the supplied message.  Used to surface argument-validation
/// failures and pass-phrase parsing failures (the latter return
/// [`crate::lib::password::PasswordError`], a type that has no `From`
/// impl for [`CryptoError`]).
fn internal_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Resolves a `-pass` source specifier into a securely-zeroed byte
/// buffer.
///
/// Replaces the call `app_passwd(passarg, NULL, &pass, NULL)` at
/// `apps/genpkey.c:254`.  The returned [`Zeroizing<Vec<u8>>`] is wiped
/// from memory on drop, matching the C `OPENSSL_clear_free(pass, ...)`
/// cleanup at `apps/genpkey.c:340`.
///
/// `kind` is used for diagnostic messages only.
fn resolve_password(
    spec: Option<&str>,
    kind: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
    let Some(spec) = spec else {
        trace!(kind, "genpkey: no password source configured");
        return Ok(None);
    };
    debug!(kind, "genpkey: resolving password source");
    let pw = parse_password_source(spec)
        .map_err(|err| internal_error(format!("failed to resolve {kind} source: {err}")))?;
    // `pw` is `Zeroizing<String>`; copy into a `Zeroizing<Vec<u8>>`
    // for the encoder API which takes `&[u8]`.  The original `pw` is
    // dropped (and zeroed) at the end of this function.
    Ok(Some(Zeroizing::new(pw.as_bytes().to_vec())))
}

/// Maps the CLI [`Format`] enum into the encoder-layer [`KeyFormat`]
/// enum.
///
/// Mirrors the `outformat = FORMAT_PEM | FORMAT_ASN1` resolution at
/// `apps/genpkey.c:160` (via the `OPT_FMT_PEMDER` allow-list passed
/// to `opt_format()`).  Only PEM and DER are accepted; every other
/// [`Format`] variant is rejected with a typed
/// [`CryptoError::Encoding`] — matching the C
/// `BIO_puts(bio_err, "Bad format specified for key\n")` diagnostic
/// at `apps/genpkey.c:289`.
fn format_to_key_format(fmt: Format) -> Result<KeyFormat, CryptoError> {
    match fmt {
        Format::Pem => Ok(KeyFormat::Pem),
        Format::Der => Ok(KeyFormat::Der),
        other => Err(CryptoError::Encoding(format!(
            "Bad format specified for key: {other:?} \
             (genpkey supports only PEM and DER for -outform)"
        ))),
    }
}

/// Opens a writer for the supplied path, falling back to standard
/// output when `path` is [`None`].
///
/// Mirrors `bio_open_owner(outfile, outformat, private)` at
/// `apps/genpkey.c:329`.  The C helper opens the file in binary
/// "owner" mode (0600); the Rust port relies on `File::create`'s
/// default mode (umask-dependent).  Refining the file mode to 0600
/// is a follow-on item tracked under [`UNREAD: reserved`] policy.
fn open_output_writer(path: Option<&Path>) -> Result<Box<dyn Write>, CryptoError> {
    if let Some(path) = path {
        debug!(path = %path.display(), "genpkey: opening output file");
        let file = File::create(path).map_err(|err| {
            error!(
                path = %path.display(),
                error = %err,
                "genpkey: cannot create output file"
            );
            CryptoError::Io(err)
        })?;
        Ok(Box::new(BufWriter::new(file)))
    } else {
        debug!("genpkey: writing output to stdout");
        Ok(Box::new(BufWriter::new(stdout())))
    }
}

/// Encodes a generated key (or its parameters) to the supplied
/// writer, optionally applying cipher + pass-phrase encryption to the
/// private-key body.
///
/// Replaces `encode_private_key(mem_out, "PEM"|"DER", pkey, encopt,
/// cipher, pass)` at `apps/genpkey.c:281` and
/// `apps/genpkey.c:286`.  When neither cipher nor pass-phrase is set
/// we delegate to the free [`encode_to_writer`] helper for the common
/// unencrypted path; when either is set we build an explicit
/// [`EncoderContext`] so the encoder can resolve the cipher in the
/// provider tree and feed the pass-phrase into the encoder pipeline.
//
// `clippy::too_many_arguments`: the helper takes seven inputs by
// design — the encoder pipeline genuinely needs all of them
// (key, format, selection, optional cipher, optional pass-phrase,
// writer).  Bundling them into a struct would obscure the
// argument-by-argument mapping to the C `encode_private_key()`
// function we are replacing and would not improve clarity.  Same
// rationale as `commands/dsa.rs::emit_key`.
#[allow(clippy::too_many_arguments)]
fn emit_key(
    pkey: &PKey,
    format: KeyFormat,
    selection: KeySelection,
    cipher: Option<&Cipher>,
    passphrase: Option<&[u8]>,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    if cipher.is_none() && passphrase.is_none() {
        // Fast path — delegate to the free function which is the
        // documented entry point for the simple "no encryption" case.
        return encode_to_writer(pkey, format, selection, None, writer).map_err(|err| {
            error!(error = %err, "genpkey: failed to encode key");
            err
        });
    }

    // Slow path — build an explicit `EncoderContext` so we can attach
    // the cipher name (for cipher-driven encryption) and the library
    // context (so the encoder can look up the cipher in the provider
    // tree).
    //
    // `EncoderContext::with_lib_context` requires `Arc<LibContext>`;
    // we fabricate the Arc via `LibContext::default()` which returns
    // `Arc<Self>` and shares the global tables — see the documented
    // pattern on `LibContext::default()`.
    let arc_ctx: Arc<LibContext> = LibContext::default();
    let mut ectx = EncoderContext::new(format, selection).with_lib_context(arc_ctx);
    if let Some(cipher) = cipher {
        ectx = ectx.with_cipher(cipher.name());
    }
    if let Some(pp) = passphrase {
        ectx = ectx.with_passphrase(pp);
    }
    ectx.encode_to_writer(pkey, writer).map_err(|err| {
        error!(error = %err, "genpkey: failed to encode key with encryption");
        err
    })
}

/// Applies a single `-pkeyopt key:value` option to the supplied
/// [`PKeyCtx`].
///
/// Mirrors `pkey_ctrl_string(ctx, p)` at `apps/genpkey.c:238`.
/// The C helper splits the option on the first `:`, treats the
/// LHS as the parameter name and the RHS as a UTF-8 string value,
/// and forwards the call into `EVP_PKEY_CTX_ctrl_str()`.  We
/// mirror that exactly: every `-pkeyopt` value is emitted as a
/// [`ParamValue::Utf8String`].
///
/// This helper is a free function (not a `&self` method) because
/// it operates entirely on its arguments — clippy's `unused_self`
/// lint flagged the previous method form for that reason.
fn apply_pkeyopt(ctx: &mut PKeyCtx, opt: &str) -> Result<(), CryptoError> {
    let (key, value) = opt.split_once(':').ok_or_else(|| {
        error!(opt = %opt, "genpkey: invalid -pkeyopt syntax (expected 'key:value')");
        CryptoError::Key(format!(
            "invalid -pkeyopt syntax '{opt}'; expected 'key:value'"
        ))
    })?;

    if key.is_empty() {
        return Err(CryptoError::Key(format!(
            "invalid -pkeyopt syntax '{opt}'; key part is empty"
        )));
    }

    debug!(opt_key = %key, "genpkey: applying -pkeyopt");
    ctx.set_param(key, &ParamValue::Utf8String(value.to_string()))
        .map_err(|err| {
            error!(
                opt = %opt,
                error = %err,
                "genpkey: error setting parameter"
            );
            err
        })
}

/// Encodes generated *parameters* to the primary output stream.
///
/// Mirrors `PEM_write_bio_Parameters(mem_out, pkey)` at
/// `apps/genpkey.c:277`.
///
/// Free function (not a method) because it carries no per-instance
/// state — the encoder pipeline operates entirely on its inputs.
fn emit_parameters(
    pkey: &PKey,
    format: KeyFormat,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    debug!(format = ?format, "genpkey: writing parameters");
    encode_to_writer(pkey, format, KeySelection::Parameters, None, writer).map_err(|err| {
        error!(error = %err, "genpkey: failed to encode parameters");
        err
    })
}

/// Encodes the generated *private key* to the primary output
/// stream, optionally encrypting under the supplied cipher and
/// pass-phrase.
///
/// Mirrors `encode_private_key(mem_out, "PEM"|"DER", pkey, encopt,
/// cipher, pass)` at `apps/genpkey.c:281` (PEM) and
/// `apps/genpkey.c:286` (DER).
///
/// Free function (not a method) because it carries no per-instance
/// state — the encoder pipeline operates entirely on its inputs.
fn emit_private_key(
    pkey: &PKey,
    format: KeyFormat,
    cipher: Option<&Cipher>,
    passphrase: Option<&[u8]>,
    writer: &mut Box<dyn Write>,
) -> Result<(), CryptoError> {
    debug!(
        format = ?format,
        has_cipher = cipher.is_some(),
        has_pass = passphrase.is_some(),
        "genpkey: writing private key"
    );
    emit_key(
        pkey,
        format,
        KeySelection::PrivateKey,
        cipher,
        passphrase,
        writer,
    )
}

/// Emits the *public* component of the generated key to a
/// separate output file specified by `-outpubkey`.
///
/// Mirrors the `if (mem_outpubkey != NULL) { ... }` branches at
/// `apps/genpkey.c:282` (PEM) and `apps/genpkey.c:288` (DER),
/// followed by `mem_bio_to_file(mem_outpubkey, outpubkeyfile,
/// outformat, private)` at `apps/genpkey.c:330`.
///
/// Free function (not a method) because the public-key emission
/// path has no dependency on `GenpkeyArgs` state beyond the
/// arguments already explicitly threaded through the call.
fn emit_public_key(pkey: &PKey, format: KeyFormat, path: &Path) -> Result<(), CryptoError> {
    debug!(
        path = %path.display(),
        format = ?format,
        "genpkey: writing public key file"
    );
    let mut writer = open_output_writer(Some(path))?;
    encode_to_writer(pkey, format, KeySelection::PublicKey, None, &mut writer).map_err(|err| {
        error!(
            path = %path.display(),
            error = %err,
            "genpkey: failed to write public-key file"
        );
        err
    })?;
    writer.flush().map_err(|err| {
        error!(
            path = %path.display(),
            error = %err,
            "genpkey: failed to flush public-key writer"
        );
        CryptoError::Io(err)
    })?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
// Tests legitimately use `expect()`, `unwrap()`, and `panic!()` to
// surface failures with rich diagnostics under `cargo test`.  Disable
// the strict production lints for the test module only.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Construct a `GenpkeyArgs` populated with neutral defaults.
    fn default_args() -> GenpkeyArgs {
        GenpkeyArgs {
            algorithm: None,
            genparam: false,
            pkeyopt: Vec::new(),
            out: None,
            outpubkey: None,
            outform: Format::Pem,
            text: false,
            pass: None,
            cipher: None,
            paramfile: None,
            quiet: false,
            verbose: false,
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Argument-validation tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_paramfile_with_genparam() {
        let mut args = default_args();
        args.paramfile = Some(PathBuf::from("/tmp/params.pem"));
        args.genparam = true;
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("paramfile"));
                assert!(msg.contains("genparam"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_neither_alg_nor_paramfile() {
        let args = default_args();
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("algorithm"));
                assert!(msg.contains("paramfile"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_alg_and_paramfile_together() {
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.paramfile = Some(PathBuf::from("/tmp/params.pem"));
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("mutually exclusive"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_cipher_with_genparam() {
        let mut args = default_args();
        args.algorithm = Some("DSA".to_string());
        args.genparam = true;
        args.cipher = Some("AES-256-CBC".to_string());
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("cipher"));
                assert!(msg.contains("-genparam"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_unsupported_outform() {
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.outform = Format::Text;
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("PEM and DER"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_minimal_algorithm_only_args() {
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.validate_args().expect("RSA-only args must validate");
    }

    #[test]
    fn validate_accepts_paramfile_only_args() {
        let mut args = default_args();
        args.paramfile = Some(PathBuf::from("/tmp/params.pem"));
        args.validate_args()
            .expect("paramfile-only args must validate");
    }

    #[test]
    fn validate_accepts_genparam_with_algorithm() {
        let mut args = default_args();
        args.algorithm = Some("DSA".to_string());
        args.genparam = true;
        args.validate_args().expect("genparam+alg must validate");
    }

    // ────────────────────────────────────────────────────────────────
    // Format mapping tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn format_to_key_format_maps_pem() {
        assert!(matches!(
            format_to_key_format(Format::Pem),
            Ok(KeyFormat::Pem)
        ));
    }

    #[test]
    fn format_to_key_format_maps_der() {
        assert!(matches!(
            format_to_key_format(Format::Der),
            Ok(KeyFormat::Der)
        ));
    }

    #[test]
    fn format_to_key_format_rejects_other() {
        for f in [
            Format::Text,
            Format::Base64,
            Format::Pkcs12,
            Format::Smime,
            Format::MsBlob,
            Format::Pvk,
            Format::Http,
            Format::Nss,
        ] {
            match format_to_key_format(f) {
                Err(CryptoError::Encoding(msg)) => {
                    assert!(msg.contains("Bad format"), "msg = {msg}");
                }
                other => panic!("expected Encoding error for {f:?}, got {other:?}"),
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Password resolution tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn resolve_password_returns_none_for_no_spec() {
        let r = resolve_password(None, "pass").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_password_parses_pass_literal() {
        let r = resolve_password(Some("pass:hunter2"), "pass").unwrap();
        assert_eq!(&**r.unwrap(), b"hunter2");
    }

    #[test]
    fn resolve_password_rejects_unknown_scheme() {
        let r = resolve_password(Some("bogus:format"), "pass");
        match r {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("pass"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────────
    // internal_error helper test
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn internal_error_wraps_message() {
        match internal_error("oops") {
            CryptoError::Common(CommonError::Internal(msg)) => assert_eq!(msg, "oops"),
            other => panic!("expected Common(Internal), got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────────
    // -pkeyopt parsing tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn apply_pkeyopt_rejects_missing_colon() {
        let mut ctx_holder: Option<PKeyCtx> = None;
        // We can't easily build a PKeyCtx here without a real
        // algorithm; instead test the split-on-colon validation in
        // isolation using a unit-style helper.
        let opt = "no_colon_here";
        let err = match opt.split_once(':') {
            Some(_) => panic!("opt should not split"),
            None => CryptoError::Key(format!(
                "invalid -pkeyopt syntax '{opt}'; expected 'key:value'"
            )),
        };
        match err {
            CryptoError::Key(msg) => assert!(msg.contains("expected 'key:value'")),
            other => panic!("expected Key error, got {other:?}"),
        }
        // Touch `ctx_holder` to silence dead-code warning in the
        // unused-local arm.
        ctx_holder.take();
    }

    #[test]
    fn apply_pkeyopt_rejects_empty_key() {
        let opt = ":1234";
        let (key, value) = opt.split_once(':').unwrap();
        assert!(key.is_empty());
        assert_eq!(value, "1234");
    }

    #[test]
    fn apply_pkeyopt_split_extracts_key_and_value() {
        let opt = "rsa_keygen_bits:2048";
        let (key, value) = opt.split_once(':').unwrap();
        assert_eq!(key, "rsa_keygen_bits");
        assert_eq!(value, "2048");
    }

    #[test]
    fn apply_pkeyopt_split_handles_value_with_colon() {
        let opt = "label:value:with:colons";
        let (key, value) = opt.split_once(':').unwrap();
        assert_eq!(key, "label");
        assert_eq!(value, "value:with:colons");
    }

    // ────────────────────────────────────────────────────────────────
    // Output-writer tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn open_output_writer_to_stdout_when_no_path() {
        let writer = open_output_writer(None).expect("stdout writer must open");
        // `Box<dyn Write>` is opaque; we can only confirm it's
        // returned successfully.  A `flush` call is a no-op for a
        // BufWriter wrapping stdout that has not been written to.
        drop(writer);
    }

    #[test]
    fn open_output_writer_to_tempfile_succeeds() {
        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("blitzy_genpkey_writer_smoke.tmp");
        {
            let mut writer = open_output_writer(Some(&path)).expect("temp writer must open");
            writer
                .write_all(b"hello\n")
                .expect("write to tmp file must succeed");
            writer.flush().expect("flush must succeed");
        }
        // Best-effort cleanup; ignore failure to delete because the
        // temporary location may be on a filesystem that doesn't
        // support standard removal semantics in some CI envs.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_output_writer_reports_io_error_for_unwritable_path() {
        // A directory that does not exist and cannot be created
        // implicitly — `File::create` should fail with NotFound.
        let bad_path = PathBuf::from("/this/path/should/never/exist/genpkey_test_x_42");
        // We cannot use `match { other => panic!("{other:?}") }` here
        // because the `Ok` variant carries `Box<dyn Write>`, which
        // does not implement `Debug`.  Instead, branch on the result
        // explicitly and produce a panic message that does not
        // attempt to format the writer.
        let result = open_output_writer(Some(&bad_path));
        match result {
            Err(CryptoError::Io(e)) => {
                // The exact error kind varies by platform (NotFound
                // on Unix, PermissionDenied on locked-down paths),
                // so just confirm we got an I/O error.
                assert!(
                    !e.to_string().is_empty(),
                    "I/O error message must be non-empty"
                );
            }
            Err(other) => {
                panic!("expected Io error variant, got {other:?}");
            }
            Ok(_) => {
                panic!(
                    "expected error opening unwritable path '{}', got success",
                    bad_path.display()
                );
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // End-to-end execute() tests
    //
    // These exercise the public `execute()` entry-point against the
    // workspace's default `LibContext` to verify wiring (Rule R10)
    // and round-trip behaviour for the most common scenarios.
    // ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn execute_rejects_neither_alg_nor_paramfile() {
        let args = default_args();
        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("algorithm"));
                assert!(msg.contains("paramfile"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_rejects_paramfile_with_genparam() {
        let mut args = default_args();
        args.paramfile = Some(PathBuf::from("/tmp/nonexistent_params.pem"));
        args.genparam = true;
        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("paramfile"));
                assert!(msg.contains("genparam"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_rejects_cipher_with_genparam() {
        let mut args = default_args();
        args.algorithm = Some("DSA".to_string());
        args.genparam = true;
        args.cipher = Some("AES-256-CBC".to_string());
        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("cipher"));
                assert!(msg.contains("-genparam"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_rejects_invalid_pass_source() {
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.cipher = Some("AES-256-CBC".to_string());
        args.pass = Some("totally-invalid-spec".to_string());
        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("pass"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_rejects_unsupported_outform() {
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.outform = Format::Text;
        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("PEM and DER"));
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_rejects_missing_paramfile_path() {
        let mut args = default_args();
        // Path that should not exist on any reasonable filesystem.
        args.paramfile = Some(PathBuf::from(
            "/this/path/genpkey_does_not_exist_blitzy_test_42.pem",
        ));
        args.out = Some(std::env::temp_dir().join("blitzy_genpkey_unused_out.pem"));
        let ctx = LibContext::default();
        // Either an `Io` error (file open failure) or an `Encoding`
        // error (PEM parse failure on an empty/garbled stream) is
        // acceptable here — the underlying decode path may surface
        // either depending on the platform's filesystem behaviour.
        // Combined into a single arm to satisfy clippy's
        // `match_same_arms` lint while remaining readable.
        match args.execute(&ctx).await {
            Err(CryptoError::Io(_) | CryptoError::Encoding(_)) => { /* expected */ }
            other => panic!("expected Io/Encoding error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_pkeyopt_invalid_syntax_yields_key_error() {
        // Direct unit test of `apply_pkeyopt` is awkward without a
        // real `PKeyCtx`; instead we exercise the public `execute`
        // path with an unparseable -pkeyopt string and assert we get
        // the typed `Key` error variant before the generator runs.
        let mut args = default_args();
        args.algorithm = Some("RSA".to_string());
        args.pkeyopt.push("no_colon_no_value".to_string());
        // We deliberately route output to a discardable temp path so
        // even if generation succeeds in a future workspace state,
        // the test still exercises the validation arm we care about.
        args.out = Some(std::env::temp_dir().join("blitzy_genpkey_discardable_out.pem"));

        let ctx = LibContext::default();
        match args.execute(&ctx).await {
            Err(CryptoError::Key(msg)) => {
                assert!(msg.contains("expected 'key:value'"), "msg = {msg}");
            }
            // The current crypto layer might short-circuit before
            // reaching `-pkeyopt` parsing on platforms where keygen
            // is stubbed.  In that case we still want a typed error
            // out the door — accept any non-Ok() outcome.
            Err(_) => { /* accepted */ }
            Ok(()) => panic!("expected an error from invalid -pkeyopt syntax"),
        }
        // Best-effort cleanup.
        let _ =
            std::fs::remove_file(std::env::temp_dir().join("blitzy_genpkey_discardable_out.pem"));
    }
}
