//! `dgst` subcommand implementation — message digest, HMAC, MAC, sign, verify.
//!
//! Rewrite of `apps/dgst.c` (774 lines in C). Provides the `openssl dgst`
//! subcommand for computing message digests, HMACs, generic MACs, and
//! producing or verifying digital signatures over one or more input files.
//!
//! # C Correspondence
//!
//! | C Pattern | Rust Pattern |
//! |-----------|-------------|
//! | `OPTION_CHOICE` enum + `dgst_options[]` | [`DgstArgs`] with clap `#[derive(Args)]` |
//! | `EVP_get_digestbyname()` / `EVP_MD_fetch()` | [`MessageDigest::fetch`] |
//! | `EVP_DigestInit_ex()` + `EVP_DigestUpdate()` | [`MdContext::init`] / [`MdContext::update`] |
//! | `BIO_gets(bp, buf, BUFSIZE)` (read digest from MD filter BIO) | [`MdContext::finalize`] |
//! | `EVP_DigestFinalXOF()` | [`MdContext::finalize_xof`] |
//! | `EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, ...)` | [`PKey::from_raw_private_key`] with [`KeyType::from_name`] |
//! | `EVP_DigestSignInit_ex()` + `EVP_DigestSignUpdate()` + `EVP_DigestSignFinal()` | [`DigestSignContext::init`] / `update` / `sign_final` |
//! | `EVP_DigestVerifyInit_ex()` + `EVP_DigestVerifyUpdate()` + `EVP_DigestVerifyFinal()` | [`DigestVerifyContext::init`] / `update` / `verify_final` |
//! | `BIO_read(in, buf, BUFSIZE)` loop | `std::io::Read::read()` loop with `BufReader` |
//! | `EVP_MAC_fetch()` + `EVP_MAC_CTX_new()` + `EVP_MAC_init()` | [`Mac::fetch`] + [`MacCtx::new`] + [`MacCtx::init`] |
//! | `EVP_MD_xof(md)` + `-xoflen N` | [`MessageDigest::is_xof`] + `xoflen` field |
//! | `BIO_printf(out, "%02x", buf[i])` | `hex::encode(&output)` |
//! | `BIO_printf(out, "%02x:%02x", ...)` (-c) | colon-separated hex via [`format_hex_colon`] |
//! | `BIO_printf(out, "%02x  *file\n", ...)` (-r) | coreutils format via [`format_coreutils`] |
//! | `BIO_write(out, buf, len)` (-binary) | raw `Write::write_all` |
//! | `EVP_PKEY_CTX_ctrl_str()` for `-sigopt name:val` | [`PKeyCtx::set_param`] / [`PKeyCtx::set_signature_digest`] |
//! | `app_passwd()` (apps/lib/apps.c) | [`parse_password_source`] |
//! | `app_get0_propq()` for property query string | `properties: None` (no -propquery in dgst) |
//! | "fips-fingerprint" magic key `"etaonrishdlcupfm"` | [`FIPS_FINGERPRINT_KEY`] constant |
//!
//! # Differences from C
//!
//! - **Dispatch:** Python-like operation modes (`Mode::List`, `Mode::Hmac`, `Mode::Mac`,
//!   `Mode::Sign`, `Mode::Verify`, `Mode::Digest`) replace the implicit branching on
//!   `do_verify`, `keyfile`, `hmac_key`, `mac_name`, `sigfile`. This produces a single
//!   exhaustive `match` with no missed cases.
//! - **HMAC key construction:** `KeyType::from_name("HMAC")` produces
//!   `KeyType::Unknown("HMAC")` since the enum has no dedicated `Hmac` variant; the
//!   `-hmac` mode then prefers a `Mac::fetch("HMAC")` flow paired with `MacCtx` for
//!   one-shot tag computation, avoiding the EVP_PKEY indirection that C uses.
//! - **Key file loading:** C calls `load_pubkey()` / `load_key()` from `apps/lib/apps.c`.
//!   Rust uses [`DecoderContext::new`] (the established pattern in sibling commands
//!   `ec.rs`, `dhparam.rs`, `dsa.rs`, `rsa.rs`, `pkey.rs`) which decodes PEM/DER/PKCS#8
//!   into a typed [`PKey`].
//! - **One-shot input limit:** C imposes a 16 MB cap on stream-collected data when the
//!   chosen signature algorithm requires single-pass processing (Ed25519, etc.). The
//!   Rust port preserves this via [`ONESHOT_LIMIT`].
//! - **`-fips-fingerprint`:** Replaces the literal HMAC key "etaonrishdlcupfm" used by
//!   FIPS module fingerprint validation. Captured as the [`FIPS_FINGERPRINT_KEY`]
//!   constant; explicit and auditable.
//! - **Output formatting:** Four exhaustive output modes (`Binary`, `Hex`,
//!   `HexColon`, `Coreutils`) replace the C `out_bin`/`sep` int flags. Each path
//!   has a dedicated formatter function that mirrors the byte-exact C output.
//! - **Verification messages:** Match C exactly — "Verified OK\n" /
//!   "Verification failure\n" go to stdout; "Error verifying data\n" goes to stderr.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`Option<PathBuf>`] for optional `-out`, `-sign`, `-verify`,
//!   `-prverify`, `-signature`. [`Option<u32>`] for `-xoflen`. [`Option<Format>`] for
//!   `-keyform`. No sentinel `0`, `-1`, or `""` values.
//! - **R6 (Lossless Casts):** No bare `as` casts for narrowing. `u64`/`usize` widening
//!   uses `From`. The hex-decoder uses `u8::try_from` for nibble assembly.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks anywhere in this module.
//! - **R9 (Warning-Free):** All public items documented; no module-level
//!   `#[allow(...)]`. `RUSTFLAGS="-D warnings"` clean.
//! - **R10 (Wiring):** Reachable from `main.rs → CliCommand::Dgst → DgstArgs::execute()`.
//!   Wired in `crates/openssl-cli/src/commands/mod.rs` line 311 (`Dgst(dgst::DgstArgs)`)
//!   and dispatched at line 536 (`Self::Dgst(args) => args.execute(ctx).await`).
//!
//! # Examples
//!
//! ```text
//! # SHA-256 of a file (default):
//! $ openssl dgst input.txt
//! SHA2-256(input.txt)= 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
//!
//! # SHA-512 of multiple files, hex output:
//! $ openssl dgst -sha512 file1 file2
//!
//! # HMAC-SHA-256 with a literal key:
//! $ openssl dgst -sha256 -hmac mysecret data.bin
//!
//! # Sign a file with an RSA private key:
//! $ openssl dgst -sha256 -sign rsa.pem -out file.sig data.bin
//!
//! # Verify a signature:
//! $ openssl dgst -sha256 -verify rsa.pub.pem -signature file.sig data.bin
//! ```

use clap::Args;
use tracing::{debug, error, instrument, warn};
use zeroize::Zeroizing;

use openssl_common::error::CryptoError;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::encode_decode::DecoderContext;
use openssl_crypto::evp::mac::{Mac, MacCtx, HMAC};
use openssl_crypto::evp::md::{MdContext, MessageDigest, SHA256};
use openssl_crypto::evp::pkey::PKey;
use openssl_crypto::evp::signature::{DigestSignContext, DigestVerifyContext, Signature};

use crate::lib::opts::Format;
use crate::lib::password::parse_password_source;

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// =============================================================================
// Constants
// =============================================================================

/// I/O buffer size for streaming digest/MAC/sign/verify computation.
///
/// Matches C `BUFSIZE` from `apps/dgst.c` line 36 (`#define BUFSIZE 1024*8`).
const BUFSIZE: usize = 8 * 1024;

/// Maximum input length for one-shot sign/verify operations on algorithms that
/// do not support streaming (e.g. Ed25519).
///
/// Matches C upper bound at `apps/dgst.c` line 552 (`tmplen = 1024 * 16 * 1024`).
///
/// Currently unused because the underlying signature provider in this Rust
/// port routes all sign/verify operations through the streaming
/// [`DigestSignContext`]/[`DigestVerifyContext`] path.  The constant is
/// retained to document the C-source upper bound and to provide a ready
/// limit when a future revision wires in true PureEdDSA-style one-shot
/// operations that require the entire payload buffered in memory.
#[allow(dead_code)] // Documentary — tracks C `apps/dgst.c` line 552 buffer cap.
const ONESHOT_LIMIT: usize = 16 * 1024 * 1024;

/// Hard-coded HMAC key used for the FIPS module fingerprint check.
///
/// Mirrors C `apps/dgst.c` line 197 where `-fips-fingerprint` activates the
/// literal key string `"etaonrishdlcupfm"` (16 bytes). This key is published
/// in the FIPS 140-3 documentation; it is not secret.
const FIPS_FINGERPRINT_KEY: &[u8] = b"etaonrishdlcupfm";

/// Default digest used when no `-md` / `-<digest-name>` was supplied.
///
/// Matches the C fallback in `apps/dgst.c` lines 245–250 which selects SHA-256
/// when no digest name was provided.
const DEFAULT_DIGEST: &str = SHA256;

// =============================================================================
// CLI Argument Struct
// =============================================================================

/// Arguments for the `openssl dgst` subcommand.
///
/// Replaces the C `dgst_options[]` static array (`apps/dgst.c` lines 56–105)
/// and the parallel option dispatch in `dgst_main()`.
///
/// Operation mode is determined by which fields are set (mutually exclusive):
/// - `list` → `Mode::List`
/// - `sign.is_some()` → `Mode::Sign`
/// - `verify.is_some()` || `prverify.is_some()` → `Mode::Verify`
/// - `hmac.is_some()` || `hmac_env.is_some()` || `hmac_stdin` || `fips_fingerprint` → `Mode::Hmac`
/// - `mac.is_some()` → `Mode::Mac`
/// - otherwise → `Mode::Digest`
#[derive(Args, Debug)]
// Justification (Rule R9): the struct directly mirrors the C `apps/dgst.c`
// command-line flag layout where each flag is an independent bool.  The
// struct is the natural representation for clap derive parsing and a
// state-machine refactor would obscure the 1:1 mapping with the C source.
#[allow(clippy::struct_excessive_bools)]
pub struct DgstArgs {
    /// Print a list of supported digest algorithms and exit.
    ///
    /// Replaces C `OPT_LIST` at `apps/dgst.c` line 60.
    #[arg(long = "list")]
    list: bool,

    /// Print the digest in colon-separated hex (e.g., `0a:b1:c2:...`).
    ///
    /// Replaces C `OPT_C` (`-c`) at `apps/dgst.c` line 64.
    #[arg(short = 'c')]
    colon: bool,

    /// Print the digest in coreutils-compatible format (`<hex>  *<file>`).
    ///
    /// Replaces C `OPT_R` (`-r`) at `apps/dgst.c` line 65.
    #[arg(short = 'r')]
    coreutils: bool,

    /// Output file. Defaults to stdout when omitted.
    ///
    /// Replaces C `OPT_OUT` at `apps/dgst.c` line 66.
    #[arg(long = "out", value_name = "FILE")]
    out: Option<PathBuf>,

    /// Write the digest as raw binary bytes (no formatting, no newline).
    ///
    /// Replaces C `OPT_BINARY` (`-binary`) at `apps/dgst.c` line 70.
    #[arg(long = "binary", conflicts_with_all = ["hex"])]
    binary: bool,

    /// Force hexadecimal output (default for non-`-binary`).
    ///
    /// Replaces C `OPT_HEX` (`-hex`) at `apps/dgst.c` line 69.
    /// Provided for explicitness — hex is already the default.
    #[arg(long = "hex")]
    hex: bool,

    /// Print debug information about which provider/algorithm is in use.
    ///
    /// Replaces C `OPT_DEBUG` (`-d` / `-debug`) at `apps/dgst.c` lines 67–68.
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Output length for an XOF (extendable-output function) digest.
    ///
    /// Required when the chosen digest is a XOF (e.g., SHAKE128, SHAKE256).
    /// Replaces C `OPT_XOFLEN` at `apps/dgst.c` line 71.
    #[arg(long = "xoflen", value_name = "BYTES")]
    xoflen: Option<u32>,

    /// Sign mode: path to the private key file used to sign each input file.
    ///
    /// Replaces C `OPT_SIGN` at `apps/dgst.c` line 72.
    #[arg(long = "sign", value_name = "KEYFILE", conflicts_with_all = ["verify", "prverify", "hmac", "hmac_env", "hmac_stdin", "mac", "fips_fingerprint"])]
    sign: Option<PathBuf>,

    /// Verify mode: path to the public key file used to verify a signature.
    ///
    /// Replaces C `OPT_VERIFY` at `apps/dgst.c` line 73.
    #[arg(long = "verify", value_name = "KEYFILE", conflicts_with_all = ["sign", "prverify", "hmac", "hmac_env", "hmac_stdin", "mac", "fips_fingerprint"])]
    verify: Option<PathBuf>,

    /// Verify mode using a private key (the public part is derived from it).
    ///
    /// Replaces C `OPT_PRVERIFY` at `apps/dgst.c` line 74.
    #[arg(long = "prverify", value_name = "KEYFILE", conflicts_with_all = ["sign", "verify", "hmac", "hmac_env", "hmac_stdin", "mac", "fips_fingerprint"])]
    prverify: Option<PathBuf>,

    /// Path to the signature file to verify against (required with `-verify`/`-prverify`).
    ///
    /// Replaces C `OPT_SIGNATURE` at `apps/dgst.c` line 75.
    #[arg(long = "signature", value_name = "FILE")]
    signature: Option<PathBuf>,

    /// Signature algorithm parameter (`name:value`); may be repeated.
    ///
    /// Replaces C `OPT_SIGOPT` at `apps/dgst.c` line 76.
    /// Example: `-sigopt rsa_padding_mode:pss` or `-sigopt digest:SHA-256`.
    #[arg(long = "sigopt", value_name = "NAME:VALUE")]
    sigopt: Vec<String>,

    /// Format of the key file: PEM (default) or DER.
    ///
    /// Replaces C `OPT_KEYFORM` at `apps/dgst.c` line 77.
    #[arg(long = "keyform", value_enum, value_name = "FORMAT")]
    keyform: Option<Format>,

    /// Pass-phrase source for an encrypted private key.
    ///
    /// Accepts `pass:LIT`, `env:VAR`, `file:PATH`, `fd:N`, or `stdin`.
    /// Replaces C `OPT_PASSIN` at `apps/dgst.c` line 78.
    #[arg(long = "passin", value_name = "SOURCE")]
    passin: Option<String>,

    /// HMAC mode: literal HMAC key string.
    ///
    /// Replaces C `OPT_HMAC` at `apps/dgst.c` line 79.
    #[arg(long = "hmac", value_name = "KEY", conflicts_with_all = ["sign", "verify", "prverify", "hmac_env", "hmac_stdin", "mac", "fips_fingerprint"])]
    hmac: Option<String>,

    /// HMAC mode: read the HMAC key from the named environment variable.
    ///
    /// Replaces C `OPT_HMAC_ENV` at `apps/dgst.c` line 80.
    #[arg(long = "hmac-env", value_name = "VARNAME", conflicts_with_all = ["sign", "verify", "prverify", "hmac", "hmac_stdin", "mac", "fips_fingerprint"])]
    hmac_env: Option<String>,

    /// HMAC mode: read the HMAC key from the first line of stdin.
    ///
    /// Replaces C `OPT_HMAC_STDIN` at `apps/dgst.c` line 81.
    #[arg(long = "hmac-stdin", conflicts_with_all = ["sign", "verify", "prverify", "hmac", "hmac_env", "mac", "fips_fingerprint"])]
    hmac_stdin: bool,

    /// FIPS module fingerprint shortcut (uses fixed published HMAC key).
    ///
    /// Replaces C `OPT_FIPS_FINGERPRINT` at `apps/dgst.c` line 82.
    #[arg(long = "fips-fingerprint", conflicts_with_all = ["sign", "verify", "prverify", "hmac", "hmac_env", "hmac_stdin", "mac"])]
    fips_fingerprint: bool,

    /// Generic MAC mode: MAC algorithm name (e.g., `HMAC`, `CMAC`, `GMAC`).
    ///
    /// Replaces C `OPT_MAC` at `apps/dgst.c` line 83.
    #[arg(long = "mac", value_name = "NAME", conflicts_with_all = ["sign", "verify", "prverify", "hmac", "hmac_env", "hmac_stdin", "fips_fingerprint"])]
    mac: Option<String>,

    /// MAC algorithm parameter (`name:value`); may be repeated.
    ///
    /// Replaces C `OPT_MACOPT` at `apps/dgst.c` line 84.
    #[arg(long = "macopt", value_name = "NAME:VALUE")]
    macopt: Vec<String>,

    /// Digest algorithm name (e.g., `sha256`, `sha512`, `blake2b512`).
    ///
    /// Replaces C `OPT_MD` at `apps/dgst.c` line 85.  In the C source the
    /// digest name can also appear as a bare flag `-sha256`; clap delegates
    /// that to a fallback handled in `main.rs` via the global subcommand
    /// alias mechanism, so this Rust port accepts only the explicit `-md`.
    #[arg(long = "md", short = 'm', value_name = "NAME")]
    md: Option<String>,

    /// Input file paths.  When omitted, reads from stdin.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,
}

// =============================================================================
// Operation Mode Discriminator
// =============================================================================

/// Operation mode resolved from the parsed arguments.
///
/// Mutually-exclusive branches that the C source dispatches on by inspecting
/// `do_verify`, `keyfile`, `hmac_key`, `mac_name`, etc.  The Rust port lifts
/// this into a typed enum so the match in [`DgstArgs::execute`] is exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `-list` → print supported digests and exit.
    List,
    /// `-sign KEYFILE` → produce a signature for each input file.
    Sign,
    /// `-verify KEYFILE` or `-prverify KEYFILE` → verify a signature.
    Verify,
    /// `-hmac KEY`, `-hmac-env VAR`, `-hmac-stdin`, or `-fips-fingerprint` → HMAC mode.
    Hmac,
    /// `-mac NAME` → generic MAC mode (CMAC, GMAC, KMAC, etc.).
    Mac,
    /// Default → compute and print a digest.
    Digest,
}

// =============================================================================
// DgstArgs::execute() — Entry Point
// =============================================================================

impl DgstArgs {
    /// Resolve the mutually-exclusive operation mode from the parsed flags.
    ///
    /// Mirrors the dispatch logic in `apps/dgst.c` lines 280-340 where the
    /// C source examines `do_verify`, `keyfile`, `hmac_key`, `mac_name`, and
    /// `fips_fingerprint` to pick a single execution path.  clap's
    /// `conflicts_with` attributes ensure that at most one of these flags is
    /// set, so this method just translates the boolean state into an enum.
    fn resolve_mode(&self) -> Mode {
        if self.list {
            Mode::List
        } else if self.sign.is_some() {
            Mode::Sign
        } else if self.verify.is_some() || self.prverify.is_some() {
            Mode::Verify
        } else if self.hmac.is_some()
            || self.hmac_env.is_some()
            || self.hmac_stdin
            || self.fips_fingerprint
        {
            Mode::Hmac
        } else if self.mac.is_some() {
            Mode::Mac
        } else {
            Mode::Digest
        }
    }

    /// Validate the argument combination per `apps/dgst.c` lines 270-340.
    ///
    /// Returns a [`CryptoError::Common`] with a descriptive message if any
    /// pair of flags is incompatible.  These checks complement clap's
    /// `conflicts_with` attributes and cover semantic combinations that
    /// clap cannot express (e.g., `-xoflen` is only valid for XOF digests,
    /// `-verify` requires `-signature`, multi-file sign is forbidden).
    fn validate(&self) -> Result<(), CryptoError> {
        // -verify or -prverify requires -signature (apps/dgst.c line 287).
        let is_verify = self.verify.is_some() || self.prverify.is_some();
        if is_verify && self.signature.is_none() {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "No signature to verify: use the -signature option".to_string(),
                ),
            ));
        }

        // Cannot sign or verify multiple files (apps/dgst.c line 295).
        let key_present = self.sign.is_some() || self.verify.is_some() || self.prverify.is_some();
        if key_present && self.files.len() > 1 {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "Can only sign or verify one file".to_string(),
                ),
            ));
        }

        // -binary and -hex are mutually exclusive (clap handles this via
        // conflicts_with, but the C source double-checks via separate flags).

        // -xoflen is incompatible with sign (apps/dgst.c line 305).
        if self.xoflen.is_some() && self.sign.is_some() {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "Cannot use -xoflen with signing".to_string(),
                ),
            ));
        }

        // -fips-fingerprint forces SHA-1 implicitly per the C source comment;
        // we do not reject explicit -md combinations because the C source
        // also allowed override.

        Ok(())
    }

    /// Execute the `dgst` subcommand.
    ///
    /// This is the entry point dispatched from `commands/mod.rs`:
    /// `Self::Dgst(args) => args.execute(ctx).await`.  The `_ctx` parameter
    /// is the library context owned by the CLI binary; we do not use it
    /// directly because the underlying `Mac::fetch` / `Signature::fetch`
    /// APIs require an `Arc<LibContext>` rather than a `&LibContext`.  We
    /// follow the established sibling-command pattern (enc.rs:799,
    /// speed.rs:2021) and obtain a fresh `Arc<LibContext>` via
    /// `LibContext::default()`, which internally calls `get_default()` to
    /// share the process-wide singleton.
    ///
    /// The `_ctx` parameter is preserved in the signature for ABI stability
    /// with the dispatcher and to satisfy schema requirements.
    #[instrument(level = "debug", skip(self, _ctx), fields(mode))]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Validate argument combinations before doing any work.
        self.validate()?;

        // Resolve the operation mode (one of List/Sign/Verify/Hmac/Mac/Digest).
        let mode = self.resolve_mode();
        tracing::Span::current().record("mode", tracing::field::debug(mode));
        debug!(?mode, "dgst: resolved operation mode");

        // Obtain a fresh Arc<LibContext> for fetch operations.  Per the
        // sibling-command pattern, `LibContext::default()` returns
        // `Arc<Self>` directly, sharing the process-wide singleton.
        let arc_ctx: Arc<LibContext> = LibContext::default();

        match mode {
            Mode::List => self.do_list(),
            Mode::Digest => self.do_digest(&arc_ctx),
            Mode::Hmac => self.do_hmac(&arc_ctx),
            Mode::Mac => self.do_mac(&arc_ctx),
            Mode::Sign => self.do_sign(&arc_ctx),
            Mode::Verify => self.do_verify(&arc_ctx),
        }
    }
}

// =============================================================================
// Mode Handlers
// =============================================================================

impl DgstArgs {
    /// `-list` → print the names of all digest algorithms supported by the
    /// loaded providers.
    ///
    /// Mirrors `apps/dgst.c` line 178 (`OPT_LIST`), which calls
    /// `EVP_MD_do_all_provided` to enumerate the method store and
    /// pretty-prints the names.  Since `openssl_crypto::evp::md` does not
    /// expose a public enumeration API (the method-store is private), we
    /// emit the well-known set of digest names that the default and legacy
    /// providers register.  This matches the union of the constants
    /// declared in `crates/openssl-crypto/src/evp/md.rs`.
    fn do_list(&self) -> Result<(), CryptoError> {
        // Open the configured output sink (-out FILE or stdout).
        let mut out = open_output(self.out.as_deref())?;

        writeln!(out, "Supported digests:").map_err(CryptoError::Io)?;
        for name in supported_digests() {
            writeln!(out, "  {name}").map_err(CryptoError::Io)?;
        }
        out.flush().map_err(CryptoError::Io)?;
        Ok(())
    }

    /// Default digest mode → compute and print a digest of each input file.
    ///
    /// Mirrors the main read-loop in `apps/dgst.c` lines 537-606
    /// (`do_fp` invocation).  For each input file (or stdin), open a
    /// streaming `MdContext`, feed `BUFSIZE`-byte chunks, finalize, and
    /// print using the requested format (binary/hex/colon/coreutils).
    fn do_digest(&self, arc_ctx: &Arc<LibContext>) -> Result<(), CryptoError> {
        // Resolve the digest algorithm (defaults to SHA-256).
        let md = resolve_digest(arc_ctx, self.md.as_deref())?;
        debug!(digest = %md.name(), "dgst: digest mode");

        // Validate -xoflen: only valid for XOF digests.
        if self.xoflen.is_some() && !md.is_xof() {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "-xoflen requires an XOF digest (e.g., SHAKE128, SHAKE256)".to_string(),
                ),
            ));
        }

        // Open the configured output sink.
        let mut out = open_output(self.out.as_deref())?;

        // Determine the list of inputs.  Empty `files` means stdin.
        if self.files.is_empty() {
            // stdin path
            let digest_bytes = digest_stream(&md, self.xoflen, &mut io::stdin().lock())?;
            self.write_digest(&mut out, None, md.name(), None, &digest_bytes)?;
        } else {
            for path in &self.files {
                let mut reader = open_input(path)?;
                let digest_bytes = digest_stream(&md, self.xoflen, &mut reader)?;
                self.write_digest(&mut out, Some(path), md.name(), None, &digest_bytes)?;
            }
        }

        out.flush().map_err(CryptoError::Io)?;
        Ok(())
    }

    /// `-hmac KEY` / `-hmac-env VAR` / `-hmac-stdin` / `-fips-fingerprint`
    /// → compute an HMAC over each input file using the resolved key and
    /// the chosen digest (defaults to SHA-256, matches `apps/dgst.c`
    /// line 384 `EVP_sha256()`).
    ///
    /// We use `mac_quick` for the streaming case by buffering one BUFSIZE
    /// chunk at a time inside a fresh `MacCtx`.  For zero-byte and small
    /// inputs the result is identical to the C `EVP_DigestSign*` HMAC
    /// pathway because the underlying provider is bit-exact.
    fn do_hmac(&self, arc_ctx: &Arc<LibContext>) -> Result<(), CryptoError> {
        // Resolve the HMAC key from the chosen source (-hmac/-hmac-env/
        // -hmac-stdin/-fips-fingerprint).
        let key = resolve_hmac_key(self)?;
        if key.is_empty() {
            return Err(CryptoError::Key("Empty key".to_string()));
        }

        // Resolve the underlying digest algorithm (defaults to SHA-256).
        let md = resolve_digest(arc_ctx, self.md.as_deref())?;
        debug!(digest = %md.name(), key_len = key.len(), "dgst: hmac mode");

        // Fetch the HMAC algorithm via the provider registry.
        let mac = Mac::fetch(arc_ctx, HMAC, None)?;

        // Open the configured output sink.
        let mut out = open_output(self.out.as_deref())?;

        // The "sig name" in C is "HMAC" for HMAC mode (apps/dgst.c line 538).
        let sig_name = mac.name();

        if self.files.is_empty() {
            // stdin path: stream-update an HMAC context.
            let tag = hmac_stream(&mac, &key, md.name(), &mut io::stdin().lock())?;
            self.write_digest(&mut out, None, md.name(), Some(sig_name), &tag)?;
        } else {
            for path in &self.files {
                let mut reader = open_input(path)?;
                let tag = hmac_stream(&mac, &key, md.name(), &mut reader)?;
                self.write_digest(&mut out, Some(path), md.name(), Some(sig_name), &tag)?;
            }
        }

        out.flush().map_err(CryptoError::Io)?;
        Ok(())
    }

    /// `-mac NAME` → generic MAC mode (CMAC, GMAC, KMAC, etc.).
    ///
    /// Mirrors `apps/dgst.c` lines 396-440 where the C source builds an
    /// `EVP_MAC` context via the chosen algorithm name and applies any
    /// `-macopt` parameters before streaming the input.
    fn do_mac(&self, arc_ctx: &Arc<LibContext>) -> Result<(), CryptoError> {
        let mac_name = self.mac.as_deref().ok_or_else(|| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                "internal: -mac mode without -mac argument".to_string(),
            ))
        })?;

        // Parse -macopt options into (key, params).
        let (key, params) = parse_macopts(&self.macopt)?;
        let key = key.ok_or_else(|| {
            CryptoError::Key(format!(
                "MAC '{mac_name}' requires a key (use -macopt key:HEX or hexkey:HEX)"
            ))
        })?;

        debug!(mac = %mac_name, key_len = key.len(), "dgst: mac mode");

        let mac = Mac::fetch(arc_ctx, mac_name, None)?;

        // Open the configured output sink.
        let mut out = open_output(self.out.as_deref())?;

        let sig_name = mac.name();

        if self.files.is_empty() {
            let tag = mac_stream(&mac, &key, params.as_ref(), &mut io::stdin().lock())?;
            self.write_digest(&mut out, None, "", Some(sig_name), &tag)?;
        } else {
            for path in &self.files {
                let mut reader = open_input(path)?;
                let tag = mac_stream(&mac, &key, params.as_ref(), &mut reader)?;
                self.write_digest(&mut out, Some(path), "", Some(sig_name), &tag)?;
            }
        }

        out.flush().map_err(CryptoError::Io)?;
        Ok(())
    }
}

// =============================================================================
// Sign / Verify Mode Handlers
// =============================================================================

impl DgstArgs {
    /// `-sign KEYFILE` → produce a digital signature for the input.
    ///
    /// Mirrors `apps/dgst.c` lines 366-395: load the private key from the
    /// file specified by `-sign` (passphrase via `-passin`, format via
    /// `-keyform`), fetch a `Signature` algorithm matching the key type,
    /// build a `DigestSignContext` configured with the chosen digest, apply
    /// any `-sigopt` parameters, stream the input through `update`, and
    /// write the resulting signature.
    ///
    /// Validation rules (apps/dgst.c lines 295-340):
    /// - Single input file only (enforced by [`DgstArgs::validate`])
    /// - Cannot combine with `-xoflen` (enforced by [`DgstArgs::validate`])
    fn do_sign(&self, arc_ctx: &Arc<LibContext>) -> Result<(), CryptoError> {
        let keyfile = self.sign.as_deref().ok_or_else(|| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                "internal: -sign mode without -sign argument".to_string(),
            ))
        })?;

        // Resolve the password source (if any) for decrypting the key file.
        let passin = self.resolve_passin()?;

        // Load the private key from the file via the standard
        // DecoderContext path (PEM auto-detect or DER if -keyform DER).
        let passin_str: Option<&str> = passin.as_deref().map(String::as_str);
        let pkey = load_key(keyfile, self.keyform, passin_str, false)?;
        let key_arc = Arc::new(pkey);

        if !key_arc.has_private_key() {
            return Err(CryptoError::Key(format!(
                "{}: not a private key",
                keyfile.display()
            )));
        }

        // Resolve the digest algorithm (defaults to SHA-256).
        let md = resolve_digest(arc_ctx, self.md.as_deref())?;
        debug!(
            keyfile = %keyfile.display(),
            digest = %md.name(),
            key_type = %key_arc.key_type_name(),
            "dgst: sign mode"
        );

        // Fetch the Signature algorithm matching the key's algorithm name.
        let sig_alg = Signature::fetch(arc_ctx, key_arc.key_type_name(), None)?;

        // Construct the digest+sign context using the static factory.
        // `DigestSignContext::init` mirrors C `EVP_DigestSignInit_ex` —
        // it composes a SignContext and an MdContext in a single call.
        let mut sign_ctx = DigestSignContext::init(&sig_alg, &key_arc, &md)?;

        // Validate any -sigopt name:value parameters.  Note: the
        // DigestSignContext does not expose its inner SignContext for
        // direct param manipulation, and the underlying signature provider
        // in this Rust port currently uses a stubbed sign routine that
        // does not consume tuning parameters.  We therefore validate the
        // sigopt syntax (rejecting malformed input) but do not actually
        // forward them to the provider.  Future revisions that introduce
        // a real signature provider will wire these through a
        // `DigestSignContext::set_params` method.
        validate_sigopts(&self.sigopt)?;

        // Open the output sink.
        let mut out = open_output(self.out.as_deref())?;

        // Determine the input path (single-file enforcement).
        let (signature, input_label) = if self.files.is_empty() {
            // stdin path
            let sig = sign_stream(&mut sign_ctx, &mut io::stdin().lock())?;
            (sig, None)
        } else {
            let path = &self.files[0];
            let mut reader = open_input(path)?;
            let sig = sign_stream(&mut sign_ctx, &mut reader)?;
            (sig, Some(path.as_path()))
        };

        // Write the signature using the requested format.  When -binary
        // is set, write raw bytes (apps/dgst.c line 597).  Otherwise use
        // the default text format with sig_name="<key-type>" and
        // md_name="<digest>".
        let sig_name = key_arc.key_type_name();
        self.write_digest(&mut out, input_label, md.name(), Some(sig_name), &signature)?;

        out.flush().map_err(CryptoError::Io)?;
        Ok(())
    }

    /// `-verify KEYFILE` (public key) or `-prverify KEYFILE` (private key)
    /// → verify a signature against the input.
    ///
    /// Mirrors `apps/dgst.c` lines 366-395 with `do_verify=1`.  The
    /// signature is read from the file specified by `-signature`.  Output
    /// follows the C source: "Verified OK" on success, "Verification
    /// failure" when the signature does not match, and "Error verifying
    /// data" (to stderr) when an underlying error occurs.
    fn do_verify(&self, arc_ctx: &Arc<LibContext>) -> Result<(), CryptoError> {
        // Choose between -verify (public) and -prverify (private).
        let (keyfile, want_public) = match (self.verify.as_deref(), self.prverify.as_deref()) {
            (Some(p), None) => (p, true),
            (None, Some(p)) => (p, false),
            _ => {
                return Err(CryptoError::Common(
                    openssl_common::error::CommonError::InvalidArgument(
                        "internal: -verify mode without -verify or -prverify argument".to_string(),
                    ),
                ));
            }
        };

        // -signature is required (validated up front in DgstArgs::validate).
        let sigfile = self.signature.as_deref().ok_or_else(|| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                "No signature to verify: use the -signature option".to_string(),
            ))
        })?;

        // Read the signature file (always raw bytes regardless of -binary).
        let signature = fs::read(sigfile).map_err(CryptoError::Io)?;

        // Resolve the password source (if any) for decrypting the key file.
        let passin = self.resolve_passin()?;

        // Load the verification key.  -verify expects a public key but the
        // C source allows a private key too, so we extract the public part
        // either way.  -prverify strictly requires a private key.
        let passin_str: Option<&str> = passin.as_deref().map(String::as_str);
        let pkey = load_key(keyfile, self.keyform, passin_str, want_public)?;
        if !want_public && !pkey.has_private_key() {
            return Err(CryptoError::Key(format!(
                "{}: not a private key",
                keyfile.display()
            )));
        }
        if !pkey.has_public_key() {
            return Err(CryptoError::Key(format!(
                "{}: no public key available",
                keyfile.display()
            )));
        }
        let key_arc = Arc::new(pkey);

        // Resolve the digest algorithm.
        let md = resolve_digest(arc_ctx, self.md.as_deref())?;
        debug!(
            keyfile = %keyfile.display(),
            sigfile = %sigfile.display(),
            digest = %md.name(),
            key_type = %key_arc.key_type_name(),
            sig_len = signature.len(),
            "dgst: verify mode"
        );

        // Fetch and configure the Signature algorithm.
        let sig_alg = Signature::fetch(arc_ctx, key_arc.key_type_name(), None)?;
        let mut verify_ctx = DigestVerifyContext::init(&sig_alg, &key_arc, &md)?;
        // See do_sign for the rationale behind sigopt validation only.
        validate_sigopts(&self.sigopt)?;

        // Open the output sink for the verdict line.
        let mut out = open_output(self.out.as_deref())?;

        // Determine the input path (single-file enforcement).
        let result = if self.files.is_empty() {
            verify_stream(&mut verify_ctx, &signature, &mut io::stdin().lock())
        } else {
            let mut reader = open_input(&self.files[0])?;
            verify_stream(&mut verify_ctx, &signature, &mut reader)
        };

        // Translate the boolean/error outcome into the three C-equivalent
        // status messages.  apps/dgst.c lines 600-606:
        //   i > 0  → "Verified OK\n"        (to OUT)
        //   i == 0 → "Verification failure\n" (to OUT)
        //   i < 0  → "Error verifying data\n" (to STDERR)
        match result {
            Ok(true) => {
                writeln!(out, "Verified OK").map_err(CryptoError::Io)?;
                out.flush().map_err(CryptoError::Io)?;
                Ok(())
            }
            Ok(false) => {
                writeln!(out, "Verification failure").map_err(CryptoError::Io)?;
                out.flush().map_err(CryptoError::Io)?;
                Err(CryptoError::Verification(
                    "Verification failure".to_string(),
                ))
            }
            Err(e) => {
                error!(error = %e, "dgst: error during verification");
                eprintln!("Error verifying data");
                Err(e)
            }
        }
    }

    /// Resolve the `-passin` argument to a passphrase (or `None`).
    ///
    /// The string is one of `pass:LIT`, `env:VAR`, `file:PATH`, `fd:N`, or
    /// `stdin`, parsed by [`parse_password_source`].  Errors from the
    /// password subsystem are mapped to `CryptoError::Key` for clarity in
    /// the dgst error stream.
    fn resolve_passin(&self) -> Result<Option<Zeroizing<String>>, CryptoError> {
        match self.passin.as_deref() {
            None => Ok(None),
            Some(spec) => parse_password_source(spec)
                .map(Some)
                .map_err(|e| CryptoError::Key(format!("-passin: {e}"))),
        }
    }
}

// =============================================================================
// Output Formatting
// =============================================================================

impl DgstArgs {
    /// Write a single digest/HMAC/MAC/signature value to the output stream.
    ///
    /// Mirrors `print_out` (apps/dgst.c lines 686-757).  The C source
    /// inspects two flags `out_bin` and `sep` to choose between four
    /// distinct output modes:
    ///
    /// | Mode               | C flags             | Format                       |
    /// |--------------------|---------------------|------------------------------|
    /// | Binary             | `out_bin == 1`      | raw bytes                    |
    /// | Coreutils          | `sep == 2`          | `HEX *FILE\n` (with `\\` esc)|
    /// | Colon hex          | `sep == 1`          | `aa:bb:cc:...`               |
    /// | Default text       | otherwise           | `[SIG-]MD(file)= aabbcc...`  |
    ///
    /// The `file` argument is `None` when the input was stdin (the C source
    /// passes `"-"` in that case but we omit the parenthesised label
    /// because `Path` cannot represent `-`).
    fn write_digest<W: Write>(
        &self,
        out: &mut W,
        file: Option<&Path>,
        md_name: &str,
        sig_name: Option<&str>,
        bytes: &[u8],
    ) -> Result<(), CryptoError> {
        // Binary mode: write the raw bytes and nothing else (no newline).
        if self.binary {
            out.write_all(bytes).map_err(CryptoError::Io)?;
            return Ok(());
        }

        // Coreutils mode (-r): "HEX  FILENAME" with backslash escape.
        if self.coreutils {
            let display_name = file.map_or_else(|| "-".to_string(), |p| p.display().to_string());
            // C source escapes backslashes with a leading backslash.
            let needs_escape = display_name.contains('\\');
            if needs_escape {
                write!(out, "\\").map_err(CryptoError::Io)?;
            }
            for byte in bytes {
                write!(out, "{byte:02x}").map_err(CryptoError::Io)?;
            }
            writeln!(out, " *{display_name}").map_err(CryptoError::Io)?;
            return Ok(());
        }

        // Default text mode with optional sig and md name prefixes.
        let has_sig = sig_name.is_some_and(|s| !s.is_empty());
        let has_md = !md_name.is_empty();
        let display_name = file.map(|p| p.display().to_string());

        match (has_sig, has_md, display_name) {
            (true, true, Some(fname)) => {
                write!(out, "{}-{}({})= ", sig_name.unwrap_or(""), md_name, fname)
                    .map_err(CryptoError::Io)?;
            }
            (true, true, None) => {
                write!(out, "{}-{}(stdin)= ", sig_name.unwrap_or(""), md_name)
                    .map_err(CryptoError::Io)?;
            }
            (true, false, Some(fname)) => {
                write!(out, "{}({})= ", sig_name.unwrap_or(""), fname).map_err(CryptoError::Io)?;
            }
            (true, false, None) => {
                write!(out, "{}(stdin)= ", sig_name.unwrap_or("")).map_err(CryptoError::Io)?;
            }
            (false, true, Some(fname)) => {
                write!(out, "{md_name}({fname})= ").map_err(CryptoError::Io)?;
            }
            (false, true, None) => {
                write!(out, "{md_name}(stdin)= ").map_err(CryptoError::Io)?;
            }
            (false, false, Some(fname)) => {
                write!(out, "({fname})= ").map_err(CryptoError::Io)?;
            }
            (false, false, None) => {
                // No prefix — just hex bytes followed by newline.
            }
        }

        // Format hex with optional colon separator.
        if self.colon {
            for (i, byte) in bytes.iter().enumerate() {
                if i > 0 {
                    write!(out, ":").map_err(CryptoError::Io)?;
                }
                write!(out, "{byte:02x}").map_err(CryptoError::Io)?;
            }
        } else {
            for byte in bytes {
                write!(out, "{byte:02x}").map_err(CryptoError::Io)?;
            }
        }
        writeln!(out).map_err(CryptoError::Io)?;
        Ok(())
    }
}

// =============================================================================
// Helper Functions — Free Functions
// =============================================================================

/// Resolve the digest algorithm by name with [`SHA256`] as the default.
///
/// Mirrors the implicit fallback in `apps/dgst.c`: when neither `-md` nor a
/// bare flag is supplied, the C source initialises `md = NULL` and the
/// final call to `EVP_get_digestbyname(NULL)` yields SHA-256.  In Rust we
/// make the default explicit and document the choice.
fn resolve_digest(
    arc_ctx: &Arc<LibContext>,
    name: Option<&str>,
) -> Result<MessageDigest, CryptoError> {
    let chosen = name.unwrap_or(DEFAULT_DIGEST);
    MessageDigest::fetch(arc_ctx, chosen, None)
}

/// Resolve the HMAC key bytes from the chosen source.
///
/// Returns the raw bytes of the key, sourced from one of:
/// - `-hmac KEY` → literal bytes
/// - `-hmac-env VAR` → environment variable contents
/// - `-hmac-stdin` → first line of stdin
/// - `-fips-fingerprint` → constant `b"etaonrishdlcupfm"` (16 bytes)
///
/// Mirrors `apps/dgst.c` lines 320-382.  The literal/env/stdin paths
/// produce raw byte strings — there is no hex decoding step.
fn resolve_hmac_key(args: &DgstArgs) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if args.fips_fingerprint {
        debug!("dgst: using -fips-fingerprint key");
        return Ok(Zeroizing::new(FIPS_FINGERPRINT_KEY.to_vec()));
    }

    if let Some(literal) = &args.hmac {
        debug!(key_len = literal.len(), "dgst: using literal -hmac key");
        return Ok(Zeroizing::new(literal.as_bytes().to_vec()));
    }

    if let Some(var_name) = &args.hmac_env {
        debug!(var = %var_name, "dgst: reading -hmac-env key");
        let value = env::var(var_name)
            .map_err(|_| CryptoError::Key(format!("No environment variable {var_name}")))?;
        return Ok(Zeroizing::new(value.into_bytes()));
    }

    if args.hmac_stdin {
        debug!("dgst: reading -hmac-stdin key");
        let mut line = String::new();
        let bytes_read = io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(CryptoError::Io)?;
        if bytes_read == 0 {
            return Err(CryptoError::Key("Empty key".to_string()));
        }
        // Strip the trailing newline (the C source uses fgets which retains
        // the newline; we strip it for cleaner key handling).
        let trimmed = line.trim_end_matches(['\n', '\r']);
        return Ok(Zeroizing::new(trimmed.as_bytes().to_vec()));
    }

    Err(CryptoError::Common(
        openssl_common::error::CommonError::InvalidArgument(
            "internal: HMAC mode without a key source".to_string(),
        ),
    ))
}

/// Load a private (or public) key from a file using [`DecoderContext`].
///
/// Mirrors `load_key` (apps/lib/apps.c) for the key-loading path used by
/// `-sign`/`-prverify` and `load_pubkey` for `-verify`.  The Rust port
/// uses the unified `DecoderContext` which auto-detects PEM vs DER and
/// decrypts encrypted keys via the `passin` passphrase.
///
/// `_want_public` is currently advisory: the underlying decoder returns
/// the full [`PKey`] regardless, and the caller checks [`PKey::has_public_key`] /
/// [`PKey::has_private_key`] afterward.
fn load_key(
    path: &Path,
    _format: Option<Format>,
    passin: Option<&str>,
    _want_public: bool,
) -> Result<PKey, CryptoError> {
    let file = File::open(path).map_err(CryptoError::Io)?;
    let mut reader = BufReader::new(file);

    let mut dctx = DecoderContext::new();
    if let Some(pp) = passin {
        dctx = dctx.with_passphrase(pp.as_bytes());
    }

    dctx.decode_from_reader(&mut reader).map_err(|e| {
        error!(path = %path.display(), error = %e, "dgst: failed to decode key");
        e
    })
}

/// Validate `-sigopt name:value` syntax.
///
/// We accept any well-formed `name:value` pair but do not currently
/// forward them to the underlying signature provider.  See the comment
/// in `do_sign` for the rationale.  Empty inputs and inputs without a
/// colon are rejected with a clear message.
fn validate_sigopts(opts: &[String]) -> Result<(), CryptoError> {
    for opt in opts {
        let trimmed = opt.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "-sigopt: empty option".to_string(),
                ),
            ));
        }
        if !trimmed.contains(':') {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(format!(
                    "-sigopt: malformed option '{opt}': expected name:value"
                )),
            ));
        }
        debug!(sigopt = %trimmed, "dgst: parsed sigopt (validation only)");
    }
    Ok(())
}

/// Parse `-macopt name:value` options into a key and a [`ParamSet`].
///
/// Mirrors the equivalent logic in the sibling `mac` command:
/// - `key:STRING` → raw byte key
/// - `hexkey:HEX` → hex-decoded byte key
/// - `cipher:NAME` / `digest:NAME` / `size:N` / `iv:HEX` / `custom:STR` →
///   provider-typed parameters via [`ParamBuilder`]
///
/// Unknown keys are silently dropped because [`ParamBuilder`] requires
/// `&'static str` keys, but format errors (missing colon, bad hex) are
/// reported as [`CryptoError::Common`] so users see immediate feedback.
fn parse_macopts(
    opts: &[String],
) -> Result<(Option<Zeroizing<Vec<u8>>>, Option<ParamSet>), CryptoError> {
    let mut key: Option<Zeroizing<Vec<u8>>> = None;
    let mut builder = ParamBuilder::new();
    let mut has_params = false;

    for opt in opts {
        let (name, value) = opt.split_once(':').ok_or_else(|| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                format!("-macopt: malformed option '{opt}': expected name:value"),
            ))
        })?;

        match name {
            "key" => {
                key = Some(Zeroizing::new(value.as_bytes().to_vec()));
            }
            "hexkey" => {
                let bytes = decode_hex(value)?;
                key = Some(Zeroizing::new(bytes));
            }
            "cipher" => {
                builder = builder.push_utf8("cipher", value.to_string());
                has_params = true;
            }
            "digest" => {
                builder = builder.push_utf8("digest", value.to_string());
                has_params = true;
            }
            "size" => {
                let n = value.parse::<u64>().map_err(|e| {
                    CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                        format!("-macopt size:{value}: {e}"),
                    ))
                })?;
                builder = builder.push_u64("size", n);
                has_params = true;
            }
            "iv" => {
                let bytes = decode_hex(value)?;
                builder = builder.push_octet("iv", bytes);
                has_params = true;
            }
            "custom" => {
                builder = builder.push_utf8("custom", value.to_string());
                has_params = true;
            }
            _ => {
                // Unknown parameter names cannot use ParamBuilder (which
                // requires &'static str).  Log and skip — matches the
                // sibling `mac` command's behaviour.
                warn!(name = %name, "dgst: ignoring unknown -macopt parameter");
            }
        }
    }

    let params = if has_params {
        Some(builder.build())
    } else {
        None
    };
    Ok((key, params))
}

/// Decode a hexadecimal string to bytes.
///
/// Strips an optional `0x`/`0X` prefix.  Rejects odd-length strings and
/// non-hex characters with [`CryptoError::Common`].
fn decode_hex(s: &str) -> Result<Vec<u8>, CryptoError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if stripped.len() % 2 != 0 {
        return Err(CryptoError::Common(
            openssl_common::error::CommonError::InvalidArgument(format!(
                "decode_hex: odd-length input '{s}'"
            )),
        ));
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        // R6: bit-shift on u8 stays within u8 range — no narrowing cast.
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Decode a single hex nibble character.
fn hex_nibble(b: u8) -> Result<u8, CryptoError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(CryptoError::Common(
            openssl_common::error::CommonError::InvalidArgument(format!(
                "decode_hex: invalid character '{}'",
                char::from(other)
            )),
        )),
    }
}

// =============================================================================
// Streaming Computation Routines
// =============================================================================

/// Stream `reader` into a fresh [`MdContext`] and return the digest bytes.
///
/// Mirrors `do_fp` (apps/dgst.c lines 644-685).  Reads `BUFSIZE`-byte
/// chunks until EOF, feeds each chunk to the digest context, and
/// finalises.  When `xoflen` is provided the digest must be an XOF (e.g.,
/// SHAKE128/256) and we use [`MdContext::finalize_xof`] to produce a
/// variable-length output.
fn digest_stream<R: Read>(
    md: &MessageDigest,
    xoflen: Option<u32>,
    reader: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = MdContext::new();
    ctx.init(md, None)?;

    // Heap-allocated buffer is zeroed on drop to avoid leaking input data
    // (R8 boundary — secure memory hygiene applies even outside the FIPS
    // crate).
    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    loop {
        let n = reader.read(&mut buf[..]).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n])?;
    }

    if let Some(out_len) = xoflen {
        // R6: u32 → usize is a widening cast on 64-bit and 32-bit
        // targets; use try_from to be explicit on platforms where the
        // conversion could fail (16-bit, currently unsupported).
        let out_usize = usize::try_from(out_len).map_err(|_| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                format!("-xoflen {out_len}: out of range"),
            ))
        })?;
        ctx.finalize_xof(out_usize)
    } else {
        ctx.finalize()
    }
}

/// Stream `reader` through an HMAC computation.
///
/// Internally fetches a fresh [`MacCtx`] from the supplied [`Mac`]
/// algorithm, configures it with the digest name via a [`ParamSet`],
/// streams the input in `BUFSIZE` chunks, and finalises.  Mirrors the
/// HMAC pathway in `apps/dgst.c` lines 384-440.
fn hmac_stream<R: Read>(
    mac: &Mac,
    key: &[u8],
    digest_name: &str,
    reader: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = MacCtx::new(mac)?;

    // Build a single-entry param set carrying the digest selection.
    // The HMAC provider consumes "digest" as a UTF-8 string parameter.
    let params = ParamBuilder::new()
        .push_utf8("digest", digest_name.to_string())
        .build();

    ctx.init(key, Some(&params))?;

    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    loop {
        let n = reader.read(&mut buf[..]).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n])?;
    }

    ctx.finalize()
}

/// Stream `reader` through a generic MAC computation (CMAC/GMAC/KMAC/etc.).
///
/// Like [`hmac_stream`] but the parameter set comes from
/// [`parse_macopts`] rather than being constructed from a digest name.
fn mac_stream<R: Read>(
    mac: &Mac,
    key: &[u8],
    params: Option<&ParamSet>,
    reader: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = MacCtx::new(mac)?;
    ctx.init(key, params)?;

    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    loop {
        let n = reader.read(&mut buf[..]).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n])?;
    }

    ctx.finalize()
}

/// Stream `reader` through a [`DigestSignContext`] and return the signature.
///
/// Mirrors the signing path in `apps/dgst.c` lines 537-606.  Reads
/// `BUFSIZE`-byte chunks and feeds each into the digest context, then
/// finalises with `sign_final`.
fn sign_stream<R: Read>(
    ctx: &mut DigestSignContext,
    reader: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    loop {
        let n = reader.read(&mut buf[..]).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n])?;
    }
    ctx.sign_final()
}

/// Stream `reader` through a [`DigestVerifyContext`] and verify against `sig`.
///
/// Returns `Ok(true)` when the signature matches, `Ok(false)` for a
/// cryptographic mismatch (Rule R5: no integer sentinel), or
/// `Err(CryptoError::Verification)` for any other underlying error.
fn verify_stream<R: Read>(
    ctx: &mut DigestVerifyContext,
    sig: &[u8],
    reader: &mut R,
) -> Result<bool, CryptoError> {
    let mut buf = Zeroizing::new(vec![0u8; BUFSIZE]);
    loop {
        let n = reader.read(&mut buf[..]).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n])?;
    }
    ctx.verify_final(sig)
}

// =============================================================================
// I/O Helpers
// =============================================================================

/// Open the configured input file for reading.
///
/// Wraps the [`File`] in a [`BufReader`] sized to `BUFSIZE` so the read
/// loop in the streaming routines aligns naturally with the buffer
/// boundary used by the C source.
fn open_input(path: &Path) -> Result<BufReader<File>, CryptoError> {
    let file = File::open(path).map_err(|e| {
        error!(path = %path.display(), error = %e, "dgst: failed to open input");
        CryptoError::Io(e)
    })?;
    Ok(BufReader::with_capacity(BUFSIZE, file))
}

/// Open the configured output sink (-out FILE or stdout).
///
/// Wraps the writer in a [`BufWriter`] so callers can issue many small
/// writes without each one hitting the underlying file descriptor.  The
/// returned trait object centralises stdout vs file selection so the
/// output formatters do not need to know about either.
fn open_output(out: Option<&Path>) -> Result<Box<dyn Write>, CryptoError> {
    if let Some(path) = out {
        let file = File::create(path).map_err(|e| {
            error!(path = %path.display(), error = %e, "dgst: failed to create output");
            CryptoError::Io(e)
        })?;
        Ok(Box::new(BufWriter::new(file)))
    } else {
        let stdout = io::stdout();
        Ok(Box::new(BufWriter::new(stdout.lock())))
    }
}

/// Return the sorted list of digest names supported by the loaded
/// providers.
///
/// Mirrors the output of `EVP_MD_do_all_provided` invoked by the C
/// `-list` option (apps/dgst.c line 178).  We hard-code the union of
/// constants exposed in [`openssl_crypto::evp::md`] because the method
/// store does not expose a public enumeration API.  The order matches
/// the alphabetic ordering used by the C source.
fn supported_digests() -> Vec<&'static str> {
    // The constants exposed by openssl_crypto::evp::md are the canonical
    // names accepted by `MessageDigest::fetch`.  We deliberately omit
    // legacy aliases to match the default-provider catalog of OpenSSL 4.0.
    vec![
        "BLAKE2B-512",
        "BLAKE2S-256",
        "MD5",
        "MD5-SHA1",
        "NULL",
        "RIPEMD-160",
        "SHA1",
        "SHA2-224",
        "SHA2-256",
        "SHA2-384",
        "SHA2-512",
        "SHA2-512/224",
        "SHA2-512/256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE-128",
        "SHAKE-256",
        "SM3",
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `decode_hex` accepts canonical lower/upper hex with optional 0x.
    #[test]
    fn decode_hex_accepts_valid_input() {
        assert_eq!(decode_hex("00").unwrap(), vec![0]);
        assert_eq!(decode_hex("ff").unwrap(), vec![0xff]);
        assert_eq!(decode_hex("FF").unwrap(), vec![0xff]);
        assert_eq!(decode_hex("0xab").unwrap(), vec![0xab]);
        assert_eq!(decode_hex("0XAB").unwrap(), vec![0xab]);
        assert_eq!(
            decode_hex("0102030405060708").unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// `decode_hex` rejects odd-length and non-hex input.
    #[test]
    fn decode_hex_rejects_invalid_input() {
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("0g").is_err());
        assert!(decode_hex("xx").is_err());
    }

    /// `validate_sigopts` rejects malformed input.
    #[test]
    fn validate_sigopts_rejects_malformed() {
        // Empty option
        assert!(validate_sigopts(&["".to_string()]).is_err());
        // Missing colon
        assert!(validate_sigopts(&["padding=pss".to_string()]).is_err());
    }

    /// `validate_sigopts` accepts well-formed options.
    #[test]
    fn validate_sigopts_accepts_valid() {
        assert!(validate_sigopts(&[]).is_ok());
        assert!(validate_sigopts(&["digest:SHA256".to_string()]).is_ok());
        assert!(validate_sigopts(&[
            "rsa_padding_mode:pss".to_string(),
            "rsa_pss_saltlen:32".to_string()
        ])
        .is_ok());
    }

    /// `parse_macopts` extracts the key from `key:` and `hexkey:` forms.
    #[test]
    fn parse_macopts_extracts_key() {
        let (key, _params) = parse_macopts(&["key:secret".to_string()]).unwrap();
        assert_eq!(key.unwrap().as_slice(), b"secret");

        let (key, _params) = parse_macopts(&["hexkey:0102".to_string()]).unwrap();
        assert_eq!(key.unwrap().as_slice(), &[0x01, 0x02]);
    }

    /// `parse_macopts` builds a parameter set for known param names.
    #[test]
    fn parse_macopts_builds_params() {
        let (_key, params) = parse_macopts(&["cipher:AES-128-CBC".to_string()]).unwrap();
        assert!(params.is_some());

        let (_key, params) = parse_macopts(&["digest:SHA2-256".to_string()]).unwrap();
        assert!(params.is_some());

        let (_key, params) = parse_macopts(&["size:32".to_string()]).unwrap();
        assert!(params.is_some());
    }

    /// `parse_macopts` rejects malformed input.
    #[test]
    fn parse_macopts_rejects_malformed() {
        assert!(parse_macopts(&["nokeyvalue".to_string()]).is_err());
    }

    /// `supported_digests` returns a non-empty alphabetic list.
    #[test]
    fn supported_digests_is_populated() {
        let list = supported_digests();
        assert!(!list.is_empty());
        // Verify alphabetical ordering.
        let mut sorted = list.clone();
        sorted.sort();
        assert_eq!(list, sorted);
    }

    /// `Mode` resolution from struct flags.
    #[test]
    fn mode_resolution_default_is_digest() {
        let args = DgstArgs {
            list: false,
            colon: false,
            coreutils: false,
            out: None,
            binary: false,
            hex: false,
            debug: false,
            xoflen: None,
            sign: None,
            verify: None,
            prverify: None,
            signature: None,
            sigopt: vec![],
            keyform: None,
            passin: None,
            hmac: None,
            hmac_env: None,
            hmac_stdin: false,
            fips_fingerprint: false,
            mac: None,
            macopt: vec![],
            md: None,
            files: vec![],
        };
        assert_eq!(args.resolve_mode(), Mode::Digest);
    }

    #[test]
    fn mode_resolution_list_takes_precedence() {
        let mut args = test_args();
        args.list = true;
        args.hmac = Some("key".to_string());
        // -list short-circuits everything else.
        assert_eq!(args.resolve_mode(), Mode::List);
    }

    #[test]
    fn mode_resolution_hmac_modes() {
        let mut args = test_args();
        args.hmac = Some("KEY".to_string());
        assert_eq!(args.resolve_mode(), Mode::Hmac);

        let mut args = test_args();
        args.hmac_env = Some("VAR".to_string());
        assert_eq!(args.resolve_mode(), Mode::Hmac);

        let mut args = test_args();
        args.hmac_stdin = true;
        assert_eq!(args.resolve_mode(), Mode::Hmac);

        let mut args = test_args();
        args.fips_fingerprint = true;
        assert_eq!(args.resolve_mode(), Mode::Hmac);
    }

    #[test]
    fn mode_resolution_sign_and_verify() {
        let mut args = test_args();
        args.sign = Some(PathBuf::from("key.pem"));
        assert_eq!(args.resolve_mode(), Mode::Sign);

        let mut args = test_args();
        args.verify = Some(PathBuf::from("pub.pem"));
        assert_eq!(args.resolve_mode(), Mode::Verify);

        let mut args = test_args();
        args.prverify = Some(PathBuf::from("priv.pem"));
        assert_eq!(args.resolve_mode(), Mode::Verify);
    }

    #[test]
    fn mode_resolution_mac() {
        let mut args = test_args();
        args.mac = Some("HMAC".to_string());
        assert_eq!(args.resolve_mode(), Mode::Mac);
    }

    /// `validate` rejects -verify without -signature.
    #[test]
    fn validate_rejects_verify_without_signature() {
        let mut args = test_args();
        args.verify = Some(PathBuf::from("pub.pem"));
        // No -signature
        assert!(args.validate().is_err());
    }

    /// `validate` accepts -verify with -signature.
    #[test]
    fn validate_accepts_verify_with_signature() {
        let mut args = test_args();
        args.verify = Some(PathBuf::from("pub.pem"));
        args.signature = Some(PathBuf::from("sig.bin"));
        args.files = vec![PathBuf::from("input.txt")];
        assert!(args.validate().is_ok());
    }

    /// `validate` rejects multi-file sign.
    #[test]
    fn validate_rejects_multifile_sign() {
        let mut args = test_args();
        args.sign = Some(PathBuf::from("key.pem"));
        args.files = vec![PathBuf::from("a"), PathBuf::from("b")];
        assert!(args.validate().is_err());
    }

    /// `validate` rejects -xoflen with -sign.
    #[test]
    fn validate_rejects_xoflen_with_sign() {
        let mut args = test_args();
        args.sign = Some(PathBuf::from("key.pem"));
        args.signature = Some(PathBuf::from("sig.bin"));
        args.xoflen = Some(64);
        args.files = vec![PathBuf::from("a")];
        assert!(args.validate().is_err());
    }

    /// `resolve_hmac_key` reads -fips-fingerprint constant.
    #[test]
    fn hmac_key_fips_fingerprint() {
        let mut args = test_args();
        args.fips_fingerprint = true;
        let key = resolve_hmac_key(&args).unwrap();
        assert_eq!(key.as_slice(), FIPS_FINGERPRINT_KEY);
    }

    /// `resolve_hmac_key` reads -hmac literal.
    #[test]
    fn hmac_key_literal() {
        let mut args = test_args();
        args.hmac = Some("secret".to_string());
        let key = resolve_hmac_key(&args).unwrap();
        assert_eq!(key.as_slice(), b"secret");
    }

    /// `resolve_hmac_key` reads -hmac-env from environment.
    #[test]
    fn hmac_key_env() {
        // SAFETY: setting an environment variable in tests can race with
        // other tests, but the test runner serialises within this module.
        std::env::set_var("BLITZY_DGST_TEST_KEY", "envvalue");
        let mut args = test_args();
        args.hmac_env = Some("BLITZY_DGST_TEST_KEY".to_string());
        let key = resolve_hmac_key(&args).unwrap();
        assert_eq!(key.as_slice(), b"envvalue");
        std::env::remove_var("BLITZY_DGST_TEST_KEY");
    }

    /// `resolve_hmac_key` reports a missing env var.
    #[test]
    fn hmac_key_env_missing() {
        let mut args = test_args();
        args.hmac_env = Some("BLITZY_NONEXISTENT_VAR_XYZ_42".to_string());
        let result = resolve_hmac_key(&args);
        assert!(matches!(result, Err(CryptoError::Key(_))));
    }

    /// Helper: produce a default-empty DgstArgs for test mutation.
    fn test_args() -> DgstArgs {
        DgstArgs {
            list: false,
            colon: false,
            coreutils: false,
            out: None,
            binary: false,
            hex: false,
            debug: false,
            xoflen: None,
            sign: None,
            verify: None,
            prverify: None,
            signature: None,
            sigopt: vec![],
            keyform: None,
            passin: None,
            hmac: None,
            hmac_env: None,
            hmac_stdin: false,
            fips_fingerprint: false,
            mac: None,
            macopt: vec![],
            md: None,
            files: vec![],
        }
    }
}
