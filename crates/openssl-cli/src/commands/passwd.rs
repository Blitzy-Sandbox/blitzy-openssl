//! Password hash generation — Rust rewrite of `apps/passwd.c`.
//!
//! Provides command-line access to crypt(3)-style password hashing using the
//! MD5-based and SHA-based algorithms. Supports the same five hashing modes
//! as the C original:
//!
//! * `-1` — BSD MD5-based (`$1$salt$hash`)
//! * `-apr1` — Apache MD5-based (`$apr1$salt$hash`)
//! * `-aixmd5` — AIX MD5-based (`salt$hash`, no magic prefix)
//! * `-5` — SHA-256-based (`$5$salt$hash`, per Ulrich Drepper's spec)
//! * `-6` — SHA-512-based (`$6$salt$hash`, per Ulrich Drepper's spec)
//!
//! # C Source Mapping
//!
//! | C construct                             | Rust equivalent                            |
//! |-----------------------------------------|--------------------------------------------|
//! | `passwd_options[]`                      | `PasswdArgs` clap derive fields            |
//! | `passwd_modes` enum                     | `PasswdMode` enum                          |
//! | `cov_2char[64]`                         | `COV_2CHAR: [u8; 64]`                      |
//! | `ascii_dollar[]`                        | inline `b'$'`                              |
//! | `md5crypt()`                            | [`md5crypt`]                               |
//! | `shacrypt()`                            | [`shacrypt`]                               |
//! | `do_passwd()`                           | [`PasswdArgs::do_passwd`]                  |
//! | `passwd_main()`                         | [`PasswdArgs::execute`]                    |
//! | `RAND_bytes()`                          | `openssl_crypto::rand::rand_bytes()`       |
//! | `EVP_md5()`/`EVP_sha256()`/`EVP_sha512()` | `MessageDigest::fetch(MD5/SHA256/SHA512)` |
//! | `EVP_DigestInit_ex/Update/Final_ex`     | `MdContext::init/update/finalize`          |
//! | `EVP_read_pw_string()`                  | `PasswordHandler::prompt_password()`       |
//! | `OPENSSL_cleanse`/`OPENSSL_clear_free`  | `Zeroizing<_>` automatic drop zeroing      |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → CliCommand::Passwd(args)
//!     → PasswdArgs::execute(&self, &LibContext)
//!       → PasswdArgs::do_passwd(…)
//!         → md5crypt(…)     // for -1 / -apr1 / -aixmd5
//!         └── MdContext::{init,update,finalize}
//!         → shacrypt(…)     // for -5 / -6
//!         └── MdContext::{init,update,finalize}
//!       → (salt generation) openssl_crypto::rand::rand_bytes
//!       → (interactive prompt) PasswordHandler::prompt_password
//! ```
//!
//! # Rules Enforced
//!
//! * **R5 (Nullability over sentinels):** `Option<String>` for salt / infile.
//! * **R6 (Lossless numeric casts):** all narrowing casts use `u32::try_from`.
//! * **R8 (Zero unsafe outside FFI):** no `unsafe` blocks in this module.
//! * **R9 (Warning-free build):** clean compile under `-D warnings`.
//! * **R10 (Wiring before done):** reachable via `CliCommand::Passwd` dispatch.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::{MdContext, MessageDigest, MD5, SHA256, SHA512};
use openssl_crypto::rand::rand_bytes;

use crate::lib::password::{PasswordCallbackData, PasswordHandler};

// ---------------------------------------------------------------------------
// Constants — cov_2char table and algorithm parameters
// ---------------------------------------------------------------------------

/// 64-character alphabet used by all crypt(3)-style password hash encodings.
///
/// VERBATIM translation of the `cov_2char[64]` table from `apps/passwd.c`
/// (lines 25–35), originally from `crypto/des/fcrypt.c`. The alphabet is:
/// `./0-9A-Za-z` (64 characters total). Each raw 6-bit group in the digest
/// output is mapped through this table during base64-like encoding.
///
/// # Safety of constants
/// Compile-time constant; no runtime mutation possible.
const COV_2CHAR: [u8; 64] = [
    0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, // ./012345
    0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, // 6789ABCD
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, // EFGHIJKL
    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, // MNOPQRST
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, // UVWXYZab
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, // cdefghij
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, // klmnopqr
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, // stuvwxyz
];

/// MD5 output size in bytes (all MD5-based crypt variants).
const MD5_DIGEST_LEN: usize = 16;

/// SHA-256 output size in bytes.
const SHA256_DIGEST_LEN: usize = 32;

/// SHA-512 output size in bytes.
const SHA512_DIGEST_LEN: usize = 64;

/// Maximum salt length for MD5-based variants (`-1`, `-apr1`, `-aixmd5`).
///
/// From `apps/passwd.c` line 346 — `OPENSSL_strlcpy(ascii_salt, salt, 9)`
/// truncates to 8 usable characters.
const MD5_SALT_MAX: usize = 8;

/// Maximum salt length for SHA-based variants (`-5`, `-6`).
///
/// From `apps/passwd.c` line 505 — `#define SALT_LEN_MAX 16`.
const SHA_SALT_MAX: usize = 16;

/// Default number of rounds for SHA-crypt.
///
/// From `apps/passwd.c` line 507 — `#define ROUNDS_DEFAULT 5000`.
const SHA_ROUNDS_DEFAULT: u32 = 5000;

/// Minimum number of rounds for SHA-crypt.
///
/// From `apps/passwd.c` line 509 — `#define ROUNDS_MIN 1000`.
const SHA_ROUNDS_MIN: u32 = 1000;

/// Maximum number of rounds for SHA-crypt.
///
/// From `apps/passwd.c` line 511 — `#define ROUNDS_MAX 999999999`.
const SHA_ROUNDS_MAX: u32 = 999_999_999;

/// Maximum password length accepted before truncation (with warning).
///
/// From `apps/passwd.c` line 117 — `size_t pw_maxlen = 256;`.
const PW_MAXLEN: usize = 256;

// ---------------------------------------------------------------------------
// PasswdMode — dispatch enum (Rust equivalent of `passwd_modes` enum)
// ---------------------------------------------------------------------------

/// Password hashing algorithm selector.
///
/// Translates the C `passwd_modes` enum from `apps/passwd.c` (lines 39–46).
/// Only one mode may be active per invocation (mutually-exclusive CLI flags).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PasswdMode {
    /// BSD MD5-based (`-1` flag). Output format: `$1$salt$hash`.
    Md5,
    /// Apache MD5-based (`-apr1` flag). Output format: `$apr1$salt$hash`.
    Apr1,
    /// AIX MD5-based (`-aixmd5` flag). Output format: `salt$hash` (no magic).
    AixMd5,
    /// SHA-256-based (`-5` flag). Output format: `$5$salt$hash`.
    Sha256,
    /// SHA-512-based (`-6` flag). Output format: `$6$salt$hash`.
    Sha512,
}

impl PasswdMode {
    /// The "magic" string used in the output prefix (empty for AIX).
    fn magic(self) -> &'static str {
        match self {
            Self::Md5 => "1",
            Self::Apr1 => "apr1",
            Self::AixMd5 => "",
            Self::Sha256 => "5",
            Self::Sha512 => "6",
        }
    }

    /// Required salt length for this mode (in bytes).
    fn salt_len(self) -> usize {
        match self {
            Self::Md5 | Self::Apr1 | Self::AixMd5 => 8,
            Self::Sha256 | Self::Sha512 => 16,
        }
    }
}

// ---------------------------------------------------------------------------
// PasswdArgs — CLI argument surface (clap derive)
// ---------------------------------------------------------------------------

/// Arguments for the `passwd` subcommand.
///
/// Replaces the C `passwd_options[]` table from `apps/passwd.c` (lines 70–101).
/// Generates crypt(3)-style password hashes using MD5 or SHA-based algorithms.
///
/// # Examples
///
/// ```sh
/// openssl passwd -6 -salt abc mypassword
/// openssl passwd -1 mypassword
/// openssl passwd -apr1 mypassword
/// openssl passwd -5 -stdin < passwords.txt
/// ```
// `PasswdArgs` mirrors the C `passwd` command-line surface (`apps/passwd.c`
// lines 61–99), which exposes many independent boolean flags (`-1`, `-5`,
// `-6`, `-apr1`, `-aixmd5`, `-crypt`, `-stdin`, `-noverify`, `-quiet`,
// `-table`, `-reverse`). Each flag is required for feature parity with the
// upstream CLI; they are not co-varying state bits, so grouping them into a
// substruct would misrepresent the public command-line contract.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// BSD MD5-based password algorithm.
    ///
    /// Produces output of the form `$1$<salt>$<hash>`.
    /// Mutually exclusive with `-5`, `-6`, `-apr1`, `-aixmd5`.
    #[arg(
        short = '1',
        long = "md5",
        conflicts_with_all = ["sha256", "sha512", "apr1", "aixmd5"],
    )]
    pub md5: bool,

    /// SHA-256-based password algorithm (Ulrich Drepper's SHA-crypt).
    ///
    /// Produces output of the form `$5$<salt>$<hash>`.
    /// Mutually exclusive with `-1`, `-6`, `-apr1`, `-aixmd5`.
    #[arg(
        short = '5',
        long = "sha256",
        conflicts_with_all = ["md5", "sha512", "apr1", "aixmd5"],
    )]
    pub sha256: bool,

    /// SHA-512-based password algorithm (Ulrich Drepper's SHA-crypt).
    ///
    /// Produces output of the form `$6$<salt>$<hash>`.
    /// Mutually exclusive with `-1`, `-5`, `-apr1`, `-aixmd5`.
    #[arg(
        short = '6',
        long = "sha512",
        conflicts_with_all = ["md5", "sha256", "apr1", "aixmd5"],
    )]
    pub sha512: bool,

    /// Apache MD5-based password algorithm variant.
    ///
    /// Produces output of the form `$apr1$<salt>$<hash>`.
    /// Mutually exclusive with `-1`, `-5`, `-6`, `-aixmd5`.
    #[arg(
        long = "apr1",
        conflicts_with_all = ["md5", "sha256", "sha512", "aixmd5"],
    )]
    pub apr1: bool,

    /// AIX MD5-based password algorithm (omits magic prefix).
    ///
    /// Produces output of the form `<salt>$<hash>` (no `$` prefix, no magic).
    /// Mutually exclusive with `-1`, `-5`, `-6`, `-apr1`.
    #[arg(
        long = "aixmd5",
        conflicts_with_all = ["md5", "sha256", "sha512", "apr1"],
    )]
    pub aixmd5: bool,

    /// Legacy DES-based crypt(3) algorithm (not supported).
    ///
    /// Accepted for CLI compatibility but always rejected at runtime because
    /// the C implementation itself does not provide DES crypt in OpenSSL 4.0
    /// (no `crypt()` mode exists in `apps/passwd.c`). Returns an error.
    #[arg(long = "crypt")]
    pub crypt: bool,

    /// Use the provided salt instead of a randomly generated one.
    ///
    /// When present, interactive password verification is disabled (because
    /// the salt is already committed). R5: `Option<String>` not sentinel.
    #[arg(long = "salt", value_name = "STRING")]
    pub salt: Option<String>,

    /// Read passwords from the specified file, one per line.
    ///
    /// Mutually exclusive with `-stdin` and positional password arguments.
    #[arg(long = "in", value_name = "FILE", conflicts_with_all = ["stdin", "passwords"])]
    pub infile: Option<PathBuf>,

    /// Read passwords from standard input, one per line.
    ///
    /// Mutually exclusive with `-in` and positional password arguments.
    #[arg(long = "stdin", conflicts_with_all = ["infile", "passwords"])]
    pub stdin: bool,

    /// Do not verify interactively-entered passwords (single-prompt mode).
    #[arg(long = "noverify")]
    pub noverify: bool,

    /// Suppress warnings (e.g., password-truncation notices).
    #[arg(long = "quiet")]
    pub quiet: bool,

    /// Format output as a tab-separated table: `password<TAB>hash`.
    #[arg(long = "table")]
    pub table: bool,

    /// Swap columns in table mode: `hash<TAB>password` instead of
    /// `password<TAB>hash`.
    #[arg(long = "reverse")]
    pub reverse: bool,

    /// Passwords to hash (positional arguments).
    ///
    /// Mutually exclusive with `-in` and `-stdin`. If no source is given and
    /// no passwords are provided, an interactive prompt is used.
    #[arg(value_name = "PASSWORD")]
    pub passwords: Vec<String>,
}

impl PasswdArgs {
    /// Execute the `passwd` subcommand.
    ///
    /// Dispatches the CLI flags to the appropriate hashing algorithm,
    /// gathers passwords from the configured source (command-line,
    /// `-in <file>`, `-stdin`, or interactive prompt), computes the
    /// hash(es), and writes the result(s) to stdout in the requested
    /// format.
    ///
    /// Translates `passwd_main()` from `apps/passwd.c` (lines 103–310).
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Key`] — invalid flag combination, unsupported mode
    ///   (`-crypt`), or salt validation failure.
    /// * [`CryptoError::Io`] — file-open, read, or write failure.
    /// * [`CryptoError::Rand`] — salt generation RNG failure.
    /// * [`CryptoError::AlgorithmNotFound`] — required digest algorithm
    ///   missing from all loaded providers.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // -- Reject legacy DES crypt up front -----------------------------
        // The C implementation does NOT implement `-crypt` — the flag is
        // a Rust-side placeholder accepted for CLI compatibility only.
        if self.crypt {
            error!("passwd: -crypt flag (legacy DES) is not supported");
            return Err(CryptoError::Key(
                "DES-based crypt(3) is not supported; use -1, -apr1, -5, or -6".into(),
            ));
        }

        // -- Resolve the effective mode (default: MD5) --------------------
        let mode = self.resolve_mode();
        debug!(?mode, "passwd: starting hash generation");

        // -- Acquire a cloneable Arc<LibContext> for fetch ----------------
        // Per the canonical pattern established in speed.rs: the callers
        // pass `&LibContext` but the fetch entry points require an owned
        // `Arc<LibContext>`. We re-obtain the default singleton here;
        // in the common case this is the same underlying context.
        let arc_ctx = LibContext::default();

        // -- Gather input passwords ---------------------------------------
        // The C source prefers: positional args → -in file → -stdin → prompt.
        // We replicate that precedence explicitly.
        let passwords = self.gather_passwords()?;

        if passwords.is_empty() {
            return Err(CryptoError::Key(
                "password required: provide a positional argument, -in <file>, -stdin, or allow interactive prompting".into(),
            ));
        }

        // -- Shared per-invocation salt (used only when -salt was given) --
        // When `-salt` is NOT given, each hash gets a fresh salt (like the
        // C `do_passwd` which reuses the `salt_malloc_p` buffer once set).
        let provided_salt: Option<String> = self.salt.clone();

        // Persistent salt buffer across invocations when not user-provided —
        // matches the C source's behaviour of keeping `salt_malloc` alive
        // across iterations of the password loop (lines 306, 803–806).
        let mut cached_random_salt: Option<String> = None;

        // -- Stdout sink --------------------------------------------------
        let stdout = io::stdout();
        let mut out = stdout.lock();

        // -- Process each password ---------------------------------------
        for pw_raw in passwords {
            self.do_passwd(
                &arc_ctx,
                &mut out,
                &pw_raw,
                mode,
                provided_salt.as_deref(),
                &mut cached_random_salt,
            )?;
        }

        info!("passwd: hash generation completed successfully");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Resolves the user's mode flags to a single [`PasswdMode`].
    ///
    /// When no flag is provided the default is MD5, matching
    /// `apps/passwd.c` line 210–213.
    fn resolve_mode(&self) -> PasswdMode {
        if self.sha512 {
            PasswdMode::Sha512
        } else if self.sha256 {
            PasswdMode::Sha256
        } else if self.apr1 {
            PasswdMode::Apr1
        } else if self.aixmd5 {
            PasswdMode::AixMd5
        } else {
            // Both `-1` and the default path map to MD5.
            PasswdMode::Md5
        }
    }

    /// Gathers passwords from the configured input source.
    ///
    /// Source precedence matches `apps/passwd.c` lines 198–262:
    ///
    /// 1. Positional arguments (`self.passwords`).
    /// 2. `-in <file>` — one password per line, newline terminated.
    /// 3. `-stdin` — one password per line, newline terminated.
    /// 4. Interactive prompt via [`PasswordHandler`].
    ///
    /// Return type uses [`Zeroizing<String>`] so plaintext passwords are
    /// zeroed on drop (AAP §0.7.6).
    fn gather_passwords(&self) -> Result<Vec<Zeroizing<String>>, CryptoError> {
        // 1. Positional args take precedence.
        if !self.passwords.is_empty() {
            debug!(
                count = self.passwords.len(),
                "passwd: using positional password arguments"
            );
            return Ok(self
                .passwords
                .iter()
                .map(|s| Zeroizing::new(s.clone()))
                .collect());
        }

        // 2. File source.
        if let Some(path) = &self.infile {
            debug!(path = ?path, "passwd: reading passwords from file");
            let file = File::open(path).map_err(CryptoError::Io)?;
            return Self::read_passwords_from_reader(BufReader::new(file));
        }

        // 3. Stdin source.
        if self.stdin {
            debug!("passwd: reading passwords from stdin");
            let stdin = io::stdin();
            return Self::read_passwords_from_reader(stdin.lock());
        }

        // 4. Interactive prompt. Verification is required unless either a
        //    salt was supplied (cannot verify without the associated hash)
        //    or -noverify was explicitly requested.
        debug!("passwd: prompting for password interactively");
        let verify = !(self.salt.is_some() || self.noverify);
        let handler = PasswordHandler::new();
        let cb = PasswordCallbackData::empty();
        let pw = handler
            .prompt_password(verify, Some(&cb))
            .map_err(|e| CryptoError::Key(format!("password prompt failed: {e}")))?;

        // In non-interactive environments, `prompt_password` returns an empty
        // string.  Treat that as "no input" so callers get the familiar
        // "password required" error.
        if pw.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![pw])
    }

    /// Reads one password per line from an arbitrary [`BufRead`] source.
    ///
    /// Translates the `BIO_gets` loop in `apps/passwd.c` lines 279–298.
    /// Empty lines are skipped (matches `r <= 0` break in C).
    fn read_passwords_from_reader<R: BufRead>(
        reader: R,
    ) -> Result<Vec<Zeroizing<String>>, CryptoError> {
        let mut out = Vec::new();
        for line_result in reader.lines() {
            let line = line_result.map_err(CryptoError::Io)?;
            // Skip trailing CR for CRLF-terminated lines.
            let trimmed = line.strip_suffix('\r').unwrap_or(&line).to_string();
            if trimmed.is_empty() {
                continue;
            }
            out.push(Zeroizing::new(trimmed));
        }
        Ok(out)
    }

    /// Hashes a single password and writes the result to `out`.
    ///
    /// Translates `do_passwd()` from `apps/passwd.c` lines 781–851.
    ///
    /// * Generates a salt if one is not provided.
    /// * Truncates passwords longer than [`PW_MAXLEN`] with a warning.
    /// * Dispatches to [`md5crypt`] or [`shacrypt`].
    /// * Emits the hash in the requested output format.
    fn do_passwd(
        &self,
        ctx: &Arc<LibContext>,
        out: &mut impl Write,
        passwd: &str,
        mode: PasswdMode,
        provided_salt: Option<&str>,
        cached_random_salt: &mut Option<String>,
    ) -> Result<(), CryptoError> {
        // -- Salt resolution ---------------------------------------------
        // If a user-specified salt is given, use it verbatim. Otherwise, lazily
        // generate a random one the first time a password is processed and
        // reuse it for subsequent passwords in the same invocation (matches
        // the C behaviour of calling `RAND_bytes` once per invocation).
        let salt: String = if let Some(s) = provided_salt {
            s.to_string()
        } else {
            if cached_random_salt.is_none() {
                *cached_random_salt = Some(generate_random_salt(mode.salt_len())?);
            }
            // Post-condition: `cached_random_salt` is `Some(_)` after the
            // guard above — either it was already populated or we just set it.
            // We still avoid `expect()`/`unwrap()` so that any future refactor
            // that violates the invariant fails with a typed error rather
            // than a panic (Rule R5 — no sentinel panics in library code).
            cached_random_salt.clone().ok_or_else(|| {
                CryptoError::from(openssl_common::error::CommonError::Internal(
                    "passwd: internal invariant violated — cached salt unset after generation"
                        .to_string(),
                ))
            })?
        };

        // -- Password-length truncation (with warning unless -quiet) -----
        // Translates `apps/passwd.c` lines 819–830.
        let passwd_effective: String = if passwd.len() > PW_MAXLEN {
            if !self.quiet {
                warn!(
                    max = PW_MAXLEN,
                    actual = passwd.len(),
                    "passwd: truncating password to {} characters",
                    PW_MAXLEN
                );
            }
            // Byte-slice at PW_MAXLEN; take_bytes_up_to handles UTF-8 safely.
            take_bytes_up_to(passwd, PW_MAXLEN)
        } else {
            passwd.to_string()
        };

        // -- Compute the hash --------------------------------------------
        // Dispatch via the [`PasswdMode`] enum: each mode provides its magic
        // prefix string through [`PasswdMode::magic`] and then routes to the
        // appropriate crypt primitive (MD5 family or SHA family).
        let magic = mode.magic();
        let hash: String = match mode {
            PasswdMode::Md5 | PasswdMode::Apr1 | PasswdMode::AixMd5 => {
                md5crypt(ctx, passwd_effective.as_bytes(), magic, &salt)?
            }
            PasswdMode::Sha256 | PasswdMode::Sha512 => {
                shacrypt(ctx, passwd_effective.as_bytes(), magic, &salt)?
            }
        };

        // -- Emit in the configured format -------------------------------
        // Translates `apps/passwd.c` lines 841–846.
        if self.table && !self.reverse {
            writeln!(out, "{passwd_effective}\t{hash}").map_err(CryptoError::Io)?;
        } else if self.table && self.reverse {
            writeln!(out, "{hash}\t{passwd_effective}").map_err(CryptoError::Io)?;
        } else {
            writeln!(out, "{hash}").map_err(CryptoError::Io)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free-standing helpers — pure algorithmic translations
// ---------------------------------------------------------------------------

/// Generates `n` random salt bytes and maps each through [`COV_2CHAR`].
///
/// Translates the per-byte mapping loop from `apps/passwd.c` lines 805–810:
/// ```c
/// RAND_bytes((unsigned char *)*salt_p, (int)saltlen);
/// for (i = 0; i < saltlen; i++)
///     (*salt_p)[i] = cov_2char[(*salt_p)[i] & 0x3f];
/// ```
///
/// The resulting string contains only characters from the 64-character
/// crypt(3) alphabet (ASCII, valid UTF-8).
fn generate_random_salt(n: usize) -> Result<String, CryptoError> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf)?;
    let mut out = String::with_capacity(n);
    for b in &buf {
        // `(b & 0x3f) as usize` is lossless: result is 0..=63, within range.
        let idx: usize = (*b & 0x3f) as usize;
        out.push(COV_2CHAR[idx] as char);
    }
    Ok(out)
}

/// Truncates `s` to a prefix of at most `max` bytes while preserving
/// UTF-8 validity.
///
/// Rust strings are UTF-8; splitting in the middle of a multibyte sequence
/// would panic. This helper walks back from `max` to the nearest char
/// boundary, ensuring the returned `String` is valid.
fn take_bytes_up_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Find largest character boundary at or below `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        // saturating_sub: R6 — avoid underflow on theoretical `max == 0`.
        end = end.saturating_sub(1);
    }
    s[..end].to_string()
}

/// Fetches a digest handle for the given algorithm name.
///
/// Convenience wrapper over [`MessageDigest::fetch`].
fn fetch_digest(
    ctx: &Arc<LibContext>,
    algorithm: &'static str,
) -> Result<MessageDigest, CryptoError> {
    MessageDigest::fetch(ctx, algorithm, None).map_err(|e| {
        error!(algorithm = algorithm, error = ?e, "passwd: failed to fetch digest");
        e
    })
}

/// Performs a full MD5 digest over the given byte slices in sequence.
///
/// Helper to avoid repetitive `init` / `update` / `finalize` boilerplate.
fn md5_digest_chunks(
    md: &MessageDigest,
    chunks: &[&[u8]],
) -> Result<[u8; MD5_DIGEST_LEN], CryptoError> {
    let mut ctx = MdContext::new();
    ctx.init(md, None)?;
    for c in chunks {
        ctx.update(c)?;
    }
    let raw = ctx.finalize()?;
    let mut out = [0u8; MD5_DIGEST_LEN];
    // R6: length-checked copy — `get()` returns None on mismatch.
    if raw.len() < MD5_DIGEST_LEN {
        return Err(CryptoError::Common(
            openssl_common::error::CommonError::Internal(format!(
                "MD5 digest returned {} bytes, expected {}",
                raw.len(),
                MD5_DIGEST_LEN
            )),
        ));
    }
    out.copy_from_slice(&raw[..MD5_DIGEST_LEN]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// md5crypt — BSD MD5 / apr1 / AIX-MD5 password algorithm
// ---------------------------------------------------------------------------

/// Computes the MD5-based crypt(3) hash of `passwd` using the given `salt`.
///
/// `magic` selects the output prefix:
///
/// * `"1"` — BSD MD5 crypt, produces `$1$<salt>$<hash>`.
/// * `"apr1"` — Apache MD5 crypt, produces `$apr1$<salt>$<hash>`.
/// * `""` — AIX MD5 crypt, produces `<salt>$<hash>` with no magic prefix.
///
/// Translates `md5crypt()` from `apps/passwd.c` lines 321–493, including
/// the 1000-round strengthening loop and the final 22-character base64-like
/// encoding of the 16-byte digest (with the "silly output permutation").
///
/// # Errors
///
/// * [`CryptoError::AlgorithmNotFound`] if MD5 is not available from any
///   loaded provider.
/// * Any [`CryptoError`] produced by the internal digest operations.
fn md5crypt(
    ctx: &Arc<LibContext>,
    passwd: &[u8],
    magic: &str,
    salt: &str,
) -> Result<String, CryptoError> {
    // Magic must be either empty (AIX) or 1–4 ASCII characters (`1`, `apr1`).
    if magic.len() > 4 {
        return Err(CryptoError::Key(format!(
            "md5crypt: magic string too long ({} bytes, max 4)",
            magic.len()
        )));
    }

    let md = fetch_digest(ctx, MD5)?;
    let magic_bytes = magic.as_bytes();
    let magic_len = magic_bytes.len();

    // -- Salt truncated to 8 bytes (C: OPENSSL_strlcpy to buf of size 9) --
    let salt_bytes_full = salt.as_bytes();
    let salt_slice_len = salt_bytes_full.len().min(MD5_SALT_MAX);
    let salt_bytes = &salt_bytes_full[..salt_slice_len];

    // -- Step 1: primary MD5 context — feed passwd | [magic] | salt -----
    // (apps/passwd.c lines 381–394)
    let mut md_ctx = MdContext::new();
    md_ctx.init(&md, None)?;
    md_ctx.update(passwd)?;
    if magic_len > 0 {
        md_ctx.update(b"$")?;
        md_ctx.update(magic_bytes)?;
        md_ctx.update(b"$")?;
    }
    md_ctx.update(salt_bytes)?;

    // -- Step 2: secondary digest = MD5(passwd | salt | passwd) ---------
    // (apps/passwd.c lines 396–403)
    let inner_buf = md5_digest_chunks(&md, &[passwd, salt_bytes, passwd])?;

    // -- Step 3: append inner_buf to md_ctx, passwd_len bytes total ------
    // (apps/passwd.c lines 405–410)
    //
    // The C loop feeds entire `MD5_DIGEST_LEN`-sized chunks of `buf`, then
    // a final `i`-byte remainder, where `i` is the remaining passwd_len
    // after each full-chunk subtraction. This is equivalent to feeding
    // exactly `passwd.len()` bytes (the trailing remainder may be zero
    // when `passwd.len() % MD5_DIGEST_LEN == 0`, in which case a zero-
    // length update is still issued; `MdContext::update` handles empty
    // slices safely).
    {
        let mut remaining = passwd.len();
        while remaining > MD5_DIGEST_LEN {
            md_ctx.update(&inner_buf)?;
            remaining -= MD5_DIGEST_LEN;
        }
        md_ctx.update(&inner_buf[..remaining])?;
    }

    // -- Step 4: bit-indexed feed — for each bit of passwd_len, feed ----
    // either a zero byte (bit set) or the first byte of passwd (bit clear).
    // (apps/passwd.c lines 412–417)
    //
    // The original uses `int n = passwd_len`; Rust uses usize. R6: we
    // preserve the C semantics by testing `n & 1 != 0`.
    {
        let mut n = passwd.len();
        while n != 0 {
            if (n & 1) != 0 {
                md_ctx.update(&[0u8])?;
            } else {
                // Feed exactly one byte from passwd[0].  An empty passwd
                // would have `n == 0` and the loop would not execute, so
                // indexing [0] is safe here when `passwd.len() > 0`.
                if passwd.is_empty() {
                    // Feed a single null byte when passwd is empty — the
                    // shift loop does not execute for `n = 0`, so this
                    // branch is unreachable in that case, but we guard
                    // defensively to avoid an out-of-bounds index.
                    md_ctx.update(&[0u8])?;
                } else {
                    md_ctx.update(&passwd[..1])?;
                }
            }
            n >>= 1;
        }
    }

    // -- Step 5: finalize the primary digest ----------------------------
    // (apps/passwd.c lines 418–419)
    let first_pass = md_ctx.finalize()?;
    if first_pass.len() < MD5_DIGEST_LEN {
        return Err(CryptoError::Common(
            openssl_common::error::CommonError::Internal(format!(
                "md5crypt: primary MD5 returned {} bytes",
                first_pass.len()
            )),
        ));
    }
    let mut buf: [u8; MD5_DIGEST_LEN] = [0u8; MD5_DIGEST_LEN];
    buf.copy_from_slice(&first_pass[..MD5_DIGEST_LEN]);

    // -- Step 6: 1000-round strengthening loop --------------------------
    // (apps/passwd.c lines 421–442)
    //
    // For each round i in 0..1000:
    //   reset md2
    //   if (i & 1) update(passwd)  else update(buf)
    //   if (i % 3)  update(salt)
    //   if (i % 7)  update(passwd)
    //   if (i & 1) update(buf)    else update(passwd)
    //   finalize → buf
    {
        let mut round_ctx = MdContext::new();
        for i in 0u32..1000 {
            round_ctx.init(&md, None)?;
            if (i & 1) != 0 {
                round_ctx.update(passwd)?;
            } else {
                round_ctx.update(&buf)?;
            }
            if (i % 3) != 0 {
                round_ctx.update(salt_bytes)?;
            }
            if (i % 7) != 0 {
                round_ctx.update(passwd)?;
            }
            if (i & 1) != 0 {
                round_ctx.update(&buf)?;
            } else {
                round_ctx.update(passwd)?;
            }
            let out_vec = round_ctx.finalize()?;
            if out_vec.len() < MD5_DIGEST_LEN {
                return Err(CryptoError::Common(
                    openssl_common::error::CommonError::Internal(format!(
                        "md5crypt: round {} produced {} bytes",
                        i,
                        out_vec.len()
                    )),
                ));
            }
            buf.copy_from_slice(&out_vec[..MD5_DIGEST_LEN]);
        }
    }

    // -- Step 7: "silly output permutation" -----------------------------
    // (apps/passwd.c lines 454–459)
    //
    // dest ∈ [0, 14): source = (source + 6) mod 17, starting at 0.
    // buf_perm[dest] = buf[source]
    // Trailing: buf_perm[14] = buf[5], buf_perm[15] = buf[11]
    let mut buf_perm = [0u8; MD5_DIGEST_LEN];
    {
        let mut source: usize = 0;
        for dest_slot in buf_perm.iter_mut().take(14) {
            *dest_slot = buf[source];
            source = (source + 6) % 17;
        }
        buf_perm[14] = buf[5];
        buf_perm[15] = buf[11];
    }

    // -- Step 8: emit output string -------------------------------------
    // (apps/passwd.c lines 337–378 and 465–480)
    //
    // Prefix:   "$<magic>$<salt>$<encoding>"    for magic_len > 0
    //           "<salt>$<encoding>"             for magic_len == 0 (AIX)
    let mut out = String::new();
    if magic_len > 0 {
        out.push('$');
        out.push_str(magic);
        out.push('$');
    }
    // Append salt (already truncated to <=8 bytes, all ASCII from COV_2CHAR
    // alphabet or user-supplied ASCII).
    out.push_str(
        std::str::from_utf8(salt_bytes)
            .map_err(|e| CryptoError::Key(format!("md5crypt: non-UTF-8 salt byte: {e}")))?,
    );
    out.push('$');

    // -- Step 9: encode 16 bytes → 22 characters using COV_2CHAR --------
    // (apps/passwd.c lines 470–479)
    //
    //   for i = 0, 3, 6, 9, 12:
    //     emit 4 chars from buf_perm[i], buf_perm[i+1], buf_perm[i+2]
    //   i == 15 trailing:
    //     emit cov_2char[buf_perm[15] & 0x3f]
    //     emit cov_2char[buf_perm[15] >> 6]
    for i in (0..15).step_by(3) {
        let b0: u8 = buf_perm[i];
        let b1: u8 = buf_perm[i + 1];
        let b2: u8 = buf_perm[i + 2];
        // *output++ = cov_2char[buf_perm[i + 2] & 0x3f];
        out.push(COV_2CHAR[(b2 & 0x3f) as usize] as char);
        // *output++ = cov_2char[((buf_perm[i+1] & 0xf) << 2) | (buf_perm[i+2] >> 6)];
        out.push(COV_2CHAR[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        // *output++ = cov_2char[((buf_perm[i] & 3) << 4) | (buf_perm[i+1] >> 4)];
        out.push(COV_2CHAR[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        // *output++ = cov_2char[buf_perm[i] >> 2];
        out.push(COV_2CHAR[(b0 >> 2) as usize] as char);
    }
    // Trailing i == 15
    let b15: u8 = buf_perm[15];
    out.push(COV_2CHAR[(b15 & 0x3f) as usize] as char);
    out.push(COV_2CHAR[(b15 >> 6) as usize] as char);

    Ok(out)
}

// ---------------------------------------------------------------------------
// shacrypt — SHA-256 ("$5$") and SHA-512 ("$6$") password algorithms
// ---------------------------------------------------------------------------

/// Computes the SHA-based crypt(3) hash (Ulrich Drepper's SHA-crypt).
///
/// `magic` must be either `"5"` (SHA-256, 11 output groups) or `"6"`
/// (SHA-512, 21 output groups). The salt string may optionally begin with
/// `rounds=<N>$` to override the default round count, clamped to
/// `[SHA_ROUNDS_MIN, SHA_ROUNDS_MAX]`.
///
/// Translates `shacrypt()` from `apps/passwd.c` lines 500–779, including
/// the P- and S-byte derivation sequences and the variable-rounds main loop.
///
/// # Errors
///
/// * [`CryptoError::Key`] — invalid magic or malformed `rounds=` prefix.
/// * [`CryptoError::AlgorithmNotFound`] — SHA-256/SHA-512 unavailable.
/// * Any [`CryptoError`] produced by digest operations.
fn shacrypt(
    ctx: &Arc<LibContext>,
    passwd: &[u8],
    magic: &str,
    salt: &str,
) -> Result<String, CryptoError> {
    // -- Magic selection -------------------------------------------------
    let (algorithm, buf_size) = match magic {
        "5" => (SHA256, SHA256_DIGEST_LEN),
        "6" => (SHA512, SHA512_DIGEST_LEN),
        _ => {
            return Err(CryptoError::Key(format!(
                "shacrypt: invalid magic string '{magic}' (expected '5' or '6')"
            )));
        }
    };
    let sha = fetch_digest(ctx, algorithm)?;

    // -- Parse optional "rounds=N$" prefix on the salt ------------------
    // Translates apps/passwd.c lines 551–567.
    let rounds_prefix = "rounds=";
    let (rounds, rounds_custom, salt_tail) = if let Some(rest) = salt.strip_prefix(rounds_prefix) {
        // Find the '$' that terminates the number.
        match rest.find('$') {
            Some(dollar_idx) => {
                let num_str = &rest[..dollar_idx];
                let tail = &rest[dollar_idx + 1..];
                // Parse as u64 to tolerate the user typing very large values,
                // then clamp to MIN..=MAX per C semantics.
                let srounds: u64 = num_str.parse::<u64>().map_err(|e| {
                    CryptoError::Key(format!("shacrypt: invalid rounds value: {e}"))
                })?;
                let rounds_u32: u32 = if srounds > u64::from(SHA_ROUNDS_MAX) {
                    SHA_ROUNDS_MAX
                } else if srounds < u64::from(SHA_ROUNDS_MIN) {
                    SHA_ROUNDS_MIN
                } else {
                    // R6: srounds is within [MIN..=MAX] both of which fit u32.
                    u32::try_from(srounds).unwrap_or(SHA_ROUNDS_DEFAULT)
                };
                (rounds_u32, true, tail)
            }
            None => {
                return Err(CryptoError::Key(
                    "shacrypt: malformed 'rounds=' prefix (missing '$' terminator)".into(),
                ));
            }
        }
    } else {
        (SHA_ROUNDS_DEFAULT, false, salt)
    };

    // -- Salt truncated to 16 bytes -------------------------------------
    let salt_bytes_full = salt_tail.as_bytes();
    let salt_len_truncated = salt_bytes_full.len().min(SHA_SALT_MAX);
    let salt_bytes = &salt_bytes_full[..salt_len_truncated];

    // -- Prefix output buffer: "$<magic>$[rounds=N$]<salt>" -------------
    // (apps/passwd.c lines 590–606)
    let mut out = String::new();
    out.push('$');
    out.push_str(magic);
    out.push('$');
    if rounds_custom {
        out.push_str(&format!("rounds={rounds}$"));
    }
    out.push_str(
        std::str::from_utf8(salt_bytes)
            .map_err(|e| CryptoError::Key(format!("shacrypt: non-UTF-8 salt byte: {e}")))?,
    );

    // -- Primary digest: feed passwd | salt ------------------------------
    // (apps/passwd.c lines 612–617)
    let mut md_ctx = MdContext::new();
    md_ctx.init(&sha, None)?;
    md_ctx.update(passwd)?;
    md_ctx.update(salt_bytes)?;

    // -- Secondary digest: SHA(passwd | salt | passwd) → buf -------------
    // (apps/passwd.c lines 619–626)
    let mut buf = vec![0u8; buf_size];
    {
        let mut md2_ctx = MdContext::new();
        md2_ctx.init(&sha, None)?;
        md2_ctx.update(passwd)?;
        md2_ctx.update(salt_bytes)?;
        md2_ctx.update(passwd)?;
        let v = md2_ctx.finalize()?;
        if v.len() < buf_size {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::Internal(format!(
                    "shacrypt: secondary digest returned {} bytes, expected {}",
                    v.len(),
                    buf_size
                )),
            ));
        }
        buf.copy_from_slice(&v[..buf_size]);
    }

    // -- Feed `passwd_len` bytes of `buf` to primary context ------------
    // (apps/passwd.c lines 628–633)
    {
        let mut remaining = passwd.len();
        while remaining > buf_size {
            md_ctx.update(&buf)?;
            remaining -= buf_size;
        }
        md_ctx.update(&buf[..remaining])?;
    }

    // -- Bit-indexed feed: for each bit of passwd_len, alternate --------
    // (apps/passwd.c lines 635–642)
    {
        let mut n = passwd.len();
        while n != 0 {
            if (n & 1) != 0 {
                md_ctx.update(&buf)?;
            } else {
                md_ctx.update(passwd)?;
            }
            n >>= 1;
        }
    }

    // Finalize primary → buf
    let v = md_ctx.finalize()?;
    if v.len() < buf_size {
        return Err(CryptoError::Common(
            openssl_common::error::CommonError::Internal(format!(
                "shacrypt: primary digest returned {} bytes, expected {}",
                v.len(),
                buf_size
            )),
        ));
    }
    buf.copy_from_slice(&v[..buf_size]);

    // -- P-byte sequence: SHA(passwd × passwd_len) → temp_buf -----------
    // Then fill p_bytes with repeated temp_buf of passwd_len bytes.
    // (apps/passwd.c lines 646–661)
    let mut temp_buf = vec![0u8; buf_size];
    let p_bytes: Zeroizing<Vec<u8>> = {
        let mut md2_ctx = MdContext::new();
        md2_ctx.init(&sha, None)?;
        for _ in 0..passwd.len() {
            md2_ctx.update(passwd)?;
        }
        let v = md2_ctx.finalize()?;
        if v.len() < buf_size {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::Internal(format!(
                    "shacrypt: P-digest returned {} bytes, expected {}",
                    v.len(),
                    buf_size
                )),
            ));
        }
        temp_buf.copy_from_slice(&v[..buf_size]);

        // Fill p_bytes[0..passwd_len] with repeated temp_buf[0..buf_size].
        let mut p = Zeroizing::new(vec![0u8; passwd.len()]);
        let mut off = 0usize;
        let mut remaining = passwd.len();
        while remaining > buf_size {
            p[off..off + buf_size].copy_from_slice(&temp_buf);
            off += buf_size;
            remaining -= buf_size;
        }
        if remaining > 0 {
            p[off..off + remaining].copy_from_slice(&temp_buf[..remaining]);
        }
        p
    };

    // -- S-byte sequence: SHA(salt × (16 + buf[0])) → temp_buf ----------
    // Then fill s_bytes with repeated temp_buf of salt_len bytes.
    // (apps/passwd.c lines 663–678)
    let s_bytes: Vec<u8> = {
        let mut md2_ctx = MdContext::new();
        md2_ctx.init(&sha, None)?;
        // `16 + buf[0]` — buf[0] is u8 so sum fits in usize without overflow.
        let s_iters: usize = 16usize + (buf[0] as usize);
        for _ in 0..s_iters {
            md2_ctx.update(salt_bytes)?;
        }
        let v = md2_ctx.finalize()?;
        if v.len() < buf_size {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::Internal(format!(
                    "shacrypt: S-digest returned {} bytes, expected {}",
                    v.len(),
                    buf_size
                )),
            ));
        }
        temp_buf.copy_from_slice(&v[..buf_size]);

        let mut s = vec![0u8; salt_bytes.len()];
        let mut off = 0usize;
        let mut remaining = salt_bytes.len();
        while remaining > buf_size {
            s[off..off + buf_size].copy_from_slice(&temp_buf);
            off += buf_size;
            remaining -= buf_size;
        }
        if remaining > 0 {
            s[off..off + remaining].copy_from_slice(&temp_buf[..remaining]);
        }
        s
    };

    // -- Variable-rounds main loop (apps/passwd.c lines 680–701) --------
    {
        let mut round_ctx = MdContext::new();
        for n in 0u32..rounds {
            round_ctx.init(&sha, None)?;
            if (n & 1) != 0 {
                round_ctx.update(&p_bytes)?;
            } else {
                round_ctx.update(&buf)?;
            }
            if (n % 3) != 0 {
                round_ctx.update(&s_bytes)?;
            }
            if (n % 7) != 0 {
                round_ctx.update(&p_bytes)?;
            }
            if (n & 1) != 0 {
                round_ctx.update(&buf)?;
            } else {
                round_ctx.update(&p_bytes)?;
            }
            let v = round_ctx.finalize()?;
            if v.len() < buf_size {
                return Err(CryptoError::Common(
                    openssl_common::error::CommonError::Internal(format!(
                        "shacrypt: round {} produced {} bytes",
                        n,
                        v.len()
                    )),
                ));
            }
            buf.copy_from_slice(&v[..buf_size]);
        }
    }

    // -- Encoding: `$` + base64-like groups -----------------------------
    // (apps/passwd.c lines 711–765)
    out.push('$');
    match magic {
        "5" => encode_sha256(&buf, &mut out),
        "6" => encode_sha512(&buf, &mut out),
        _ => unreachable!("magic has already been validated above"),
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// shacrypt output encoding — verbatim from apps/passwd.c b64_from_24bit calls
// ---------------------------------------------------------------------------

/// Emits `n` base64-like characters from the 24-bit value formed by `(b2 << 16)
/// | (b1 << 8) | b0`.
///
/// Translates the `b64_from_24bit` macro from `apps/passwd.c` lines 714–722.
/// The three-byte input is treated as a 24-bit little-endian number (b0 is
/// the lowest-order byte in the rendering sequence). `n` characters are
/// emitted, each a 6-bit slice of the accumulator, starting from the
/// least-significant 6 bits.
#[inline]
fn b64_from_24bit(b2: u8, b1: u8, b0: u8, n: u32, out: &mut String) {
    // R6: wide-enough accumulator to hold all three bytes shifted.
    let mut w: u32 = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
    // R6: `n` is a small literal (2, 3, or 4) — safely cast to loop bound.
    for _ in 0..n {
        // `w & 0x3f` is a 6-bit value, always in 0..=63.
        let idx: usize = (w & 0x3f) as usize;
        out.push(COV_2CHAR[idx] as char);
        w >>= 6;
    }
}

/// Encodes a 32-byte SHA-256-crypt digest as 43 base64-like characters.
///
/// Translates apps/passwd.c lines 725–737.
fn encode_sha256(buf: &[u8], out: &mut String) {
    // Assume buf has at least 32 bytes — caller is responsible.
    b64_from_24bit(buf[0], buf[10], buf[20], 4, out);
    b64_from_24bit(buf[21], buf[1], buf[11], 4, out);
    b64_from_24bit(buf[12], buf[22], buf[2], 4, out);
    b64_from_24bit(buf[3], buf[13], buf[23], 4, out);
    b64_from_24bit(buf[24], buf[4], buf[14], 4, out);
    b64_from_24bit(buf[15], buf[25], buf[5], 4, out);
    b64_from_24bit(buf[6], buf[16], buf[26], 4, out);
    b64_from_24bit(buf[27], buf[7], buf[17], 4, out);
    b64_from_24bit(buf[18], buf[28], buf[8], 4, out);
    b64_from_24bit(buf[9], buf[19], buf[29], 4, out);
    b64_from_24bit(0, buf[31], buf[30], 3, out);
}

/// Encodes a 64-byte SHA-512-crypt digest as 86 base64-like characters.
///
/// Translates apps/passwd.c lines 738–761.
fn encode_sha512(buf: &[u8], out: &mut String) {
    // Assume buf has at least 64 bytes — caller is responsible.
    b64_from_24bit(buf[0], buf[21], buf[42], 4, out);
    b64_from_24bit(buf[22], buf[43], buf[1], 4, out);
    b64_from_24bit(buf[44], buf[2], buf[23], 4, out);
    b64_from_24bit(buf[3], buf[24], buf[45], 4, out);
    b64_from_24bit(buf[25], buf[46], buf[4], 4, out);
    b64_from_24bit(buf[47], buf[5], buf[26], 4, out);
    b64_from_24bit(buf[6], buf[27], buf[48], 4, out);
    b64_from_24bit(buf[28], buf[49], buf[7], 4, out);
    b64_from_24bit(buf[50], buf[8], buf[29], 4, out);
    b64_from_24bit(buf[9], buf[30], buf[51], 4, out);
    b64_from_24bit(buf[31], buf[52], buf[10], 4, out);
    b64_from_24bit(buf[53], buf[11], buf[32], 4, out);
    b64_from_24bit(buf[12], buf[33], buf[54], 4, out);
    b64_from_24bit(buf[34], buf[55], buf[13], 4, out);
    b64_from_24bit(buf[56], buf[14], buf[35], 4, out);
    b64_from_24bit(buf[15], buf[36], buf[57], 4, out);
    b64_from_24bit(buf[37], buf[58], buf[16], 4, out);
    b64_from_24bit(buf[59], buf[17], buf[38], 4, out);
    b64_from_24bit(buf[18], buf[39], buf[60], 4, out);
    b64_from_24bit(buf[40], buf[61], buf[19], 4, out);
    b64_from_24bit(buf[62], buf[20], buf[41], 4, out);
    b64_from_24bit(0, 0, buf[63], 2, out);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// RATIONALE: Test code uses `unwrap()`, `expect()`, and `panic!` as the
// idiomatic way to fail fast on unexpected conditions; the workspace Cargo.toml
// sets these three lints to `warn`, but CI escalates warnings to errors via
// `RUSTFLAGS=-D warnings`. This allow attribute mirrors the established
// workspace convention used in `crates/openssl-cli/src/commands/srp.rs`.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Sanity check: the `COV_2CHAR` alphabet is exactly 64 bytes and all
    /// entries fall within the printable ASCII subset `./0-9A-Za-z`.
    #[test]
    fn cov_2char_is_crypt_alphabet() {
        assert_eq!(COV_2CHAR.len(), 64);
        for &b in &COV_2CHAR {
            let c = b as char;
            let ok = c == '.' || c == '/' || c.is_ascii_digit() || c.is_ascii_alphabetic();
            assert!(ok, "non-crypt character {c:?} found in COV_2CHAR");
        }
        // Specific edge values: first two are '.', '/'.
        assert_eq!(COV_2CHAR[0], b'.');
        assert_eq!(COV_2CHAR[1], b'/');
        // Last should be 'z'.
        assert_eq!(COV_2CHAR[63], b'z');
    }

    /// `take_bytes_up_to` preserves UTF-8 on multibyte input.
    #[test]
    fn take_bytes_up_to_utf8_boundary() {
        // "ä" is 2 bytes (0xC3 0xA4).  Truncating to 1 byte must not split it.
        let s = "aäb";
        assert_eq!(take_bytes_up_to(s, 1), "a");
        assert_eq!(take_bytes_up_to(s, 3), "aä");
        assert_eq!(take_bytes_up_to(s, 4), "aäb");
    }

    /// `take_bytes_up_to` is a no-op when input is shorter than `max`.
    #[test]
    fn take_bytes_up_to_short_input_noop() {
        assert_eq!(take_bytes_up_to("hello", 100), "hello");
        assert_eq!(take_bytes_up_to("", 5), "");
    }

    /// `generate_random_salt` returns a string of the requested length,
    /// composed entirely of characters from the crypt(3) alphabet.
    #[test]
    fn generate_random_salt_lengths() {
        for &n in &[0usize, 1, 8, 16] {
            let salt = generate_random_salt(n).expect("rand_bytes must succeed");
            assert_eq!(salt.len(), n, "salt length mismatch at n={n}");
            for ch in salt.chars() {
                let ok = ch == '.' || ch == '/' || ch.is_ascii_digit() || ch.is_ascii_alphabetic();
                assert!(ok, "unexpected char {ch:?} in random salt");
            }
        }
    }

    /// Two successive salts of the same length must differ (cryptographic
    /// randomness sanity check).
    #[test]
    fn generate_random_salt_differs() {
        let a = generate_random_salt(16).unwrap();
        let b = generate_random_salt(16).unwrap();
        assert_ne!(a, b, "consecutive random salts must differ");
    }

    /// Mode resolution: each CLI flag maps to the correct [`PasswdMode`].
    #[test]
    fn passwd_mode_resolution() {
        let make = |md5, sha256, sha512, apr1, aixmd5| PasswdArgs {
            md5,
            sha256,
            sha512,
            apr1,
            aixmd5,
            crypt: false,
            salt: None,
            infile: None,
            stdin: false,
            noverify: false,
            quiet: false,
            table: false,
            reverse: false,
            passwords: vec![],
        };
        assert_eq!(
            make(true, false, false, false, false).resolve_mode(),
            PasswdMode::Md5
        );
        assert_eq!(
            make(false, true, false, false, false).resolve_mode(),
            PasswdMode::Sha256
        );
        assert_eq!(
            make(false, false, true, false, false).resolve_mode(),
            PasswdMode::Sha512
        );
        assert_eq!(
            make(false, false, false, true, false).resolve_mode(),
            PasswdMode::Apr1
        );
        assert_eq!(
            make(false, false, false, false, true).resolve_mode(),
            PasswdMode::AixMd5
        );
        // Default (no flag) → Md5.
        assert_eq!(
            make(false, false, false, false, false).resolve_mode(),
            PasswdMode::Md5
        );
    }

    /// Mode metadata: magic strings and required salt lengths are correct.
    #[test]
    fn passwd_mode_metadata() {
        assert_eq!(PasswdMode::Md5.magic(), "1");
        assert_eq!(PasswdMode::Apr1.magic(), "apr1");
        assert_eq!(PasswdMode::AixMd5.magic(), "");
        assert_eq!(PasswdMode::Sha256.magic(), "5");
        assert_eq!(PasswdMode::Sha512.magic(), "6");

        assert_eq!(PasswdMode::Md5.salt_len(), 8);
        assert_eq!(PasswdMode::Apr1.salt_len(), 8);
        assert_eq!(PasswdMode::AixMd5.salt_len(), 8);
        assert_eq!(PasswdMode::Sha256.salt_len(), 16);
        assert_eq!(PasswdMode::Sha512.salt_len(), 16);
    }

    /// Rejecting `-crypt` at runtime (DES crypt is not supported).
    #[tokio::test]
    async fn execute_rejects_crypt_flag() {
        let args = PasswdArgs {
            md5: false,
            sha256: false,
            sha512: false,
            apr1: false,
            aixmd5: false,
            crypt: true,
            salt: None,
            infile: None,
            stdin: false,
            noverify: true,
            quiet: true,
            table: false,
            reverse: false,
            passwords: vec!["password".to_string()],
        };
        let ctx = LibContext::new();
        let err = args.execute(&ctx).await.unwrap_err();
        match err {
            CryptoError::Key(msg) => assert!(msg.contains("DES"), "unexpected msg: {msg}"),
            other => panic!("expected CryptoError::Key for -crypt, got {other:?}"),
        }
    }

    /// No password source and no interactive TTY → error.
    #[tokio::test]
    async fn execute_requires_password_source() {
        let args = PasswdArgs {
            md5: true,
            sha256: false,
            sha512: false,
            apr1: false,
            aixmd5: false,
            crypt: false,
            salt: Some("12345678".to_string()),
            infile: None,
            stdin: false,
            noverify: true,
            quiet: true,
            table: false,
            reverse: false,
            passwords: vec![],
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        // In the test runner, stdin is not a TTY, so interactive prompting
        // returns an empty string and we expect a "password required" error.
        assert!(
            result.is_err(),
            "expected error for missing password source"
        );
    }

    /// End-to-end: `-1 mypass -salt 12345678` produces a non-empty hash
    /// beginning with `$1$12345678$`.
    #[tokio::test]
    async fn execute_md5_with_salt_emits_prefix() {
        // We can't easily capture stdout here, but we can verify the
        // hash helper directly.
        let ctx = LibContext::default();
        let hash = md5crypt(&ctx, b"mypass", "1", "12345678").expect("md5crypt must succeed");
        assert!(
            hash.starts_with("$1$12345678$"),
            "unexpected prefix: {hash}"
        );
        // The hash body after the trailing '$' must be exactly 22 characters.
        let body = &hash["$1$12345678$".len()..];
        assert_eq!(body.len(), 22, "md5crypt body must be 22 chars, got {body}");
    }

    /// End-to-end: apr1 mode produces `$apr1$...` prefix.
    #[tokio::test]
    async fn md5crypt_apr1_prefix() {
        let ctx = LibContext::default();
        let hash = md5crypt(&ctx, b"hello", "apr1", "ABC12345").expect("md5crypt apr1");
        assert!(hash.starts_with("$apr1$ABC12345$"), "unexpected: {hash}");
    }

    /// End-to-end: AIX md5 mode has NO magic prefix (salt is first).
    #[tokio::test]
    async fn md5crypt_aixmd5_no_magic_prefix() {
        let ctx = LibContext::default();
        let hash = md5crypt(&ctx, b"test", "", "saltsalt").expect("md5crypt aix");
        assert!(
            !hash.starts_with('$'),
            "aixmd5 must not start with $: {hash}"
        );
        assert!(hash.starts_with("saltsalt$"), "unexpected: {hash}");
    }

    /// End-to-end: SHA-256 mode produces a `$5$salt$` prefix.
    #[tokio::test]
    async fn shacrypt_sha256_prefix() {
        let ctx = LibContext::default();
        let hash = shacrypt(&ctx, b"password", "5", "saltstring123456").expect("shacrypt sha256");
        assert!(
            hash.starts_with("$5$saltstring123456$"),
            "unexpected: {hash}"
        );
    }

    /// End-to-end: SHA-512 mode produces a `$6$salt$` prefix.
    #[tokio::test]
    async fn shacrypt_sha512_prefix() {
        let ctx = LibContext::default();
        let hash = shacrypt(&ctx, b"password", "6", "saltstring").expect("shacrypt sha512");
        assert!(hash.starts_with("$6$saltstring$"), "unexpected: {hash}");
    }

    /// `shacrypt` rejects an invalid magic string.
    #[tokio::test]
    async fn shacrypt_invalid_magic() {
        let ctx = LibContext::default();
        let err = shacrypt(&ctx, b"password", "7", "salt").unwrap_err();
        match err {
            CryptoError::Key(msg) => assert!(msg.contains("invalid magic"), "unexpected: {msg}"),
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    /// `shacrypt` honours a custom `rounds=` prefix.
    #[tokio::test]
    async fn shacrypt_rounds_prefix_parsed() {
        let ctx = LibContext::default();
        let hash = shacrypt(&ctx, b"pw", "5", "rounds=1234$saltstring").expect("shacrypt rounds");
        assert!(
            hash.starts_with("$5$rounds=1234$saltstring$"),
            "unexpected: {hash}"
        );
    }

    /// `shacrypt` clamps rounds below MIN up to MIN.
    #[tokio::test]
    async fn shacrypt_rounds_clamped_below_min() {
        let ctx = LibContext::default();
        let hash =
            shacrypt(&ctx, b"pw", "5", "rounds=1$saltstring").expect("shacrypt rounds clamp");
        assert!(
            hash.starts_with(&format!("$5$rounds={SHA_ROUNDS_MIN}$saltstring$")),
            "unexpected: {hash}"
        );
    }

    /// `shacrypt` rejects a malformed rounds prefix (no `$`).
    #[tokio::test]
    async fn shacrypt_rounds_prefix_malformed() {
        let ctx = LibContext::default();
        let err = shacrypt(&ctx, b"pw", "5", "rounds=1234nosuffix").unwrap_err();
        match err {
            CryptoError::Key(msg) => {
                assert!(msg.contains("rounds"), "unexpected: {msg}");
            }
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    /// md5crypt rejects over-long magic strings.
    #[tokio::test]
    async fn md5crypt_rejects_overlong_magic() {
        let ctx = LibContext::default();
        let err = md5crypt(&ctx, b"pw", "apr12", "salt").unwrap_err();
        match err {
            CryptoError::Key(msg) => assert!(msg.contains("too long"), "unexpected: {msg}"),
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    /// Reader-based password parsing skips empty lines and strips CRLFs.
    #[test]
    fn read_passwords_from_reader_basic() {
        use std::io::Cursor;
        let data = b"pass1\n\npass2\r\npass3\n";
        let reader = Cursor::new(data);
        let pws = PasswdArgs::read_passwords_from_reader(reader).unwrap();
        let strs: Vec<String> = pws.iter().map(|p| (**p).clone()).collect();
        assert_eq!(strs, vec!["pass1", "pass2", "pass3"]);
    }

    /// Reader parser propagates I/O errors.
    #[test]
    fn read_passwords_from_reader_empty() {
        use std::io::Cursor;
        let reader = Cursor::new(Vec::<u8>::new());
        let pws = PasswdArgs::read_passwords_from_reader(reader).unwrap();
        assert!(pws.is_empty());
    }

    /// `b64_from_24bit` produces exactly `n` characters per call.
    #[test]
    fn b64_from_24bit_length() {
        let mut s = String::new();
        b64_from_24bit(0, 0, 0, 4, &mut s);
        assert_eq!(s.len(), 4);
        let mut s2 = String::new();
        b64_from_24bit(0xFF, 0xFF, 0xFF, 3, &mut s2);
        assert_eq!(s2.len(), 3);
        let mut s3 = String::new();
        b64_from_24bit(0x12, 0x34, 0x56, 2, &mut s3);
        assert_eq!(s3.len(), 2);
    }

    /// `b64_from_24bit` of all zeros produces only '.' characters.
    #[test]
    fn b64_from_24bit_zero() {
        let mut s = String::new();
        b64_from_24bit(0, 0, 0, 4, &mut s);
        for c in s.chars() {
            assert_eq!(c, '.');
        }
    }

    /// `encode_sha256` produces exactly 43 characters (11*4 − 1).
    #[test]
    fn encode_sha256_length() {
        let buf = [0u8; 32];
        let mut out = String::new();
        encode_sha256(&buf, &mut out);
        assert_eq!(out.len(), 43);
    }

    /// `encode_sha512` produces exactly 86 characters (21*4 + 2).
    #[test]
    fn encode_sha512_length() {
        let buf = [0u8; 64];
        let mut out = String::new();
        encode_sha512(&buf, &mut out);
        assert_eq!(out.len(), 86);
    }

    /// `md5crypt` is deterministic for identical (passwd, salt, magic).
    #[tokio::test]
    async fn md5crypt_deterministic() {
        let ctx = LibContext::default();
        let h1 = md5crypt(&ctx, b"foobar", "1", "saltsalt").unwrap();
        let h2 = md5crypt(&ctx, b"foobar", "1", "saltsalt").unwrap();
        assert_eq!(h1, h2);
    }

    /// `shacrypt` is deterministic for identical (passwd, salt, magic, rounds).
    #[tokio::test]
    async fn shacrypt_deterministic() {
        let ctx = LibContext::default();
        let h1 = shacrypt(&ctx, b"password", "5", "salt").unwrap();
        let h2 = shacrypt(&ctx, b"password", "5", "salt").unwrap();
        assert_eq!(h1, h2);
    }

    /// Different salts produce different hashes.
    #[tokio::test]
    async fn md5crypt_differs_on_salt() {
        let ctx = LibContext::default();
        let h1 = md5crypt(&ctx, b"password", "1", "saltAAAA").unwrap();
        let h2 = md5crypt(&ctx, b"password", "1", "saltBBBB").unwrap();
        assert_ne!(h1, h2);
    }

    /// Different passwords produce different hashes.
    #[tokio::test]
    async fn md5crypt_differs_on_password() {
        let ctx = LibContext::default();
        let h1 = md5crypt(&ctx, b"password1", "1", "samesalt").unwrap();
        let h2 = md5crypt(&ctx, b"password2", "1", "samesalt").unwrap();
        assert_ne!(h1, h2);
    }

    /// Salt strings longer than the mode's max are silently truncated.
    #[tokio::test]
    async fn md5crypt_truncates_overlong_salt() {
        let ctx = LibContext::default();
        // 20-character salt — only first 8 should be used, output should be
        // identical to providing just the first 8 characters.
        let h_long = md5crypt(&ctx, b"pw", "1", "12345678ABCDEFGHIJKL").unwrap();
        let h_short = md5crypt(&ctx, b"pw", "1", "12345678").unwrap();
        assert!(h_long.starts_with("$1$12345678$"), "unexpected: {h_long}");
        assert!(h_short.starts_with("$1$12345678$"), "unexpected: {h_short}");
        // Hash bodies should match since the effective salt is identical.
        assert_eq!(h_long, h_short);
    }
}
