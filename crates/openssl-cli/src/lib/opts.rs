//! Shared option parsing helpers, format enums, and display utilities.
//!
//! Consolidates 6 C source files (1,573 total lines) into supplementary
//! helpers for the clap-based CLI argument parsing:
//! - `opts.rs` replaces: `opt.c` (1,276), `columns.c` (26), `fmt.c` (15),
//!   `names.c` (46), `app_params.c` (186), `apps_opt_printf.c` (24)
//!
//! ## Architecture
//!
//! The core option parsing infrastructure (`opt_init`/`opt_next`/`opt_help`)
//! from `opt.c` is entirely replaced by clap's derive macros in each
//! command module. This module provides domain-specific helpers that
//! clap doesn't provide natively:
//!
//! - [`Format`] enum for `-inform`/`-outform` parsing
//! - [`FormatFlags`] bitflags for validating acceptable formats per command
//! - [`VerifyParams`] clap `Args` struct for X.509 verification parameters
//! - [`DisplayColumns`] and [`calculate_columns`] for list/help column layout
//! - [`name_cmp`] and [`print_names`] for algorithm name collection and display
//! - [`ParamType`], [`ParamValue`], and associated printing functions for
//!   provider diagnostics
//! - [`opt_printf_stderr`] for structured error output

use std::cmp::Ordering;
use std::fmt;
use std::io::{self, Write};
use std::str::FromStr;

use bitflags::bitflags;
use clap::ValueEnum;
use thiserror::Error;
use tracing::{error, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of octet bytes to display before truncating with `"..."`.
///
/// Matches `MAX_OCTET_STRING_OUTPUT_BYTES` from `app_params.c:14`.
const MAX_OCTET_STRING_OUTPUT_BYTES: usize = 24;

/// Terminal width assumed for column layout calculations.
///
/// Matches the `80` constant used in `columns.c:23-25`.
const TERMINAL_WIDTH: usize = 80;

// ---------------------------------------------------------------------------
// FormatError — replaces opt_format_error() from opt.c:261-272
// ---------------------------------------------------------------------------

/// Errors arising from format parsing or validation.
///
/// Replaces manual error message construction in `opt_format_error()`
/// from `opt.c:261-272` and `print_format_error()` from `opt.c:388-397`.
#[derive(Debug, Error)]
pub enum FormatError {
    /// A known format was provided but is not supported in this context.
    ///
    /// Carries the format name and a comma-separated list of valid formats
    /// derived from the [`FormatFlags`] bitmask for the current command.
    #[error("unsupported format '{format}'; must be one of: {valid_formats}")]
    UnsupportedFormat {
        /// The format the user provided.
        format: String,
        /// Comma-separated list of formats that are valid in this context.
        valid_formats: String,
    },

    /// An unrecognised format string was provided.
    #[error("unknown format: {0}")]
    UnknownFormat(String),
}

// ---------------------------------------------------------------------------
// Format enum — replaces FORMAT_* constants from fmt.h
// ---------------------------------------------------------------------------

/// I/O format for keys, certificates, and other cryptographic objects.
///
/// Replaces C's `FORMAT_*` constants from `apps/include/fmt.h`:
///
/// | C Constant       | Value | Rust Variant |
/// |------------------|-------|--------------|
/// | `FORMAT_PEM`     | 5 or B | [`Pem`](Format::Pem)     |
/// | `FORMAT_ASN1`    | 4     | [`Der`](Format::Der)     |
/// | `FORMAT_BASE64`  | 3 or B | [`Base64`](Format::Base64) |
/// | `FORMAT_PKCS12`  | 6     | [`Pkcs12`](Format::Pkcs12) |
/// | `FORMAT_SMIME`   | 7 or B | [`Smime`](Format::Smime)   |
/// | `FORMAT_MSBLOB`  | 11    | [`MsBlob`](Format::MsBlob) |
/// | `FORMAT_PVK`     | 12    | [`Pvk`](Format::Pvk)       |
/// | `FORMAT_HTTP`    | 13    | [`Http`](Format::Http)     |
/// | `FORMAT_NSS`     | 14    | [`Nss`](Format::Nss)       |
/// | `FORMAT_TEXT`     | 1 or B | [`Text`](Format::Text)     |
///
/// ## Usage with clap
///
/// Used in command structs via `#[arg(value_enum)]`:
/// ```rust,ignore
/// #[arg(short, long, default_value_t = Format::Pem)]
/// inform: Format,
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum Format {
    /// PEM format (Base64-encoded with header/footer lines).
    Pem,
    /// DER format (raw ASN.1 binary encoding).
    Der,
    /// Base64-encoded (no PEM header/footer).
    Base64,
    /// PKCS#12 archive format.
    Pkcs12,
    /// S/MIME format.
    Smime,
    /// Microsoft blob format.
    MsBlob,
    /// PVK (Microsoft private key) format.
    Pvk,
    /// HTTP download format.
    Http,
    /// NSS key log format.
    Nss,
    /// Human-readable plain text format.
    Text,
}

impl Format {
    /// Returns `true` if this format is text-based.
    ///
    /// Text formats use text-mode I/O (e.g. line-ending conversion on Windows).
    ///
    /// Replaces `FMT_istext()` from `fmt.c:12-15` and the `B_FORMAT_TEXT`
    /// bitmask (`0x8000`) from `fmt.h`.
    ///
    /// The following formats are text-based:
    /// [`Pem`](Format::Pem), [`Base64`](Format::Base64),
    /// [`Smime`](Format::Smime), [`Text`](Format::Text),
    /// [`Nss`](Format::Nss).
    #[must_use]
    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Self::Pem | Self::Base64 | Self::Smime | Self::Text | Self::Nss
        )
    }

    /// Validates that this format is permitted by the given [`FormatFlags`].
    ///
    /// Replaces the per-format `(flags & OPT_FMT_X) == 0` checks in
    /// `opt_format()` from `opt.c:275-358`.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::UnsupportedFormat`] with a descriptive message
    /// listing all valid formats when this format is not among those allowed
    /// by `flags`.
    pub fn matches_flags(&self, flags: FormatFlags) -> Result<(), FormatError> {
        let flag = self.to_format_flag();
        if flags.contains(flag) {
            Ok(())
        } else {
            Err(FormatError::UnsupportedFormat {
                format: self.to_string(),
                valid_formats: format_flags_to_names(flags),
            })
        }
    }

    /// Maps this format variant to its corresponding single [`FormatFlags`] bit.
    fn to_format_flag(self) -> FormatFlags {
        match self {
            Self::Pem => FormatFlags::PEM,
            Self::Der => FormatFlags::DER,
            Self::Base64 => FormatFlags::B64,
            Self::Pkcs12 => FormatFlags::PKCS12,
            Self::Smime => FormatFlags::SMIME,
            Self::MsBlob => FormatFlags::MSBLOB,
            Self::Pvk => FormatFlags::PVK,
            Self::Http => FormatFlags::HTTP,
            Self::Nss => FormatFlags::NSS,
            Self::Text => FormatFlags::TEXT,
        }
    }
}

/// Display implementation returning uppercase format names.
///
/// Replaces `format2str()` from `opt.c:361-385`.
///
/// Note: PKCS#12 is displayed as `"P12"` to match the C implementation.
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Pem => "PEM",
            Self::Der => "DER",
            Self::Base64 => "BASE64",
            Self::Pkcs12 => "P12",
            Self::Smime => "SMIME",
            Self::MsBlob => "MSBLOB",
            Self::Pvk => "PVK",
            Self::Http => "HTTP",
            Self::Nss => "NSS",
            Self::Text => "TEXT",
        };
        f.write_str(name)
    }
}

/// Parse a format from a string (case-insensitive).
///
/// Replaces `opt_format()` from `opt.c:275-358` with its complex
/// switch-case character matching. Supports the same abbreviations:
///
/// | Input (case-insensitive) | Result |
/// |--------------------------|--------|
/// | `"pem"`, `"p"`           | [`Pem`](Format::Pem) |
/// | `"der"`, `"d"`           | [`Der`](Format::Der) |
/// | `"b64"`, `"base64"`, `"b"` | [`Base64`](Format::Base64) |
/// | `"pkcs12"`, `"p12"`, `"1"` | [`Pkcs12`](Format::Pkcs12) |
/// | `"smime"`, `"s"`         | [`Smime`](Format::Smime) |
/// | `"msblob"`, `"m"`        | [`MsBlob`](Format::MsBlob) |
/// | `"pvk"`                  | [`Pvk`](Format::Pvk) |
/// | `"http"`, `"h"`          | [`Http`](Format::Http) |
/// | `"nss"`, `"n"`           | [`Nss`](Format::Nss) |
/// | `"text"`, `"t"`          | [`Text`](Format::Text) |
impl FromStr for Format {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "pem" | "p" => Ok(Self::Pem),
            "der" | "d" => Ok(Self::Der),
            "b64" | "base64" | "b" => Ok(Self::Base64),
            "pkcs12" | "p12" | "1" => Ok(Self::Pkcs12),
            "smime" | "s" => Ok(Self::Smime),
            "msblob" | "m" => Ok(Self::MsBlob),
            "pvk" => Ok(Self::Pvk),
            "http" | "h" => Ok(Self::Http),
            "nss" | "n" => Ok(Self::Nss),
            "text" | "t" => Ok(Self::Text),
            _ => Err(FormatError::UnknownFormat(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// FormatFlags — replaces OPT_FMT_* bitmask from opt.h
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags indicating which formats are acceptable for a given option.
    ///
    /// Replaces C's `OPT_FMT_*` constants from `opt.h`.
    /// Used to validate that a user-specified format is acceptable
    /// for a particular command/option context.
    ///
    /// ## Predefined Combinations
    ///
    /// | Constant | Meaning                         |
    /// |----------|---------------------------------|
    /// | [`PDE`](FormatFlags::PDE) | PEM + DER (most key/cert ops) |
    /// | [`PDS`](FormatFlags::PDS) | PEM + DER + S/MIME            |
    /// | [`ANY`](FormatFlags::ANY) | All commonly-used formats     |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FormatFlags: u32 {
        /// PEM format accepted (`OPT_FMT_PEM`).
        const PEM    = 0x0001;
        /// DER format accepted (`OPT_FMT_DER`).
        const DER    = 0x0002;
        /// Base64 format accepted (`OPT_FMT_B64`).
        const B64    = 0x0004;
        /// PKCS#12 format accepted (`OPT_FMT_PKCS12`).
        const PKCS12 = 0x0008;
        /// S/MIME format accepted (`OPT_FMT_SMIME`).
        const SMIME  = 0x0010;
        /// Microsoft blob format accepted (`OPT_FMT_MSBLOB`).
        const MSBLOB = 0x0020;
        /// NSS key log format accepted (`OPT_FMT_NSS`).
        const NSS    = 0x0040;
        /// Text format accepted (`OPT_FMT_TEXT`).
        const TEXT   = 0x0080;
        /// HTTP format accepted (`OPT_FMT_HTTP`).
        const HTTP   = 0x0100;
        /// PVK format accepted (`OPT_FMT_PVK`).
        const PVK    = 0x0200;

        // Common combinations used by commands:

        /// PEM + DER — used by most key/certificate operations.
        const PDE = Self::PEM.bits() | Self::DER.bits();
        /// PEM + DER + S/MIME.
        const PDS = Self::PEM.bits() | Self::DER.bits() | Self::SMIME.bits();
        /// All commonly-used formats (PEM, DER, Base64, PKCS#12, S/MIME,
        /// Microsoft blob, PVK).
        const ANY = Self::PEM.bits() | Self::DER.bits() | Self::B64.bits()
                  | Self::PKCS12.bits() | Self::SMIME.bits()
                  | Self::MSBLOB.bits() | Self::PVK.bits();
    }
}

/// Builds a comma-separated list of format names enabled in the given flags.
///
/// Used internally by [`Format::matches_flags`] to produce helpful error
/// messages listing all valid formats for a given command context.
fn format_flags_to_names(flags: FormatFlags) -> String {
    let mapping: &[(FormatFlags, &str)] = &[
        (FormatFlags::PEM, "PEM"),
        (FormatFlags::DER, "DER"),
        (FormatFlags::B64, "BASE64"),
        (FormatFlags::PKCS12, "P12"),
        (FormatFlags::SMIME, "SMIME"),
        (FormatFlags::MSBLOB, "MSBLOB"),
        (FormatFlags::NSS, "NSS"),
        (FormatFlags::TEXT, "TEXT"),
        (FormatFlags::HTTP, "HTTP"),
        (FormatFlags::PVK, "PVK"),
    ];
    let names: Vec<&str> = mapping
        .iter()
        .filter(|(flag, _)| flags.contains(*flag))
        .map(|(_, name)| *name)
        .collect();
    names.join(", ")
}

// ---------------------------------------------------------------------------
// VerifyParams — replaces OPT_V_OPTIONS macro + opt_verify()
// ---------------------------------------------------------------------------

/// X.509 certificate chain verification parameters.
///
/// Replaces the `OPT_V_OPTIONS` macro from `opt.h:36-85` and the
/// `opt_verify()` function from `opt.c:709-936` (a 227-line switch
/// statement mapping CLI flags to `X509_VERIFY_PARAM_*` calls).
///
/// ## Usage with clap
///
/// Flattened into command structs:
/// ```rust,ignore
/// #[derive(clap::Parser)]
/// struct VerifyCmd {
///     #[command(flatten)]
///     verify: VerifyParams,
/// }
/// ```
///
/// ## Design Notes
///
/// - **Rule R5 (Nullability):** Every optional value uses `Option<T>` —
///   no sentinel `0` / `-1` values.
/// - **Rule R6 (Lossless Casts):** `verify_depth` and `auth_level` are
///   `u32`, not bare `int`.
// Justification: this struct mirrors the 27+ boolean CLI flags from the C
// OPT_V_OPTIONS macro. Each bool is an independent verification toggle
// controlled by a separate `--flag` argument.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct VerifyParams {
    /// Certificate policy OID(s) to add to the acceptable policy set.
    ///
    /// Replaces: `OPT_V_POLICY` from `opt.h`.
    #[arg(long = "policy")]
    pub policy: Vec<String>,

    /// Certificate chain verification purpose.
    ///
    /// Replaces: `OPT_V_PURPOSE`.
    #[arg(long = "purpose")]
    pub purpose: Option<String>,

    /// Verification policy name.
    ///
    /// Replaces: `OPT_V_VERIFY_NAME`.
    #[arg(long = "verify_name")]
    pub verify_name: Option<String>,

    /// Maximum chain verification depth.
    ///
    /// Replaces: `OPT_V_VERIFY_DEPTH`.
    #[arg(long = "verify_depth")]
    pub verify_depth: Option<u32>,

    /// Chain authentication security level.
    ///
    /// Replaces: `OPT_V_VERIFY_AUTH_LEVEL`.
    #[arg(long = "auth_level")]
    pub auth_level: Option<u32>,

    /// Verification epoch time (Unix timestamp).
    ///
    /// Replaces: `OPT_V_ATTIME`.
    #[arg(long = "attime")]
    pub attime: Option<i64>,

    /// Expected peer hostname for verification.
    ///
    /// Replaces: `OPT_V_VERIFY_HOSTNAME`.
    #[arg(long = "verify_hostname")]
    pub verify_hostname: Option<String>,

    /// Expected peer email for verification.
    ///
    /// Replaces: `OPT_V_VERIFY_EMAIL`.
    #[arg(long = "verify_email")]
    pub verify_email: Option<String>,

    /// Expected peer IP address for verification.
    ///
    /// Replaces: `OPT_V_VERIFY_IP`.
    #[arg(long = "verify_ip")]
    pub verify_ip: Option<String>,

    /// Permit unhandled critical extensions.
    ///
    /// Replaces: `OPT_V_IGNORE_CRITICAL`.
    #[arg(long)]
    pub ignore_critical: bool,

    /// Check leaf certificate revocation via CRL.
    ///
    /// Replaces: `OPT_V_CRL_CHECK`.
    #[arg(long)]
    pub crl_check: bool,

    /// Check full chain revocation via CRL.
    ///
    /// Replaces: `OPT_V_CRL_CHECK_ALL`.
    #[arg(long)]
    pub crl_check_all: bool,

    /// Perform RFC 5280 policy checks.
    ///
    /// Replaces: `OPT_V_POLICY_CHECK`.
    #[arg(long)]
    pub policy_check: bool,

    /// Set explicit policy requirement.
    ///
    /// Replaces: `OPT_V_EXPLICIT_POLICY`.
    #[arg(long)]
    pub explicit_policy: bool,

    /// Inhibit any-policy extension.
    ///
    /// Replaces: `OPT_V_INHIBIT_ANY`.
    #[arg(long)]
    pub inhibit_any: bool,

    /// Inhibit policy mapping.
    ///
    /// Replaces: `OPT_V_INHIBIT_MAP`.
    #[arg(long)]
    pub inhibit_map: bool,

    /// Disable certificate compatibility work-arounds.
    ///
    /// Replaces: `OPT_V_X509_STRICT`.
    #[arg(long)]
    pub x509_strict: bool,

    /// Enable extended CRL features.
    ///
    /// Replaces: `OPT_V_EXTENDED_CRL`.
    #[arg(long)]
    pub extended_crl: bool,

    /// Use delta CRLs.
    ///
    /// Replaces: `OPT_V_USE_DELTAS`.
    #[arg(long)]
    pub use_deltas: bool,

    /// Print policy processing diagnostics.
    ///
    /// Replaces: `OPT_V_POLICY_PRINT`.
    #[arg(long)]
    pub policy_print: bool,

    /// Check root CA self-signatures.
    ///
    /// Replaces: `OPT_V_CHECK_SS_SIG`.
    #[arg(long)]
    pub check_ss_sig: bool,

    /// Search trust store first.
    ///
    /// Replaces: `OPT_V_TRUSTED_FIRST`.
    #[arg(long)]
    pub trusted_first: bool,

    /// Accept chains anchored by intermediate trust-store CAs.
    ///
    /// Replaces: `OPT_V_PARTIAL_CHAIN`.
    #[arg(long)]
    pub partial_chain: bool,

    /// Ignore certificate validity time.
    ///
    /// Replaces: `OPT_V_NO_CHECK_TIME`.
    #[arg(long)]
    pub no_check_time: bool,

    /// Allow proxy certificates.
    ///
    /// Replaces: `OPT_V_ALLOW_PROXY_CERTS`.
    #[arg(long)]
    pub allow_proxy_certs: bool,

    /// Suite B 128-bit-only mode.
    ///
    /// Replaces: `OPT_V_SUITEB_128_ONLY`.
    #[arg(long = "suiteB_128_only")]
    pub suite_b_128_only: bool,

    /// Suite B 128-bit mode (also allowing 192-bit).
    ///
    /// Replaces: `OPT_V_SUITEB_128`.
    #[arg(long = "suiteB_128")]
    pub suite_b_128: bool,

    /// Suite B 192-bit-only mode.
    ///
    /// Replaces: `OPT_V_SUITEB_192`.
    #[arg(long = "suiteB_192")]
    pub suite_b_192: bool,
}

// ---------------------------------------------------------------------------
// DisplayColumns + calculate_columns — replaces columns.c
// ---------------------------------------------------------------------------

/// Column layout parameters for help output.
///
/// Replaces C's `DISPLAY_COLUMNS` from `function.h` and
/// `calculate_columns()` from `columns.c:14-26`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayColumns {
    /// Width of each column (including padding).
    pub width: usize,
    /// Number of columns that fit in an 80-character terminal.
    pub columns: usize,
}

/// Calculate column layout for a list of names.
///
/// Replaces `calculate_columns()` from `columns.c:14-26`:
/// ```c
/// dc->width = maxlen + 2;
/// dc->columns = (80 - 1) / dc->width;
/// ```
///
/// Uses `usize` arithmetic exclusively — no narrowing casts (Rule R6).
///
/// # Arguments
///
/// * `names` — Iterator of command/algorithm names to lay out.
///
/// # Returns
///
/// Column layout parameters for 80-column terminal display. Returns
/// at least 1 column even when all names are extremely long.
pub fn calculate_columns<'a>(names: impl Iterator<Item = &'a str>) -> DisplayColumns {
    let maxlen = names.map(str::len).max().unwrap_or(0);
    let width = maxlen.saturating_add(2);
    // (80 - 1) / width, ensuring at least 1 column
    let columns = if width == 0 {
        1
    } else {
        (TERMINAL_WIDTH.saturating_sub(1) / width).max(1)
    };
    DisplayColumns { width, columns }
}

// ---------------------------------------------------------------------------
// Name collection and printing — replaces names.c
// ---------------------------------------------------------------------------

/// Case-insensitive name comparison.
///
/// Replaces `name_cmp()` from `names.c:16-19` which used
/// `OPENSSL_strcasecmp`.
///
/// Compares the ASCII-lowercased forms of both strings so that
/// algorithm names sort naturally regardless of case (e.g.
/// `"AES-128-CBC"` groups with `"aes-128-cbc"`).
#[must_use]
pub fn name_cmp(a: &str, b: &str) -> Ordering {
    // Compare byte-by-byte to avoid allocating lowercased strings.
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = a_bytes.len().min(b_bytes.len());
    for i in 0..min_len {
        let ca = a_bytes[i].to_ascii_lowercase();
        let cb = b_bytes[i].to_ascii_lowercase();
        match ca.cmp(&cb) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a_bytes.len().cmp(&b_bytes.len())
}

/// Collect names, sort case-insensitively, and print with brace formatting.
///
/// Replaces `collect_names()` and `print_names()` from `names.c` (46 lines).
///
/// Output format (matching C behaviour):
/// - Single name: `name`
/// - Multiple names: `{ name1, name2, name3 }`
///
/// # Arguments
///
/// * `out` — Output writer.
/// * `names` — Mutable slice of names to sort in-place and print.
///
/// # Errors
///
/// Returns an I/O error if writing to `out` fails.
pub fn print_names(out: &mut dyn Write, names: &mut [&str]) -> io::Result<()> {
    names.sort_by(|a, b| name_cmp(a, b));
    let count = names.len();
    if count > 1 {
        write!(out, "{{ ")?;
    }
    for (idx, name) in names.iter().enumerate() {
        if idx > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{name}")?;
    }
    if count > 1 {
        write!(out, " }}")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ParamType / ParamValue — replaces OSSL_PARAM display from app_params.c
// ---------------------------------------------------------------------------

/// Parameter data type for display purposes.
///
/// Replaces C's `OSSL_PARAM` `data_type` constants used in
/// `app_params.c`'s `describe_param_type()` and `print_param_value()`.
///
/// | C Constant                    | Rust Variant     |
/// |-------------------------------|------------------|
/// | `OSSL_PARAM_INTEGER`          | [`Integer`](ParamType::Integer) |
/// | `OSSL_PARAM_UNSIGNED_INTEGER` | [`UnsignedInteger`](ParamType::UnsignedInteger) |
/// | `OSSL_PARAM_UTF8_STRING`      | [`Utf8String`](ParamType::Utf8String) |
/// | `OSSL_PARAM_UTF8_PTR`         | [`Utf8Ptr`](ParamType::Utf8Ptr) |
/// | `OSSL_PARAM_OCTET_STRING`     | [`OctetString`](ParamType::OctetString) |
/// | `OSSL_PARAM_OCTET_PTR`        | [`OctetPtr`](ParamType::OctetPtr) |
/// | (other)                       | [`Unknown`](ParamType::Unknown) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// Signed integer parameter.
    Integer,
    /// Unsigned integer parameter.
    UnsignedInteger,
    /// UTF-8 string (value stored inline).
    Utf8String,
    /// Pointer to a UTF-8 string (value stored externally).
    Utf8Ptr,
    /// Octet string (value stored inline).
    OctetString,
    /// Pointer to an octet string (value stored externally).
    OctetPtr,
    /// Unknown or unrecognised parameter type with its raw type code.
    Unknown(u32),
}

/// Typed parameter value for display purposes.
///
/// Represents the concrete value held by a provider parameter, used by
/// [`print_param_value`] to render human-readable output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    /// Signed integer value.
    Integer(i64),
    /// Unsigned integer value.
    UnsignedInteger(u64),
    /// UTF-8 string value.
    Utf8String(String),
    /// Octet string (raw bytes).
    OctetString(Vec<u8>),
}

/// Describe a parameter's type for human-readable output.
///
/// Replaces `describe_param_type()` from `app_params.c:16-76`.
///
/// Produces strings like:
/// - `"key: integer (max 8 bytes large)"`
/// - `"key: unsigned integer (max 8 bytes large)"`
/// - `"key: pointer to a UTF8 encoded string (arbitrary size)"`
/// - `"key: octet string (max 32 bytes large)"`
/// - `"key: unknown type [42] (arbitrary size)"`
///
/// # Arguments
///
/// * `key` — Parameter name.
/// * `param_type` — Parameter data type.
/// * `data_size` — Maximum data size in bytes; `0` means arbitrary size.
#[must_use]
pub fn describe_param_type(key: &str, param_type: ParamType, data_size: usize) -> String {
    let (type_mod, type_name, show_type_number) = match param_type {
        ParamType::UnsignedInteger => ("unsigned ", "integer", None),
        ParamType::Integer => ("", "integer", None),
        ParamType::Utf8Ptr => ("pointer to a ", "UTF8 encoded string", None),
        ParamType::Utf8String => ("", "UTF8 encoded string", None),
        ParamType::OctetPtr => ("pointer to an ", "octet string", None),
        ParamType::OctetString => ("", "octet string", None),
        ParamType::Unknown(code) => ("", "unknown type", Some(code)),
    };

    let mut desc = format!("{key}: {type_mod}{type_name}");

    if let Some(code) = show_type_number {
        use std::fmt::Write as _;
        // Infallible write to String — ignoring the result is safe.
        let _ = write!(desc, " [{code}]");
    }

    if data_size == 0 {
        desc.push_str(" (arbitrary size)");
    } else {
        use std::fmt::Write as _;
        // Infallible write to String — ignoring the result is safe.
        let _ = write!(desc, " (max {data_size} bytes large)");
    }

    desc
}

/// Print a list of parameter type definitions.
///
/// Replaces `print_param_types()` from `app_params.c:78-98`.
///
/// Output format:
/// ```text
///   Settable parameters:
///     key: UTF8 encoded string (max 64 bytes large)
///     size: unsigned integer (max 8 bytes large)
/// ```
///
/// # Arguments
///
/// * `out` — Output writer.
/// * `thing` — Label for the parameter list (e.g. `"Gettable"`, `"Settable"`).
/// * `params` — Slice of `(key, type, size)` tuples describing each parameter.
/// * `indent` — Number of spaces to indent each line.
///
/// # Errors
///
/// Returns an I/O error if writing to `out` fails.
pub fn print_param_types(
    out: &mut dyn Write,
    thing: &str,
    params: &[(String, ParamType, usize)],
    indent: usize,
) -> io::Result<()> {
    if params.is_empty() {
        return Ok(());
    }
    writeln!(out, "{:indent$}{thing} parameters:", "", indent = indent)?;
    let inner_indent = indent.saturating_add(2);
    for (key, param_type, data_size) in params {
        let desc = describe_param_type(key, *param_type, *data_size);
        writeln!(out, "{:indent$}{desc}", "", indent = inner_indent)?;
    }
    Ok(())
}

/// Print a parameter's value in human-readable format.
///
/// Replaces `print_param_value()` from `app_params.c:150-186`.
///
/// Handles:
/// - Integers: printed as decimal (`key: 12345`).
/// - Strings: printed with single quotes (`key: 'value'`).
/// - Octets: printed as hex with a byte count prefix and truncation at
///   24 bytes (`key: <32 bytes> aabbccdd...`).
///
/// # Arguments
///
/// * `out` — Output writer.
/// * `key` — Parameter name.
/// * `value` — Typed parameter value.
/// * `indent` — Number of spaces to indent the line.
///
/// # Errors
///
/// Returns an I/O error if writing to `out` fails.
pub fn print_param_value(
    out: &mut dyn Write,
    key: &str,
    value: &ParamValue,
    indent: usize,
) -> io::Result<()> {
    write!(out, "{:indent$}{key}: ", "", indent = indent)?;
    match value {
        ParamValue::Integer(i) => writeln!(out, "{i}"),
        ParamValue::UnsignedInteger(u) => writeln!(out, "{u}"),
        ParamValue::Utf8String(s) => writeln!(out, "'{s}'"),
        ParamValue::OctetString(bytes) => {
            let len = bytes.len();
            write!(out, "<{len} bytes>")?;
            if bytes.is_empty() {
                writeln!(out)
            } else {
                write!(out, " ")?;
                let display_len = len.min(MAX_OCTET_STRING_OUTPUT_BYTES);
                for b in &bytes[..display_len] {
                    write!(out, "{b:02x}")?;
                }
                if len > MAX_OCTET_STRING_OUTPUT_BYTES {
                    writeln!(out, "...")
                } else {
                    writeln!(out)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// opt_printf_stderr — replaces apps_opt_printf.c
// ---------------------------------------------------------------------------

/// Print a formatted error message to stderr with structured logging.
///
/// Replaces `opt_printf_stderr()` from `apps_opt_printf.c` (24 lines)
/// which was a thin wrapper around `BIO_vprintf(bio_err, ...)`.
///
/// In Rust, this is trivially `eprintln!()` — but we provide this
/// helper for consistency with C source tracing and for structured
/// logging integration via `tracing`.
///
/// Messages are emitted both to the `tracing` error span (for structured
/// log collection) and directly to stderr (for immediate user visibility).
pub fn opt_printf_stderr(msg: &str) {
    error!("{}", msg);
    eprintln!("{msg}");
}

// ---------------------------------------------------------------------------
// Diagnostic warning helper
// ---------------------------------------------------------------------------

/// Emit a diagnostic warning to the structured log.
///
/// Provides a tracing-integrated wrapper for non-fatal diagnostic messages
/// during option parsing or parameter inspection. Complements
/// [`opt_printf_stderr`] for non-error conditions.
pub fn opt_warn_diagnostic(msg: &str) {
    warn!("{}", msg);
}
