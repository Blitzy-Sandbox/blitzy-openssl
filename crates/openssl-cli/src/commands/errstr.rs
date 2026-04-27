//! `errstr` subcommand implementation.
//!
//! Decodes OpenSSL numeric error codes to human-readable error strings.
//! This is the Rust equivalent of the C `openssl errstr` command from
//! `apps/errstr.c`.
//!
//! # C Source Mapping
//!
//! | C Function / Pattern            | Rust Equivalent                           |
//! |---------------------------------|-------------------------------------------|
//! | `errstr_main()`                 | `ErrstrArgs::execute()`                 |
//! | `sscanf(*argv, "%lx", &l)`      | `u64::from_str_radix(s, 16)`              |
//! | `ERR_error_string_n(l, buf, …)` | `decode_error_code()` + `ErrorDetail` |
//! | `OPT_SECTION` / `OPTIONS[]`     | `#[derive(clap::Args)]`                   |
//! | `ERR_GET_LIB(l)`                | `library_from_code()`                   |
//! | `ERR_GET_REASON(l)`             | Bit masking: `code & ERR_REASON_MASK`     |
//!
//! # Error Code Bit Layout
//!
//! OpenSSL packs error information into a single `unsigned long` value
//! (see `include/openssl/err.h.in`, lines 203–215):
//!
//! ```text
//! Bit 31:      System error flag (ERR_SYSTEM_FLAG = 0x8000_0000)
//! Bits 23–30:  Library code     (ERR_LIB_OFFSET = 23, ERR_LIB_MASK = 0xFF)
//! Bits 18–22:  Reason flags     (ERR_RFLAGS_OFFSET = 18, ERR_RFLAGS_MASK = 0x1F)
//! Bits 0–22:   Reason code      (ERR_REASON_MASK = 0x7F_FFFF, 23 bits)
//! ```
//!
//! When bit 31 is set, the code represents an OS system error (`errno`)
//! and the library is implicitly `ERR_LIB_SYS`.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Uses `Option<T>` for optional data; no sentinel
//!   values. Invalid hex inputs produce a user-facing message rather than a
//!   numeric return code.
//! - **R6 (Lossless Casts):** All bit extractions operate on `u64` directly;
//!   no narrowing `as` casts. The `library_from_code()` function takes `u64`
//!   to avoid truncation.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no blanket `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `main()` via
//!   `CliCommand::Errstr(args) => args.execute(ctx).await` in `mod.rs`.

use std::io::Write;

use clap::Args;
use openssl_common::err_detail;
use openssl_common::error::{CryptoError, ErrorDetail, ErrorLibrary};
use openssl_crypto::context::LibContext;

// =============================================================================
// OpenSSL Error Code Bit Layout Constants
// =============================================================================
//
// Translated from `include/openssl/err.h.in` lines 203–215.
// These constants define how a packed error code encodes the library
// identifier, reason flags, and reason code into a single `u64`.

/// Bit flag indicating a system error (bit 31 of the packed code).
///
/// When set, the error represents an OS `errno` value and the library is
/// implicitly [`ErrorLibrary::Sys`].
///
/// C: `#define ERR_SYSTEM_FLAG ((unsigned int)INT_MAX + 1)`
const ERR_SYSTEM_FLAG: u64 = 0x8000_0000;

/// Mask for extracting the system error code (bits 0–30).
///
/// C: `#define ERR_SYSTEM_MASK ((unsigned int)INT_MAX)`
const ERR_SYSTEM_MASK: u64 = 0x7FFF_FFFF;

/// Bit offset for the library code field.
///
/// The library identifier occupies bits 23–30 (8 bits) of the packed code.
///
/// C: `#define ERR_LIB_OFFSET 23L`
const ERR_LIB_OFFSET: u32 = 23;

/// Mask for extracting the library code after shifting.
///
/// C: `#define ERR_LIB_MASK 0xFF`
const ERR_LIB_MASK: u64 = 0xFF;

/// Mask for extracting the reason code (bits 0–22, 23 bits).
///
/// Includes the reason flags in bits 18–22 as part of the full reason
/// value, matching the semantics of `ERR_GET_REASON()` in C.
///
/// C: `#define ERR_REASON_MASK 0X7FFFFF`
const ERR_REASON_MASK: u64 = 0x7F_FFFF;

// =============================================================================
// ErrstrArgs — CLI Argument Definition
// =============================================================================

/// Arguments for the `errstr` subcommand.
///
/// Accepts one or more hexadecimal error code strings on the command line
/// and decodes each into a human-readable error string, replicating the
/// behavior of the C `openssl errstr` command.
///
/// Replaces the C `OPTIONS[]` array and `opt_next()` loop from
/// `apps/errstr.c` (lines 23–36) with clap's declarative derive macro.
///
/// # Usage
///
/// ```text
/// openssl errstr <ERROR_CODE> [<ERROR_CODE> ...]
/// ```
///
/// Error codes may be specified with or without a `0x` prefix:
///
/// ```text
/// openssl errstr 1E08010C
/// openssl errstr 0x1408F10B 0x14090086
/// ```
///
/// # Output Format
///
/// Each successfully decoded code produces a line:
/// ```text
/// error:XXXXXXXX:library_name::reason(NNN)
/// ```
///
/// Invalid hex inputs produce:
/// ```text
/// <input>: bad error code
/// ```
#[derive(Args, Debug)]
pub struct ErrstrArgs {
    /// Hexadecimal error codes to decode.
    ///
    /// Each code is parsed as a hexadecimal value (with or without `0x`/`0X`
    /// prefix) and decoded into a human-readable error string showing the
    /// library and reason code components.
    ///
    /// Replaces the C `opt_rest()` positional argument parsing pattern from
    /// `apps/errstr.c`.
    #[arg(required = true, value_name = "ERROR_CODE")]
    error_codes: Vec<String>,
}

// =============================================================================
// ErrstrArgs — Command Execution
// =============================================================================

impl ErrstrArgs {
    /// Execute the `errstr` subcommand.
    ///
    /// For each error code argument, this method:
    ///
    /// 1. Strips an optional `0x` or `0X` prefix (matching C `sscanf("%lx")`
    ///    behavior which accepts both prefixed and unprefixed hex).
    /// 2. Parses the hex string into a `u64` packed error code.
    /// 3. Unpacks the library code and reason code using the OpenSSL bit
    ///    layout constants defined in `include/openssl/err.h.in`.
    /// 4. Maps the library code to an [`ErrorLibrary`] variant.
    /// 5. Constructs an `ErrorDetail` via the [`err_detail!`] macro for
    ///    structured logging and output formatting.
    /// 6. Prints the decoded error string to stdout.
    ///
    /// Invalid hex inputs produce a warning via [`tracing::warn!`] and a
    /// user-facing "bad error code" message, then processing continues with
    /// the remaining arguments. This matches the C implementation's behavior
    /// of incrementing `ret` for bad codes but continuing the loop.
    ///
    /// # Arguments
    ///
    /// * `_ctx` — Library context ([`LibContext`]), required by the dispatch
    ///   signature in `mod.rs`. In C, `errstr_main()` calls
    ///   `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS …)` to populate
    ///   the global error string table; in Rust, the error strings are
    ///   statically compiled into [`ErrorLibrary`]'s `Display` implementation,
    ///   so the context is not needed for string lookup.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] if writing to stdout fails. All hex parse
    /// failures are handled inline (warning + "bad error code" output) rather
    /// than propagated as errors, matching the C implementation's behavior.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        for code_str in &self.error_codes {
            // Strip optional "0x" or "0X" prefix.
            // C's sscanf("%lx", …) accepts both "0x1E08010C" and "1E08010C";
            // Rust's u64::from_str_radix requires the prefix to be removed.
            let hex_str = code_str
                .strip_prefix("0x")
                .or_else(|| code_str.strip_prefix("0X"))
                .unwrap_or(code_str);

            if let Ok(packed_code) = u64::from_str_radix(hex_str, 16) {
                // Decode the packed error code into structured components.
                let detail: ErrorDetail = decode_error_code(packed_code);

                tracing::debug!(
                    error_code = packed_code,
                    hex = %code_str,
                    library = %detail.library,
                    reason = %detail.reason,
                    "decoded error code"
                );

                // Output format matches C `ERR_error_string_n()`:
                //   error:XXXXXXXX:library_name::reason_string
                // The empty field between the two colons corresponds to the
                // deprecated function name field (always empty since
                // OpenSSL 3.0, see ERR_GET_FUNC → 0 in err.h.in).
                writeln!(
                    out,
                    "error:{packed_code:08X}:{}::{}",
                    detail.library, detail.reason
                )?;
            } else {
                tracing::warn!(
                    input = %code_str,
                    "invalid hexadecimal error code"
                );
                // Match C behavior: print the invalid input followed by
                // an error message, then continue processing.
                writeln!(out, "{code_str}: bad error code")?;
            }
        }

        Ok(())
    }
}

// =============================================================================
// Error Code Decoding — Private Helpers
// =============================================================================

/// Decodes a packed OpenSSL error code into an `ErrorDetail`.
///
/// Implements the equivalent of C's `ERR_error_string_n()` from
/// `crypto/err/err.c`. The packed error code uses the bit layout
/// defined in `include/openssl/err.h.in` (lines 203–215).
///
/// # System Errors
///
/// When bit 31 is set (`ERR_SYSTEM_FLAG`), the error represents an OS
/// system error (`errno`). The library is implicitly [`ErrorLibrary::Sys`]
/// and the reason code is the raw errno value (bits 0–30).
///
/// # Normal Errors
///
/// For non-system errors, the library code is extracted from bits 23–30
/// and the reason code from bits 0–22. The library code is mapped to an
/// [`ErrorLibrary`] variant via `library_from_code()`.
///
/// # Examples
///
/// ```ignore
/// // Library=0x3C (DECODER=60), Reason=0x10C
/// let detail = decode_error_code(0x1E00_010C);
/// // detail.library == ErrorLibrary::Decoder
/// // detail.reason == "reason(268)"
/// ```
fn decode_error_code(packed_code: u64) -> ErrorDetail {
    let is_system_error = (packed_code & ERR_SYSTEM_FLAG) != 0;

    let (library, reason_code) = if is_system_error {
        // System errors: library is implicitly SYS, reason is the OS errno.
        // C: `ERR_GET_LIB()` returns `ERR_LIB_SYS` when system flag is set.
        // C: `ERR_GET_REASON()` returns `errcode & ERR_SYSTEM_MASK`.
        (ErrorLibrary::Sys, packed_code & ERR_SYSTEM_MASK)
    } else {
        // Normal errors: extract library and reason from bit fields.
        // C: `ERR_GET_LIB()` = `(errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK`
        // C: `ERR_GET_REASON()` = `errcode & ERR_REASON_MASK`
        let lib_code = (packed_code >> ERR_LIB_OFFSET) & ERR_LIB_MASK;
        let reason = packed_code & ERR_REASON_MASK;
        (library_from_code(lib_code), reason)
    };

    // Format the reason string. System errors display the errno value;
    // normal errors display the reason code number. In the C implementation,
    // `ERR_error_string_n()` would look up a static reason string table;
    // here we display the numeric code since the full reason string table
    // is not yet loaded into the Rust workspace.
    let reason_string = if is_system_error {
        format!("system error {reason_code}")
    } else {
        format!("reason({reason_code})")
    };

    // Construct an ErrorDetail via the err_detail! macro, which captures
    // source location automatically (file!(), line!(), module_path!()).
    // This provides structured error information for tracing and diagnostics.
    err_detail!(library, reason_string)
}

/// Maps an OpenSSL library code number to an [`ErrorLibrary`] variant.
///
/// Library codes are defined as `ERR_LIB_*` constants in
/// `include/openssl/err.h.in` (lines 56–107). The mapping covers all
/// 42 library identifiers that have corresponding [`ErrorLibrary`] variants.
///
/// Codes without a matching Rust variant map to [`ErrorLibrary::None`]:
/// - `ERR_LIB_COMP = 41` (compression, removed in modern OpenSSL)
/// - `ERR_LIB_ECDSA = 42` (merged into EC in OpenSSL 1.1.0+)
/// - `ERR_LIB_ECDH = 43` (merged into EC in OpenSSL 1.1.0+)
/// - `ERR_LIB_PROP = 55` (internal property subsystem, not exposed)
///
/// # Arguments
///
/// * `code` — The 8-bit library code extracted from the packed error value.
///   Passed as `u64` to avoid a narrowing cast from the already-masked
///   extraction result, satisfying **Rule R6** (lossless numeric casts).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(library_from_code(4), ErrorLibrary::Rsa);
/// assert_eq!(library_from_code(20), ErrorLibrary::Ssl);
/// assert_eq!(library_from_code(255), ErrorLibrary::None); // unknown
/// ```
fn library_from_code(code: u64) -> ErrorLibrary {
    match code {
        // 1 = ERR_LIB_NONE — falls through to wildcard (same variant)
        2 => ErrorLibrary::Sys,
        3 => ErrorLibrary::Bn,
        4 => ErrorLibrary::Rsa,
        5 => ErrorLibrary::Dh,
        6 => ErrorLibrary::Evp,
        7 => ErrorLibrary::Buf,
        8 => ErrorLibrary::Obj,
        9 => ErrorLibrary::Pem,
        10 => ErrorLibrary::Dsa,
        11 => ErrorLibrary::X509,
        // 12 = ERR_LIB_METH — removed, no variant
        13 => ErrorLibrary::Asn1,
        14 => ErrorLibrary::Conf,
        15 => ErrorLibrary::Crypto,
        16 => ErrorLibrary::Ec,
        // 17–19 = unassigned
        20 => ErrorLibrary::Ssl,
        // 21–31 = unassigned / removed (SSL23, SSL2, SSL3, RSAREF, PROXY)
        32 => ErrorLibrary::Bio,
        33 => ErrorLibrary::Pkcs7,
        34 => ErrorLibrary::X509v3,
        35 => ErrorLibrary::Pkcs12,
        36 => ErrorLibrary::Rand,
        37 => ErrorLibrary::Dso,
        38 => ErrorLibrary::Engine,
        39 => ErrorLibrary::Ocsp,
        40 => ErrorLibrary::Ui,
        // 41 = ERR_LIB_COMP — no Rust variant (compression removed)
        // 42 = ERR_LIB_ECDSA — merged into EC
        // 43 = ERR_LIB_ECDH — merged into EC
        44 => ErrorLibrary::Store,
        45 => ErrorLibrary::Fips,
        46 => ErrorLibrary::Cms,
        47 => ErrorLibrary::Ts,
        48 => ErrorLibrary::Hmac,
        // 49 = ERR_LIB_JPAKE — removed
        50 => ErrorLibrary::Ct,
        51 => ErrorLibrary::Async,
        52 => ErrorLibrary::Kdf,
        53 => ErrorLibrary::Sm2,
        54 => ErrorLibrary::Ess,
        // 55 = ERR_LIB_PROP — internal, no Rust variant
        56 => ErrorLibrary::Crmf,
        57 => ErrorLibrary::Provider,
        58 => ErrorLibrary::Cmp,
        59 => ErrorLibrary::Encoder,
        60 => ErrorLibrary::Decoder,
        61 => ErrorLibrary::Http,
        // 128 = ERR_LIB_USER — user-defined, maps to None
        _ => ErrorLibrary::None,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // library_from_code tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_library_from_code_known_libraries() {
        assert_eq!(library_from_code(1), ErrorLibrary::None);
        assert_eq!(library_from_code(2), ErrorLibrary::Sys);
        assert_eq!(library_from_code(3), ErrorLibrary::Bn);
        assert_eq!(library_from_code(4), ErrorLibrary::Rsa);
        assert_eq!(library_from_code(5), ErrorLibrary::Dh);
        assert_eq!(library_from_code(6), ErrorLibrary::Evp);
        assert_eq!(library_from_code(7), ErrorLibrary::Buf);
        assert_eq!(library_from_code(8), ErrorLibrary::Obj);
        assert_eq!(library_from_code(9), ErrorLibrary::Pem);
        assert_eq!(library_from_code(10), ErrorLibrary::Dsa);
        assert_eq!(library_from_code(11), ErrorLibrary::X509);
        assert_eq!(library_from_code(13), ErrorLibrary::Asn1);
        assert_eq!(library_from_code(14), ErrorLibrary::Conf);
        assert_eq!(library_from_code(15), ErrorLibrary::Crypto);
        assert_eq!(library_from_code(16), ErrorLibrary::Ec);
        assert_eq!(library_from_code(20), ErrorLibrary::Ssl);
        assert_eq!(library_from_code(32), ErrorLibrary::Bio);
        assert_eq!(library_from_code(33), ErrorLibrary::Pkcs7);
        assert_eq!(library_from_code(34), ErrorLibrary::X509v3);
        assert_eq!(library_from_code(35), ErrorLibrary::Pkcs12);
        assert_eq!(library_from_code(36), ErrorLibrary::Rand);
        assert_eq!(library_from_code(37), ErrorLibrary::Dso);
        assert_eq!(library_from_code(38), ErrorLibrary::Engine);
        assert_eq!(library_from_code(39), ErrorLibrary::Ocsp);
        assert_eq!(library_from_code(40), ErrorLibrary::Ui);
        assert_eq!(library_from_code(44), ErrorLibrary::Store);
        assert_eq!(library_from_code(45), ErrorLibrary::Fips);
        assert_eq!(library_from_code(46), ErrorLibrary::Cms);
        assert_eq!(library_from_code(47), ErrorLibrary::Ts);
        assert_eq!(library_from_code(48), ErrorLibrary::Hmac);
        assert_eq!(library_from_code(50), ErrorLibrary::Ct);
        assert_eq!(library_from_code(51), ErrorLibrary::Async);
        assert_eq!(library_from_code(52), ErrorLibrary::Kdf);
        assert_eq!(library_from_code(53), ErrorLibrary::Sm2);
        assert_eq!(library_from_code(54), ErrorLibrary::Ess);
        assert_eq!(library_from_code(56), ErrorLibrary::Crmf);
        assert_eq!(library_from_code(57), ErrorLibrary::Provider);
        assert_eq!(library_from_code(58), ErrorLibrary::Cmp);
        assert_eq!(library_from_code(59), ErrorLibrary::Encoder);
        assert_eq!(library_from_code(60), ErrorLibrary::Decoder);
        assert_eq!(library_from_code(61), ErrorLibrary::Http);
    }

    #[test]
    fn test_library_from_code_unknown_codes() {
        // Gaps in the numbering should map to None
        assert_eq!(library_from_code(0), ErrorLibrary::None);
        assert_eq!(library_from_code(12), ErrorLibrary::None); // ERR_LIB_METH removed
        assert_eq!(library_from_code(17), ErrorLibrary::None); // unassigned
        assert_eq!(library_from_code(41), ErrorLibrary::None); // ERR_LIB_COMP
        assert_eq!(library_from_code(42), ErrorLibrary::None); // ERR_LIB_ECDSA
        assert_eq!(library_from_code(43), ErrorLibrary::None); // ERR_LIB_ECDH
        assert_eq!(library_from_code(55), ErrorLibrary::None); // ERR_LIB_PROP
        assert_eq!(library_from_code(128), ErrorLibrary::None); // ERR_LIB_USER
        assert_eq!(library_from_code(255), ErrorLibrary::None); // max 8-bit value
    }

    // -------------------------------------------------------------------------
    // decode_error_code tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_decode_normal_error_code() {
        // Pack: library=RSA(4), reason=0x10C (268)
        // Packed = (4 << 23) | 0x10C = 0x0200_010C
        let packed = (4_u64 << ERR_LIB_OFFSET) | 0x10C;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Rsa);
        assert_eq!(detail.reason, "reason(268)");
        assert!(detail.data.is_none());
    }

    #[test]
    fn test_decode_ssl_error_code() {
        // Pack: library=SSL(20), reason=0x86 (134)
        // Packed = (20 << 23) | 0x86 = 0x0A00_0086
        let packed = (20_u64 << ERR_LIB_OFFSET) | 0x86;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Ssl);
        assert_eq!(detail.reason, "reason(134)");
    }

    #[test]
    fn test_decode_decoder_error_code() {
        // Pack: library=DECODER(60=0x3C), reason=0x10C (268)
        // Packed = (0x3C << 23) | 0x10C = 0x1E00_010C
        let packed = (60_u64 << ERR_LIB_OFFSET) | 0x10C;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Decoder);
        assert_eq!(detail.reason, "reason(268)");
    }

    #[test]
    fn test_decode_system_error() {
        // System error: bit 31 set, errno = 2 (ENOENT)
        let packed = ERR_SYSTEM_FLAG | 2;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Sys);
        assert_eq!(detail.reason, "system error 2");
    }

    #[test]
    fn test_decode_system_error_large_errno() {
        // System error with large errno value
        let packed = ERR_SYSTEM_FLAG | 0x7FFF_FFFF;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Sys);
        assert_eq!(detail.reason, format!("system error {}", 0x7FFF_FFFFu64));
    }

    #[test]
    fn test_decode_zero_error_code() {
        let detail = decode_error_code(0);
        assert_eq!(detail.library, ErrorLibrary::None);
        assert_eq!(detail.reason, "reason(0)");
    }

    #[test]
    fn test_decode_unknown_library() {
        // Library code 255 (unassigned), reason 1
        let packed = (255_u64 << ERR_LIB_OFFSET) | 1;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::None);
        assert_eq!(detail.reason, "reason(1)");
    }

    #[test]
    fn test_decode_reason_mask_boundary() {
        // Maximum reason code: 0x7F_FFFF (23 bits, all ones)
        let packed = (6_u64 << ERR_LIB_OFFSET) | ERR_REASON_MASK;
        let detail = decode_error_code(packed);
        assert_eq!(detail.library, ErrorLibrary::Evp);
        assert_eq!(detail.reason, format!("reason({})", ERR_REASON_MASK));
    }

    // -------------------------------------------------------------------------
    // ErrorDetail formatting tests (via Display)
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_detail_display_format() {
        let detail = decode_error_code((4_u64 << ERR_LIB_OFFSET) | 0x10C);
        let display = format!("{detail}");
        // ErrorDetail Display: "library:reason:file:line:function"
        assert!(display.contains("rsa routines"));
        assert!(display.contains("reason(268)"));
    }

    // -------------------------------------------------------------------------
    // Bit layout constant sanity tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_bit_layout_constants() {
        // Verify constants match the C header definitions
        assert_eq!(ERR_SYSTEM_FLAG, 0x8000_0000);
        assert_eq!(ERR_SYSTEM_MASK, 0x7FFF_FFFF);
        assert_eq!(ERR_LIB_OFFSET, 23);
        assert_eq!(ERR_LIB_MASK, 0xFF);
        assert_eq!(ERR_REASON_MASK, 0x7F_FFFF);

        // Verify no overlap between system flag and normal fields
        assert_eq!(ERR_SYSTEM_FLAG & ERR_SYSTEM_MASK, 0);

        // Verify library field and reason field don't overlap
        let lib_field = ERR_LIB_MASK << ERR_LIB_OFFSET;
        assert_eq!(lib_field & ERR_REASON_MASK, 0);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        // Verify that packing and unpacking produce consistent results.
        // C: ERR_PACK(lib, func, reason) = ((lib & 0xFF) << 23) | (reason & 0x7FFFFF)
        let lib: u64 = 57; // ERR_LIB_PROV
        let reason: u64 = 0x123;
        let packed = (lib << ERR_LIB_OFFSET) | reason;

        let extracted_lib = (packed >> ERR_LIB_OFFSET) & ERR_LIB_MASK;
        let extracted_reason = packed & ERR_REASON_MASK;

        assert_eq!(extracted_lib, lib);
        assert_eq!(extracted_reason, reason);
    }
}
