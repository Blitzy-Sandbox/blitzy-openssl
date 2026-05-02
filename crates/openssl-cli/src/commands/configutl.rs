//! `configutl` subcommand implementation.
//!
//! Reads an OpenSSL configuration file, expands variable references and
//! `.include` directives, and outputs the canonical/expanded form.
//!
//! This is the Rust equivalent of `apps/configutl.c` in the C codebase.
//! The C implementation uses `NCONF_load()` + `NCONF_get_section_names()` +
//! `NCONF_get_section()` to read, expand, and enumerate configuration data.
//! The Rust rewrite delegates to [`openssl_common::config::ConfigParser`] for
//! parsing/expansion and [`openssl_common::config::Config`] for enumeration.
//!
//! # Output Format
//!
//! The output follows the same ordering as the C implementation:
//!
//! 1. Optional header comment (`# This configuration file was linearized …`)
//! 2. The `"default"` section values **without** a `[default]` header
//! 3. All remaining sections with `\n[section_name]\n` headers
//!
//! Values are escaped so that the output is a valid OpenSSL configuration
//! file that can be re-parsed without data loss.
//!
//! # Rules Applied
//!
//! - **R5**: `Option<T>` used for optional paths; no sentinel values.
//! - **R6**: No bare `as` casts; all numeric handling uses safe idioms.
//! - **R8**: Zero `unsafe` — this crate forbids unsafe code.
//! - **R9**: Warning-free under `RUSTFLAGS="-D warnings"`.
//! - **R10**: Wired from `mod.rs` `CliCommand::Configutl` dispatch, reachable
//!   from the entry point.

use std::fs::File;
use std::io::{self, stdout, BufWriter, Write};
use std::path::PathBuf;

use clap::Args;
use tracing::{debug, info, warn};

use openssl_common::config::{get_default_config_path, Config, ConfigParser};
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

// ───────────────────────────────────────────────────────────────────────────
// Constants
// ───────────────────────────────────────────────────────────────────────────

/// Section name for the implicit default section (matches C `"default"`).
const DEFAULT_SECTION: &str = "default";

// ───────────────────────────────────────────────────────────────────────────
// CLI Argument Struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `configutl` subcommand.
///
/// Reads an OpenSSL configuration file (defaulting to the system
/// `openssl.cnf`), expands all variable references and `.include`
/// directives, and writes the canonical form to stdout or a file.
///
/// Replaces the C `configutl_options[]` / `opt_init()`/`opt_next()` pattern
/// from `apps/configutl.c:87–102` with declarative clap derives.
#[derive(Args, Debug)]
pub struct ConfigutlArgs {
    /// Path to the configuration file to process.
    ///
    /// If omitted, the default OpenSSL configuration file is used
    /// (resolved via `$OPENSSL_CONF` or the platform default path).
    /// Rule R5: `Option<PathBuf>` instead of a null/empty sentinel.
    #[arg(short = 'i', long = "in", value_name = "FILE")]
    input: Option<PathBuf>,

    /// Write output to this file instead of stdout.
    ///
    /// Rule R5: `None` means stdout (no sentinel like `"-"`).
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Dump only the named section instead of the entire config.
    ///
    /// When specified, only the key-value pairs within this section are
    /// printed (with no section header). When omitted, all sections are
    /// printed in the canonical ordering.
    /// Rule R5: `None` means all sections.
    #[arg(short = 's', long = "section", value_name = "NAME")]
    section: Option<String>,

    /// Enable verbose output.
    ///
    /// When set, additional diagnostic information is printed (e.g. the
    /// resolved config file path and the number of sections found).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Suppress the header comment that identifies the source file.
    ///
    /// Replaces C `OPT_NOHEADER` / `no_header` flag from
    /// `apps/configutl.c:90,117,175`.
    #[arg(long = "noheader")]
    no_header: bool,

    /// Provider name to load before processing.
    ///
    /// Corresponds to the C `-provider` option. Currently accepted for
    /// CLI compatibility; provider loading is handled by the library
    /// context initialization chain.
    #[arg(long = "provider-name", value_name = "NAME")]
    provider: Option<String>,

    /// Provider module search path.
    ///
    /// Corresponds to the C `-provider_path` option.
    #[arg(long = "provider_path", value_name = "DIR")]
    provider_path: Option<PathBuf>,

    /// Property query string for algorithm fetching.
    ///
    /// Corresponds to the C `-propquery` option.
    #[arg(long = "propquery", value_name = "QUERY")]
    propquery: Option<String>,
}

// ───────────────────────────────────────────────────────────────────────────
// Core Implementation
// ───────────────────────────────────────────────────────────────────────────

impl ConfigutlArgs {
    /// Execute the `configutl` subcommand.
    ///
    /// Loads the configuration file (or the default), expands all variable
    /// references and `.include` directives via `ConfigParser::parse_file`,
    /// and writes the canonical output to stdout or the specified output file.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on:
    /// - Missing or unresolvable default config path
    /// - Config file parse/expansion failures (propagated from
    ///   [`openssl_common::config::ConfigParser`])
    /// - I/O errors writing output
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Configutl(args)` → `args.execute(ctx).await`.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // ── Step 1: Resolve config file path ────────────────────────────
        let config_path = self.resolve_config_path()?;
        debug!(path = %config_path.display(), "Resolved configuration file path");

        if self.verbose {
            info!(path = %config_path.display(), "Loading configuration file");
        }

        // ── Step 2: Parse and expand the configuration file ─────────────
        let config = ConfigParser::parse_file(&config_path)?;
        let section_count = config.sections().count();
        debug!(
            sections = section_count,
            "Configuration parsed successfully"
        );

        if self.verbose {
            info!(
                sections = section_count,
                "Loaded configuration with {section_count} section(s)",
            );
        }

        // ── Step 3: Open output writer ──────────────────────────────────
        let mut writer: Box<dyn Write> = if let Some(ref path) = self.output {
            debug!(path = %path.display(), "Writing output to file");
            let file = File::create(path)?;
            Box::new(BufWriter::new(file))
        } else {
            Box::new(BufWriter::new(stdout()))
        };

        // ── Step 4: Write output ────────────────────────────────────────
        if let Some(ref section_name) = self.section {
            // Single-section mode: dump only the named section
            Self::write_single_section(&mut writer, &config, section_name)?;
        } else {
            // Full-config mode: canonical ordering per C implementation
            self.write_full_config(&mut writer, &config, &config_path)?;
        }

        // Ensure all buffered output is flushed
        writer.flush()?;

        Ok(())
    }

    // ───────────────────────────────────────────────────────────────────
    // Private helpers
    // ───────────────────────────────────────────────────────────────────

    /// Resolves the configuration file path from the `-in` argument or
    /// the system default.
    ///
    /// Replaces the C logic at `apps/configutl.c:158–162`:
    /// ```c
    /// if (configfile == NULL)
    ///     configfile = CONF_get1_default_config_file();
    /// if (configfile == NULL)
    ///     goto end;
    /// ```
    ///
    /// Rule R5: uses `Option<PathBuf>` — no null pointer or empty-string
    /// sentinel.
    fn resolve_config_path(&self) -> Result<PathBuf, CryptoError> {
        if let Some(ref path) = self.input {
            return Ok(path.clone());
        }

        // Fall back to the default config file path
        if let Some(path) = get_default_config_path() {
            debug!(path = %path.display(), "Using default configuration file");
            Ok(path)
        } else {
            warn!("No default configuration file path could be determined");
            Err(CryptoError::Common(
                openssl_common::error::CommonError::Config {
                    message: "unable to determine default configuration file path".to_string(),
                },
            ))
        }
    }

    /// Writes the full canonical configuration output.
    ///
    /// Matches the C output ordering from `apps/configutl.c:175–191`:
    /// 1. Optional header comment identifying the source file.
    /// 2. Default section values (no `[default]` header).
    /// 3. All other sections with `\n[section_name]\n` headers.
    fn write_full_config(
        &self,
        writer: &mut dyn Write,
        config: &Config,
        config_path: &std::path::Path,
    ) -> Result<(), CryptoError> {
        // 1. Optional header comment
        if !self.no_header {
            writeln!(
                writer,
                "# This configuration file was linearized and expanded from {}",
                config_path.display(),
            )?;
        }

        // 2. Default section WITHOUT [default] header
        //    (matches C: `default_section_idx != -1 → print_section(out, cnf, "default")`)
        if let Some(section_map) = config.get_section(DEFAULT_SECTION) {
            write_section_entries(writer, section_map)?;
        }

        // 3. All other sections with headers
        //    Collect and sort section names for deterministic output ordering.
        let mut other_sections: Vec<&str> = config
            .sections()
            .filter(|s| *s != DEFAULT_SECTION)
            .collect();
        other_sections.sort_unstable();

        for section_name in other_sections {
            writeln!(writer)?;
            writeln!(writer, "[{section_name}]")?;

            if let Some(section_map) = config.get_section(section_name) {
                write_section_entries(writer, section_map)?;
            } else {
                // Section enumerated but empty — log a diagnostic
                warn!(
                    section = section_name,
                    "Section listed but contains no entries"
                );
            }
        }

        Ok(())
    }

    /// Writes a single section's key-value pairs.
    ///
    /// Used when the `-section` argument is provided. Only the named
    /// section is printed, without any section header.
    fn write_single_section(
        writer: &mut dyn Write,
        config: &Config,
        section_name: &str,
    ) -> Result<(), CryptoError> {
        if let Some(section_map) = config.get_section(section_name) {
            write_section_entries(writer, section_map)?;
            Ok(())
        } else {
            warn!(
                section = section_name,
                "Requested section not found in configuration"
            );
            Err(CryptoError::Common(
                openssl_common::error::CommonError::Config {
                    message: format!("section '{section_name}' not found in configuration"),
                },
            ))
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Output Formatting Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Writes all key-value entries from a section map to the given writer.
///
/// Keys are sorted alphabetically for deterministic output. Each entry is
/// written as `key = <escaped_value>\n`.
///
/// Replaces C `print_section()` from `apps/configutl.c:73–85`.
fn write_section_entries(
    writer: &mut dyn Write,
    section: &std::collections::HashMap<String, String>,
) -> Result<(), io::Error> {
    // Sort keys for deterministic output ordering
    let mut keys: Vec<&String> = section.keys().collect();
    keys.sort();

    for key in keys {
        if let Some(value) = section.get(key) {
            write!(writer, "{key} = ")?;
            write_escaped_value(writer, value)?;
            writeln!(writer)?;
        }
    }

    Ok(())
}

/// Writes a configuration value with proper escaping.
///
/// This is a direct translation of C `print_escaped_value()` from
/// `apps/configutl.c:20–68`. The escaping rules ensure the output is
/// a valid OpenSSL configuration file that can be re-parsed:
///
/// - `"`, `'`, `#`, `\`, `$` → backslash-escaped
/// - Newline → `\n`
/// - Carriage return → `\r`
/// - Backspace → `\b`
/// - Tab → `\t`
/// - Leading/trailing spaces → quoted with `" "`
/// - All other characters → literal
fn write_escaped_value(writer: &mut dyn Write, value: &str) -> Result<(), io::Error> {
    let bytes = value.as_bytes();
    let len = bytes.len();

    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'"' | b'\'' | b'#' | b'\\' | b'$' => {
                writer.write_all(b"\\")?;
                writer.write_all(&[byte])?;
            }
            b'\n' => {
                writer.write_all(b"\\n")?;
            }
            b'\r' => {
                writer.write_all(b"\\r")?;
            }
            b'\x08' => {
                // Backspace (0x08)
                writer.write_all(b"\\b")?;
            }
            b'\t' => {
                writer.write_all(b"\\t")?;
            }
            b' ' if i == 0 || i == len - 1 => {
                // Quote leading/trailing spaces with `" "` notation.
                // This matches the C logic at apps/configutl.c:47–60:
                // spaces at the start or end of the value are wrapped in
                // double quotes to preserve them through re-parsing.
                writer.write_all(b"\" \"")?;
            }
            _ => {
                writer.write_all(&[byte])?;
            }
        }
    }

    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Unit Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that basic characters pass through unescaped.
    #[test]
    fn test_escape_plain_text() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, "hello world").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "hello world");
    }

    /// Verify that special characters are backslash-escaped.
    #[test]
    fn test_escape_special_chars() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, r#"a"b'c#d\e$f"#).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), r#"a\"b\'c\#d\\e\$f"#);
    }

    /// Verify that control characters are escaped to their named forms.
    #[test]
    fn test_escape_control_chars() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, "line1\nline2\r\t\x08end").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "line1\\nline2\\r\\t\\bend");
    }

    /// Verify that leading and trailing spaces are quoted.
    #[test]
    fn test_escape_leading_trailing_spaces() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, " padded ").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), r#"" "padded" ""#);
    }

    /// Verify that a single space is quoted (both leading and trailing).
    #[test]
    fn test_escape_single_space() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, " ").unwrap();
        // A single space is both leading AND trailing, so it becomes `" "`
        assert_eq!(String::from_utf8(buf).unwrap(), r#"" ""#);
    }

    /// Verify that an empty value produces empty output.
    #[test]
    fn test_escape_empty() {
        let mut buf = Vec::new();
        write_escaped_value(&mut buf, "").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "");
    }

    /// Verify that section entries are sorted and properly formatted.
    #[test]
    fn test_write_section_entries() {
        let mut section = std::collections::HashMap::new();
        section.insert("zebra".to_string(), "z_val".to_string());
        section.insert("alpha".to_string(), "a_val".to_string());
        section.insert("middle".to_string(), "m_val".to_string());

        let mut buf = Vec::new();
        write_section_entries(&mut buf, &section).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Keys should be sorted alphabetically
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "alpha = a_val");
        assert_eq!(lines[1], "middle = m_val");
        assert_eq!(lines[2], "zebra = z_val");
    }

    /// Verify section entries with values needing escaping.
    #[test]
    fn test_write_section_entries_with_escaping() {
        let mut section = std::collections::HashMap::new();
        section.insert("key".to_string(), "value with $dollar".to_string());

        let mut buf = Vec::new();
        write_section_entries(&mut buf, &section).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(output, "key = value with \\$dollar\n");
    }
}
