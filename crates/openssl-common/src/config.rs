//! Configuration file parser for the OpenSSL Rust workspace, replacing the
//! C NCONF/CONF subsystem.
//!
//! The C implementation is spread across `crypto/conf/conf_def.c` (default
//! parser), `crypto/conf/conf_api.c` (storage engine), `crypto/conf/conf_lib.c`
//! (API bridge), `crypto/conf/conf_mod.c` (module runtime), and related files.
//!
//! # Data Model
//!
//! OpenSSL configuration files are INI-style text files organized into sections
//! (`[section_name]`) containing key=value pairs. The C implementation stores
//! these in an `LHASH_OF(CONF_VALUE)` hash table; this Rust translation uses
//! nested [`HashMap`]s for clarity and safety.
//!
//! # Parser Features
//!
//! The parser supports:
//! - Section headers: `[section_name]`
//! - Key-value assignments: `key = value` and `section::key = value`
//! - Variable expansion: `$var`, `${var}`, `$section::var`, `${section::var}`
//! - Continuation lines via trailing backslash (`\`)
//! - Comments (lines starting with `#` and inline `#` comments)
//! - Single and double-quoted strings with escape sequences
//! - `.include` directives for files and directories
//! - `.pragma` directives (`dollarid`, `abspath`, `includedir`)
//! - UTF-8 BOM stripping
//!
//! # Config Module System
//!
//! The [`ConfigModule`] trait and [`ConfigModuleRegistry`] replicate the C
//! `CONF_MODULE` / `CONF_IMODULE` runtime from `crypto/conf/conf_mod.c`,
//! allowing subsystems to register configuration handlers that are invoked
//! during config loading.
//!
//! # C Mapping
//!
//! | C Construct                | Rust Equivalent                          |
//! |----------------------------|------------------------------------------|
//! | `CONF` / `NCONF`           | [`Config`]                               |
//! | `CONF_VALUE`               | [`ConfValue`]                            |
//! | `_CONF_get_string()`       | [`Config::get_string()`]                 |
//! | `_CONF_get_section()`      | [`Config::get_section()`]                |
//! | `_CONF_add_string()`       | [`Config::set_string()`]                 |
//! | `NCONF_load()`             | [`ConfigParser::parse_file()`]           |
//! | `NCONF_load_bio()`         | [`ConfigParser::parse_reader()`]         |
//! | `CONF_modules_load()`      | [`ConfigModuleRegistry::load_modules()`] |
//! | `CONF_get1_default_config_file()` | [`get_default_config_path()`]     |
//! | `MAX_CONF_VALUE_LENGTH`    | [`MAX_CONF_VALUE_LENGTH`]                |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `get_string()` returns `Option<&str>`, not empty
//!   string sentinel. `get_section()` returns `Option`.
//! - **R6 (Lossless Casts):** No bare `as` casts; numeric parsing uses
//!   `str::parse::<T>()` returning `Result`.
//! - **R7 (Lock Granularity):** `ConfigModuleRegistry.modules` documented with
//!   `// LOCK-SCOPE:` comment.
//! - **R8 (Zero Unsafe):** Zero `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from entry point via
//!   `openssl-crypto::init` → `config::load_config()`.

use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::error::CommonError;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for a configuration value after variable expansion.
///
/// Mirrors the C `#define MAX_CONF_VALUE_LENGTH 65536` from
/// `crypto/conf/conf_def.c` (line 43). This guard prevents runaway
/// recursive expansion from consuming unbounded memory.
pub const MAX_CONF_VALUE_LENGTH: usize = 65536;

/// The default section name used when no explicit section is specified.
///
/// Mirrors the C `"default"` section string used in `def_load_bio()` and
/// `_CONF_get_string()`.
const DEFAULT_SECTION: &str = "default";

// =============================================================================
// ConfValue — Individual Configuration Entry
// =============================================================================

/// A single configuration key-value entry with its owning section.
///
/// Translates the C `CONF_VALUE` struct from `include/openssl/conf.h`:
///
/// ```c
/// typedef struct {
///     char *section;
///     char *name;
///     char *value;
/// } CONF_VALUE;
/// ```
///
/// In the C implementation, `CONF_VALUE` is stored in an
/// `LHASH_OF(CONF_VALUE)` keyed by `(section, name)`. Here, the owning
/// [`Config`] stores values in nested `HashMap`s, and `ConfValue` serves
/// as a convenient transport type for returning complete entries.
///
/// # Examples
///
/// ```
/// use openssl_common::config::ConfValue;
///
/// let val = ConfValue {
///     section: "tls".to_string(),
///     name: "min_protocol".to_string(),
///     value: "TLSv1.3".to_string(),
/// };
/// assert_eq!(val.section, "tls");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfValue {
    /// The section this entry belongs to (e.g., `"default"`, `"tls"`).
    pub section: String,
    /// The key name within the section (e.g., `"min_protocol"`).
    pub name: String,
    /// The resolved value string (e.g., `"TLSv1.3"`).
    pub value: String,
}

// =============================================================================
// Config — Configuration Data Store
// =============================================================================

/// In-memory representation of a parsed OpenSSL-style configuration file.
///
/// Replaces the C `CONF` / `NCONF` type and its backing `LHASH_OF(CONF_VALUE)`
/// storage engine. Sections are keyed by name; each section contains a map of
/// key-value string pairs.
///
/// # Lookup Precedence
///
/// [`Config::get_string()`] follows the same precedence as the C
/// `_CONF_get_string()` function in `crypto/conf/conf_api.c`:
///
/// 1. Look up in the explicitly requested section.
/// 2. Fall back to the `"default"` section.
/// 3. Return `None` (Rule R5 — no sentinel values).
///
/// Unlike the C version, environment variable lookup (`$ENV::VAR`) is NOT
/// performed implicitly — callers that need environment expansion should
/// do so explicitly.
///
/// # Examples
///
/// ```
/// use openssl_common::config::Config;
///
/// let mut cfg = Config::new();
/// cfg.set_string("openssl_init", "providers", "provider_sect".to_string());
/// assert_eq!(cfg.get_string("openssl_init", "providers"), Some("provider_sect"));
/// ```
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Sections keyed by section name, each containing (name → value) mappings.
    ///
    /// Replaces the C `LHASH_OF(CONF_VALUE)` keyed by `(section, name)` with
    /// per-section `STACK_OF(CONF_VALUE)` lists.
    sections: HashMap<String, HashMap<String, String>>,
}

impl Config {
    /// Creates an empty configuration with no sections.
    ///
    /// Equivalent to `NCONF_new()` in C, which allocates a `CONF` struct and
    /// initializes an empty hash table.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::config::Config;
    ///
    /// let cfg = Config::new();
    /// assert!(cfg.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            sections: HashMap::new(),
        }
    }

    /// Returns all key-value pairs in the given section, or `None` if the
    /// section does not exist.
    ///
    /// Replaces `_CONF_get_section()` from `crypto/conf/conf_api.c`.
    /// Returns `Option` per Rule R5 (no sentinel values).
    ///
    /// # Parameters
    ///
    /// * `section` — The section name to look up.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::config::Config;
    ///
    /// let mut cfg = Config::new();
    /// cfg.set_string("my_sect", "key1", "value1".to_string());
    /// let sect = cfg.get_section("my_sect").unwrap();
    /// assert_eq!(sect.get("key1"), Some(&"value1".to_string()));
    /// assert!(cfg.get_section("nonexistent").is_none());
    /// ```
    pub fn get_section(&self, section: &str) -> Option<&HashMap<String, String>> {
        self.sections.get(section)
    }

    /// Looks up a string value by section and name, with fallback to the
    /// `"default"` section.
    ///
    /// Replaces `_CONF_get_string()` from `crypto/conf/conf_api.c`.
    ///
    /// # Lookup Precedence
    ///
    /// 1. `sections[section][name]` — exact section match.
    /// 2. `sections["default"][name]` — fallback to default section.
    /// 3. `None` — not found (Rule R5: no sentinel).
    ///
    /// # Parameters
    ///
    /// * `section` — The section to search first.
    /// * `name` — The key name to look up.
    pub fn get_string(&self, section: &str, name: &str) -> Option<&str> {
        // First, try the exact section
        if let Some(sect_map) = self.sections.get(section) {
            if let Some(val) = sect_map.get(name) {
                return Some(val.as_str());
            }
        }
        // Fall back to the "default" section (matching C _CONF_get_string behavior)
        if section != DEFAULT_SECTION {
            if let Some(default_map) = self.sections.get(DEFAULT_SECTION) {
                if let Some(val) = default_map.get(name) {
                    return Some(val.as_str());
                }
            }
        }
        None
    }

    /// Sets a string value in the given section, creating the section if it
    /// does not yet exist.
    ///
    /// Replaces `_CONF_add_string()` from `crypto/conf/conf_api.c`. If a
    /// value already exists for the given section and name, it is overwritten
    /// (matching the C behavior where `lh_CONF_VALUE_insert()` replaces
    /// existing entries).
    ///
    /// # Parameters
    ///
    /// * `section` — The section to insert into.
    /// * `name` — The key name.
    /// * `value` — The value to store.
    pub fn set_string(&mut self, section: &str, name: &str, value: String) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .insert(name.to_string(), value);
    }

    /// Returns an iterator over all section names in the configuration.
    ///
    /// Replaces `NCONF_get_section_names()` from `crypto/conf/conf_lib.c`.
    pub fn sections(&self) -> impl Iterator<Item = &str> {
        self.sections.keys().map(String::as_str)
    }

    /// Removes a value from the given section and returns it, or `None` if
    /// the section or key did not exist.
    ///
    /// No direct C equivalent — this is an ergonomic addition for Rust
    /// callers that need to mutate configuration at runtime.
    pub fn remove(&mut self, section: &str, name: &str) -> Option<String> {
        self.sections
            .get_mut(section)
            .and_then(|sect| sect.remove(name))
    }

    /// Returns `true` if the configuration contains no sections at all.
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// Merges another configuration into this one. Values from `other`
    /// overwrite existing values in `self` when both section and key match.
    ///
    /// Sections present in `other` but not in `self` are created. Keys
    /// present in `other` but not in the corresponding section of `self`
    /// are added. This mirrors the behavior of loading multiple config
    /// files sequentially in the C implementation.
    pub fn merge(&mut self, other: &Config) {
        for (section, entries) in &other.sections {
            let target = self.sections.entry(section.clone()).or_default();
            for (key, value) in entries {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

// =============================================================================
// ParserPragmas — Internal Parser State for .pragma Directives
// =============================================================================

/// Internal parser state tracking active `.pragma` directives.
///
/// Maps the C `CONF` flags `flag_dollarid` and `flag_abspath`, plus the
/// `includedir` string, from `crypto/conf/conf_def.c`.
#[derive(Debug, Clone, Default)]
struct ParserPragmas {
    /// When `true`, `$` is treated as an identifier character and variable
    /// expansion requires braces: `${var}` or `$(var)`.
    ///
    /// Set by `.pragma dollarid:true` (C: `conf->flag_dollarid`).
    dollar_in_identifiers: bool,
    /// When `true`, `.include` paths must be absolute.
    ///
    /// Set by `.pragma abspath:true` (C: `conf->flag_abspath`).
    absolute_include_path: bool,
    /// Optional directory prefix for relative `.include` paths.
    ///
    /// Set by `.pragma includedir:<path>` or the `OPENSSL_CONF_INCLUDE`
    /// environment variable (C: `conf->includedir`).
    include_dir: Option<String>,
}

// =============================================================================
// ConfigParser — OpenSSL Configuration File Parser
// =============================================================================

/// Parser for OpenSSL-style INI configuration files.
///
/// Translates the C `def_load_bio()` function from `crypto/conf/conf_def.c`
/// into an idiomatic Rust streaming parser. The parser processes lines
/// sequentially, maintaining state for the current section, pragma flags,
/// and continuation lines.
///
/// # Supported Syntax
///
/// ```text
/// # Comment lines
/// [section_name]
/// key = value
/// key = "quoted value with spaces"
/// key = 'single quoted value'
/// section::key = cross-section assignment
/// key = $variable_expansion
/// key = ${section::variable}
/// .include /path/to/file.cnf
/// .include /path/to/directory/
/// .pragma dollarid:true
/// .pragma abspath:true
/// .pragma includedir:/etc/openssl/conf.d
/// ```
///
/// # Examples
///
/// ```
/// use openssl_common::config::ConfigParser;
///
/// let input = b"[default]\nkey = value\n";
/// let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
/// assert_eq!(cfg.get_string("default", "key"), Some("value"));
/// ```
pub struct ConfigParser {
    /// The configuration being built during parsing.
    config: Config,
    /// The current section name — initially `"default"`.
    current_section: String,
    /// Active pragma flags affecting parser behavior.
    pragmas: ParserPragmas,
}

impl ConfigParser {
    /// Parses a configuration file from disk.
    ///
    /// Opens the file at `path`, wraps it in a [`BufReader`], and delegates
    /// to [`parse_reader()`](Self::parse_reader). Returns the fully parsed
    /// [`Config`] on success.
    ///
    /// Replaces `NCONF_load()` / `def_load()` from `crypto/conf/conf_def.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::Io`] if the file cannot be opened or read.
    /// Returns [`CommonError::Config`] if the file contains syntax errors.
    pub fn parse_file(path: &Path) -> Result<Config, CommonError> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        Self::parse_reader(reader)
    }

    /// Parses configuration from any buffered reader.
    ///
    /// Replaces `def_load_bio()` from `crypto/conf/conf_def.c`. Reads lines
    /// from `reader`, handles continuation, strips comments, parses section
    /// headers, key-value assignments, `.include` and `.pragma` directives,
    /// and performs variable expansion.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::Io`] on reader failures.
    /// Returns [`CommonError::Config`] on syntax errors.
    pub fn parse_reader<R: BufRead>(reader: R) -> Result<Config, CommonError> {
        let mut parser = ConfigParser {
            config: Config::new(),
            current_section: DEFAULT_SECTION.to_string(),
            pragmas: ParserPragmas::default(),
        };

        // Pre-create the default section (matching C behavior in def_load_bio)
        parser
            .config
            .sections
            .entry(DEFAULT_SECTION.to_string())
            .or_default();

        let mut line_num: usize = 0;
        let mut continuation_buf = String::new();
        let mut continuation_start_line: usize = 0;
        let mut first_line = true;

        for line_result in reader.lines() {
            let raw_line = line_result?;
            line_num += 1;

            let mut line = raw_line;

            // Strip UTF-8 BOM on first line (matching C def_load_bio BOM handling)
            if first_line {
                if line.starts_with('\u{FEFF}') {
                    line = line['\u{FEFF}'.len_utf8()..].to_string();
                }
                first_line = false;
            }

            // Handle continuation lines (trailing backslash)
            if continuation_buf.is_empty() {
                continuation_start_line = line_num;
            }

            // Count consecutive trailing backslashes.  An odd count means
            // the final `\` is an unescaped continuation marker; an even count
            // means all backslashes are escaped (literal) and the line is NOT
            // a continuation.  This matches C OpenSSL's `CONF_get_line()`
            // behaviour where `\\` is a literal backslash.
            let trailing_backslashes = line
                .as_bytes()
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            if trailing_backslashes % 2 == 1 {
                // Strip the single trailing continuation backslash and accumulate.
                continuation_buf.push_str(&line[..line.len() - 1]);
                continue;
            }

            // If we had accumulated continuation lines, combine them
            let full_line = if continuation_buf.is_empty() {
                line
            } else {
                continuation_buf.push_str(&line);
                let result = continuation_buf.clone();
                continuation_buf.clear();
                result
            };

            parser.parse_line(&full_line, continuation_start_line)?;
        }

        // If there is leftover continuation content (file ended with backslash),
        // process it as a final line
        if !continuation_buf.is_empty() {
            parser.parse_line(&continuation_buf, continuation_start_line)?;
        }

        Ok(parser.config)
    }

    /// Parses a single logical line (after continuation joining).
    ///
    /// Translates the core parsing loop body from `def_load_bio()` in
    /// `crypto/conf/conf_def.c` (lines 250–558).
    fn parse_line(&mut self, line: &str, line_num: usize) -> Result<(), CommonError> {
        // Strip comments respecting quotes and escapes
        let stripped = Self::clear_comments(line);

        // Trim leading whitespace
        let trimmed = stripped.trim();

        // Skip blank lines
        if trimmed.is_empty() {
            return Ok(());
        }

        // Section header: [section_name]
        if trimmed.starts_with('[') {
            return self.parse_section_header(trimmed, line_num);
        }

        // Check for .pragma directive
        if let Some(rest) = Self::strip_directive_prefix(trimmed, ".pragma") {
            return self.parse_pragma(rest, line_num);
        }

        // Check for .include directive
        if let Some(rest) = Self::strip_directive_prefix(trimmed, ".include") {
            return self.process_include(rest.trim());
        }

        // Key=value assignment
        self.parse_assignment(trimmed, line_num)
    }

    /// Parses a `[section_name]` header line.
    fn parse_section_header(&mut self, trimmed: &str, line_num: usize) -> Result<(), CommonError> {
        // Find closing bracket
        let inner = &trimmed[1..]; // skip '['
        let close_pos = inner.find(']').ok_or_else(|| CommonError::Config {
            message: format!("line {line_num}: missing close square bracket"),
        })?;
        let section_name = inner[..close_pos].trim().to_string();

        if section_name.is_empty() {
            return Err(CommonError::Config {
                message: format!("line {line_num}: empty section name"),
            });
        }

        // Expand variables in the section name (matching C str_copy behavior)
        let expanded = self.expand_variables(&self.current_section.clone(), &section_name)?;

        // Ensure the section exists in config
        self.config.sections.entry(expanded.clone()).or_default();

        self.current_section = expanded;
        Ok(())
    }

    /// Parses a `.pragma keyword:value` directive.
    ///
    /// Translates the pragma handling from `def_load_bio()` in
    /// `crypto/conf/conf_def.c` (lines 392–435).
    fn parse_pragma(&mut self, rest: &str, line_num: usize) -> Result<(), CommonError> {
        let rest = rest.trim();

        // Strip optional leading '='
        let rest = if let Some(after_eq) = rest.strip_prefix('=') {
            after_eq.trim()
        } else {
            rest
        };

        // Pragma values take the form keyword:value
        let colon_pos = rest.find(':').ok_or_else(|| CommonError::Config {
            message: format!("line {line_num}: invalid pragma, expected keyword:value"),
        })?;

        if colon_pos == 0 || colon_pos == rest.len() - 1 {
            return Err(CommonError::Config {
                message: format!("line {line_num}: invalid pragma, empty keyword or value"),
            });
        }

        let keyword = rest[..colon_pos].trim();
        let pval = rest[colon_pos + 1..].trim();

        match keyword {
            "dollarid" => {
                self.pragmas.dollar_in_identifiers = Self::parse_bool_value(pval, line_num)?;
            }
            "abspath" => {
                self.pragmas.absolute_include_path = Self::parse_bool_value(pval, line_num)?;
            }
            "includedir" => {
                self.pragmas.include_dir = Some(pval.to_string());
            }
            _ => {
                // Unknown pragmas are silently ignored (matching C behavior)
            }
        }

        Ok(())
    }

    /// Parses a boolean pragma value.
    ///
    /// Translates `parsebool()` from `crypto/conf/conf_def.c` (lines 192-205).
    /// Accepts `"on"`, `"true"` (→ `true`) and `"off"`, `"false"` (→ `false`),
    /// case-insensitive.
    fn parse_bool_value(val: &str, line_num: usize) -> Result<bool, CommonError> {
        match val.to_ascii_lowercase().as_str() {
            "on" | "true" => Ok(true),
            "off" | "false" => Ok(false),
            _ => Err(CommonError::Config {
                message: format!(
                    "line {line_num}: invalid boolean value '{val}', expected on/true/off/false"
                ),
            }),
        }
    }

    /// Parses a key=value assignment, with optional cross-section syntax.
    ///
    /// Handles both `key = value` (assigned to current section) and
    /// `section::key = value` (assigned to the named section), translating
    /// the assignment parsing from `def_load_bio()` lines 379–558.
    fn parse_assignment(&mut self, trimmed: &str, line_num: usize) -> Result<(), CommonError> {
        // Find the '=' separator
        // First, extract the key part (everything before '=')
        let eq_pos = Self::find_unquoted_char(trimmed, '=').ok_or_else(|| CommonError::Config {
            message: format!("line {line_num}: missing equal sign"),
        })?;

        let key_part = trimmed[..eq_pos].trim();
        let value_part = trimmed[eq_pos + 1..].trim();

        // Check for cross-section assignment: "section::key"
        let (target_section, key_name) = if let Some(sep_pos) = key_part.find("::") {
            let sect = key_part[..sep_pos].trim();
            let key = key_part[sep_pos + 2..].trim();
            (sect.to_string(), key.to_string())
        } else {
            (self.current_section.clone(), key_part.to_string())
        };

        if key_name.is_empty() {
            return Err(CommonError::Config {
                message: format!("line {line_num}: empty key name"),
            });
        }

        // Decode the value (handle quotes, escapes)
        let decoded = Self::decode_string(value_part);

        // Expand variables in the decoded value
        let expanded = self.expand_variables(&target_section, &decoded)?;

        // Ensure section exists and insert the value
        self.config
            .sections
            .entry(target_section)
            .or_default()
            .insert(key_name, expanded);

        Ok(())
    }

    /// Expands variable references in a value string.
    ///
    /// Translates the variable expansion logic from `str_copy()` in
    /// `crypto/conf/conf_def.c` (lines 641–791). Supports:
    ///
    /// - `$identifier` — expands from the current section
    /// - `${identifier}` — expands from the current section (braced)
    /// - `$section::identifier` — expands from the named section
    /// - `${section::identifier}` — expands from the named section (braced)
    ///
    /// When `dollar_in_identifiers` pragma is active, bare `$` without braces
    /// is treated as a literal character.
    fn expand_variables(&self, section: &str, value: &str) -> Result<String, CommonError> {
        let mut result = String::with_capacity(value.len());
        let chars: Vec<char> = value.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            if chars[i] == '$' {
                // Check if dollar_in_identifiers pragma requires braces
                if self.pragmas.dollar_in_identifiers {
                    if i + 1 < len && (chars[i + 1] == '{' || chars[i + 1] == '(') {
                        // Braced expansion allowed
                    } else {
                        // Bare $ treated as literal when dollarid is on
                        result.push('$');
                        i += 1;
                        continue;
                    }
                }

                i += 1; // skip '$'
                if i >= len {
                    result.push('$');
                    break;
                }

                // Determine if braced: ${...} or $(...)
                let (close_char, braced) = match chars.get(i).copied() {
                    Some('{') => (Some('}'), true),
                    Some('(') => (Some(')'), true),
                    _ => (None, false),
                };

                if braced {
                    i += 1; // skip opening brace/paren
                }

                // Read the variable name (possibly with section:: prefix)
                let var_start = i;
                while i < len && Self::is_identifier_char(chars[i]) {
                    i += 1;
                }

                // Check for section::name syntax
                let (var_section, var_name) =
                    if i + 1 < len && chars[i] == ':' && chars[i + 1] == ':' {
                        let sect_part: String = chars[var_start..i].iter().collect();
                        i += 2; // skip '::'
                        let name_start = i;
                        while i < len && Self::is_identifier_char(chars[i]) {
                            i += 1;
                        }
                        let name_part: String = chars[name_start..i].iter().collect();
                        (sect_part, name_part)
                    } else {
                        let name_part: String = chars[var_start..i].iter().collect();
                        (section.to_string(), name_part)
                    };

                // Consume closing brace if braced
                if braced {
                    if let Some(close) = close_char {
                        if i < len && chars[i] == close {
                            i += 1;
                        } else {
                            return Err(CommonError::Config {
                                message: format!("variable expansion: missing closing '{close}'"),
                            });
                        }
                    }
                }

                // Look up the variable value
                let resolved =
                    self.config
                        .get_string(&var_section, &var_name)
                        .ok_or_else(|| CommonError::Config {
                            message: format!("variable '{var_section}::{var_name}' has no value"),
                        })?;

                result.push_str(resolved);

                // Check expanded length limit
                if result.len() > MAX_CONF_VALUE_LENGTH {
                    return Err(CommonError::Config {
                        message: "variable expansion too long".to_string(),
                    });
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }

        if result.len() > MAX_CONF_VALUE_LENGTH {
            return Err(CommonError::Config {
                message: "variable expansion too long".to_string(),
            });
        }

        Ok(result)
    }

    /// Processes an `.include` directive.
    ///
    /// Translates `process_include()` from `crypto/conf/conf_def.c`
    /// (lines 793–825). If the path refers to a file, it is parsed
    /// recursively. If it refers to a directory, all `.cnf` and `.conf`
    /// files within it are parsed in sorted order.
    fn process_include(&mut self, raw_path: &str) -> Result<(), CommonError> {
        // Strip optional leading '='
        let path_str = if let Some(after_eq) = raw_path.strip_prefix('=') {
            after_eq.trim()
        } else {
            raw_path.trim()
        };

        // Decode quotes and escapes in the include path
        let decoded_path = Self::decode_string(path_str);

        // Resolve relative paths against the include directory if set
        let resolved = self.resolve_include_path(&decoded_path);

        // Enforce abspath pragma
        if self.pragmas.absolute_include_path && !Path::new(&resolved).is_absolute() {
            return Err(CommonError::Config {
                message: format!(
                    ".include path must be absolute when abspath pragma is set: {resolved}"
                ),
            });
        }

        let path = Path::new(&resolved);

        if path.is_dir() {
            self.include_directory(path)?;
        } else if path.is_file() {
            self.include_file(path)?;
        }
        // Missing include files are not fatal (matching C behavior where
        // process_include returns NULL for missing files)

        Ok(())
    }

    /// Resolves a possibly relative include path against the configured
    /// include directory or the `OPENSSL_CONF_INCLUDE` environment variable.
    fn resolve_include_path(&self, path: &str) -> String {
        if Path::new(path).is_absolute() {
            return path.to_string();
        }

        // Check OPENSSL_CONF_INCLUDE env var first, then pragma includedir
        let include_dir = std::env::var("OPENSSL_CONF_INCLUDE")
            .ok()
            .or_else(|| self.pragmas.include_dir.clone());

        if let Some(dir) = include_dir {
            let mut full = PathBuf::from(&dir);
            full.push(path);
            full.to_string_lossy().into_owned()
        } else {
            path.to_string()
        }
    }

    /// Parses all `.cnf` and `.conf` files in a directory, sorted by name.
    ///
    /// Translates `get_next_file()` from `crypto/conf/conf_def.c`
    /// (lines 831–876), which iterates directory entries and filters
    /// by `.cnf` / `.conf` extension.
    fn include_directory(&mut self, dir: &Path) -> Result<(), CommonError> {
        let mut entries: Vec<PathBuf> = Vec::new();

        for entry_result in fs::read_dir(dir)? {
            let entry = entry_result?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_ascii_lowercase();
                    if ext_lower == "cnf" || ext_lower == "conf" {
                        entries.push(path);
                    }
                }
            }
        }

        // Sort entries by filename for deterministic ordering
        entries.sort();

        for file_path in entries {
            self.include_file(&file_path)?;
        }

        Ok(())
    }

    /// Parses a single included configuration file, merging results into
    /// the current parser state.
    fn include_file(&mut self, path: &Path) -> Result<(), CommonError> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);

        let mut line_num: usize = 0;
        let mut continuation_buf = String::new();
        let mut continuation_start_line: usize = 0;
        let mut first_line = true;

        for line_result in reader.lines() {
            let raw_line = line_result?;
            line_num += 1;

            let mut line = raw_line;

            // Strip UTF-8 BOM on first line
            if first_line {
                if line.starts_with('\u{FEFF}') {
                    line = line['\u{FEFF}'.len_utf8()..].to_string();
                }
                first_line = false;
            }

            if continuation_buf.is_empty() {
                continuation_start_line = line_num;
            }

            if line.ends_with('\\') && !line.ends_with("\\\\") {
                continuation_buf.push_str(&line[..line.len() - 1]);
                continue;
            }

            let full_line = if continuation_buf.is_empty() {
                line
            } else {
                continuation_buf.push_str(&line);
                let result = continuation_buf.clone();
                continuation_buf.clear();
                result
            };

            self.parse_line(&full_line, continuation_start_line)?;
        }

        if !continuation_buf.is_empty() {
            self.parse_line(&continuation_buf, continuation_start_line)?;
        }

        Ok(())
    }

    /// Strips comments from a line, respecting quoted strings and escape
    /// sequences.
    ///
    /// Translates `clear_comments()` from `crypto/conf/conf_def.c`
    /// (lines 604–639). The `#` character starts a comment when outside
    /// of quoted regions and not preceded by an escape.
    fn clear_comments(line: &str) -> &str {
        let bytes = line.as_bytes();
        let len = bytes.len();
        let mut i = 0;
        let mut in_single_quote = false;
        let mut in_double_quote = false;

        while i < len {
            let ch = bytes[i];
            if in_single_quote {
                // C OpenSSL's `clear_comments()` in `conf_def.c` does NOT
                // honour backslash escapes inside single-quoted strings for
                // the purpose of comment stripping.  Only the closing `'`
                // terminates the quoted region.  (Backslash escapes inside
                // single quotes are handled separately in `str_copy()` /
                // `decode_string()` during value decoding, not here.)
                if ch == b'\'' {
                    in_single_quote = false;
                }
            } else if in_double_quote {
                if ch == b'"' {
                    // Check for doubled double-quote escape: "" -> "
                    if i + 1 < len && bytes[i + 1] == b'"' {
                        i += 1; // skip the doubled quote
                    } else {
                        in_double_quote = false;
                    }
                }
            } else {
                match ch {
                    b'#' => return &line[..i],
                    b'\'' => in_single_quote = true,
                    b'"' => in_double_quote = true,
                    b'\\' if i + 1 < len => {
                        i += 1; // skip escaped character
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        line
    }

    /// Decodes a value string, handling quoted regions and escape sequences.
    ///
    /// Translates the quote/escape handling from `str_copy()` in
    /// `crypto/conf/conf_def.c` (lines 653–695):
    ///
    /// - Single-quoted strings: `'value'` — backslash escapes are honored
    /// - Double-quoted strings: `"value"` — doubled `""` is the escape for `"`
    /// - Backslash escapes outside quotes: `\n`, `\r`, `\t`, `\b`, `\\`
    fn decode_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let chars: Vec<char> = s.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            match chars.get(i).copied() {
                Some('\'') => {
                    // Single-quoted region
                    i += 1;
                    while i < len && chars.get(i).copied() != Some('\'') {
                        if chars.get(i).copied() == Some('\\') && i + 1 < len {
                            i += 1;
                            if let Some(&esc) = chars.get(i) {
                                result.push(Self::decode_escape_char(esc));
                            }
                        } else if let Some(&ch) = chars.get(i) {
                            result.push(ch);
                        }
                        i += 1;
                    }
                    if i < len {
                        i += 1; // skip closing quote
                    }
                }
                Some('"') => {
                    // Double-quoted region (doubled "" is escape for ")
                    i += 1;
                    while i < len {
                        if chars.get(i).copied() == Some('"') {
                            if chars.get(i + 1).copied() == Some('"') {
                                result.push('"');
                                i += 2;
                            } else {
                                break;
                            }
                        } else if let Some(&ch) = chars.get(i) {
                            result.push(ch);
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    if i < len {
                        i += 1; // skip closing quote
                    }
                }
                Some('\\') => {
                    // Backslash escape outside quotes
                    i += 1;
                    if let Some(&esc) = chars.get(i) {
                        result.push(Self::decode_escape_char(esc));
                        i += 1;
                    }
                }
                Some(other) => {
                    result.push(other);
                    i += 1;
                }
                None => break,
            }
        }

        result
    }

    /// Decodes a single escape character following a backslash.
    ///
    /// Translates the escape handling from `str_copy()` in `conf_def.c`
    /// (lines 686–695).
    fn decode_escape_char(ch: char) -> char {
        match ch {
            'r' => '\r',
            'n' => '\n',
            'b' => '\x08', // backspace
            't' => '\t',
            _ => ch, // literal for unknown escapes (including '\\' → '\')
        }
    }

    /// Checks if a character is valid in an identifier (variable name or
    /// section name).
    ///
    /// Corresponds to the `IS_ALNUM` macro in `crypto/conf/conf_def.h`,
    /// which matches `[A-Za-z0-9_]`.
    fn is_identifier_char(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '_'
    }

    /// Finds the position of a character outside of quoted regions.
    fn find_unquoted_char(s: &str, target: char) -> Option<usize> {
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut prev_was_escape = false;

        for (i, ch) in s.char_indices() {
            if prev_was_escape {
                prev_was_escape = false;
                continue;
            }
            if ch == '\\' {
                prev_was_escape = true;
                continue;
            }
            if in_single_quote {
                if ch == '\'' {
                    in_single_quote = false;
                }
                continue;
            }
            if in_double_quote {
                if ch == '"' {
                    in_double_quote = false;
                }
                continue;
            }
            if ch == '\'' {
                in_single_quote = true;
                continue;
            }
            if ch == '"' {
                in_double_quote = true;
                continue;
            }
            if ch == target {
                return Some(i);
            }
        }
        None
    }

    /// Strips a directive prefix (`.pragma` or `.include`) from the start of
    /// a line, returning the remainder.
    ///
    /// Case-sensitive match as in the C implementation. Also handles the
    /// optional `=` separator between the directive and its argument.
    fn strip_directive_prefix<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
        line.strip_prefix(prefix).filter(|rest| {
            // The rest must start with whitespace, '=', or be at end of string
            rest.is_empty() || rest.starts_with(char::is_whitespace) || rest.starts_with('=')
        })
    }
}

// =============================================================================
// ConfigModule — Configuration Module Trait
// =============================================================================

/// A configuration module that can be loaded and initialized from config data.
///
/// Translates the C `CONF_MODULE` / `conf_init_func` / `conf_finish_func`
/// pattern from `crypto/conf/conf_mod.c`. Each module registers a name and
/// provides `init` (called during config loading) and `finish` (called
/// during cleanup) callbacks.
///
/// # Examples
///
/// ```
/// use openssl_common::config::{Config, ConfigModule};
/// use openssl_common::error::CommonError;
///
/// struct SslConfigModule;
///
/// impl ConfigModule for SslConfigModule {
///     fn name(&self) -> &str { "ssl_conf" }
///
///     fn init(&self, config: &Config, section: &str) -> Result<(), CommonError> {
///         // Process SSL-specific configuration from the given section
///         Ok(())
///     }
///
///     fn finish(&self) -> Result<(), CommonError> {
///         Ok(())
///     }
/// }
/// ```
pub trait ConfigModule: Send + Sync {
    /// Returns the module's name, used for matching against configuration
    /// section references.
    ///
    /// This corresponds to the C `CONF_MODULE.name` field in
    /// `crypto/conf/conf_mod.c`.
    fn name(&self) -> &str;

    /// Initializes the module with configuration data from the given section.
    ///
    /// Called during [`ConfigModuleRegistry::load_modules()`] when a
    /// matching section reference is found. Corresponds to
    /// `conf_init_func` in C.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::Config`] if the section contains invalid
    /// configuration values, or [`CommonError::InvalidArgument`] if
    /// required keys are missing.
    fn init(&self, config: &Config, section: &str) -> Result<(), CommonError>;

    /// Cleans up any resources allocated during [`init()`](Self::init).
    ///
    /// Called during shutdown. Corresponds to `conf_finish_func` in C.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError`] if cleanup fails.
    fn finish(&self) -> Result<(), CommonError>;
}

// =============================================================================
// ConfigModuleRegistry — Module Registration and Loading
// =============================================================================

/// Registry of configuration modules that can be loaded from config data.
///
/// Translates the C `supported_modules` stack and `CONF_modules_load()`
/// function from `crypto/conf/conf_mod.c` (lines 32–151).
///
/// # Lifecycle
///
/// 1. Modules register themselves via [`register()`](Self::register).
/// 2. After config parsing, [`load_modules()`](Self::load_modules) iterates
///    the main config section looking for registered module names.
/// 3. Matched modules have their [`init()`](ConfigModule::init) called.
/// 4. On shutdown, [`finish_all()`](Self::finish_all) calls each module's
///    [`finish()`](ConfigModule::finish).
pub struct ConfigModuleRegistry {
    // LOCK-SCOPE: module registry, write at startup only, read during config loading.
    // This Vec is populated during initialization (before any concurrent access)
    // and only read during config loading. No Mutex needed because the write
    // phase completes before the read phase begins (sequential initialization).
    modules: Vec<Box<dyn ConfigModule>>,
}

impl ConfigModuleRegistry {
    /// Creates an empty module registry.
    ///
    /// Corresponds to initialization of `supported_modules` in
    /// `crypto/conf/conf_mod.c`.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Registers a configuration module.
    ///
    /// Corresponds to `CONF_module_add()` in C. The module's
    /// [`name()`](ConfigModule::name) is used for matching against
    /// configuration section references during [`load_modules()`](Self::load_modules).
    pub fn register(&mut self, module: Box<dyn ConfigModule>) {
        self.modules.push(module);
    }

    /// Loads and initializes configuration modules based on the parsed config.
    ///
    /// Translates `CONF_modules_load()` from `crypto/conf/conf_mod.c`
    /// (lines 92–151). The algorithm:
    ///
    /// 1. Look up the `openssl_conf` key in the default section to find the
    ///    name of the master configuration section.
    /// 2. Iterate the key-value pairs in the master section.
    /// 3. For each pair, the key is the module name and the value is the
    ///    section name containing module-specific configuration.
    /// 4. Find the matching registered module and call its
    ///    [`init()`](ConfigModule::init) with the referenced section.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::Config`] if a referenced module is not found
    /// in the registry, or propagates errors from module initialization.
    pub fn load_modules(&self, config: &Config) -> Result<(), CommonError> {
        // Find the master section name from "openssl_conf" in the default section
        let master_section = match config.get_string(DEFAULT_SECTION, "openssl_conf") {
            Some(sect) => sect.to_string(),
            None => {
                // No openssl_conf directive — nothing to load (matching C behavior)
                return Ok(());
            }
        };

        // Get the master section's key-value pairs
        let entries = match config.get_section(&master_section) {
            Some(sect) => sect.clone(),
            None => {
                return Err(CommonError::Config {
                    message: format!("openssl_conf references missing section: {master_section}"),
                });
            }
        };

        // For each entry, find the matching module and initialize it
        for (module_name, section_name) in &entries {
            let module = self
                .modules
                .iter()
                .find(|m| m.name() == module_name.as_str());

            match module {
                Some(m) => {
                    m.init(config, section_name)?;
                }
                None => {
                    // Unknown modules are not fatal in the default C behavior
                    // (CONF_MFLAGS_IGNORE_ERRORS can be set), but we report
                    // them as errors for Rust strictness. Callers that want
                    // lenient behavior can catch and ignore this error.
                    return Err(CommonError::Config {
                        message: format!("unknown module name: {module_name}"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Calls [`finish()`](ConfigModule::finish) on all registered modules.
    ///
    /// Translates `conf_modules_finish_int()` from `crypto/conf/conf_mod.c`.
    /// Errors from individual modules are collected but do not prevent
    /// other modules from being finalized.
    pub fn finish_all(&self) -> Result<(), CommonError> {
        let mut last_error: Option<CommonError> = None;
        for module in &self.modules {
            if let Err(e) = module.finish() {
                last_error = Some(e);
            }
        }
        match last_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Default for ConfigModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Loads and parses a configuration file from the given path.
///
/// High-level entry point that combines file opening and parsing.
/// Replaces `CONF_modules_load_file()` from `crypto/conf/conf_mod.c`
/// (lines 154–211), minus the module-loading step.
///
/// # Errors
///
/// Returns [`CommonError::Io`] if the file cannot be opened.
/// Returns [`CommonError::Config`] on parse errors.
///
/// # Examples
///
/// ```no_run
/// use openssl_common::config::load_config;
/// use std::path::Path;
///
/// let config = load_config(Path::new("/etc/ssl/openssl.cnf")).unwrap();
/// ```
pub fn load_config(path: &Path) -> Result<Config, CommonError> {
    ConfigParser::parse_file(path)
}

/// Loads configuration from the default path, returning an empty config
/// if no default configuration file is found.
///
/// Replaces the C pattern of calling `CONF_get1_default_config_file()`
/// followed by `NCONF_load()` with fallback to empty config on
/// `CONF_R_NO_SUCH_FILE`.
///
/// The default path is determined by [`get_default_config_path()`]:
///
/// 1. `$OPENSSL_CONF` environment variable.
/// 2. Platform-specific default (`/etc/ssl/openssl.cnf` on Unix).
///
/// # Errors
///
/// Returns [`CommonError::Config`] if the file exists but contains
/// syntax errors.
///
/// # Examples
///
/// ```
/// use openssl_common::config::load_config_or_default;
///
/// let config = load_config_or_default().unwrap();
/// // Returns empty config if no default file found
/// ```
pub fn load_config_or_default() -> Result<Config, CommonError> {
    match get_default_config_path() {
        Some(path) if path.is_file() => ConfigParser::parse_file(&path),
        _ => Ok(Config::new()),
    }
}

/// Returns the default configuration file path, if one can be determined.
///
/// Replaces `CONF_get1_default_config_file()` from `crypto/conf/conf_lib.c`.
///
/// # Resolution Order
///
/// 1. The `OPENSSL_CONF` environment variable, if set and non-empty.
/// 2. Platform default: `/etc/ssl/openssl.cnf` on Unix-like systems.
///
/// Returns `None` if no default path can be determined (e.g., on platforms
/// without a standard location and no env var set).
///
/// # Examples
///
/// ```
/// use openssl_common::config::get_default_config_path;
///
/// if let Some(path) = get_default_config_path() {
///     println!("Default config: {}", path.display());
/// }
/// ```
pub fn get_default_config_path() -> Option<PathBuf> {
    // Check OPENSSL_CONF environment variable first
    if let Ok(conf_path) = std::env::var("OPENSSL_CONF") {
        if !conf_path.is_empty() {
            return Some(PathBuf::from(conf_path));
        }
    }

    // Platform-specific default path
    #[cfg(unix)]
    {
        Some(PathBuf::from("/etc/ssl/openssl.cnf"))
    }

    #[cfg(windows)]
    {
        // On Windows, check CommonProgramFiles
        if let Ok(common) = std::env::var("CommonProgramFiles") {
            let mut path = PathBuf::from(common);
            path.push("SSL");
            path.push("openssl.cnf");
            return Some(path);
        }
        return Some(PathBuf::from("C:\\OpenSSL\\openssl.cnf"));
    }

    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::stable_sort_primitive,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new_is_empty() {
        let cfg = Config::new();
        assert!(cfg.is_empty());
    }

    #[test]
    fn test_set_and_get_string() {
        let mut cfg = Config::new();
        cfg.set_string("section1", "key1", "value1".to_string());
        assert_eq!(cfg.get_string("section1", "key1"), Some("value1"));
    }

    #[test]
    fn test_get_string_fallback_to_default() {
        let mut cfg = Config::new();
        cfg.set_string("default", "fallback_key", "fallback_val".to_string());
        // Querying a non-existent section should fall back to "default"
        assert_eq!(
            cfg.get_string("nonexistent", "fallback_key"),
            Some("fallback_val")
        );
    }

    #[test]
    fn test_get_string_no_fallback_for_default_section() {
        let mut cfg = Config::new();
        cfg.set_string("default", "key", "val".to_string());
        // Querying "default" section directly should work without double-lookup
        assert_eq!(cfg.get_string("default", "key"), Some("val"));
    }

    #[test]
    fn test_get_string_returns_none_for_missing() {
        let cfg = Config::new();
        assert!(cfg.get_string("any", "missing").is_none());
    }

    #[test]
    fn test_get_section() {
        let mut cfg = Config::new();
        cfg.set_string("sect", "k1", "v1".to_string());
        cfg.set_string("sect", "k2", "v2".to_string());
        let sect = cfg.get_section("sect").unwrap();
        assert_eq!(sect.len(), 2);
        assert_eq!(sect.get("k1"), Some(&"v1".to_string()));
    }

    #[test]
    fn test_get_section_none_for_missing() {
        let cfg = Config::new();
        assert!(cfg.get_section("nonexistent").is_none());
    }

    #[test]
    fn test_remove() {
        let mut cfg = Config::new();
        cfg.set_string("s", "k", "v".to_string());
        assert_eq!(cfg.remove("s", "k"), Some("v".to_string()));
        assert!(cfg.get_string("s", "k").is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut cfg = Config::new();
        assert!(cfg.remove("s", "k").is_none());
    }

    #[test]
    fn test_sections_iterator() {
        let mut cfg = Config::new();
        cfg.set_string("alpha", "k", "v".to_string());
        cfg.set_string("beta", "k", "v".to_string());
        let mut names: Vec<&str> = cfg.sections().collect();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_merge() {
        let mut cfg1 = Config::new();
        cfg1.set_string("sect", "k1", "old".to_string());
        cfg1.set_string("sect", "k2", "keep".to_string());

        let mut cfg2 = Config::new();
        cfg2.set_string("sect", "k1", "new".to_string());
        cfg2.set_string("other", "k3", "added".to_string());

        cfg1.merge(&cfg2);
        assert_eq!(cfg1.get_string("sect", "k1"), Some("new"));
        assert_eq!(cfg1.get_string("sect", "k2"), Some("keep"));
        assert_eq!(cfg1.get_string("other", "k3"), Some("added"));
    }

    #[test]
    fn test_parse_basic_ini() {
        let input = b"[default]\nkey1 = value1\nkey2 = value2\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key1"), Some("value1"));
        assert_eq!(cfg.get_string("default", "key2"), Some("value2"));
    }

    #[test]
    fn test_parse_multiple_sections() {
        let input = b"[section_a]\nk = a_val\n[section_b]\nk = b_val\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("section_a", "k"), Some("a_val"));
        assert_eq!(cfg.get_string("section_b", "k"), Some("b_val"));
    }

    #[test]
    fn test_parse_comments() {
        let input = b"[default]\n# this is a comment\nkey = value # inline comment\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("value"));
    }

    #[test]
    fn test_parse_continuation_line() {
        let input = b"[default]\nkey = hello \\\nworld\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("hello world"));
    }

    #[test]
    fn test_parse_variable_expansion() {
        let input = b"[default]\nbase = /usr/local\ndir = $base/ssl\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "dir"), Some("/usr/local/ssl"));
    }

    #[test]
    fn test_parse_braced_variable_expansion() {
        let input = b"[default]\nbase = /usr/local\ndir = ${base}/ssl\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "dir"), Some("/usr/local/ssl"));
    }

    #[test]
    fn test_parse_cross_section_variable() {
        let input = b"[paths]\nroot = /opt\n[default]\nfull = $paths::root/openssl\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "full"), Some("/opt/openssl"));
    }

    #[test]
    fn test_parse_braced_cross_section_variable() {
        let input = b"[paths]\nroot = /opt\n[default]\nfull = ${paths::root}/openssl\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "full"), Some("/opt/openssl"));
    }

    #[test]
    fn test_parse_cross_section_assignment() {
        let input = b"[default]\nother_sect::key = cross_val\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("other_sect", "key"), Some("cross_val"));
    }

    #[test]
    fn test_parse_quoted_string_single() {
        let input = b"[default]\nkey = 'hello world'\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("hello world"));
    }

    #[test]
    fn test_parse_quoted_string_double() {
        let input = b"[default]\nkey = \"hello world\"\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("hello world"));
    }

    #[test]
    fn test_parse_escape_sequences() {
        let input = b"[default]\nkey = hello\\nworld\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("hello\nworld"));
    }

    #[test]
    fn test_parse_pragma_dollarid() {
        let input = b".pragma dollarid:true\n[default]\nkey = $literal\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        // With dollarid:true, bare $literal is treated as literal "$literal"
        assert_eq!(cfg.get_string("default", "key"), Some("$literal"));
    }

    #[test]
    fn test_parse_blank_lines_and_whitespace() {
        let input = b"\n\n[default]\n\n  key = value  \n\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("value"));
    }

    #[test]
    fn test_parse_missing_close_bracket() {
        let input = b"[unclosed\nkey = val\n";
        let result = ConfigParser::parse_reader(&input[..]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("missing close square bracket"));
    }

    #[test]
    fn test_parse_missing_equal_sign() {
        let input = b"[default]\nbadline\n";
        let result = ConfigParser::parse_reader(&input[..]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("missing equal sign"));
    }

    #[test]
    fn test_variable_expansion_too_long() {
        // Create a value that will exceed MAX_CONF_VALUE_LENGTH after expansion
        let big_val = "x".repeat(MAX_CONF_VALUE_LENGTH);
        let input = format!("[default]\nbig = {}\nresult = ${{big}}${{big}}\n", big_val);
        let result = ConfigParser::parse_reader(input.as_bytes());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too long"));
    }

    #[test]
    fn test_undefined_variable_error() {
        let input = b"[default]\nkey = $undefined_var\n";
        let result = ConfigParser::parse_reader(&input[..]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("has no value"));
    }

    #[test]
    fn test_max_conf_value_length_constant() {
        assert_eq!(MAX_CONF_VALUE_LENGTH, 65536);
    }

    #[test]
    fn test_conf_value_serialize_deserialize() {
        let val = ConfValue {
            section: "sect".to_string(),
            name: "key".to_string(),
            value: "val".to_string(),
        };
        let json = serde_json::to_string(&val).unwrap();
        let restored: ConfValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, restored);
    }

    #[test]
    fn test_config_serialize_deserialize() {
        let mut cfg = Config::new();
        cfg.set_string("sect", "key", "val".to_string());
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.get_string("sect", "key"), Some("val"));
    }

    #[test]
    fn test_config_module_registry() {
        struct TestModule;
        impl ConfigModule for TestModule {
            fn name(&self) -> &str {
                "test_mod"
            }
            fn init(&self, _config: &Config, _section: &str) -> Result<(), CommonError> {
                Ok(())
            }
            fn finish(&self) -> Result<(), CommonError> {
                Ok(())
            }
        }

        let mut registry = ConfigModuleRegistry::new();
        registry.register(Box::new(TestModule));

        let mut cfg = Config::new();
        cfg.set_string("default", "openssl_conf", "conf_sect".to_string());
        cfg.set_string("conf_sect", "test_mod", "test_section".to_string());
        cfg.set_string("test_section", "option", "val".to_string());

        let result = registry.load_modules(&cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_module_registry_no_openssl_conf() {
        let registry = ConfigModuleRegistry::new();
        let cfg = Config::new();
        // No openssl_conf directive — should succeed without loading anything
        assert!(registry.load_modules(&cfg).is_ok());
    }

    #[test]
    fn test_config_module_registry_unknown_module() {
        let registry = ConfigModuleRegistry::new();
        let mut cfg = Config::new();
        cfg.set_string("default", "openssl_conf", "conf_sect".to_string());
        cfg.set_string("conf_sect", "nonexistent_mod", "some_section".to_string());
        cfg.set_string("some_section", "k", "v".to_string());

        let result = registry.load_modules(&cfg);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unknown module name"));
    }

    #[test]
    fn test_get_default_config_path_returns_some() {
        // This should return Some on any platform with OPENSSL_CONF or a default
        let path = get_default_config_path();
        assert!(path.is_some());
    }

    #[test]
    fn test_load_config_or_default_returns_ok() {
        // Should always succeed, returning empty config if no default file exists
        let result = load_config_or_default();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_utf8_bom() {
        let mut input = Vec::new();
        input.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // UTF-8 BOM
        input.extend_from_slice(b"[default]\nkey = value\n");
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("value"));
    }

    #[test]
    fn test_parse_pragma_abspath() {
        let input = b".pragma abspath:true\n[default]\nkey = value\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "key"), Some("value"));
    }

    #[test]
    fn test_clear_comments_preserves_quoted_hash() {
        // Hash inside quotes should not be treated as comment
        let result = ConfigParser::clear_comments("key = 'val#ue'");
        assert_eq!(result, "key = 'val#ue'");
    }

    #[test]
    fn test_clear_comments_strips_inline() {
        let result = ConfigParser::clear_comments("key = value # comment");
        assert_eq!(result, "key = value ");
    }

    #[test]
    fn test_decode_string_backslash_escapes() {
        assert_eq!(ConfigParser::decode_string("hello\\nworld"), "hello\nworld");
        assert_eq!(ConfigParser::decode_string("tab\\there"), "tab\there");
        assert_eq!(ConfigParser::decode_string("back\\bspace"), "back\x08space");
        assert_eq!(ConfigParser::decode_string("ret\\rurn"), "ret\rurn");
        assert_eq!(ConfigParser::decode_string("lit\\\\eral"), "lit\\eral");
    }

    #[test]
    fn test_decode_string_double_quoted_escape() {
        // Doubled double-quotes inside double-quoted string
        assert_eq!(
            ConfigParser::decode_string("\"hello\"\"world\""),
            "hello\"world"
        );
    }

    #[test]
    fn test_config_overwrite_existing() {
        let mut cfg = Config::new();
        cfg.set_string("s", "k", "old".to_string());
        cfg.set_string("s", "k", "new".to_string());
        assert_eq!(cfg.get_string("s", "k"), Some("new"));
    }

    #[test]
    fn test_parse_paren_variable_expansion() {
        let input = b"[default]\nbase = /usr\ndir = $(base)/local\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        assert_eq!(cfg.get_string("default", "dir"), Some("/usr/local"));
    }

    #[test]
    fn test_config_module_registry_finish_all() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct FinishTracker {
            finished: Arc<AtomicBool>,
        }
        impl ConfigModule for FinishTracker {
            fn name(&self) -> &str {
                "tracker"
            }
            fn init(&self, _: &Config, _: &str) -> Result<(), CommonError> {
                Ok(())
            }
            fn finish(&self) -> Result<(), CommonError> {
                self.finished.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let finished = Arc::new(AtomicBool::new(false));
        let mut registry = ConfigModuleRegistry::new();
        registry.register(Box::new(FinishTracker {
            finished: finished.clone(),
        }));

        assert!(!finished.load(Ordering::SeqCst));
        registry.finish_all().unwrap();
        assert!(finished.load(Ordering::SeqCst));
    }

    #[test]
    fn test_parse_empty_input() {
        let input = b"";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        // Should have the pre-created "default" section (empty)
        assert!(cfg.get_section("default").is_some());
    }

    #[test]
    fn test_parse_comment_only_lines() {
        let input = b"# line 1\n# line 2\n";
        let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
        // Should succeed with no useful data beyond default section
        assert!(cfg.get_section("default").is_some());
    }
}
