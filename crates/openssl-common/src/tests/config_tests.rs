// Test modules legitimately use `.unwrap()` / `.expect()`, `panic!` in
// assertion match arms, and format strings that trigger pedantic lints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_pass_by_value
)]

//! Tests for the configuration file parser in openssl-common.
//!
//! Comprehensive integration and unit tests for the [`crate::config`] module,
//! covering:
//!
//! - **Section header parsing:** empty, single, multiple, default, whitespace trimming.
//! - **Key-value assignments:** simple, no-spaces, quoted, continuation, cross-section.
//! - **Variable expansion:** `$var`, `${var}`, `$section::var`, nested, undefined,
//!   circular reference detection.
//! - **Directives:** `.include` (with real temp files) and `.pragma` handling.
//! - **Comment stripping:** `#` outside and inside quotes, full-line, blank lines.
//! - **`MAX_CONF_VALUE_LENGTH`** enforcement (65 536 characters).
//! - **Config data model:** `get`/`set`/`remove`/`merge`/`sections`/`is_empty`/default fallback.
//! - **UTF-8 BOM** handling (BOM prefix stripped transparently).
//! - **`ConfigModule`** trait and `ConfigModuleRegistry` wiring.
//!
//! Derived from C config parser behaviour in `crypto/conf/conf_def.c`.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All `get_*` methods return `Option<T>`, never sentinel
//!   empty strings. Tests verify `None` for missing keys.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in test code.
//! - **R9 (Warning-Free):** Compiles with `RUSTFLAGS="-D warnings"`.
//! - **R10 (Wiring):** All tests exercise the config module's public API.

use crate::config::{
    load_config, ConfValue, Config, ConfigModule, ConfigModuleRegistry, ConfigParser,
    MAX_CONF_VALUE_LENGTH,
};
use crate::error::CommonError;
use std::io::{BufReader, Cursor, Write};
use tempfile::NamedTempFile;

// =============================================================================
// Phase 2: Section Header Parsing Tests
// =============================================================================

/// Parse an empty input — the parser pre-creates a "default" section but it
/// contains no user-defined keys.
#[test]
fn parse_empty_config() {
    let input = b"";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    // The parser always creates a "default" section.
    assert!(cfg.get_section("default").is_some());
    // No user-defined key should be present.
    assert!(cfg.get_string("default", "userkey").is_none());
}

/// Single named section with one key-value pair.
#[test]
fn parse_single_section() {
    let input = b"[mysection]\nkey = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert!(cfg.get_section("mysection").is_some());
    assert_eq!(cfg.get_string("mysection", "key"), Some("value"));
}

/// Three distinct sections, each with its own key-value pair.
#[test]
fn parse_multiple_sections() {
    let input = b"[alpha]\nk1 = v1\n[beta]\nk2 = v2\n[gamma]\nk3 = v3\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("alpha", "k1"), Some("v1"));
    assert_eq!(cfg.get_string("beta", "k2"), Some("v2"));
    assert_eq!(cfg.get_string("gamma", "k3"), Some("v3"));
}

/// A key-value pair without a preceding section header goes into "default".
#[test]
fn parse_default_section() {
    let input = b"key = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// Section header with spaces around the name — name must be trimmed.
#[test]
fn parse_section_with_spaces() {
    let input = b"[ section_name ]\nkey = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert!(cfg.get_section("section_name").is_some());
    assert_eq!(cfg.get_string("section_name", "key"), Some("value"));
}

// =============================================================================
// Phase 3: Key-Value Assignment Tests
// =============================================================================

/// Simple assignment with spaces around `=`.
#[test]
fn parse_simple_assignment() {
    let input = b"[default]\nkey = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// Assignment without spaces around `=`.
#[test]
fn parse_assignment_no_spaces() {
    let input = b"[default]\nkey=value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// Double-quoted value — quotes stripped, whitespace inside preserved.
#[test]
fn parse_quoted_value() {
    let input = b"[default]\nkey = \"hello world\"\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("hello world"));
}

/// Continuation line: trailing `\` joins the next line.
#[test]
fn parse_continuation_line() {
    let input = b"[default]\nkey = hello \\\nworld\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("hello world"));
}

/// Cross-section qualified name: `target::name = value` stores into "target".
#[test]
fn parse_section_qualified_name() {
    let input = b"[default]\ntarget::name = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("target", "name"), Some("value"));
}

// =============================================================================
// Phase 4: Variable Expansion Tests
// =============================================================================

/// Simple `$var` expansion (unbraced).
#[test]
fn expand_simple_variable() {
    let input = b"[default]\na = hello\nb = $a world\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "b"), Some("hello world"));
}

/// Braced `${var}` expansion.
#[test]
fn expand_braced_variable() {
    let input = b"[default]\na = hello\nb = ${a} world\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "b"), Some("hello world"));
}

/// Section-qualified `$sec1::a` expansion across sections.
#[test]
fn expand_section_qualified() {
    let input = b"[sec1]\na = hello\n[sec2]\nb = $sec1::a world\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("sec2", "b"), Some("hello world"));
}

/// Nested variable references: `$a$a` expands both occurrences.
#[test]
fn expand_nested_variables() {
    let input = b"[default]\na = 1\nb = $a$a\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "b"), Some("11"));
}

/// Referencing an undefined variable must return `CommonError::Config`.
#[test]
fn expand_undefined_variable_error() {
    let input = b"[default]\nb = $nonexistent\n";
    let result = ConfigParser::parse_reader(&input[..]);
    assert!(result.is_err());
    match result.unwrap_err() {
        CommonError::Config { message } => {
            // Implementation reports "has no value" for undefined variables.
            assert!(
                message.contains("no value"),
                "Expected 'no value' in message, got: {}",
                message
            );
        }
        other => panic!("Expected CommonError::Config, got: {:?}", other),
    }
}

/// Circular / self-referencing variable: `a = $a`. Since `a` is not yet
/// stored when its own expansion is attempted, this surfaces as an
/// "undefined variable" error — same as the C parser behaviour.
#[test]
fn expand_recursive_detection() {
    let input = b"[default]\na = $a\n";
    let result = ConfigParser::parse_reader(&input[..]);
    assert!(result.is_err());
    match result.unwrap_err() {
        CommonError::Config { .. } => {
            // Expected — variable not found during its own expansion.
        }
        other => panic!("Expected CommonError::Config, got: {:?}", other),
    }
}

// =============================================================================
// Phase 5: Directive Tests
// =============================================================================

/// `.include <file>` — write a temp file containing `[included]\nk = v`, include
/// it from the main config, and verify the included section is present.
#[test]
fn include_file_directive() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"[included]\nk = v\n").unwrap();
    temp.flush().unwrap();
    let path_str = temp.path().to_str().unwrap();
    let input = format!("[default]\n.include {}\n", path_str);
    let cfg = ConfigParser::parse_reader(input.as_bytes()).unwrap();
    assert_eq!(cfg.get_string("included", "k"), Some("v"));
}

/// `.include /nonexistent/path` — per C `conf_def.c` behaviour, missing include
/// files are **not** fatal; the parser silently continues.
#[test]
fn include_nonexistent_file_error() {
    let input = b"[default]\n.include /nonexistent/path/file.cnf\n";
    let result = ConfigParser::parse_reader(&input[..]);
    // C-compatible behaviour: missing includes silently succeed.
    assert!(
        result.is_ok(),
        "Missing .include should succeed silently, got: {:?}",
        result.unwrap_err()
    );
}

/// `.pragma dollarid:true` — bare `$` is treated as a literal character;
/// only `${var}` triggers expansion.
#[test]
fn pragma_dollarid() {
    let input = b".pragma dollarid:true\n[default]\nkey = dollar$sign\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("dollar$sign"));
}

/// Unknown `.pragma` directives are silently ignored with no error.
#[test]
fn pragma_unknown_ignored() {
    let input = b".pragma unknown:value\n[default]\nkey = val\n";
    let result = ConfigParser::parse_reader(&input[..]);
    assert!(result.is_ok());
    let cfg = result.unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("val"));
}

// =============================================================================
// Phase 6: Comment Stripping Tests
// =============================================================================

/// Inline `#` comment — text after `#` stripped, value trimmed.
#[test]
fn strip_hash_comment() {
    let input = b"[default]\nkey = value # comment\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// `#` inside double-quoted strings is preserved — not treated as a comment.
#[test]
fn hash_inside_quotes_preserved() {
    let input = b"[default]\nkey = \"value # not a comment\"\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    let val = cfg.get_string("default", "key").unwrap();
    assert!(
        val.contains('#'),
        "Hash inside quotes must be preserved, got: {}",
        val
    );
    assert_eq!(val, "value # not a comment");
}

/// Full-line comments (lines starting with `#`) are skipped entirely.
#[test]
fn full_line_comment() {
    let input = b"# this is a comment\n[default]\nkey = value\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// Empty/blank lines between entries are harmlessly ignored.
#[test]
fn empty_lines_ignored() {
    let input = b"\n\n[default]\n\nkey = value\n\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

// =============================================================================
// Phase 7: MAX_CONF_VALUE_LENGTH Enforcement
// =============================================================================

/// A value of exactly `MAX_CONF_VALUE_LENGTH` characters is accepted.
#[test]
fn max_value_length_accepted() {
    let val = "x".repeat(MAX_CONF_VALUE_LENGTH);
    let input = format!("[default]\nkey = {}\n", val);
    let cfg = ConfigParser::parse_reader(input.as_bytes()).unwrap();
    assert_eq!(
        cfg.get_string("default", "key").map(str::len),
        Some(MAX_CONF_VALUE_LENGTH)
    );
}

/// A value that exceeds `MAX_CONF_VALUE_LENGTH` after expansion is rejected
/// with `CommonError::Config`.
#[test]
fn max_value_length_exceeded() {
    let big_val = "x".repeat(MAX_CONF_VALUE_LENGTH);
    let input = format!("[default]\nbig = {}\nresult = ${{big}}${{big}}\n", big_val);
    let result = ConfigParser::parse_reader(input.as_bytes());
    assert!(result.is_err());
    match result.unwrap_err() {
        CommonError::Config { message } => {
            assert!(
                message.contains("too long"),
                "Expected 'too long' in message, got: {}",
                message
            );
        }
        other => panic!("Expected CommonError::Config, got: {:?}", other),
    }
}

// =============================================================================
// Phase 8: Config Data Model Tests
// =============================================================================

/// `get_string()` returns `Some` for an existing key, `None` for a missing one
/// (Rule R5 — no sentinel empty strings).
#[test]
fn config_get_string_option() {
    let mut cfg = Config::new();
    cfg.set_string("sect", "key", "value".to_string());
    assert_eq!(cfg.get_string("sect", "key"), Some("value"));
    assert!(cfg.get_string("sect", "missing").is_none());
    assert!(cfg.get_string("nosect", "key").is_none());
}

/// `get_section()` returns `Some` for an existing section, `None` for a missing
/// one (Rule R5).
#[test]
fn config_get_section_option() {
    let mut cfg = Config::new();
    cfg.set_string("exists", "k", "v".to_string());
    assert!(cfg.get_section("exists").is_some());
    assert!(cfg.get_section("missing").is_none());
}

/// `set_string()` twice with the same key — second value overwrites the first.
#[test]
fn config_set_and_overwrite() {
    let mut cfg = Config::new();
    cfg.set_string("sect", "key", "first".to_string());
    cfg.set_string("sect", "key", "second".to_string());
    assert_eq!(cfg.get_string("sect", "key"), Some("second"));
}

/// `remove()` returns `Some(old_value)` and the key is no longer present.
#[test]
fn config_remove() {
    let mut cfg = Config::new();
    cfg.set_string("sect", "key", "value".to_string());
    assert_eq!(cfg.remove("sect", "key"), Some("value".to_string()));
    assert!(cfg.get_string("sect", "key").is_none());
}

/// `sections()` enumerates all sections that contain at least one key.
#[test]
fn config_sections_enumeration() {
    let mut cfg = Config::new();
    cfg.set_string("alpha", "k", "v".to_string());
    cfg.set_string("beta", "k", "v".to_string());
    cfg.set_string("gamma", "k", "v".to_string());
    let mut names: Vec<&str> = cfg.sections().collect();
    names.sort_unstable();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}

/// `merge()` — values from `other` overwrite existing keys; new sections and
/// keys are added.
#[test]
fn config_merge() {
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

/// `is_empty()` returns `true` for a fresh Config and `false` after adding.
#[test]
fn config_is_empty() {
    let cfg = Config::new();
    assert!(cfg.is_empty());
    let mut cfg2 = Config::new();
    cfg2.set_string("sect", "key", "val".to_string());
    assert!(!cfg2.is_empty());
}

/// `get_string("specific", "key")` falls back to the "default" section when
/// "specific" does not contain the requested key.
#[test]
fn config_default_section_fallback() {
    let mut cfg = Config::new();
    cfg.set_string("default", "shared_key", "default_val".to_string());
    // Querying a section that does not contain the key should fall back.
    assert_eq!(
        cfg.get_string("specific", "shared_key"),
        Some("default_val")
    );
}

// =============================================================================
// Phase 9: UTF-8 BOM Handling
// =============================================================================

/// A UTF-8 BOM (0xEF 0xBB 0xBF) at the start of the config is stripped
/// transparently — parsing proceeds normally.
#[test]
fn utf8_bom_stripped() {
    let mut input = Vec::new();
    input.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // UTF-8 BOM
    input.extend_from_slice(b"[default]\nkey = value\n");
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

// =============================================================================
// Phase 10: ConfigModule Trait Tests
// =============================================================================

/// Register a mock `ConfigModule`, set up a config that triggers module loading,
/// and verify that `init()` is called with the correct section.
#[test]
fn config_module_registry_register_and_load() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A mock module that records whether `init` was called.
    struct MockModule {
        init_called: Arc<AtomicBool>,
    }

    impl ConfigModule for MockModule {
        fn name(&self) -> &str {
            "mock_mod"
        }

        fn init(&self, _config: &Config, _section: &str) -> Result<(), CommonError> {
            self.init_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn finish(&self) -> Result<(), CommonError> {
            Ok(())
        }
    }

    let init_called = Arc::new(AtomicBool::new(false));
    let mut registry = ConfigModuleRegistry::new();
    registry.register(Box::new(MockModule {
        init_called: init_called.clone(),
    }));

    // Build a config that references the mock module.
    // default → openssl_conf = conf_sect
    // conf_sect → mock_mod = mock_section
    // mock_section → option = value  (arbitrary content for the module)
    let mut cfg = Config::new();
    cfg.set_string("default", "openssl_conf", "conf_sect".to_string());
    cfg.set_string("conf_sect", "mock_mod", "mock_section".to_string());
    cfg.set_string("mock_section", "option", "value".to_string());

    let result = registry.load_modules(&cfg);
    assert!(
        result.is_ok(),
        "load_modules failed: {:?}",
        result.unwrap_err()
    );
    assert!(
        init_called.load(Ordering::SeqCst),
        "MockModule::init() should have been called"
    );
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

/// `ConfValue` struct construction and field access.
#[test]
fn conf_value_construction() {
    let val = ConfValue {
        section: "test_section".to_string(),
        name: "test_key".to_string(),
        value: "test_value".to_string(),
    };
    assert_eq!(val.section, "test_section");
    assert_eq!(val.name, "test_key");
    assert_eq!(val.value, "test_value");
    // Verify Clone + PartialEq
    let val2 = val.clone();
    assert_eq!(val, val2);
}

/// Exercise `ConfigParser::parse_file()` with a real temporary file.
#[test]
fn parse_file_with_tempfile() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"[test_section]\nfoo = bar\n").unwrap();
    temp.flush().unwrap();
    let cfg = ConfigParser::parse_file(temp.path()).unwrap();
    assert_eq!(cfg.get_string("test_section", "foo"), Some("bar"));
}

/// `load_config()` with a nonexistent file returns `CommonError::Io`.
#[test]
fn load_config_nonexistent_returns_io_error() {
    let result = load_config(std::path::Path::new("/nonexistent/path/config.cnf"));
    assert!(result.is_err());
    match result.unwrap_err() {
        CommonError::Io(_) => {
            // Expected — file not found produces an I/O error.
        }
        other => panic!("Expected CommonError::Io, got: {:?}", other),
    }
}

/// Exercise `BufReader` wrapper around a `Cursor` source — ensures the
/// `parse_reader<R: BufRead>()` generic works with different `BufRead`
/// implementations.
#[test]
fn parse_via_bufreader() {
    let data = b"[default]\nkey = value\n";
    let cursor = Cursor::new(&data[..]);
    let reader = BufReader::new(cursor);
    let cfg = ConfigParser::parse_reader(reader).unwrap();
    assert_eq!(cfg.get_string("default", "key"), Some("value"));
}

/// Single-quoted value preserves the hash character inside.
#[test]
fn single_quoted_value_preserves_content() {
    let input = b"[default]\nkey = 'value # preserved'\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    let val = cfg.get_string("default", "key").unwrap();
    assert_eq!(val, "value # preserved");
}

/// Multiple keys in the same section are all accessible.
#[test]
fn multiple_keys_in_section() {
    let input = b"[default]\nk1 = v1\nk2 = v2\nk3 = v3\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "k1"), Some("v1"));
    assert_eq!(cfg.get_string("default", "k2"), Some("v2"));
    assert_eq!(cfg.get_string("default", "k3"), Some("v3"));
}

/// Braced section-qualified variable: `${sec1::a}`.
#[test]
fn expand_braced_section_qualified() {
    let input = b"[sec1]\na = hello\n[sec2]\nb = ${sec1::a} world\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("sec2", "b"), Some("hello world"));
}

/// Variable expansion chains: `c` references `b` which references `a`.
#[test]
fn expand_chained_variables() {
    let input = b"[default]\na = X\nb = $a$a\nc = $b$b\n";
    let cfg = ConfigParser::parse_reader(&input[..]).unwrap();
    assert_eq!(cfg.get_string("default", "c"), Some("XXXX"));
}
