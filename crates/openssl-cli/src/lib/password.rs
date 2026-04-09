//! Passphrase handling, secure prompting, and UI method abstraction.
//!
//! Replaces `apps/lib/apps_ui.c` (216 lines) and `apps/include/apps_ui.h`.
//! Provides secure passphrase collection with verification, prompt construction,
//! default password replay, and secure memory cleanup via [`zeroize`].
//!
//! ## Key Differences from C
//!
//! - Uses [`zeroize::Zeroizing<String>`] for all passphrase buffers (replaces
//!   `OPENSSL_cleanse` and `OPENSSL_clear_free`).
//! - RAII-based cleanup replaces manual `destroy_ui_method()` / `UI_free()`.
//! - [`rpassword`] crate for console prompting replaces `UI_OpenSSL()`.
//! - No global mutable state: [`PasswordHandler`] is an owned value.
//! - [`Result<T, PasswordError>`] replaces sentinel return values (0, -1, -2).
//!
//! ## C Source Reference
//!
//! | C Construct | Rust Replacement |
//! |-------------|-----------------|
//! | `static UI_METHOD *ui_method` (global) | [`PasswordHandler`] (owned, no global) |
//! | `PW_CB_DATA` | [`PasswordCallbackData`] with `Option<Zeroizing<String>>` |
//! | `password_callback()` returning `strlen`/`0`/`-1`/`-2` | [`PasswordHandler::prompt_password`] returning `Result` |
//! | `setup_ui_method()` / `destroy_ui_method()` | [`PasswordHandler::new()`] / `Drop` trait |
//! | `OPENSSL_cleanse(buf, bufsiz)` | [`Zeroizing<String>`] (auto-zeroed on drop) |
//! | `UI_add_input_string()` + `UI_process()` | [`rpassword::prompt_password()`] |
//! | `UI_null()` as base | `interactive: false` mode |
//! | `UI_OpenSSL()` as base | `interactive: true` mode |

use std::io::{self, BufRead, IsTerminal, Write};
use std::{env, fs};

use thiserror::Error;
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum password length accepted by password prompts.
///
/// Replaces C's `PW_MIN_LENGTH` from `apps_ui.h:13`.
/// Used in [`PasswordHandler::prompt_password`] for interactive validation
/// and corresponds to the `PW_MIN_LENGTH` parameter passed to
/// `UI_add_input_string()` in the C implementation.
pub const PW_MIN_LENGTH: usize = 4;

/// Maximum number of retry attempts for password verification when the
/// first and second passwords do not match.
///
/// This bounds the verification loop in [`PasswordHandler::prompt_password`]
/// to prevent an infinite retry cycle. The C implementation used
/// `UI_ctrl(ui, UI_CTRL_IS_REDOABLE)` which allowed a single redo;
/// we allow up to 3 attempts for better user experience while still
/// bounding the loop.
const MAX_VERIFY_RETRIES: usize = 3;

// ---------------------------------------------------------------------------
// Error Types — replaces C return codes (0, -1, -2) per Rule R5
// ---------------------------------------------------------------------------

/// Errors that can occur during password handling operations.
///
/// Replaces C's return code pattern from `password_callback()` in
/// `apps_ui.c:157-216`:
/// - `ok = strlen(buf)` → `Ok(Zeroizing<String>)`
/// - `ok = -1` → [`PasswordError::UiError`]
/// - `ok = -2` → [`PasswordError::Aborted`]
///
/// Rule R5: No sentinel values (0, -1, -2) — explicit error variants.
#[derive(Debug, Error)]
pub enum PasswordError {
    /// I/O error during password input (terminal read, file read, etc.).
    ///
    /// Auto-converted from [`std::io::Error`] via `#[from]`.
    /// Replaces C's `BIO_puts(bio_err, ...)` error output patterns.
    #[error("I/O error during password input: {0}")]
    Io(#[from] io::Error),

    /// Password is shorter than [`PW_MIN_LENGTH`] characters.
    ///
    /// Raised when the user enters a password that doesn't meet the minimum
    /// length requirement. Replaces C's silent enforcement via
    /// `UI_add_input_string(ui, prompt, flags, buf, PW_MIN_LENGTH, bufsiz - 1)`
    /// at `apps_ui.c:185-186`.
    #[error("password too short (minimum 4 characters)")]
    TooShort,

    /// First and second password entries do not match during verification.
    ///
    /// Raised after exhausting [`MAX_VERIFY_RETRIES`] attempts. Replaces C's
    /// redo loop: `do { ok = UI_process(ui); } while (ok < 0 && UI_ctrl(..))`.
    #[error("password verification failed: passwords do not match")]
    VerificationMismatch,

    /// User explicitly aborted password entry (e.g., Ctrl+C, EOF on input).
    ///
    /// Replaces C's `ok == -2` ("aborted!") case at `apps_ui.c:208-211`.
    #[error("user aborted password entry")]
    Aborted,

    /// General UI/prompting infrastructure error.
    ///
    /// Replaces C's `ok == -1` ("User interface error") case at
    /// `apps_ui.c:202-206`, including `ERR_print_errors(bio_err)`.
    #[error("UI method error: {0}")]
    UiError(String),
}

// ---------------------------------------------------------------------------
// Password Callback Data — replaces PW_CB_DATA from apps_ui.h:14-17
// ---------------------------------------------------------------------------

/// Data passed to password callback functions.
///
/// Replaces C's `PW_CB_DATA` struct from `apps_ui.h:14-17`:
/// ```c
/// typedef struct pw_cb_data {
///     const void *password;
///     const char *prompt_info;
/// } PW_CB_DATA;
/// ```
///
/// ## Key Changes from C
///
/// - `password` is `Option<Zeroizing<String>>` instead of `const void*` —
///   type-safe, auto-zeroed on drop per AAP §0.7.6.
/// - `prompt_info` is `Option<String>` instead of `const char*` — no null
///   pointer risk per Rule R5.
/// - Both fields are [`Option<T>`] rather than nullable C pointers.
#[derive(Debug, Clone)]
pub struct PasswordCallbackData {
    /// Pre-set password for non-interactive or default mode.
    ///
    /// When `Some`, this password is returned by
    /// [`PasswordHandler::prompt_password`] without prompting the user.
    /// Uses [`Zeroizing<String>`] per AAP §0.7.6 — the password is
    /// automatically zeroed in memory on drop, replacing C's
    /// `OPENSSL_cleanse()` calls.
    pub password: Option<Zeroizing<String>>,

    /// Information to display in the prompt (e.g., key file name).
    ///
    /// Replaces C's `prompt_info` field. When `Some("mykey.pem")`, the
    /// prompt becomes `"Enter pass phrase for mykey.pem: "`.
    /// When `None`, defaults to `"private key"`.
    pub prompt_info: Option<String>,
}

impl PasswordCallbackData {
    /// Create callback data with a preset password.
    ///
    /// The password will be returned without prompting when passed to
    /// [`PasswordHandler::prompt_password`].
    pub fn with_password(password: impl Into<String>) -> Self {
        Self {
            password: Some(Zeroizing::new(password.into())),
            prompt_info: None,
        }
    }

    /// Create callback data with only prompt information (no preset password).
    ///
    /// The prompt info is displayed when the user is interactively prompted
    /// for a password.
    pub fn with_prompt_info(info: impl Into<String>) -> Self {
        Self {
            password: None,
            prompt_info: Some(info.into()),
        }
    }

    /// Create empty callback data (no preset, no prompt info).
    pub fn empty() -> Self {
        Self {
            password: None,
            prompt_info: None,
        }
    }
}

impl Default for PasswordCallbackData {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// Password Handler — replaces UI_METHOD global state from apps_ui.c:15-16
// ---------------------------------------------------------------------------

/// Handler for password prompting and verification.
///
/// Replaces the C global `ui_method` / `ui_base_method` static state
/// and the `UI_METHOD` callback chain (`ui_open`, `ui_read`, `ui_write`,
/// `ui_close`, `ui_prompt_construct`) from `apps_ui.c:15-107`.
///
/// ## RAII Design
///
/// No explicit `destroy_ui_method()` needed — Rust's ownership model handles
/// cleanup. No global state — each handler is an owned value.
///
/// ## Interactive vs Non-Interactive
///
/// - **Interactive** (`interactive: true`): Prompts on the terminal via
///   [`rpassword`] without echo. Behaves like C's `UI_OpenSSL()`.
/// - **Non-Interactive** (`interactive: false`): Returns empty password or
///   preset from callback data. Behaves like C's `UI_null()`.
///
/// ## Wiring (Rule R10)
///
/// Reachable via: `main.rs` → `commands/*.rs` (any command using
/// `-passin`/`-passout`) → `lib::password::PasswordHandler`.
#[derive(Debug, Clone)]
pub struct PasswordHandler {
    /// Whether to use interactive console prompting.
    ///
    /// Determined by TTY detection in [`PasswordHandler::new()`] or
    /// explicitly set via [`PasswordHandler::with_interactive()`].
    interactive: bool,
}

impl PasswordHandler {
    /// Create a new password handler with automatic TTY detection.
    ///
    /// Replaces `setup_ui_method()` from `apps_ui.c:117-130`:
    /// - C checked `OPENSSL_NO_UI_CONSOLE` to decide between `UI_OpenSSL()`
    ///   and `UI_null()`
    /// - Rust checks whether stdin is a TTY via [`std::io::IsTerminal`]
    ///
    /// # TTY Detection
    ///
    /// If stdin is a terminal (interactive session), prompting is enabled.
    /// If stdin is piped or redirected (CI, scripts), non-interactive mode
    /// is used automatically.
    pub fn new() -> Self {
        let interactive = io::stdin().is_terminal();
        debug!(interactive, "password handler created with TTY detection");
        Self { interactive }
    }

    /// Create a new password handler with explicit interactive mode control.
    ///
    /// Replaces `set_base_ui_method()` from `apps_ui.c:109-115` which
    /// allowed switching between `UI_OpenSSL()` and `UI_null()` base methods.
    ///
    /// # Arguments
    ///
    /// * `interactive` - If `true`, prompts on terminal without echo;
    ///   if `false`, returns empty password or preset from callback data.
    pub fn with_interactive(interactive: bool) -> Self {
        debug!(interactive, "password handler created with explicit mode");
        Self { interactive }
    }

    /// Prompt for a password, optionally with verification.
    ///
    /// Replaces `password_callback()` from `apps_ui.c:157-216`.
    ///
    /// # Arguments
    ///
    /// * `verify` - If `true`, prompt twice and verify passwords match.
    ///   Replaces C's `verify` parameter and `UI_add_verify_string()`.
    /// * `cb_data` - Optional callback data with preset password and prompt
    ///   info. Replaces C's `PW_CB_DATA *cb_data` parameter.
    ///
    /// # Returns
    ///
    /// * `Ok(Zeroizing<String>)` - The entered password (zeroed on drop).
    /// * `Err(PasswordError)` - On I/O error, too-short password, mismatch,
    ///   or abort.
    ///
    /// # Security
    ///
    /// - Password buffers use [`Zeroizing<String>`] — zeroed on drop per
    ///   AAP §0.7.6.
    /// - Replaces C's manual `OPENSSL_cleanse(buf, bufsiz)` at
    ///   `apps_ui.c:198,205,211`.
    /// - Replaces C's `OPENSSL_clear_free(buff, bufsiz)` at `apps_ui.c:198`.
    ///
    /// # Behavior
    ///
    /// 1. If `cb_data.password` is `Some`, returns it without prompting
    ///    (replaces `UI_INPUT_FLAG_DEFAULT_PWD` at `apps_ui.c:31-49`).
    /// 2. If non-interactive, returns an empty password
    ///    (replaces `UI_set_result(ui, uis, "")` at `apps_ui.c:55`).
    /// 3. If interactive, prompts on the terminal without echo
    ///    (replaces `UI_add_input_string` + `UI_process` at `apps_ui.c:185-196`).
    /// 4. If `verify` is `true`, prompts again and compares
    ///    (replaces `UI_add_verify_string` at `apps_ui.c:188-192`).
    /// 5. Validates minimum length ([`PW_MIN_LENGTH`]).
    pub fn prompt_password(
        &self,
        verify: bool,
        cb_data: Option<&PasswordCallbackData>,
    ) -> Result<Zeroizing<String>, PasswordError> {
        // Step 1: Check for preset password in callback data.
        // Replaces apps_ui.c:31-49: default password replay via
        // UI_INPUT_FLAG_DEFAULT_PWD.
        if let Some(data) = cb_data {
            if let Some(ref pw) = data.password {
                debug!("using preset password from callback data");
                return Ok(pw.clone());
            }
        }

        // Step 2: Non-interactive mode → return empty password.
        // Replaces apps_ui.c:54-56: UI_set_result(ui, uis, "") fallback.
        if !self.interactive {
            debug!("non-interactive mode: returning empty password");
            return Ok(Zeroizing::new(String::new()));
        }

        // Step 3: Build the prompt string.
        // Replaces apps_ui.c:97-107: ui_prompt_construct() and
        // apps_ui.c:170-177: UI_construct_prompt(ui, "pass phrase", prompt_info).
        let prompt_info = cb_data
            .and_then(|d| d.prompt_info.as_deref())
            .unwrap_or("private key");
        let prompt = format!("Enter pass phrase for {prompt_info}: ");

        debug!("prompting for password interactively");

        // Step 4: Interactive prompting with optional verification.
        if verify {
            Self::prompt_with_verification(&prompt)
        } else {
            Self::prompt_single(&prompt)
        }
    }

    /// Prompt for a password once without verification.
    ///
    /// Reads the password from the terminal without echo using [`rpassword`].
    /// Validates that the password meets the minimum length requirement.
    ///
    /// Replaces `UI_add_input_string()` + `UI_process()` from
    /// `apps_ui.c:185-196`.
    fn prompt_single(prompt: &str) -> Result<Zeroizing<String>, PasswordError> {
        let raw = rpassword::prompt_password(prompt).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                PasswordError::Aborted
            } else {
                PasswordError::Io(e)
            }
        })?;

        let password = Zeroizing::new(raw);

        // Validate minimum length.
        // Replaces PW_MIN_LENGTH enforcement in UI_add_input_string
        // at apps_ui.c:185-186.
        if password.len() < PW_MIN_LENGTH {
            warn!(
                min_length = PW_MIN_LENGTH,
                actual_length = password.len(),
                "password too short"
            );
            return Err(PasswordError::TooShort);
        }

        Ok(password)
    }

    /// Prompt for a password with verification (ask twice, compare).
    ///
    /// Replaces the verification loop in `apps_ui.c:188-196`:
    /// ```c
    /// ok = UI_add_verify_string(ui, prompt, flags, buff,
    ///     PW_MIN_LENGTH, bufsiz - 1, buf);
    /// do {
    ///     ok = UI_process(ui);
    /// } while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));
    /// ```
    ///
    /// Bounded to [`MAX_VERIFY_RETRIES`] attempts to prevent infinite loops.
    fn prompt_with_verification(prompt: &str) -> Result<Zeroizing<String>, PasswordError> {
        for attempt in 0..MAX_VERIFY_RETRIES {
            // First prompt — reads and validates minimum length.
            let password = Self::prompt_single(prompt)?;

            // Second prompt for verification.
            let verify_prompt = format!("Verifying - {prompt}");
            let verification = rpassword::prompt_password(verify_prompt.as_str()).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    PasswordError::Aborted
                } else {
                    PasswordError::Io(e)
                }
            })?;
            let verification = Zeroizing::new(verification);

            // Compare the two entries.
            if *password == *verification {
                return Ok(password);
            }

            // Mismatch — warn and retry if attempts remain.
            let remaining = MAX_VERIFY_RETRIES.saturating_sub(attempt).saturating_sub(1);
            if remaining > 0 {
                // Write to stderr so the user sees the warning.
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "Passwords do not match, please try again ({remaining} attempt(s) remaining).",
                );
                warn!(
                    attempt = attempt.saturating_add(1),
                    max_retries = MAX_VERIFY_RETRIES,
                    "password verification mismatch, retrying"
                );
            }
        }

        // All retry attempts exhausted.
        error!("password verification failed after maximum retry attempts");
        Err(PasswordError::VerificationMismatch)
    }
}

impl Default for PasswordHandler {
    /// Creates a password handler with automatic TTY detection.
    ///
    /// Equivalent to [`PasswordHandler::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Password Source Parsing — replaces password source logic from apps.c
// ---------------------------------------------------------------------------

/// Parse a password source specification string.
///
/// Supports the same source formats as C's `apps/lib/apps.c` password handling:
///
/// - `pass:PASSWORD` — literal password on command line
/// - `env:VARNAME` — read from environment variable
/// - `file:FILENAME` — read first line from file
/// - `fd:NUMBER` — read from file descriptor (via `/dev/fd/` on Unix)
/// - `stdin` — read first line from standard input
///
/// # Returns
///
/// The password as a [`Zeroizing<String>`], or an error if the source is
/// invalid or unreadable.
///
/// # Security
///
/// - All returned passwords are wrapped in [`Zeroizing`] for automatic
///   secure memory cleanup on drop.
/// - `pass:` sources expose the password on the command line (visible in
///   `/proc/*/cmdline`). Prefer `env:` or `file:` for production use.
///
/// # Errors
///
/// Returns [`PasswordError::Io`] for file/fd read failures,
/// [`PasswordError::UiError`] for invalid source formats or missing
/// environment variables.
pub fn parse_password_source(source: &str) -> Result<Zeroizing<String>, PasswordError> {
    if let Some(literal) = source.strip_prefix("pass:") {
        // Literal password on command line.
        debug!("reading password from command-line literal");
        return Ok(Zeroizing::new(literal.to_string()));
    }

    if let Some(var_name) = source.strip_prefix("env:") {
        // Read from environment variable.
        debug!("reading password from environment variable");
        let value = env::var(var_name).map_err(|e| match e {
            env::VarError::NotPresent => {
                PasswordError::UiError(format!("environment variable '{var_name}' is not set"))
            }
            env::VarError::NotUnicode(_) => PasswordError::UiError(format!(
                "environment variable '{var_name}' contains invalid Unicode"
            )),
        })?;
        return Ok(Zeroizing::new(value));
    }

    if let Some(filename) = source.strip_prefix("file:") {
        // Read first line from file.
        debug!("reading password from file");
        let file = fs::File::open(filename)?;
        let reader = io::BufReader::new(file);
        let first_line = reader.lines().next().transpose()?.unwrap_or_default();
        return Ok(Zeroizing::new(first_line));
    }

    if let Some(fd_str) = source.strip_prefix("fd:") {
        // Read from file descriptor via /dev/fd/ path.
        // This avoids unsafe code by using the filesystem interface
        // to file descriptors available on Linux and macOS.
        debug!("reading password from file descriptor");
        let fd_num: u32 = fd_str.parse().map_err(|_| {
            PasswordError::UiError(format!("invalid file descriptor number: '{fd_str}'"))
        })?;
        let fd_path = format!("/dev/fd/{fd_num}");
        let file = fs::File::open(&fd_path).map_err(|e| {
            PasswordError::UiError(format!("cannot read from file descriptor {fd_num}: {e}"))
        })?;
        let reader = io::BufReader::new(file);
        let first_line = reader.lines().next().transpose()?.unwrap_or_default();
        return Ok(Zeroizing::new(first_line));
    }

    if source == "stdin" {
        // Read first line from standard input.
        debug!("reading password from stdin");
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        // Remove trailing newline characters (LF on Unix, CRLF on Windows).
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        return Ok(Zeroizing::new(line));
    }

    // Unrecognized source format.
    Err(PasswordError::UiError(format!(
        "unrecognized password source: '{source}'. \
         Expected one of: pass:<pw>, env:<var>, file:<path>, fd:<num>, stdin"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pw_min_length_value() {
        assert_eq!(PW_MIN_LENGTH, 4);
    }

    #[test]
    fn test_password_callback_data_default() {
        let data = PasswordCallbackData::default();
        assert!(data.password.is_none());
        assert!(data.prompt_info.is_none());
    }

    #[test]
    fn test_password_callback_data_with_password() {
        let data = PasswordCallbackData::with_password("test1234");
        assert!(data.password.is_some());
        assert_eq!(&**data.password.as_ref().unwrap(), "test1234");
        assert!(data.prompt_info.is_none());
    }

    #[test]
    fn test_password_callback_data_with_prompt_info() {
        let data = PasswordCallbackData::with_prompt_info("mykey.pem");
        assert!(data.password.is_none());
        assert_eq!(data.prompt_info.as_deref(), Some("mykey.pem"));
    }

    #[test]
    fn test_handler_non_interactive_no_data() {
        let handler = PasswordHandler::with_interactive(false);
        let result = handler.prompt_password(false, None);
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "");
    }

    #[test]
    fn test_handler_non_interactive_with_preset() {
        let handler = PasswordHandler::with_interactive(false);
        let data = PasswordCallbackData::with_password("preset123");
        let result = handler.prompt_password(false, Some(&data));
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "preset123");
    }

    #[test]
    fn test_handler_interactive_with_preset() {
        // Even in interactive mode, a preset password is returned directly.
        let handler = PasswordHandler::with_interactive(true);
        let data = PasswordCallbackData::with_password("preset456");
        let result = handler.prompt_password(false, Some(&data));
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "preset456");
    }

    #[test]
    fn test_parse_password_source_pass() {
        let pw = parse_password_source("pass:mysecret").unwrap();
        assert_eq!(&*pw, "mysecret");
    }

    #[test]
    fn test_parse_password_source_pass_empty() {
        let pw = parse_password_source("pass:").unwrap();
        assert_eq!(&*pw, "");
    }

    #[test]
    fn test_parse_password_source_pass_with_colons() {
        let pw = parse_password_source("pass:my:secret:value").unwrap();
        assert_eq!(&*pw, "my:secret:value");
    }

    #[test]
    fn test_parse_password_source_env() {
        env::set_var("OPENSSL_TEST_PW_12345", "envpassword");
        let pw = parse_password_source("env:OPENSSL_TEST_PW_12345").unwrap();
        assert_eq!(&*pw, "envpassword");
        env::remove_var("OPENSSL_TEST_PW_12345");
    }

    #[test]
    fn test_parse_password_source_env_missing() {
        let result = parse_password_source("env:NONEXISTENT_VAR_XYZ_99999");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, PasswordError::UiError(_)));
    }

    #[test]
    fn test_parse_password_source_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pw_file.txt");
        fs::write(&path, "filepassword\nsecond line\n").unwrap();
        let pw = parse_password_source(&format!("file:{}", path.display())).unwrap();
        assert_eq!(&*pw, "filepassword");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_password_source_file_missing() {
        let result = parse_password_source("file:/nonexistent/path/to/file.txt");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordError::Io(_)));
    }

    #[test]
    fn test_parse_password_source_fd_invalid() {
        let result = parse_password_source("fd:notanumber");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordError::UiError(_)));
    }

    #[test]
    fn test_parse_password_source_unknown() {
        let result = parse_password_source("unknown:source");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, PasswordError::UiError(_)));
        let msg = err.to_string();
        assert!(msg.contains("unrecognized password source"));
    }

    #[test]
    fn test_password_error_display() {
        let err = PasswordError::TooShort;
        assert_eq!(err.to_string(), "password too short (minimum 4 characters)");

        let err = PasswordError::VerificationMismatch;
        assert!(err.to_string().contains("do not match"));

        let err = PasswordError::Aborted;
        assert!(err.to_string().contains("aborted"));

        let err = PasswordError::UiError("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_password_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let pw_err: PasswordError = io_err.into();
        assert!(matches!(pw_err, PasswordError::Io(_)));
    }

    #[test]
    fn test_handler_with_interactive_creates_correct_mode() {
        let handler = PasswordHandler::with_interactive(true);
        assert!(handler.interactive);

        let handler = PasswordHandler::with_interactive(false);
        assert!(!handler.interactive);
    }

    #[test]
    fn test_password_callback_data_clone() {
        let data = PasswordCallbackData::with_password("clonetest");
        let cloned = data.clone();
        assert_eq!(
            data.password.as_deref().map(|s| s.as_str()),
            cloned.password.as_deref().map(|s| s.as_str())
        );
    }
}
