//! Shared CLI infrastructure library.
//!
//! This module provides common helpers used across multiple CLI subcommands,
//! including option parsing utilities, format handling, and display helpers.
//!
//! Replaces `apps/lib/*.c` (21 C source files) with idiomatic Rust modules.

pub mod opts;
pub mod password;
