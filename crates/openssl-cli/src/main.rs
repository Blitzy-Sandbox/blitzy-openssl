//! OpenSSL CLI - Command-line interface for the OpenSSL Rust workspace.
//!
//! This binary provides the `openssl-rs` command with 56+ subcommands.

// Justification: `lib` is an intra-crate module directory containing shared CLI
// helpers, not the crate's library root. This crate is a binary-only target.
// The crate-level allow is required because item-level #[allow] does not fully
// suppress special_module_name when RUSTFLAGS="-D warnings" is set.
#![allow(special_module_name)]

pub mod lib;

fn main() {
    println!("openssl-rs: CLI stub - implementation pending");
}
