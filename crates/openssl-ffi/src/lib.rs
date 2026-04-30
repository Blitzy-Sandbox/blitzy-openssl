//! OpenSSL FFI - C ABI compatibility layer.
//!
//! This is the ONLY crate in the workspace that is permitted to use `unsafe` code.
//! It provides C-compatible function exports via `#[no_mangle] pub extern "C" fn`
//! for backward compatibility with existing C consumers.

#![allow(unsafe_code)]

pub mod bio;
pub mod crypto;
pub mod evp;
