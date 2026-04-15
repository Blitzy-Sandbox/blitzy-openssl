//! OpenSSL Common - Shared foundation types, error handling, and configuration.
//!
//! This crate provides shared types and utilities used across the OpenSSL Rust workspace.

#![forbid(unsafe_code)]

pub mod constant_time;
pub mod error;
pub mod mem;
pub mod observability;
pub mod param;
pub mod safe_math;
pub mod time;
pub mod types;

#[cfg(test)]
mod tests;
