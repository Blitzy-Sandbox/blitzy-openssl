//! OpenSSL Common - Shared foundation types, error handling, and configuration.
//!
//! This crate provides shared types and utilities used across the OpenSSL Rust workspace.

#![forbid(unsafe_code)]

pub mod constant_time;
pub mod error;
pub mod observability;
pub mod types;
