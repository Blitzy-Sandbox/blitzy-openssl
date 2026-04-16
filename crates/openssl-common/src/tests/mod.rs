//! Test modules for the openssl-common foundation crate.
//!
//! Contains comprehensive test suites for all openssl-common submodules.
//! Each submodule exercises the corresponding source module through its
//! public API, enforcing Rule R10 (wiring verification): `config`,
//! `constant_time`, `error`, `mem`, `observability`, `param`, `safe_math`,
//! `time`, and `types`.

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod constant_time_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod mem_tests;
#[cfg(test)]
mod observability_tests;
#[cfg(test)]
mod param_tests;
#[cfg(test)]
mod safe_math_tests;
#[cfg(test)]
mod time_tests;
#[cfg(test)]
mod types_tests;
