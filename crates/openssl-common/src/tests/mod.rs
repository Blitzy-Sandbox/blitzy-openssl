//! Test modules for the openssl-common foundation crate.
//!
//! Each submodule tests a corresponding source module (error, config, param,
//! types, time, safe_math, constant_time, mem, observability). All tests
//! enforce Rule R10 by exercising modules through their public API.

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
