//! Test modules for the openssl-common foundation crate.
//!
//! Each submodule tests a corresponding source module through its public API,
//! enforcing Rule R10 (wiring verification). Currently covers the four
//! delivered source modules: `constant_time`, `error`, `observability`, and
//! `types`. Additional test modules for `config`, `mem`, `param`,
//! `safe_math`, and `time` will be added when those source modules are
//! delivered.

#[cfg(test)]
mod constant_time_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod observability_tests;
#[cfg(test)]
mod types_tests;
