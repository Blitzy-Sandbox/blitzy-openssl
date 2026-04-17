//! Integration test modules for the openssl-provider crate.
//!
//! These tests exercise cross-provider interactions that span multiple
//! provider implementations and the method store dispatch infrastructure.
//! They complement the extensive inline unit tests in each provider module
//! (default.rs, base.rs, null.rs, legacy.rs, dispatch.rs, traits.rs).
//!
//! # Modules
//!
//! - [`cross_provider`] — Tests that register multiple providers in a
//!   [`MethodStore`](crate::dispatch::MethodStore) and verify correct
//!   algorithm lookup, isolation, and precedence.

mod cross_provider;
mod test_algorithm_correctness;
mod test_base_provider;
mod test_default_provider;
mod test_dispatch;
#[cfg(feature = "legacy")]
mod test_legacy_provider;
mod test_provider_lifecycle;
