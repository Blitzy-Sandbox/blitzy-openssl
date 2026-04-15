//! Unit tests for FIPS module state machine (`FipsState`) and per-test state
//! tracking (`TestState`). Covers valid/invalid transitions, atomic
//! thread-safety, and rate-limited error reporting.
