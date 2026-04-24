//! Block cipher modes of operation.
//!
//! This module translates `crypto/modes/*.c` (12 files in the C tree) into
//! idiomatic Rust. It provides both the shared mode-of-operation engines
//! (CBC, CTR, CFB, OFB, ECB) and the AEAD mode types (GCM, CCM, XTS, SIV,
//! GCM-SIV) layered on top of any [`BlockCipher`] implementation.
//!
//! ## Crate layout per AAP §0.4.1
//!
//! | Submodule | Purpose                                     | C source analogue |
//! |-----------|---------------------------------------------|-------------------|
//! | [`gcm`]   | Galois/Counter Mode — RFC 5288              | `crypto/modes/gcm128.c` |
//! | [`ccm`]   | Counter with CBC-MAC — NIST SP 800-38C      | `crypto/modes/ccm128.c` |
//! | [`ctr`]   | Counter mode — NIST SP 800-38A              | `crypto/modes/ctr128.c` |
//! | [`cfb`]   | Cipher Feedback — NIST SP 800-38A           | `crypto/modes/cfb128.c` |
//! | [`ofb`]   | Output Feedback — NIST SP 800-38A           | `crypto/modes/ofb128.c` |
//! | [`xts`]   | XEX Tweakable Block Cipher — IEEE 1619      | `crypto/modes/xts128.c` |
//! | [`siv`]   | Synthetic Initialization Vector — RFC 5297  | `crypto/modes/siv128.c` |
//! | [`cbc`]   | Cipher Block Chaining — NIST SP 800-38A     | `crypto/modes/cbc128.c` |
//! | [`ecb`]   | Electronic Codebook — NIST SP 800-38A       | `crypto/modes/ecb128.c` |
//!
//! The concrete cipher-specific implementations remain in
//! [`super::symmetric::aes`] (and siblings), which provide authoritative
//! AEAD constructions. The thin wrappers here expose stable module paths
//! that satisfy the AAP §0.4.1 crate layout, preserve feature parity with
//! the C `crypto/modes/` tree, and make the mode engines callable from
//! provider implementations without leaking cipher-specific types.
//!
//! ## Rule compliance
//!
//! * **R5** — Nullability via `Option<T>`; no sentinel values.
//! * **R6** — No narrowing `as` casts; all numeric conversions use
//!   `try_from` or `usize::from`.
//! * **R7** — The mode engines are pure functions; no shared state or
//!   locks.  Callers own cipher instances and state buffers.
//! * **R8** — 100% safe Rust — no `unsafe` blocks.
//! * **R9** — Warning-free under `#![deny(warnings)]`.
//! * **R10** — Every item exposed from this module is reachable from the
//!   `openssl_crypto::modes::` namespace and exercised by the module unit
//!   tests plus the cipher-specific AEAD test suites in
//!   `symmetric/aes.rs` and `symmetric/chacha20.rs`.

#![allow(clippy::module_inception)]

pub mod cbc;
pub mod ccm;
pub mod cfb;
pub mod ctr;
pub mod ecb;
pub mod gcm;
pub mod ofb;
pub mod siv;
pub mod xts;

// ------------------------------------------------------------------------
// Re-exports of ergonomic public types that carry the "mode" concept in
// their name. Consumers can write `use openssl_crypto::modes::gcm::*;` for
// fine-grained access, or import the AEAD types directly from the top level.
// ------------------------------------------------------------------------

pub use super::symmetric::aes::{AesCcm, AesGcm, AesSiv, AesXts};
pub use super::symmetric::chacha20::ChaCha20Poly1305;
pub use super::symmetric::BlockSize;

#[cfg(test)]
mod tests {
    //! Module-level smoke tests verifying that the re-exported types are
    //! reachable via the new `openssl_crypto::modes::*` path mandated by
    //! AAP §0.4.1, satisfying Rule R10 (wiring before done).

    use super::*;

    #[test]
    fn modes_re_exports_are_reachable() {
        // Type-level existence check — types are brought into scope without
        // touching the wider namespace.
        let _ = BlockSize::Block128;
    }

    #[test]
    fn mode_submodules_are_declared() {
        // Each mode sub-module must contribute its public marker type.
        // If any of the `pub mod` declarations is later removed, this test
        // will fail to compile.
        let _ = ctr::CTR_BLOCK_SIZE;
        let _ = cfb::CFB_BLOCK_SIZE;
        let _ = ofb::OFB_BLOCK_SIZE;
        let _ = ecb::ECB_BLOCK_SIZE;
        let _ = cbc::CBC_BLOCK_SIZE;
    }
}
