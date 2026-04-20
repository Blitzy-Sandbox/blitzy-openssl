//! ECX key exchange provider implementation (X25519, X448).
//!
//! Provides the `KEYEXCH` interface for Montgomery-curve key exchange:
//!
//! - **X25519:** 32-byte shared secret (RFC 7748 §5).
//! - **X448:**   56-byte shared secret (RFC 7748 §5).
//!
//! This is the simplest of the exchange implementations — no KDF modes, no
//! configurable parameters, just a fixed-size shared secret produced by a
//! single scalar-multiplication operation. The actual Montgomery-ladder
//! arithmetic lives in [`openssl_crypto::ec::curve25519`]; this module
//! merely wires it into the provider framework.
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyExchange)
//!         → implementations::all_exchange_descriptors()
//!           → exchange::descriptors()           (sibling mod.rs)
//!             → ecx::descriptors()              (this file)
//!               → ecx::X25519Exchange / X448Exchange
//!                 → ecx::EcxExchangeContext
//!                   → openssl_crypto::ec::curve25519::{x25519, x448}
//! ```
//!
//! # Security Properties
//!
//! - Private key material is held in a `Zeroizing<Vec<u8>>` wrapper and
//!   explicitly zeroed on drop via [`zeroize::Zeroize`] (Rule R8).
//! - Key-length mismatches are rejected before any cryptographic work.
//! - All cryptographic errors surface as [`ProviderError`]; none silently
//!   succeed.
//! - Zero `unsafe` blocks — the crate enforces `#![forbid(unsafe_code)]`.
//!
//! # C Source Mapping
//!
//! | Rust construct                        | C construct                                  | Source (`ecx_exch.c`) |
//! |---------------------------------------|----------------------------------------------|------------------------|
//! | [`X25519Exchange`]                    | `ossl_x25519_keyexch_functions` dispatch     | lines 215–226          |
//! | [`X448Exchange`]                      | `ossl_x448_keyexch_functions` dispatch       | lines 228–239          |
//! | [`X25519Exchange::new_ctx`]           | `x25519_newctx` → `ecx_newctx(_, 32)`        | lines 49–64            |
//! | [`X448Exchange::new_ctx`]             | `x448_newctx` → `ecx_newctx(_, 56)`          | lines 66–72            |
//! | [`EcxExchangeContext`]                | `PROV_ECX_CTX`                               | lines 43–47            |
//! | [`EcxExchangeContext::init`]          | `ecx_init` / `x25519_init` / `x448_init`     | lines 75–111           |
//! | [`EcxExchangeContext::set_peer`]      | `ecx_set_peer`                               | lines 113–132          |
//! | [`EcxExchangeContext::derive`]        | `ecx_derive` → `ossl_ecx_compute_key`        | lines 134–143          |
//! | [`EcxExchangeContext::get_params`]    | `ecx_get_ctx_params`                         | lines 200–213          |
//! | [`EcxExchangeContext::set_params`]    | (no dispatch entry)                          | n/a                    |
//! | [`EcxAlgorithm`]                      | `keylen` + algorithm discriminator           | inline constants       |
//! | `Drop for EcxExchangeContext`         | `ecx_freectx` → `ossl_ecx_key_free`          | lines 145–153          |
//! | `Clone for EcxExchangeContext`        | `ecx_dupctx`                                 | lines 155–182          |
//! | [`descriptors`]                       | two dispatch tables registered by provider   | lines 215–239          |
//!
//! Replaces C `providers/implementations/exchange/ecx_exch.c`.

use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::ec::curve25519::{x25519, x448, EcxKeyType, EcxPrivateKey, EcxPublicKey};

use crate::traits::{AlgorithmDescriptor, KeyExchangeContext, KeyExchangeProvider};

// =============================================================================
// Constants — matching C #defines from ecx_exch.c and ecx_key.c
// =============================================================================

/// X25519 key (both private and public) length in bytes.
///
/// Matches the C constant `X25519_KEYLEN` and RFC 7748 §5.
const X25519_KEY_LEN: usize = 32;

/// X448 key (both private and public) length in bytes.
///
/// Matches the C constant `X448_KEYLEN` and RFC 7748 §5.
const X448_KEY_LEN: usize = 56;

// =============================================================================
// EcxAlgorithm — algorithm variant discriminator
// =============================================================================

/// Identifies which Montgomery-curve algorithm a context is configured for.
///
/// The C code uses two entirely separate dispatch tables
/// (`ossl_x25519_keyexch_functions` and `ossl_x448_keyexch_functions`) plus a
/// `keylen` field inside `PROV_ECX_CTX` to discriminate. In Rust we combine
/// both concerns into a single enum so the context type can be uniform while
/// still being fully typed at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcxAlgorithm {
    /// X25519 Diffie–Hellman over Curve25519 (RFC 7748, 32-byte keys).
    X25519,
    /// X448 Diffie–Hellman over Curve448 (RFC 7748, 56-byte keys).
    X448,
}

impl EcxAlgorithm {
    /// Returns the private/public key length in bytes for this algorithm.
    ///
    /// # Returns
    ///
    /// - [`EcxAlgorithm::X25519`] → `32`
    /// - [`EcxAlgorithm::X448`]   → `56`
    pub fn key_len(&self) -> usize {
        match self {
            EcxAlgorithm::X25519 => X25519_KEY_LEN,
            EcxAlgorithm::X448 => X448_KEY_LEN,
        }
    }

    /// Returns the canonical uppercase algorithm name string.
    ///
    /// Matches the names registered in the C dispatch tables
    /// (`PROV_NAMES_X25519` / `PROV_NAMES_X448`).
    pub fn name(&self) -> &'static str {
        match self {
            EcxAlgorithm::X25519 => "X25519",
            EcxAlgorithm::X448 => "X448",
        }
    }

    /// Maps this algorithm variant to the crypto-layer [`EcxKeyType`]
    /// discriminant used by [`EcxPrivateKey`] / [`EcxPublicKey`].
    ///
    /// Takes `self` by value because `EcxAlgorithm` is `Copy` — clippy
    /// flags `&self` as unnecessary for a trivially-copyable type.
    fn key_type(self) -> EcxKeyType {
        match self {
            EcxAlgorithm::X25519 => EcxKeyType::X25519,
            EcxAlgorithm::X448 => EcxKeyType::X448,
        }
    }
}

impl std::fmt::Display for EcxAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// X25519Exchange — provider entry point for X25519
// =============================================================================

/// X25519 key exchange provider.
///
/// Zero-sized handle that, when fetched from the provider framework,
/// creates new [`EcxExchangeContext`] instances configured for X25519
/// (32-byte private/public keys, 32-byte shared secrets).
///
/// Replaces the C `ossl_x25519_keyexch_functions` dispatch table from
/// `ecx_exch.c` lines 215–226.
#[derive(Debug, Default, Clone, Copy)]
pub struct X25519Exchange;

impl X25519Exchange {
    /// Constructs a new X25519 exchange handle.
    ///
    /// This is a zero-cost constructor; the handle carries no state.
    pub const fn new() -> Self {
        X25519Exchange
    }
}

impl KeyExchangeProvider for X25519Exchange {
    fn name(&self) -> &'static str {
        "X25519"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("ecx: creating new X25519 key-exchange context");
        Ok(Box::new(EcxExchangeContext::new(EcxAlgorithm::X25519)))
    }
}

// =============================================================================
// X448Exchange — provider entry point for X448
// =============================================================================

/// X448 key exchange provider.
///
/// Zero-sized handle that, when fetched from the provider framework,
/// creates new [`EcxExchangeContext`] instances configured for X448
/// (56-byte private/public keys, 56-byte shared secrets).
///
/// Replaces the C `ossl_x448_keyexch_functions` dispatch table from
/// `ecx_exch.c` lines 228–239.
#[derive(Debug, Default, Clone, Copy)]
pub struct X448Exchange;

impl X448Exchange {
    /// Constructs a new X448 exchange handle.
    ///
    /// This is a zero-cost constructor; the handle carries no state.
    pub const fn new() -> Self {
        X448Exchange
    }
}

impl KeyExchangeProvider for X448Exchange {
    fn name(&self) -> &'static str {
        "X448"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("ecx: creating new X448 key-exchange context");
        Ok(Box::new(EcxExchangeContext::new(EcxAlgorithm::X448)))
    }
}

// =============================================================================
// EcxExchangeContext — per-operation state
// =============================================================================

/// Per-operation context for ECX key exchange (X25519 or X448).
///
/// Holds:
///
/// - The configured [`EcxAlgorithm`] variant (determines expected key length
///   and output size).
/// - The local private key bytes (populated by [`init`]); stored inside a
///   [`Zeroizing`] wrapper so the material is reliably erased on drop.
/// - The peer's public key bytes (populated by [`set_peer`]).
///
/// Typical lifecycle:
///
/// ```text
/// X25519Exchange::new_ctx()       // -> Box<EcxExchangeContext>
///   .init(private_key, None)       // install local private key
///   .set_peer(peer_public_key)     // install remote public key
///   .derive(&mut secret_buf)       // compute shared secret
///   // context dropped here — key material zeroed automatically
/// ```
///
/// Replaces C `PROV_ECX_CTX` from `ecx_exch.c` lines 43–47. The C struct
/// carries `keylen`, `key` (an `ECX_KEY *` reference-counted handle) and
/// `peerkey`; our representation folds `keylen` into the [`EcxAlgorithm`]
/// discriminator and stores keys directly as byte vectors.
///
/// [`init`]: EcxExchangeContext::init
/// [`set_peer`]: EcxExchangeContext::set_peer
pub struct EcxExchangeContext {
    /// Which algorithm this context is configured for.
    algorithm: EcxAlgorithm,
    /// Local private-key bytes. `None` until [`init`] has been called.
    /// Wrapped in [`Zeroizing`] so the material is erased when the option
    /// is overwritten or the context is dropped.
    ///
    /// [`init`]: EcxExchangeContext::init
    key: Option<Zeroizing<Vec<u8>>>,
    /// Peer public-key bytes. `None` until [`set_peer`] has been called.
    ///
    /// Peer material is public, so it is held as a plain `Vec<u8>`. It is
    /// nevertheless explicitly zeroed on drop for defence in depth.
    ///
    /// [`set_peer`]: EcxExchangeContext::set_peer
    peer_key: Option<Vec<u8>>,
}

impl EcxExchangeContext {
    /// Creates a new context for the specified [`EcxAlgorithm`].
    ///
    /// The returned context has no private key and no peer key installed;
    /// [`init`] and [`set_peer`] must be called before [`derive`] will
    /// succeed.
    ///
    /// Replaces the C `ecx_newctx()` helper from `ecx_exch.c` lines 49–59.
    ///
    /// [`init`]: EcxExchangeContext::init
    /// [`set_peer`]: EcxExchangeContext::set_peer
    /// [`derive`]: EcxExchangeContext::derive
    pub fn new(algorithm: EcxAlgorithm) -> Self {
        Self {
            algorithm,
            key: None,
            peer_key: None,
        }
    }

    /// Returns the [`EcxAlgorithm`] this context was created for.
    pub fn algorithm(&self) -> EcxAlgorithm {
        self.algorithm
    }

    /// Returns the expected private/public key length in bytes for the
    /// configured algorithm.
    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    /// Internal helper — returns `true` once a private key has been installed
    /// via [`init`].
    ///
    /// [`init`]: EcxExchangeContext::init
    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Internal helper — returns `true` once a peer key has been installed
    /// via [`set_peer`].
    ///
    /// [`set_peer`]: EcxExchangeContext::set_peer
    fn has_peer(&self) -> bool {
        self.peer_key.is_some()
    }
}

impl std::fmt::Debug for EcxExchangeContext {
    /// Custom `Debug` implementation that **never** prints key material.
    ///
    /// Only reports which algorithm the context is configured for and
    /// whether each key slot is populated. The actual key bytes in
    /// [`self.key`](EcxExchangeContext::key) and
    /// [`self.peer_key`](EcxExchangeContext::peer_key) are deliberately
    /// omitted — we call [`std::fmt::DebugStruct::finish_non_exhaustive`]
    /// to signal that the omission is intentional.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcxExchangeContext")
            .field("algorithm", &self.algorithm)
            .field("key_installed", &self.has_key())
            .field("peer_installed", &self.has_peer())
            .finish_non_exhaustive()
    }
}

impl Clone for EcxExchangeContext {
    /// Deep-clones the context including any installed key material.
    ///
    /// Replaces C `ecx_dupctx()` from `ecx_exch.c` lines 155–182. The C
    /// implementation increments the reference count on the underlying
    /// `ECX_KEY` objects; our implementation makes an independent copy of
    /// the bytes, which is both safer (no shared mutable state, Rule R7)
    /// and consistent with Rust ownership semantics.
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            key: self.key.as_ref().map(|k| Zeroizing::new(k.to_vec())),
            peer_key: self.peer_key.clone(),
        }
    }
}

impl KeyExchangeContext for EcxExchangeContext {
    /// Installs the local private key for the exchange.
    ///
    /// Validates that the supplied byte slice length equals the key length
    /// mandated by the configured algorithm (32 for X25519, 56 for X448)
    /// before copying the bytes into a zeroising buffer.
    ///
    /// Any previously installed key is overwritten (and — because it was
    /// held in a `Zeroizing<Vec<u8>>` — erased from memory as part of that
    /// replacement).
    ///
    /// Replaces C `ecx_init()` from `ecx_exch.c` lines 75–99. The C code
    /// checks `key->keylen != ecxctx->keylen` at line 85; we perform the
    /// equivalent length check here. The C code also increments a
    /// reference count on the `ECX_KEY *`; our Rust code takes an owned
    /// copy, which is simpler and avoids shared mutable state (Rule R7).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if `key.len()` does not match the
    /// expected length for this context's algorithm.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let expected = self.key_len();
        trace!(
            algorithm = %self.algorithm,
            key_len = key.len(),
            expected,
            "ecx: init"
        );

        if key.len() != expected {
            return Err(ProviderError::Init(format!(
                "{} private key must be {expected} bytes, got {}",
                self.algorithm.name(),
                key.len()
            )));
        }

        // Copy the bytes into a zeroising buffer. The previous contents
        // (if any) of `self.key` are dropped here and therefore zeroed.
        self.key = Some(Zeroizing::new(key.to_vec()));

        // Any caller-supplied params are forwarded to set_params for
        // validation. ECX has no tuneable parameters in non-FIPS builds,
        // but we honour the contract in case downstream layers grow any.
        if let Some(ps) = params {
            self.set_params(ps)?;
        }

        Ok(())
    }

    /// Installs the peer's public key for the exchange.
    ///
    /// Validates that the supplied slice length matches the algorithm's
    /// expected key length.
    ///
    /// Replaces C `ecx_set_peer()` from `ecx_exch.c` lines 113–132. The
    /// key-length check at line 123 maps directly to the comparison
    /// performed here.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if `peer_key.len()` does not match
    /// the expected length for this context's algorithm.
    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()> {
        let expected = self.key_len();
        trace!(
            algorithm = %self.algorithm,
            peer_len = peer_key.len(),
            expected,
            "ecx: set_peer"
        );

        if peer_key.len() != expected {
            return Err(ProviderError::Init(format!(
                "{} peer public key must be {expected} bytes, got {}",
                self.algorithm.name(),
                peer_key.len()
            )));
        }

        self.peer_key = Some(peer_key.to_vec());
        Ok(())
    }

    /// Computes the shared secret into the supplied output buffer.
    ///
    /// Delegates the actual Montgomery-ladder scalar multiplication to
    /// [`openssl_crypto::ec::curve25519::x25519`] or
    /// [`openssl_crypto::ec::curve25519::x448`] depending on the context's
    /// configured algorithm.
    ///
    /// The output buffer should be at least [`EcxExchangeContext::key_len`]
    /// bytes long; exactly `key_len()` bytes are written if the buffer is
    /// large enough. If the buffer is smaller, only the leading portion is
    /// filled and the smaller length is returned — this matches the
    /// behaviour of the C API, which accepts a `secret_len` cap.
    ///
    /// Replaces C `ecx_derive()` from `ecx_exch.c` lines 134–143 which
    /// delegates to `ossl_ecx_compute_key()`.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if [`init`] has not been called
    /// (no private key installed) or if [`set_peer`] has not been called
    /// (no peer key installed). Returns [`ProviderError::Dispatch`] if the
    /// underlying scalar multiplication reports an error (for example,
    /// an internal invariant violation in the crypto layer).
    ///
    /// [`init`]: EcxExchangeContext::init
    /// [`set_peer`]: EcxExchangeContext::set_peer
    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        let algorithm = self.algorithm;
        trace!(algorithm = %algorithm, "ecx: derive (start)");

        // Fetch the installed private key or fail.
        let priv_bytes = self.key.as_ref().ok_or_else(|| {
            ProviderError::Init(format!(
                "{} key exchange not initialised (no private key)",
                algorithm.name()
            ))
        })?;

        // Fetch the installed peer key or fail.
        let peer_bytes = self.peer_key.as_ref().ok_or_else(|| {
            ProviderError::Init(format!(
                "{} key exchange peer key not set",
                algorithm.name()
            ))
        })?;

        // Build the crypto-layer key handles.
        let key_type = algorithm.key_type();
        let priv_key = EcxPrivateKey::new(key_type, priv_bytes.to_vec()).map_err(|e| {
            ProviderError::Dispatch(format!(
                "{} private key construction failed: {e}",
                algorithm.name()
            ))
        })?;
        let pub_key = EcxPublicKey::new(key_type, peer_bytes.clone()).map_err(|e| {
            ProviderError::Dispatch(format!(
                "{} peer public key construction failed: {e}",
                algorithm.name()
            ))
        })?;

        // Run the scalar multiplication for the configured variant.
        let shared: Vec<u8> = match algorithm {
            EcxAlgorithm::X25519 => x25519(&priv_key, &pub_key),
            EcxAlgorithm::X448 => x448(&priv_key, &pub_key),
        }
        .map_err(|e| {
            ProviderError::Dispatch(format!(
                "{} scalar multiplication failed: {e}",
                algorithm.name()
            ))
        })?;

        // Copy the shared secret into the caller's buffer. `shared.len()`
        // is always `algorithm.key_len()` for a successful exchange, but
        // we defensively clamp to `secret.len()` to honour the caller's
        // cap — matching C's `*secretlen = keylen` / `secret_len` handling.
        let out_len = std::cmp::min(shared.len(), secret.len());
        secret[..out_len].copy_from_slice(&shared[..out_len]);

        debug!(
            algorithm = %algorithm,
            secret_len = out_len,
            "ecx: derive (complete)"
        );
        Ok(out_len)
    }

    /// Returns the gettable context parameters.
    ///
    /// For ECX key exchange this is effectively a no-op: the C code in
    /// `ecx_get_ctx_params()` (lines 200–213) exposes only a FIPS
    /// approved-algorithm indicator, and even that is only populated in
    /// FIPS module builds. For diagnostic purposes we still expose the
    /// algorithm name and the key length so callers can introspect the
    /// context.
    ///
    /// Replaces C `ecx_get_ctx_params()` from `ecx_exch.c` lines 200–213.
    #[allow(clippy::cast_possible_truncation)]
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            "algorithm",
            ParamValue::Utf8String(self.algorithm.name().to_string()),
        );
        // TRUNCATION: `key_len()` returns only the values 32 (X25519) or
        // 56 (X448), both comfortably within u32 range. The `as u32` cast
        // is therefore lossless; rationale recorded for Rule R6 audit.
        params.set("key-length", ParamValue::UInt32(self.key_len() as u32));
        Ok(params)
    }

    /// Accepts settable context parameters.
    ///
    /// ECX key exchange exposes no settable parameters in non-FIPS builds —
    /// the C dispatch tables at `ecx_exch.c` lines 215–239 deliberately
    /// omit `OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS`. We honour this by
    /// accepting any [`ParamSet`] (including the empty set) without error,
    /// which preserves forward compatibility should callers pre-emptively
    /// supply parameters intended for other algorithm families.
    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        // Intentionally a no-op: no tuneable parameters. Returning Ok
        // rather than an error matches C behaviour where the absence of a
        // `set_ctx_params` entry in the dispatch table causes callers to
        // skip the call entirely — never to observe a failure.
        Ok(())
    }
}

// =============================================================================
// Drop — secure erasure of key material
// =============================================================================

impl Drop for EcxExchangeContext {
    /// Explicitly zeroes any installed key material before the context is
    /// deallocated.
    ///
    /// The private-key storage (`self.key`) is already wrapped in
    /// [`Zeroizing`], which performs the wipe automatically when the
    /// `Option` is dropped. We additionally zero `self.peer_key` (a plain
    /// `Vec<u8>`) for defence in depth — peer keys are public material and
    /// therefore not strictly secret, but the cost of wiping them is
    /// negligible and avoids accidentally leaving recognisable patterns
    /// in freed memory.
    ///
    /// Replaces C `ecx_freectx()` from `ecx_exch.c` lines 145–153 which
    /// calls `ossl_ecx_key_free()` → `OPENSSL_cleanse` on both keys.
    ///
    /// Per Rule R8 / §0.7.6: secure erasure is achieved without any
    /// `unsafe` code by using the `zeroize` crate's safe API.
    fn drop(&mut self) {
        // Zeroing the Zeroizing<Vec<u8>> is automatic — it happens when
        // the Option is dropped at the end of this scope. We make it
        // explicit here via `take()` so that any future refactoring that
        // changes the storage type keeps the erasure intact.
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
        if let Some(mut p) = self.peer_key.take() {
            p.zeroize();
        }
    }
}

// =============================================================================
// descriptors — algorithm registration for the provider framework
// =============================================================================

/// Returns the set of [`AlgorithmDescriptor`] values this module registers
/// with the provider framework.
///
/// Exposes two entries — X25519 and X448 — both under the default provider
/// property query string (`"provider=default"`).
///
/// Replaces the two C dispatch tables `ossl_x25519_keyexch_functions`
/// (`ecx_exch.c` lines 215–226) and `ossl_x448_keyexch_functions`
/// (`ecx_exch.c` lines 228–239); in C these are registered via a provider
/// table array, in Rust we return structured descriptors consumed by the
/// provider framework's algorithm-registration pipeline.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default",
            description: "X25519 key exchange (RFC 7748)",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: "provider=default",
            description: "X448 key exchange (RFC 7748)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements
)]
mod tests {
    use super::*;

    /// Helper — decode a hex string to raw bytes for RFC 7748 test vectors.
    ///
    /// Uses `expect` on the assumption that all inputs are literal hex
    /// strings authored in the test itself; a panic here indicates a bug
    /// in the test, not in the code under test.
    fn hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = hex_nib(bytes[i]).expect("valid hex digit");
            let lo = hex_nib(bytes[i + 1]).expect("valid hex digit");
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nib(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(10 + b - b'a'),
            b'A'..=b'F' => Some(10 + b - b'A'),
            _ => None,
        }
    }

    // -------------------------------------------------------------------------
    // EcxAlgorithm
    // -------------------------------------------------------------------------

    #[test]
    fn ecx_algorithm_key_len_x25519_is_32() {
        assert_eq!(EcxAlgorithm::X25519.key_len(), 32);
    }

    #[test]
    fn ecx_algorithm_key_len_x448_is_56() {
        assert_eq!(EcxAlgorithm::X448.key_len(), 56);
    }

    #[test]
    fn ecx_algorithm_name_is_canonical() {
        assert_eq!(EcxAlgorithm::X25519.name(), "X25519");
        assert_eq!(EcxAlgorithm::X448.name(), "X448");
    }

    #[test]
    fn ecx_algorithm_display_matches_name() {
        assert_eq!(format!("{}", EcxAlgorithm::X25519), "X25519");
        assert_eq!(format!("{}", EcxAlgorithm::X448), "X448");
    }

    #[test]
    fn ecx_algorithm_key_type_maps_to_crypto_variant() {
        assert_eq!(EcxAlgorithm::X25519.key_type(), EcxKeyType::X25519);
        assert_eq!(EcxAlgorithm::X448.key_type(), EcxKeyType::X448);
    }

    // -------------------------------------------------------------------------
    // X25519Exchange / X448Exchange — provider handles
    // -------------------------------------------------------------------------

    #[test]
    fn x25519_exchange_name() {
        let ex = X25519Exchange::new();
        assert_eq!(ex.name(), "X25519");
    }

    #[test]
    fn x448_exchange_name() {
        let ex = X448Exchange::new();
        assert_eq!(ex.name(), "X448");
    }

    #[test]
    fn x25519_exchange_new_ctx_succeeds() {
        let ex = X25519Exchange::new();
        let ctx = ex.new_ctx().expect("new_ctx should succeed");
        // Context must accept an X25519-sized key.
        let mut ctx = ctx;
        let res = ctx.init(&[0u8; X25519_KEY_LEN], None);
        assert!(res.is_ok(), "X25519 init with 32-byte key should succeed");
    }

    #[test]
    fn x448_exchange_new_ctx_succeeds() {
        let ex = X448Exchange::new();
        let ctx = ex.new_ctx().expect("new_ctx should succeed");
        let mut ctx = ctx;
        let res = ctx.init(&[0u8; X448_KEY_LEN], None);
        assert!(res.is_ok(), "X448 init with 56-byte key should succeed");
    }

    // -------------------------------------------------------------------------
    // EcxExchangeContext — init / set_peer length validation
    // -------------------------------------------------------------------------

    #[test]
    fn init_rejects_wrong_length_x25519() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        // 31 bytes is not 32 — must fail.
        let err = ctx.init(&[0u8; 31], None).unwrap_err();
        match err {
            ProviderError::Init(_) => { /* expected */ }
            other => panic!("expected ProviderError::Init, got {other:?}"),
        }
        assert!(
            !ctx.has_key(),
            "key must not be installed after a failed init"
        );
    }

    #[test]
    fn init_rejects_wrong_length_x448() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X448);
        // 32 bytes is X25519's length, wrong for X448.
        let err = ctx.init(&[0u8; 32], None).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn init_accepts_correct_length() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.init(&[1u8; X25519_KEY_LEN], None)
            .expect("correct length must succeed");
        assert!(ctx.has_key());
    }

    #[test]
    fn set_peer_rejects_wrong_length() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        let err = ctx.set_peer(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn set_peer_accepts_correct_length() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X448);
        ctx.set_peer(&[7u8; X448_KEY_LEN])
            .expect("correct peer length must succeed");
        assert!(ctx.has_peer());
    }

    // -------------------------------------------------------------------------
    // EcxExchangeContext — derive error paths
    // -------------------------------------------------------------------------

    #[test]
    fn derive_without_init_fails() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.set_peer(&[0u8; X25519_KEY_LEN]).unwrap();
        let mut out = [0u8; 32];
        let err = ctx.derive(&mut out).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn derive_without_peer_fails() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.init(&[0x01u8; X25519_KEY_LEN], None).unwrap();
        let mut out = [0u8; 32];
        let err = ctx.derive(&mut out).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -------------------------------------------------------------------------
    // EcxExchangeContext — get_params / set_params
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_returns_algorithm_and_key_length_x25519() {
        let ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        let p = ctx.get_params().unwrap();
        match p.get("algorithm") {
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, "X25519"),
            other => panic!("expected Utf8String algorithm, got {other:?}"),
        }
        match p.get("key-length") {
            Some(ParamValue::UInt32(n)) => assert_eq!(*n, 32),
            other => panic!("expected UInt32 key-length, got {other:?}"),
        }
    }

    #[test]
    fn get_params_returns_algorithm_and_key_length_x448() {
        let ctx = EcxExchangeContext::new(EcxAlgorithm::X448);
        let p = ctx.get_params().unwrap();
        match p.get("algorithm") {
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, "X448"),
            other => panic!("expected Utf8String algorithm, got {other:?}"),
        }
        match p.get("key-length") {
            Some(ParamValue::UInt32(n)) => assert_eq!(*n, 56),
            other => panic!("expected UInt32 key-length, got {other:?}"),
        }
    }

    #[test]
    fn set_params_is_noop() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        // Empty set should succeed.
        ctx.set_params(&ParamSet::new()).unwrap();
        // A set with arbitrary params should also succeed — ECX ignores
        // unknown keys, matching the C dispatch-table behaviour.
        let mut ps = ParamSet::new();
        ps.set("unknown-key", ParamValue::Int32(42));
        ctx.set_params(&ps).unwrap();
    }

    // -------------------------------------------------------------------------
    // EcxExchangeContext — Clone semantics
    // -------------------------------------------------------------------------

    #[test]
    fn clone_preserves_algorithm_and_keys() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.init(&[0xAAu8; X25519_KEY_LEN], None).unwrap();
        ctx.set_peer(&[0xBBu8; X25519_KEY_LEN]).unwrap();

        let cloned = ctx.clone();
        assert_eq!(cloned.algorithm(), EcxAlgorithm::X25519);
        assert!(cloned.has_key());
        assert!(cloned.has_peer());
    }

    #[test]
    fn clone_of_empty_context() {
        let ctx = EcxExchangeContext::new(EcxAlgorithm::X448);
        let cloned = ctx.clone();
        assert_eq!(cloned.algorithm(), EcxAlgorithm::X448);
        assert!(!cloned.has_key());
        assert!(!cloned.has_peer());
    }

    // -------------------------------------------------------------------------
    // EcxExchangeContext — Debug does not leak key material
    // -------------------------------------------------------------------------

    #[test]
    fn debug_does_not_print_key_material() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        let secret_key = [0xDEu8; X25519_KEY_LEN];
        ctx.init(&secret_key, None).unwrap();
        let rendered = format!("{ctx:?}");
        // The render should not contain the raw key bytes in any hex form.
        assert!(
            !rendered.to_lowercase().contains("de de"),
            "key bytes leaked"
        );
        assert!(!rendered.contains("0xDE"), "key bytes leaked");
        // It should however report the algorithm and the installation flags.
        assert!(rendered.contains("X25519"), "algorithm missing in Debug");
        assert!(rendered.contains("key_installed"));
        assert!(rendered.contains("peer_installed"));
    }

    // -------------------------------------------------------------------------
    // descriptors()
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_lists_x25519_and_x448() {
        let d = descriptors();
        assert_eq!(d.len(), 2, "expected exactly X25519 and X448");
        let names: Vec<&str> = d.iter().flat_map(|a| a.names.iter().copied()).collect();
        assert!(names.contains(&"X25519"));
        assert!(names.contains(&"X448"));
        for a in &d {
            assert_eq!(a.property, "provider=default");
            assert!(!a.description.is_empty());
        }
    }

    // -------------------------------------------------------------------------
    // Full end-to-end exchange — RFC 7748 test vector (X25519 §6.1)
    // -------------------------------------------------------------------------

    #[test]
    fn rfc7748_x25519_shared_secret_matches() {
        // Alice's inputs.
        let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        // Bob's inputs.
        let bob_priv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        // Expected output.
        let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // Alice derives.
        let mut ctx_a = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx_a.init(&alice_priv, None).unwrap();
        ctx_a.set_peer(&bob_pub).unwrap();
        let mut shared_a = [0u8; 32];
        let n_a = ctx_a.derive(&mut shared_a).unwrap();
        assert_eq!(n_a, 32);
        assert_eq!(shared_a, expected.as_slice());

        // Bob derives — must agree with Alice.
        let mut ctx_b = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx_b.init(&bob_priv, None).unwrap();
        ctx_b.set_peer(&alice_pub).unwrap();
        let mut shared_b = [0u8; 32];
        let n_b = ctx_b.derive(&mut shared_b).unwrap();
        assert_eq!(n_b, 32);
        assert_eq!(shared_b, expected.as_slice());

        // Agreement: both parties derive the same bytes.
        assert_eq!(shared_a, shared_b);
    }

    // -------------------------------------------------------------------------
    // Full end-to-end exchange — X448 derive produces a 56-byte secret
    // -------------------------------------------------------------------------

    #[test]
    fn x448_derive_produces_56_byte_secret() {
        use openssl_crypto::ec::curve25519::x448_public_from_private;

        // Using non-trivial but simple key bytes — we're not checking against
        // an RFC vector here, only that the wiring produces a 56-byte result
        // and that both sides derive identical output.
        //
        // TRUNCATION: X448_KEY_LEN is a compile-time constant equal to 56,
        // which fits trivially in u8 (max 255). The cast is lossless by
        // construction and is confined to test code that builds a sequence
        // of sample bytes for round-trip verification.
        #[allow(clippy::cast_possible_truncation)]
        let key_len_u8: u8 = X448_KEY_LEN as u8;
        let priv_a: Vec<u8> = (0..key_len_u8).collect();
        let priv_b: Vec<u8> = (1..=key_len_u8).collect();

        // Compute the respective public keys by scalar-multiplying the base
        // point. We use the crypto layer directly for this — the exchange
        // layer doesn't expose public-key derivation, only DH.
        let priv_a_key = EcxPrivateKey::new(EcxKeyType::X448, priv_a.clone()).unwrap();
        let priv_b_key = EcxPrivateKey::new(EcxKeyType::X448, priv_b.clone()).unwrap();
        let pub_a = x448_public_from_private(&priv_a_key).unwrap();
        let pub_b = x448_public_from_private(&priv_b_key).unwrap();

        let mut ctx_a = EcxExchangeContext::new(EcxAlgorithm::X448);
        ctx_a.init(&priv_a, None).unwrap();
        ctx_a.set_peer(pub_b.as_bytes()).unwrap();
        let mut secret_a = [0u8; X448_KEY_LEN];
        assert_eq!(ctx_a.derive(&mut secret_a).unwrap(), X448_KEY_LEN);

        let mut ctx_b = EcxExchangeContext::new(EcxAlgorithm::X448);
        ctx_b.init(&priv_b, None).unwrap();
        ctx_b.set_peer(pub_a.as_bytes()).unwrap();
        let mut secret_b = [0u8; X448_KEY_LEN];
        assert_eq!(ctx_b.derive(&mut secret_b).unwrap(), X448_KEY_LEN);

        assert_eq!(secret_a, secret_b, "X448 DH must agree on both sides");
    }

    // -------------------------------------------------------------------------
    // Derive truncation — short output buffer
    // -------------------------------------------------------------------------

    #[test]
    fn derive_respects_short_output_buffer() {
        let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.init(&alice_priv, None).unwrap();
        ctx.set_peer(&bob_pub).unwrap();

        // Only request 16 bytes.
        let mut short = [0u8; 16];
        let n = ctx.derive(&mut short).unwrap();
        assert_eq!(n, 16);

        // The leading 16 bytes must match the leading 16 bytes of the
        // full 32-byte secret.
        let expected_full = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(&short[..], &expected_full[..16]);
    }

    // -------------------------------------------------------------------------
    // Key overwrite — re-init replaces previous key
    // -------------------------------------------------------------------------

    #[test]
    fn init_overwrites_previous_key() {
        let mut ctx = EcxExchangeContext::new(EcxAlgorithm::X25519);
        ctx.init(&[0xAAu8; X25519_KEY_LEN], None).unwrap();
        // A second init with a different key should succeed and replace.
        ctx.init(&[0xBBu8; X25519_KEY_LEN], None).unwrap();
        assert!(ctx.has_key());
    }
}
