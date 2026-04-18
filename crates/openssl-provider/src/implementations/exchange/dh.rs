//! Finite-Field Diffie-Hellman key exchange provider implementation.
//!
//! Translates `providers/implementations/exchange/dh_exch.c` (1 C file)
//! into idiomatic Rust, implementing `KeyExchangeProvider` + `KeyExchangeContext`
//! for classic DH key agreement.
//!
//! # Architecture
//!
//! The implementation delegates actual modular exponentiation to the
//! `openssl_crypto::dh` module. This provider layer adds:
//!
//! - Lifecycle management (`init` → `set_peer` → `derive`)
//! - Named-group parameter negotiation via `ParamSet`
//! - State validation (cannot derive without peer key)
//! - Secure zeroing of all private key material via `Zeroize`
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyExchange)
//!         → implementations::all_exchange_descriptors()
//!           → exchange::descriptors()
//!             → dh::DhKeyExchange
//! ```
//!
//! # Security Properties
//!
//! - Private key material zeroed on drop via [`zeroize::Zeroize`].
//! - Shared secret validated: not 0, 1, or p−1.
//! - Zero `unsafe` blocks (Rule R8).
//!
//! # C Source Mapping
//!
//! | Rust type | C construct | Source |
//! |-----------|------------|--------|
//! | [`DhKeyExchange`] | `ossl_dh_keyexch_functions` | `dh_exch.c` |
//! | [`DhExchangeContext`] | `PROV_DH_CTX` | `dh_exch.c:30` |

use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::bn::BigNum;
use openssl_crypto::dh::{
    compute_key, from_named_group, DhNamedGroup, DhParams, DhPrivateKey,
    DhPublicKey,
};

use crate::traits::{KeyExchangeContext, KeyExchangeProvider};

// ---------------------------------------------------------------------------
// DhKeyExchange — Provider descriptor
// ---------------------------------------------------------------------------

/// Finite-field Diffie-Hellman key exchange provider.
///
/// Supports RFC 7919 named groups (ffdhe2048–ffdhe8192) as well as
/// custom groups supplied via parameters.
pub struct DhKeyExchange;

impl KeyExchangeProvider for DhKeyExchange {
    fn name(&self) -> &'static str {
        "DH"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("DH key exchange: creating new context");
        Ok(Box::new(DhExchangeContext::new()))
    }
}

// ---------------------------------------------------------------------------
// DhExchangeContext — Stateful key-agreement context
// ---------------------------------------------------------------------------

/// DH key exchange context managing the `init` → `set_peer` → `derive` lifecycle.
///
/// Holds our private key material and the peer's public key, plus DH domain
/// parameters. All secret material is zeroed on drop.
struct DhExchangeContext {
    /// Our private key bytes (big-endian).
    our_private: Option<Zeroizing<Vec<u8>>>,
    /// Peer public key bytes (big-endian).
    peer_public: Option<Vec<u8>>,
    /// DH domain parameters (p, g, optional q).
    params: Option<DhParams>,
    /// Named group, if selected.
    group: Option<DhNamedGroup>,
    /// Pad output to modulus length (default: true, matching `DH_compute_key_padded`).
    pad: bool,
}

impl DhExchangeContext {
    /// Creates a new, uninitialised DH exchange context.
    fn new() -> Self {
        Self {
            our_private: None,
            peer_public: None,
            params: None,
            group: None,
            pad: true,
        }
    }

    /// Resolves the DH parameters — either from named group or explicit params.
    fn resolve_params(&self) -> ProviderResult<DhParams> {
        if let Some(group) = self.group {
            Ok(from_named_group(group))
        } else if let Some(ref params) = self.params {
            Ok(params.clone())
        } else {
            Err(ProviderError::Init(
                "DH parameters not set — supply a named group or explicit p/g".into(),
            ))
        }
    }

    /// Maps a group name string to the named-group enum.
    fn parse_group_name(name: &str) -> Option<DhNamedGroup> {
        match name.to_lowercase().as_str() {
            "ffdhe2048" => Some(DhNamedGroup::Ffdhe2048),
            "ffdhe3072" => Some(DhNamedGroup::Ffdhe3072),
            "ffdhe4096" => Some(DhNamedGroup::Ffdhe4096),
            "ffdhe6144" => Some(DhNamedGroup::Ffdhe6144),
            "ffdhe8192" => Some(DhNamedGroup::Ffdhe8192),
            _ => None,
        }
    }
}

impl KeyExchangeContext for DhExchangeContext {
    /// Initialises the DH key exchange with our private key material.
    ///
    /// The `key` argument is the raw big-endian private exponent.
    /// Optional `params` may include:
    /// - `"group"`: named group string (e.g., `"ffdhe2048"`)
    /// - `"p"`, `"g"`: explicit domain parameters as `OctetString` big-endian bytes
    /// - `"pad"`: boolean controlling output padding
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        trace!(key_len = key.len(), "DH exchange: init");

        if key.is_empty() {
            return Err(ProviderError::Init("DH private key is empty".into()));
        }

        self.our_private = Some(Zeroizing::new(key.to_vec()));

        if let Some(ps) = params {
            self.set_params(ps)?;
        }

        Ok(())
    }

    /// Sets the peer's public key (big-endian encoding).
    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()> {
        trace!(peer_len = peer_key.len(), "DH exchange: set_peer");

        if peer_key.is_empty() {
            return Err(ProviderError::Dispatch(
                "DH peer public key is empty".into(),
            ));
        }
        self.peer_public = Some(peer_key.to_vec());
        Ok(())
    }

    /// Derives the shared secret: `peer_public^our_private mod p`.
    ///
    /// Returns the number of bytes written into `secret`.
    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        let priv_bytes = self
            .our_private
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DH not initialised (no private key)".into()))?;

        let peer_bytes = self
            .peer_public
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DH peer key not set".into()))?;

        let dh_params = self.resolve_params()?;

        // Reconstruct BigNum-based key objects for the crypto layer
        let priv_bn = BigNum::from_bytes_be(priv_bytes);
        let peer_bn = BigNum::from_bytes_be(peer_bytes);

        let private_key = DhPrivateKey::new_from_raw(priv_bn.to_bytes_be(), dh_params.clone());
        let public_key = DhPublicKey::new_from_raw(peer_bn, dh_params.clone());

        let shared = compute_key(&private_key, &public_key, &dh_params).map_err(|e| {
            ProviderError::Dispatch(format!("DH key agreement failed: {e}"))
        })?;

        let copy_len = std::cmp::min(shared.len(), secret.len());
        secret[..copy_len].copy_from_slice(&shared[..copy_len]);

        debug!(secret_len = copy_len, "DH exchange: derived shared secret");
        Ok(copy_len)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(group) = self.group {
            ps.set("group", ParamValue::Utf8String(group.name().to_string()));
        }
        ps.set("pad", ParamValue::Int32(i32::from(self.pad)));
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Named group selection
        if let Some(ParamValue::Utf8String(name)) = params.get("group") {
            if let Some(group) = Self::parse_group_name(name) {
                self.group = Some(group);
            } else {
                return Err(ProviderError::Init(format!(
                    "unknown DH named group: {name}"
                )));
            }
        }

        // Explicit domain parameters
        if let Some(ParamValue::OctetString(p_bytes)) = params.get("p") {
            let g_bytes = match params.get("g") {
                Some(ParamValue::OctetString(g)) => g.clone(),
                _ => vec![2], // default generator g=2
            };
            let p = BigNum::from_bytes_be(p_bytes);
            let g = BigNum::from_bytes_be(&g_bytes);
            let q = params.get("q").and_then(|v| {
                if let ParamValue::OctetString(q_bytes) = v {
                    Some(BigNum::from_bytes_be(q_bytes))
                } else {
                    None
                }
            });
            self.params = Some(
                DhParams::new(p, g, q)
                    .map_err(|e| ProviderError::Init(format!("invalid DH params: {e}")))?,
            );
        }

        // Padding flag
        if let Some(ParamValue::Int32(pad)) = params.get("pad") {
            self.pad = *pad != 0;
        }

        Ok(())
    }
}

impl Drop for DhExchangeContext {
    fn drop(&mut self) {
        // Zeroize secret material on drop
        if let Some(ref mut priv_key) = self.our_private {
            priv_key.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ctx_returns_valid_context() {
        let provider = DhKeyExchange;
        assert_eq!(provider.name(), "DH");
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok());
    }

    #[test]
    fn init_requires_nonempty_key() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let result = ctx.init(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn set_peer_requires_nonempty_key() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let result = ctx.set_peer(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn derive_fails_without_init() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut secret = [0u8; 32];
        let result = ctx.derive(&mut secret);
        assert!(result.is_err());
    }

    #[test]
    fn derive_fails_without_peer() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(
            "group",
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        ctx.init(&[0x42; 32], Some(&params)).expect("init");
        let mut secret = [0u8; 256];
        let result = ctx.derive(&mut secret);
        assert!(result.is_err());
    }

    #[test]
    fn full_dh_exchange_ffdhe2048() {
        use openssl_crypto::dh::generate_key;
        // Generate two key pairs using the crypto layer
        let dh_params = from_named_group(DhNamedGroup::Ffdhe2048);
        let alice = generate_key(&dh_params).expect("alice keygen");
        let bob = generate_key(&dh_params).expect("bob keygen");

        // Provider-level exchange for Alice
        let provider = DhKeyExchange;
        let mut alice_ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set(
            "group",
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        alice_ctx
            .init(&alice.private_key().value().to_bytes_be(), Some(&ps))
            .expect("alice init");
        alice_ctx
            .set_peer(&bob.public_key().value().to_bytes_be())
            .expect("alice set_peer");

        let mut alice_secret = vec![0u8; 256];
        let alice_len = alice_ctx.derive(&mut alice_secret).expect("alice derive");

        // Provider-level exchange for Bob
        let mut bob_ctx = provider.new_ctx().expect("new_ctx");
        bob_ctx
            .init(&bob.private_key().value().to_bytes_be(), Some(&ps))
            .expect("bob init");
        bob_ctx
            .set_peer(&alice.public_key().value().to_bytes_be())
            .expect("bob set_peer");

        let mut bob_secret = vec![0u8; 256];
        let bob_len = bob_ctx.derive(&mut bob_secret).expect("bob derive");

        // Both must agree
        assert_eq!(alice_len, bob_len, "derived secret lengths must match");
        assert_eq!(
            &alice_secret[..alice_len],
            &bob_secret[..bob_len],
            "shared secrets must match"
        );
        assert!(alice_len > 0, "derived secret must not be empty");
    }

    #[test]
    fn get_params_returns_group_and_pad() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set(
            "group",
            ParamValue::Utf8String("ffdhe3072".to_string()),
        );
        ctx.init(&[0x01; 32], Some(&ps)).expect("init");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(
            params.get("group"),
            Some(&ParamValue::Utf8String("ffdhe3072".to_string()))
        );
        assert_eq!(params.get("pad"), Some(&ParamValue::Int32(1)));
    }

    #[test]
    fn unknown_group_rejected() {
        let provider = DhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set(
            "group",
            ParamValue::Utf8String("invalid_group".to_string()),
        );
        let result = ctx.init(&[0x01; 32], Some(&ps));
        assert!(result.is_err());
    }
}
