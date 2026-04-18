//! X25519 and X448 key exchange provider implementations.
//!
//! Translates `providers/implementations/exchange/ecx_exch.c` (1 C file)
//! into idiomatic Rust, implementing `KeyExchangeProvider` + `KeyExchangeContext`
//! for RFC 7748 X25519 and X448 key agreement.
//!
//! # Architecture
//!
//! Delegates to the `openssl_crypto::ec::curve25519` module which provides
//! full X25519 and X448 Montgomery-ladder scalar multiplication.
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
//!             → x25519::X25519KeyExchange / x25519::X448KeyExchange
//! ```
//!
//! # Security Properties
//!
//! - Private key material zeroed on drop via [`zeroize::Zeroize`].
//! - All-zero shared secret rejected (small-order peer key).
//! - Zero `unsafe` blocks (Rule R8).
//!
//! # C Source Mapping
//!
//! | Rust type | C construct | Source |
//! |-----------|------------|--------|
//! | [`X25519KeyExchange`] | `ossl_x25519_keyexch_functions` | `ecx_exch.c` |
//! | [`X448KeyExchange`] | `ossl_x448_keyexch_functions` | `ecx_exch.c` |

use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::ec::curve25519::{
    x25519, x448, EcxKeyType, EcxPrivateKey, EcxPublicKey,
};

use crate::traits::{KeyExchangeContext, KeyExchangeProvider};

// =============================================================================
// X25519 Key Exchange Provider
// =============================================================================

/// X25519 Diffie-Hellman key exchange provider (RFC 7748).
///
/// Produces 32-byte shared secrets from 32-byte private and public keys.
pub struct X25519KeyExchange;

impl KeyExchangeProvider for X25519KeyExchange {
    fn name(&self) -> &'static str {
        "X25519"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("X25519 key exchange: creating new context");
        Ok(Box::new(EcxExchangeContext::new(EcxKeyType::X25519)))
    }
}

// =============================================================================
// X448 Key Exchange Provider
// =============================================================================

/// X448 Diffie-Hellman key exchange provider (RFC 7748).
///
/// Produces 56-byte shared secrets from 56-byte private and public keys.
pub struct X448KeyExchange;

impl KeyExchangeProvider for X448KeyExchange {
    fn name(&self) -> &'static str {
        "X448"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("X448 key exchange: creating new context");
        Ok(Box::new(EcxExchangeContext::new(EcxKeyType::X448)))
    }
}

// =============================================================================
// EcxExchangeContext — Shared context for X25519 and X448
// =============================================================================

/// Key exchange context for X25519 and X448 Montgomery-curve DH.
///
/// Lifecycle: `init(private_key)` → `set_peer(public_key)` → `derive(secret)`.
struct EcxExchangeContext {
    /// Which curve variant this context operates on.
    key_type: EcxKeyType,
    /// Our private key bytes. Zeroed on drop.
    our_private: Option<Zeroizing<Vec<u8>>>,
    /// Peer's public key bytes.
    peer_public: Option<Vec<u8>>,
}

impl EcxExchangeContext {
    fn new(key_type: EcxKeyType) -> Self {
        Self {
            key_type,
            our_private: None,
            peer_public: None,
        }
    }

    /// Expected key length for the configured curve.
    fn key_len(&self) -> usize {
        self.key_type.key_len()
    }

    /// Curve display name.
    fn curve_name(&self) -> &'static str {
        match self.key_type {
            EcxKeyType::X25519 => "X25519",
            EcxKeyType::X448 => "X448",
            _ => "ECX",
        }
    }
}

impl KeyExchangeContext for EcxExchangeContext {
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let expected_len = self.key_len();
        trace!(
            curve = self.curve_name(),
            key_len = key.len(),
            expected = expected_len,
            "ECX exchange: init"
        );

        if key.len() != expected_len {
            return Err(ProviderError::Init(format!(
                "{} private key must be {expected_len} bytes, got {}",
                self.curve_name(),
                key.len()
            )));
        }

        self.our_private = Some(Zeroizing::new(key.to_vec()));

        if let Some(ps) = params {
            self.set_params(ps)?;
        }

        Ok(())
    }

    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()> {
        let expected_len = self.key_len();
        trace!(
            curve = self.curve_name(),
            peer_len = peer_key.len(),
            expected = expected_len,
            "ECX exchange: set_peer"
        );

        if peer_key.len() != expected_len {
            return Err(ProviderError::Dispatch(format!(
                "{} public key must be {expected_len} bytes, got {}",
                self.curve_name(),
                peer_key.len()
            )));
        }

        self.peer_public = Some(peer_key.to_vec());
        Ok(())
    }

    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        let priv_bytes = self
            .our_private
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "{} not initialised (no private key)",
                    self.curve_name()
                ))
            })?;

        let peer_bytes = self
            .peer_public
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} peer key not set", self.curve_name()))
            })?;

        // Construct crypto-layer key types
        let priv_key = EcxPrivateKey::new(self.key_type, priv_bytes.to_vec()).map_err(|e| {
            ProviderError::Dispatch(format!("{} private key construction failed: {e}", self.curve_name()))
        })?;

        let pub_key = EcxPublicKey::new(self.key_type, peer_bytes.clone()).map_err(|e| {
            ProviderError::Dispatch(format!("{} public key construction failed: {e}", self.curve_name()))
        })?;

        // Perform the key exchange
        let shared = match self.key_type {
            EcxKeyType::X25519 => x25519(&priv_key, &pub_key),
            EcxKeyType::X448 => x448(&priv_key, &pub_key),
            _ => {
                return Err(ProviderError::Dispatch(format!(
                    "unsupported ECX key type for exchange: {:?}",
                    self.key_type
                )));
            }
        }
        .map_err(|e| ProviderError::Dispatch(format!("{} key agreement failed: {e}", self.curve_name())))?;

        let out_len = std::cmp::min(shared.len(), secret.len());
        secret[..out_len].copy_from_slice(&shared[..out_len]);

        debug!(
            curve = self.curve_name(),
            secret_len = out_len,
            "ECX exchange: derived shared secret"
        );
        Ok(out_len)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        ps.set(
            "algorithm",
            ParamValue::Utf8String(self.curve_name().to_string()),
        );
        // TRUNCATION: key_len() returns 32 (X25519) or 56 (X448), always fits u32.
        ps.set(
            "key-length",
            ParamValue::UInt32(self.key_len() as u32),
        );
        Ok(ps)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        // X25519/X448 have no tuneable parameters beyond key material.
        Ok(())
    }
}

impl Drop for EcxExchangeContext {
    fn drop(&mut self) {
        if let Some(ref mut priv_key) = self.our_private {
            priv_key.zeroize();
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_crypto::ec::curve25519::generate_keypair;

    // -----------------------------------------------------------------------
    // X25519 tests
    // -----------------------------------------------------------------------

    #[test]
    fn x25519_new_ctx() {
        let provider = X25519KeyExchange;
        assert_eq!(provider.name(), "X25519");
        assert!(provider.new_ctx().is_ok());
    }

    #[test]
    fn x25519_init_rejects_wrong_length() {
        let provider = X25519KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        assert!(ctx.init(&[0x42; 16], None).is_err(), "16 bytes too short");
        assert!(ctx.init(&[0x42; 64], None).is_err(), "64 bytes too long");
    }

    #[test]
    fn x25519_set_peer_rejects_wrong_length() {
        let provider = X25519KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(&[0x42; 32], None).expect("init");
        assert!(ctx.set_peer(&[0x01; 16]).is_err());
    }

    #[test]
    fn x25519_derive_fails_without_init() {
        let provider = X25519KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut secret = [0u8; 32];
        assert!(ctx.derive(&mut secret).is_err());
    }

    #[test]
    fn x25519_derive_fails_without_peer() {
        let provider = X25519KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(&[0x42; 32], None).expect("init");
        let mut secret = [0u8; 32];
        assert!(ctx.derive(&mut secret).is_err());
    }

    #[test]
    fn x25519_full_exchange() {
        let alice_kp = generate_keypair(EcxKeyType::X25519).expect("alice keygen");
        let bob_kp = generate_keypair(EcxKeyType::X25519).expect("bob keygen");

        let provider = X25519KeyExchange;

        // Alice derives
        let mut alice_ctx = provider.new_ctx().expect("new_ctx");
        alice_ctx
            .init(alice_kp.private_key().as_bytes(), None)
            .expect("alice init");
        alice_ctx
            .set_peer(bob_kp.public_key().as_bytes())
            .expect("alice set_peer");
        let mut alice_secret = [0u8; 32];
        let alice_len = alice_ctx.derive(&mut alice_secret).expect("alice derive");

        // Bob derives
        let mut bob_ctx = provider.new_ctx().expect("new_ctx");
        bob_ctx
            .init(bob_kp.private_key().as_bytes(), None)
            .expect("bob init");
        bob_ctx
            .set_peer(alice_kp.public_key().as_bytes())
            .expect("bob set_peer");
        let mut bob_secret = [0u8; 32];
        let bob_len = bob_ctx.derive(&mut bob_secret).expect("bob derive");

        assert_eq!(alice_len, 32);
        assert_eq!(bob_len, 32);
        assert_eq!(alice_secret, bob_secret, "shared secrets must match");
        assert!(
            alice_secret.iter().any(|&b| b != 0),
            "shared secret must be non-zero"
        );
    }

    #[test]
    fn x25519_get_params() {
        let provider = X25519KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(&[0x42; 32], None).expect("init");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(
            params.get("algorithm"),
            Some(&ParamValue::Utf8String("X25519".to_string()))
        );
        assert_eq!(params.get("key-length"), Some(&ParamValue::UInt32(32)));
    }

    // -----------------------------------------------------------------------
    // X448 tests
    // -----------------------------------------------------------------------

    #[test]
    fn x448_new_ctx() {
        let provider = X448KeyExchange;
        assert_eq!(provider.name(), "X448");
        assert!(provider.new_ctx().is_ok());
    }

    #[test]
    fn x448_init_rejects_wrong_length() {
        let provider = X448KeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        assert!(ctx.init(&[0x42; 32], None).is_err(), "32 bytes too short");
    }

    #[test]
    fn x448_full_exchange() {
        let alice_kp = generate_keypair(EcxKeyType::X448).expect("alice keygen");
        let bob_kp = generate_keypair(EcxKeyType::X448).expect("bob keygen");

        let provider = X448KeyExchange;

        // Alice derives
        let mut alice_ctx = provider.new_ctx().expect("new_ctx");
        alice_ctx
            .init(alice_kp.private_key().as_bytes(), None)
            .expect("alice init");
        alice_ctx
            .set_peer(bob_kp.public_key().as_bytes())
            .expect("alice set_peer");
        let mut alice_secret = [0u8; 56];
        let alice_len = alice_ctx.derive(&mut alice_secret).expect("alice derive");

        // Bob derives
        let mut bob_ctx = provider.new_ctx().expect("new_ctx");
        bob_ctx
            .init(bob_kp.private_key().as_bytes(), None)
            .expect("bob init");
        bob_ctx
            .set_peer(alice_kp.public_key().as_bytes())
            .expect("bob set_peer");
        let mut bob_secret = [0u8; 56];
        let bob_len = bob_ctx.derive(&mut bob_secret).expect("bob derive");

        assert_eq!(alice_len, 56);
        assert_eq!(bob_len, 56);
        assert_eq!(alice_secret, bob_secret, "shared secrets must match");
        assert!(
            alice_secret.iter().any(|&b| b != 0),
            "shared secret must be non-zero"
        );
    }

    /// RFC 7748 §6.1 test vector for X25519.
    #[test]
    fn x25519_rfc7748_test_vector() {
        // Alice's private key (clamped scalar)
        let alice_priv = hex_to_bytes(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        );
        // Alice's public key = scalar * basepoint
        // Bob's private key
        let bob_priv = hex_to_bytes(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        );
        // Bob's public key
        let bob_pub = hex_to_bytes(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        );
        // Alice's public key
        let alice_pub = hex_to_bytes(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
        // Expected shared secret
        let expected_shared = hex_to_bytes(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        );

        let provider = X25519KeyExchange;

        // Alice computes shared secret with Bob's public key
        let mut alice_ctx = provider.new_ctx().expect("new_ctx");
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");
        let mut alice_secret = [0u8; 32];
        let alice_len = alice_ctx.derive(&mut alice_secret).expect("alice derive");
        assert_eq!(alice_len, 32);
        assert_eq!(&alice_secret[..], &expected_shared[..]);

        // Bob computes shared secret with Alice's public key
        let mut bob_ctx = provider.new_ctx().expect("new_ctx");
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");
        let mut bob_secret = [0u8; 32];
        let bob_len = bob_ctx.derive(&mut bob_secret).expect("bob derive");
        assert_eq!(bob_len, 32);
        assert_eq!(&bob_secret[..], &expected_shared[..]);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
