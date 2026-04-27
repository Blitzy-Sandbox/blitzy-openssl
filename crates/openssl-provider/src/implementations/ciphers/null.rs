//! NULL cipher provider implementation — a passthrough cipher performing no encryption.
//!
//! Input is copied directly to output unchanged.  Used for TLS NULL cipher
//! suites (RFC 5246 §6.2.3.1) and testing scenarios where cipher overhead must
//! be isolated.
//!
//! # C Source Reference
//!
//! Replaces `providers/implementations/ciphers/cipher_null.c` (~130 lines).
//! The C implementation defines `PROV_CIPHER_NULL_CTX` with fields `enc`,
//! `tlsmacsize`, and `tlsmac`, dispatched through the `ossl_null_functions[]`
//! table.
//!
//! # Design Decisions
//!
//! - **Rule R5:** `tls_mac_size` uses `Option<usize>` instead of the C sentinel
//!   value `0` for "unset".  `tls_mac_data` uses `Option<Vec<u8>>` instead of
//!   a raw `*const u8` pointer.
//! - **Rule R6:** All numeric conversions use `TryFrom` / checked arithmetic.
//! - **Rule R8:** Zero `unsafe` code — entirely safe Rust.
//! - **Rule R9:** Every public item documented; warning-free under `-D warnings`.
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(OperationType::Cipher)
//!         → ciphers::descriptors()
//!           → null::descriptors()
//!             → AlgorithmDescriptor { names: ["NULL"], property: "provider=default" }
//! ```

use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use super::common::param_keys;

// =============================================================================
// NullCipher — Provider-Side Cipher Descriptor
// =============================================================================

/// NULL cipher provider — passthrough, zero encryption.
///
/// Replaces the C `PROV_CIPHER_NULL_CTX` type and the `ossl_null_functions[]`
/// dispatch table from `providers/implementations/ciphers/cipher_null.c`.
///
/// The NULL cipher performs no cryptographic transformation:
/// - Key length: 0 (no key required)
/// - IV length: 0 (no initialisation vector required)
/// - Block size: 1 (stream-like, processes one byte at a time)
///
/// It simply copies input bytes to the output buffer unchanged.
///
/// # Usage
///
/// ```rust,ignore
/// use openssl_provider::implementations::ciphers::null::NullCipher;
/// use openssl_provider::traits::CipherProvider;
///
/// let cipher = NullCipher;
/// assert_eq!(cipher.name(), "NULL");
/// assert_eq!(cipher.key_length(), 0);
/// assert_eq!(cipher.iv_length(), 0);
/// assert_eq!(cipher.block_size(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct NullCipher;

impl CipherProvider for NullCipher {
    /// Returns the canonical algorithm name `"NULL"`.
    ///
    /// Corresponds to the `ossl_null_functions[]` entry registered under the
    /// algorithm name `"NULL"` in the C default provider dispatch table.
    fn name(&self) -> &'static str {
        "NULL"
    }

    /// Returns the key length in bytes: `0`.
    ///
    /// The NULL cipher requires no key material.  Corresponds to the C
    /// `ossl_cipher_generic_get_params(params, 0, 0, /*kbits=*/0, 8, 0)`
    /// where `kbits = 0`.
    fn key_length(&self) -> usize {
        0
    }

    /// Returns the IV / nonce length in bytes: `0`.
    ///
    /// The NULL cipher requires no initialisation vector.  Corresponds to the
    /// C `ossl_cipher_generic_get_params(params, 0, 0, 0, 8, /*ivbits=*/0)`
    /// where `ivbits = 0`.
    fn iv_length(&self) -> usize {
        0
    }

    /// Returns the block size in bytes: `1`.
    ///
    /// The NULL cipher operates in a stream-like fashion with a 1-byte
    /// "block".  Corresponds to the C `ossl_cipher_generic_get_params(…,
    /// /*blkbits=*/8, …)` where `blkbits = 8` → 1 byte.
    fn block_size(&self) -> usize {
        1
    }

    /// Creates a new [`NullCipherContext`] ready for encryption or decryption.
    ///
    /// Replaces the C `null_newctx()` function which performs
    /// `OPENSSL_zalloc(sizeof(PROV_CIPHER_NULL_CTX))`.  In Rust, the context
    /// is stack-allocated and boxed for trait-object dispatch.
    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(NullCipherContext {
            encrypting: true,
            tls_mac_size: None,
            tls_mac_data: None,
        }))
    }
}

// =============================================================================
// NullCipherContext — Per-Operation State
// =============================================================================

/// Context for an active NULL cipher operation.
///
/// Replaces the C `PROV_CIPHER_NULL_CTX` struct:
///
/// | C Field          | Rust Field       | Notes                                   |
/// |------------------|------------------|-----------------------------------------|
/// | `int enc`        | `encrypting`     | `bool` instead of `int` (0/1)           |
/// | `size_t tlsmacsize` | `tls_mac_size` | `Option<usize>` per Rule R5 (no sentinel) |
/// | `const unsigned char *tlsmac` | `tls_mac_data` | `Option<Vec<u8>>` — owned copy instead of raw pointer |
///
/// The context is freed automatically when dropped (Rust RAII), replacing
/// the C `null_freectx()` / `OPENSSL_free()` pattern.
#[derive(Debug)]
pub struct NullCipherContext {
    /// Whether the context is in encrypt mode (`true`) or decrypt mode (`false`).
    ///
    /// Set by [`encrypt_init()`](CipherContext::encrypt_init) and
    /// [`decrypt_init()`](CipherContext::decrypt_init).
    encrypting: bool,

    /// TLS MAC size in bytes, if set by the caller via
    /// [`set_params()`](CipherContext::set_params).
    ///
    /// When `Some(n)` with `n > 0` and the context is in decrypt mode,
    /// the [`update()`](CipherContext::update) method strips the trailing
    /// `n` bytes from the input as the TLS MAC (per RFC 5246 §6.2.3.1)
    /// and saves them in [`tls_mac_data`](Self::tls_mac_data).
    ///
    /// Replaces the C sentinel `tlsmacsize = 0` with `Option<usize>` per
    /// Rule R5 (nullability over sentinels).
    tls_mac_size: Option<usize>,

    /// The TLS MAC bytes extracted during the most recent
    /// [`update()`](CipherContext::update) call in decrypt mode.
    ///
    /// Populated when `tls_mac_size` is `Some(n)` and decryption is active.
    /// Retrievable via [`get_params()`](CipherContext::get_params) under
    /// the [`param_keys::TLS_MAC`] key.
    ///
    /// Replaces the C `const unsigned char *tlsmac` pointer with an owned
    /// byte vector, avoiding lifetime and pointer-safety concerns.
    tls_mac_data: Option<Vec<u8>>,
}

impl CipherContext for NullCipherContext {
    /// Initialises the context for encryption.
    ///
    /// Sets the direction to "encrypt" and ignores `key` and `iv` since the
    /// NULL cipher uses neither.  Replaces C `null_einit()`.
    ///
    /// # Parameters
    ///
    /// - `key`: Ignored (NULL cipher has no key).
    /// - `iv`: Ignored (NULL cipher has no IV).
    /// - `params`: Optional context parameters (currently unused during init).
    fn encrypt_init(
        &mut self,
        _key: &[u8],
        _iv: Option<&[u8]>,
        _params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.encrypting = true;
        Ok(())
    }

    /// Initialises the context for decryption.
    ///
    /// Sets the direction to "decrypt" and ignores `key` and `iv` since the
    /// NULL cipher uses neither.  Replaces C `null_dinit()`.
    ///
    /// # Parameters
    ///
    /// - `key`: Ignored (NULL cipher has no key).
    /// - `iv`: Ignored (NULL cipher has no IV).
    /// - `params`: Optional context parameters (currently unused during init).
    fn decrypt_init(
        &mut self,
        _key: &[u8],
        _iv: Option<&[u8]>,
        _params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.encrypting = false;
        Ok(())
    }

    /// Processes input data — copies bytes directly to output with no
    /// cryptographic transformation.
    ///
    /// Replaces C `null_cipher()` which performs `memcpy(out, in, inl)`.
    ///
    /// # TLS MAC Handling
    ///
    /// When decrypting with a non-zero `tls_mac_size` set via
    /// [`set_params()`](Self::set_params), the trailing `tls_mac_size` bytes
    /// are stripped from the input (per RFC 5246 §6.2.3.1) and saved into
    /// `tls_mac_data` for later retrieval via [`get_params()`](Self::get_params).
    /// Only the remaining (non-MAC) bytes are copied to the output.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError` if the input is shorter than `tls_mac_size`
    /// during TLS MAC stripping.
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let effective_input = if self.encrypting {
            // Encryption: no MAC stripping, pass all bytes through.
            input
        } else if let Some(mac_size) = self.tls_mac_size {
            // TLS NULL cipher as per RFC 5246 §6.2.3.1:
            // When decrypting, strip the trailing MAC bytes from input.
            if input.len() < mac_size {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "NULL cipher: input length ({}) is less than TLS MAC size ({})",
                        input.len(),
                        mac_size,
                    ),
                )));
            }
            let mac_start = input.len() - mac_size;
            self.tls_mac_data = Some(input[mac_start..].to_vec());
            &input[..mac_start]
        } else {
            // Decryption without TLS MAC: pass all bytes through.
            input
        };

        // NULL cipher: copy input directly to output, no transformation.
        output.extend_from_slice(effective_input);
        Ok(effective_input.len())
    }

    /// Finalises the cipher operation.
    ///
    /// For the NULL cipher this is a no-op — there is no buffered data to
    /// flush.  Returns `0` bytes written.  Replaces C `null_final()`.
    fn finalize(&mut self, _output: &mut Vec<u8>) -> ProviderResult<usize> {
        Ok(0)
    }

    /// Retrieves context parameters.
    ///
    /// Replaces C `null_get_ctx_params()`.  Returns a `ParamSet` containing:
    ///
    /// | Key                          | Value                | Notes                        |
    /// |------------------------------|----------------------|------------------------------|
    /// | [`param_keys::IVLEN`]        | `UInt32(0)`          | NULL cipher has no IV        |
    /// | [`param_keys::KEYLEN`]       | `UInt32(0)`          | NULL cipher has no key       |
    /// | [`param_keys::BLOCK_SIZE`]   | `UInt32(1)`          | Stream-like, 1-byte blocks   |
    /// | [`param_keys::TLS_MAC`]      | `OctetString(…)`     | Present only when MAC extracted |
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(param_keys::IVLEN, ParamValue::UInt32(0));
        params.set(param_keys::KEYLEN, ParamValue::UInt32(0));
        params.set(param_keys::BLOCK_SIZE, ParamValue::UInt32(1));

        // Include TLS MAC data if it was extracted during a decrypt update.
        if let Some(ref mac_data) = self.tls_mac_data {
            params.set(
                param_keys::TLS_MAC,
                ParamValue::OctetString(mac_data.clone()),
            );
        }

        Ok(params)
    }

    /// Sets context parameters.
    ///
    /// Replaces C `null_set_ctx_params()`.  Accepts:
    ///
    /// | Key                            | Expected Type       | Effect                                 |
    /// |--------------------------------|---------------------|----------------------------------------|
    /// | [`param_keys::TLS_MAC_SIZE`]   | `UInt32` or `UInt64`| Sets the TLS MAC size for decrypt mode |
    ///
    /// A value of `0` disables TLS MAC stripping (sets `tls_mac_size` to `None`).
    ///
    /// # Errors
    ///
    /// Returns `ProviderError` if the `TLS_MAC_SIZE` parameter has an
    /// incompatible type.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(param_keys::TLS_MAC_SIZE) {
            let size = match value {
                ParamValue::UInt32(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Common(CommonError::CastOverflow(e)))?,
                ParamValue::UInt64(v) => usize::try_from(*v)
                    .map_err(|e| ProviderError::Common(CommonError::CastOverflow(e)))?,
                _ => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: param_keys::TLS_MAC_SIZE.to_string(),
                        expected: "UInt32 or UInt64",
                        actual: value.param_type_name(),
                    }));
                }
            };
            // Rule R5: Map 0 → None (disabled), >0 → Some(n) (active).
            self.tls_mac_size = if size > 0 { Some(size) } else { None };
        }
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for the NULL cipher.
///
/// The NULL cipher is always available (no feature gate) and is registered
/// with the default provider.  Returns a single [`AlgorithmDescriptor`]
/// with algorithm name `"NULL"` and property `"provider=default"`.
///
/// Replaces the `ossl_null_functions[]` dispatch entry in the C default
/// provider's `OSSL_ALGORITHM` array.
///
/// # Wiring Path (Rule R10)
///
/// ```text
/// DefaultProvider::query_operation(OperationType::Cipher)
///   → implementations::all_cipher_descriptors()
///     → ciphers::descriptors()
///       → null::descriptors()  // this function
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["NULL"],
        property: "provider=default",
        description: "NULL cipher (passthrough, no encryption)",
    }]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the cipher metadata constants.
    #[test]
    fn null_cipher_metadata() {
        let cipher = NullCipher;
        assert_eq!(cipher.name(), "NULL");
        assert_eq!(cipher.key_length(), 0);
        assert_eq!(cipher.iv_length(), 0);
        assert_eq!(cipher.block_size(), 1);
    }

    /// Verify that a new context can be created.
    #[test]
    fn null_cipher_new_ctx() {
        let cipher = NullCipher;
        let ctx = cipher.new_ctx();
        assert!(ctx.is_ok());
    }

    /// Verify that encrypt passes data through unchanged.
    #[test]
    fn null_cipher_encrypt_passthrough() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&[], None, None).expect("encrypt_init");

        let plaintext = b"Hello, NULL cipher!";
        let mut output = Vec::new();
        let bytes_written = ctx.update(plaintext, &mut output).expect("update");
        assert_eq!(bytes_written, plaintext.len());
        assert_eq!(&output, plaintext);
    }

    /// Verify that decrypt passes data through unchanged.
    #[test]
    fn null_cipher_decrypt_passthrough() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&[], None, None).expect("decrypt_init");

        let ciphertext = b"Hello, NULL cipher!";
        let mut output = Vec::new();
        let bytes_written = ctx.update(ciphertext, &mut output).expect("update");
        assert_eq!(bytes_written, ciphertext.len());
        assert_eq!(&output, ciphertext);
    }

    /// Verify that finalize writes zero bytes.
    #[test]
    fn null_cipher_finalize_zero() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&[], None, None).expect("encrypt_init");

        let mut output = Vec::new();
        let bytes_written = ctx.finalize(&mut output).expect("finalize");
        assert_eq!(bytes_written, 0);
        assert!(output.is_empty());
    }

    /// Verify round-trip: encrypt then decrypt produces original data.
    #[test]
    fn null_cipher_round_trip() {
        let cipher = NullCipher;
        let data = b"Round-trip test data for NULL cipher.";

        // Encrypt
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx.encrypt_init(&[], None, None).expect("encrypt_init");
        let mut encrypted = Vec::new();
        enc_ctx.update(data, &mut encrypted).expect("update");
        enc_ctx.finalize(&mut encrypted).expect("finalize");

        // Decrypt
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx");
        dec_ctx.decrypt_init(&[], None, None).expect("decrypt_init");
        let mut decrypted = Vec::new();
        dec_ctx.update(&encrypted, &mut decrypted).expect("update");
        dec_ctx.finalize(&mut decrypted).expect("finalize");

        assert_eq!(decrypted.as_slice(), data);
    }

    /// Verify empty input produces empty output.
    #[test]
    fn null_cipher_empty_input() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&[], None, None).expect("encrypt_init");

        let mut output = Vec::new();
        let bytes_written = ctx.update(&[], &mut output).expect("update");
        assert_eq!(bytes_written, 0);
        assert!(output.is_empty());
    }

    /// Verify get_params returns expected cipher parameters.
    #[test]
    fn null_cipher_get_params() {
        let cipher = NullCipher;
        let ctx = cipher.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");

        assert_eq!(params.get(param_keys::IVLEN), Some(&ParamValue::UInt32(0)));
        assert_eq!(params.get(param_keys::KEYLEN), Some(&ParamValue::UInt32(0)));
        assert_eq!(
            params.get(param_keys::BLOCK_SIZE),
            Some(&ParamValue::UInt32(1))
        );
        // No TLS MAC data before any update call.
        assert!(params.get(param_keys::TLS_MAC).is_none());
    }

    /// Verify TLS MAC size can be set and affects decrypt behavior.
    #[test]
    fn null_cipher_tls_mac_stripping() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&[], None, None).expect("decrypt_init");

        // Set TLS MAC size to 4 bytes.
        let mut mac_params = ParamSet::new();
        mac_params.set(param_keys::TLS_MAC_SIZE, ParamValue::UInt32(4));
        ctx.set_params(&mac_params).expect("set_params");

        // Input: 10 bytes of data + 4 bytes of MAC = 14 bytes total.
        let mut input = vec![0xAA; 10];
        input.extend_from_slice(&[0xBB, 0xCC, 0xDD, 0xEE]); // 4-byte MAC

        let mut output = Vec::new();
        let bytes_written = ctx.update(&input, &mut output).expect("update");

        // Output should contain only the non-MAC data (10 bytes).
        assert_eq!(bytes_written, 10);
        assert_eq!(output, vec![0xAA; 10]);

        // Retrieve the MAC via get_params.
        let params = ctx.get_params().expect("get_params");
        let mac_value = params
            .get(param_keys::TLS_MAC)
            .expect("TLS_MAC should be set");
        assert_eq!(
            mac_value,
            &ParamValue::OctetString(vec![0xBB, 0xCC, 0xDD, 0xEE])
        );
    }

    /// Verify that TLS MAC stripping fails when input is too short.
    #[test]
    fn null_cipher_tls_mac_input_too_short() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&[], None, None).expect("decrypt_init");

        // Set TLS MAC size to 10 bytes.
        let mut mac_params = ParamSet::new();
        mac_params.set(param_keys::TLS_MAC_SIZE, ParamValue::UInt32(10));
        ctx.set_params(&mac_params).expect("set_params");

        // Input is only 5 bytes — less than MAC size.
        let input = vec![0xAA; 5];
        let mut output = Vec::new();
        let result = ctx.update(&input, &mut output);
        assert!(result.is_err());
    }

    /// Verify that TLS MAC stripping does NOT happen during encryption.
    #[test]
    fn null_cipher_tls_mac_not_in_encrypt() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&[], None, None).expect("encrypt_init");

        // Set TLS MAC size — should have no effect during encryption.
        let mut mac_params = ParamSet::new();
        mac_params.set(param_keys::TLS_MAC_SIZE, ParamValue::UInt32(4));
        ctx.set_params(&mac_params).expect("set_params");

        let input = b"full input data plus fake mac!";
        let mut output = Vec::new();
        let bytes_written = ctx.update(input, &mut output).expect("update");

        // All bytes should pass through unchanged (no MAC stripping).
        assert_eq!(bytes_written, input.len());
        assert_eq!(output.as_slice(), input);
    }

    /// Verify setting TLS MAC size to 0 disables MAC stripping.
    #[test]
    fn null_cipher_tls_mac_size_zero_disables() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&[], None, None).expect("decrypt_init");

        // Set TLS MAC size to 0 — should disable MAC stripping.
        let mut mac_params = ParamSet::new();
        mac_params.set(param_keys::TLS_MAC_SIZE, ParamValue::UInt32(0));
        ctx.set_params(&mac_params).expect("set_params");

        let input = b"all bytes should pass through";
        let mut output = Vec::new();
        let bytes_written = ctx.update(input, &mut output).expect("update");

        assert_eq!(bytes_written, input.len());
        assert_eq!(output.as_slice(), input);
    }

    /// Verify set_params rejects invalid parameter types for TLS_MAC_SIZE.
    #[test]
    fn null_cipher_set_params_type_mismatch() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");

        let mut bad_params = ParamSet::new();
        bad_params.set(
            param_keys::TLS_MAC_SIZE,
            ParamValue::Utf8String("not a number".to_string()),
        );
        let result = ctx.set_params(&bad_params);
        assert!(result.is_err());
    }

    /// Verify the algorithm descriptor.
    #[test]
    fn null_cipher_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["NULL"]);
        assert_eq!(descs[0].property, "provider=default");
        assert!(!descs[0].description.is_empty());
    }

    /// Verify UInt64 also works for TLS MAC size.
    #[test]
    fn null_cipher_tls_mac_size_u64() {
        let cipher = NullCipher;
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&[], None, None).expect("decrypt_init");

        let mut mac_params = ParamSet::new();
        mac_params.set(param_keys::TLS_MAC_SIZE, ParamValue::UInt64(2));
        ctx.set_params(&mac_params).expect("set_params u64");

        // 6 bytes of data + 2 bytes MAC
        let input = vec![1, 2, 3, 4, 5, 6, 0xAA, 0xBB];
        let mut output = Vec::new();
        let bytes_written = ctx.update(&input, &mut output).expect("update");

        assert_eq!(bytes_written, 6);
        assert_eq!(output, vec![1, 2, 3, 4, 5, 6]);

        let params = ctx.get_params().expect("get_params");
        let mac_value = params.get(param_keys::TLS_MAC).expect("TLS_MAC");
        assert_eq!(mac_value, &ParamValue::OctetString(vec![0xAA, 0xBB]));
    }
}
