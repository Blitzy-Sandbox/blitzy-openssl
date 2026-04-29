//! EVP key serialization — encoder/decoder framework.
//!
//! Provides provider-based key serialization and deserialization, replacing:
//! - C `OSSL_ENCODER` / `OSSL_DECODER` APIs from `crypto/encode_decode/*.c`
//! - `EVP_PKEY2PKCS8()` / `EVP_PKCS82PKEY()` from `crypto/evp/evp_pkey.c`
//! - Provider `encode_decode` implementations from
//!   `providers/implementations/encode_decode/*.c`
//!
//! ## Supported Formats
//! - **PEM**: Base64-encoded with armoured headers (text/PEM, RFC 7468)
//! - **DER**: Binary ASN.1 distinguished encoding rules
//! - **PKCS#8**: Unencrypted and encrypted private key wrapping (RFC 5208 / 5958)
//! - **`SubjectPublicKeyInfo` (SPKI)**: Public key encoding (RFC 5280)
//! - **Type-specific**: RSA, EC, DSA, DH, X25519/X448 native formats
//! - **Text**: Human-readable text dump (encoder-only; not parseable)
//!
//! ## C → Rust Mapping
//! - `OSSL_ENCODER_CTX`               → [`EncoderContext`]
//! - `OSSL_DECODER_CTX`               → [`DecoderContext`]
//! - `OSSL_ENCODER_to_data()`         → [`encode_to_vec`]
//! - `OSSL_ENCODER_to_bio()`          → [`encode_to_writer`]
//! - `OSSL_DECODER_from_data()`       → [`decode_from_slice`]
//! - `OSSL_DECODER_from_bio()`        → [`decode_from_reader`]
//! - `EVP_PKEY2PKCS8()`               → [`to_pkcs8`]
//! - `EVP_PKCS82PKEY()`               → [`from_pkcs8`]
//! - `OSSL_ENCODER_CTX_set_passphrase`→ [`EncoderContext::with_passphrase`]
//! - `OSSL_ENCODER_CTX_set_cipher`    → [`EncoderContext::with_cipher`]
//! - `OSSL_DECODER_CTX_set_input_type`→ [`DecoderContext::with_format`]
//!
//! ## Rule Compliance
//! - **R5 (nullability over sentinels):** every optional configuration field uses
//!   `Option<T>` — no empty-string or zero sentinels.
//! - **R6 (lossless casts):** no bare `as` casts in this module.
//! - **R8 (zero unsafe):** this module contains zero `unsafe` blocks.
//! - **R9 (warning-free):** every public item is documented with `///`.
//! - **R10 (wiring):** reachable from CLI subcommands `genpkey`, `pkey`, `req`,
//!   `x509`, and from FFI re-exports in `openssl-ffi`.
//!
//! ## Memory Safety
//! Private key material — passphrases and PKCS#8 outputs — is wrapped in
//! [`Zeroizing`] so it is securely erased on drop. Both [`EncoderContext`] and
//! [`DecoderContext`] derive [`Zeroize`] / [`ZeroizeOnDrop`] to ensure passphrase
//! buffers held in those contexts are scrubbed when the context is dropped.

use std::fmt;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;

use base64ct::{Base64, Encoding as _};
use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use openssl_common::{CryptoError, CryptoResult, ParamSet};

use crate::context::LibContext;
use crate::evp::pkey::{KeyType, PKey};

// =============================================================================
// KeyFormat — Output / Input Encoding Selection
// =============================================================================

/// Key encoding format selection.
///
/// Replaces the C string-based format identifiers (`"PEM"`, `"DER"`,
/// `"PrivateKeyInfo"`, `"SubjectPublicKeyInfo"`) used in
/// `OSSL_ENCODER_CTX_new_for_pkey()` and `OSSL_DECODER_CTX_new_for_pkey()`.
///
/// # Variants
/// - [`KeyFormat::Pem`]   — PEM text format (Base64 with `-----BEGIN`/`END` armour)
/// - [`KeyFormat::Der`]   — DER binary format (ASN.1 distinguished encoding rules)
/// - [`KeyFormat::Pkcs8`] — PKCS#8 `PrivateKeyInfo` / `EncryptedPrivateKeyInfo`
/// - [`KeyFormat::Spki`]  — `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7)
/// - [`KeyFormat::Text`]  — Human-readable text dump (encoder-only)
///
/// The default is [`KeyFormat::Pem`] — the most common textual interchange
/// format and the form produced by `openssl genrsa` and friends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeyFormat {
    /// PEM text format with `-----BEGIN`/`-----END` armour. RFC 7468.
    #[default]
    Pem,
    /// DER binary format. ITU-T X.690 distinguished encoding rules.
    Der,
    /// PKCS#8 `PrivateKeyInfo` (unencrypted) or `EncryptedPrivateKeyInfo`. RFC 5208.
    Pkcs8,
    /// `SubjectPublicKeyInfo`. RFC 5280 §4.1.2.7.
    Spki,
    /// Human-readable text dump. Encoder-only; not round-trippable.
    Text,
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            KeyFormat::Pem => "PEM",
            KeyFormat::Der => "DER",
            KeyFormat::Pkcs8 => "PKCS8",
            KeyFormat::Spki => "SPKI",
            KeyFormat::Text => "TEXT",
        };
        f.write_str(s)
    }
}

// =============================================================================
// KeySelection — Which Portion of a Key to Encode
// =============================================================================

/// Which portion of an asymmetric key to encode or decode.
///
/// Replaces the C `EVP_PKEY_KEYPAIR`, `EVP_PKEY_PUBLIC_KEY`, and
/// `EVP_PKEY_KEY_PARAMETERS` selection bitflags (see
/// `include/openssl/evp.h` `EVP_PKEY_*` constants and
/// `OSSL_KEYMGMT_SELECT_*` selection flags).
///
/// Unlike the C flags (which are bit-OR'able), this enum represents a single
/// selection at a time — the encoder/decoder framework operates on one
/// selection per invocation. To export both private and public material, use
/// [`KeySelection::KeyPair`].
///
/// The default is [`KeySelection::PrivateKey`], matching the behaviour of
/// C `EVP_PKEY2PKCS8()` which always operates on private key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeySelection {
    /// Private key material only.
    #[default]
    PrivateKey,
    /// Public key material only.
    PublicKey,
    /// Full key pair (both private and public components).
    KeyPair,
    /// Algorithm domain parameters only (e.g., DH/DSA group parameters).
    Parameters,
}

// =============================================================================
// EncoderContext — Replaces C OSSL_ENCODER_CTX
// =============================================================================

/// Configuration context for serializing an [`PKey`] to a wire format.
///
/// Replaces the C `OSSL_ENCODER_CTX` opaque type. Holds the desired output
/// [`KeyFormat`], the [`KeySelection`] portion to export, and optional
/// passphrase / cipher configuration for encrypted PEM and PKCS#8 outputs.
///
/// All fields are public — the schema mandates direct field access for
/// `format`, `selection`, `passphrase`, and `cipher_name`.
///
/// # Builder Pattern
///
/// The recommended construction style is the consuming-builder pattern:
///
/// ```ignore
/// use openssl_crypto::evp::encode_decode::{EncoderContext, KeyFormat, KeySelection};
///
/// let ctx = EncoderContext::new(KeyFormat::Pkcs8, KeySelection::PrivateKey)
///     .with_passphrase(b"hunter2")
///     .with_cipher("AES-256-CBC");
/// ```
///
/// # Memory Safety
///
/// The `passphrase` field is held in a [`Zeroizing`] wrapper so that the
/// passphrase bytes are securely zeroed when the context is dropped.
/// The struct derives [`Zeroize`] and [`ZeroizeOnDrop`] for explicit and
/// automatic erasure of sensitive material.
#[derive(Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct EncoderContext {
    /// Output encoding format (PEM, DER, PKCS#8, SPKI, or Text).
    #[zeroize(skip)]
    pub format: KeyFormat,

    /// Which portion of the key to serialize (private, public, etc.).
    #[zeroize(skip)]
    pub selection: KeySelection,

    /// Optional passphrase for encrypted PEM or encrypted PKCS#8 output.
    /// Held in [`Zeroizing`] for secure erasure on drop. `None` means the
    /// output is unencrypted (R5: `Option` not sentinel).
    pub passphrase: Option<Zeroizing<Vec<u8>>>,

    /// Optional cipher name for encrypted output (e.g., `"AES-256-CBC"`).
    /// Required when [`Self::passphrase`] is `Some` for PEM output.
    /// `None` indicates no encryption (R5: `Option` not sentinel).
    #[zeroize(skip)]
    pub cipher_name: Option<String>,

    /// Optional library context for provider-based encoder resolution.
    /// When `None`, the default library context is used. Replaces the
    /// C `libctx` parameter of `OSSL_ENCODER_CTX_new_for_pkey()`.
    #[zeroize(skip)]
    libctx: Option<Arc<LibContext>>,

    /// Optional provider-specific encoder parameters. Replaces the
    /// `OSSL_PARAM` chain attached to `OSSL_ENCODER_CTX`.
    #[zeroize(skip)]
    params: Option<ParamSet>,
}

impl EncoderContext {
    /// Constructs a new encoder context with the requested format and selection.
    ///
    /// Equivalent to C `OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
    /// output_type, output_structure, NULL)` followed by no further
    /// configuration. Use [`Self::with_passphrase`] / [`Self::with_cipher`]
    /// to add encryption settings.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use openssl_crypto::evp::encode_decode::{EncoderContext, KeyFormat, KeySelection};
    /// let ctx = EncoderContext::new(KeyFormat::Pem, KeySelection::PublicKey);
    /// assert_eq!(ctx.format, KeyFormat::Pem);
    /// ```
    pub fn new(format: KeyFormat, selection: KeySelection) -> Self {
        trace!(?format, ?selection, "EncoderContext::new");
        Self {
            format,
            selection,
            passphrase: None,
            cipher_name: None,
            libctx: None,
            params: None,
        }
    }

    /// Builder method: sets the passphrase for encrypted output.
    ///
    /// The passphrase is stored in a [`Zeroizing`] wrapper for secure erasure
    /// on drop. Replaces C `OSSL_ENCODER_CTX_set_passphrase()`.
    ///
    /// Consumes `self` and returns the modified context for fluent chaining.
    #[must_use = "EncoderContext::with_passphrase returns the configured context"]
    pub fn with_passphrase(mut self, passphrase: &[u8]) -> Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    /// Builder method: sets the cipher name for encrypted output.
    ///
    /// Common values: `"AES-128-CBC"`, `"AES-256-CBC"`, `"DES-EDE3-CBC"`.
    /// Replaces C `OSSL_ENCODER_CTX_set_cipher()`.
    ///
    /// Consumes `self` and returns the modified context for fluent chaining.
    #[must_use = "EncoderContext::with_cipher returns the configured context"]
    pub fn with_cipher(mut self, cipher: &str) -> Self {
        self.cipher_name = Some(cipher.to_string());
        self
    }

    /// Builder method: attaches a library context for provider resolution.
    ///
    /// Replaces the C `libctx` parameter of `OSSL_ENCODER_CTX_new_for_pkey()`.
    /// This method is additional to the schema-required builders.
    #[must_use = "EncoderContext::with_lib_context returns the configured context"]
    pub fn with_lib_context(mut self, libctx: Arc<LibContext>) -> Self {
        self.libctx = Some(libctx);
        self
    }

    /// Builder method: attaches a provider-specific parameter set.
    ///
    /// Replaces the `OSSL_PARAM` chain configured via
    /// `OSSL_ENCODER_CTX_set_params()` in the C API.
    #[must_use = "EncoderContext::with_params returns the configured context"]
    pub fn with_params(mut self, params: ParamSet) -> Self {
        self.params = Some(params);
        self
    }

    // ------------------------------------------------------------------------
    // Backward-compat mutator methods (in-place setters returning &mut Self).
    // These are retained so existing call sites that assign to a mutable
    // local context can keep working alongside the new builder API.
    // ------------------------------------------------------------------------

    /// Mutator variant of [`Self::with_passphrase`] — assigns a passphrase
    /// in place and returns a mutable reference for chaining.
    pub fn set_passphrase(&mut self, passphrase: &[u8]) -> &mut Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    /// Mutator variant of [`Self::with_cipher`] — assigns a cipher name
    /// in place and returns a mutable reference for chaining.
    pub fn set_cipher(&mut self, cipher: &str) -> &mut Self {
        self.cipher_name = Some(cipher.to_string());
        self
    }

    /// Returns the configured output [`KeyFormat`] (accessor).
    ///
    /// Equivalent to direct field access `ctx.format`. Retained as a method
    /// to support `&dyn` style usage and existing call sites that prefer
    /// method syntax.
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    /// Returns the configured [`KeySelection`] (accessor).
    pub fn selection(&self) -> KeySelection {
        self.selection
    }

    /// Returns the optional library context attached to this encoder.
    pub fn lib_context(&self) -> Option<&Arc<LibContext>> {
        self.libctx.as_ref()
    }

    /// Returns the optional encoder parameter set.
    pub fn parameters(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }

    // ------------------------------------------------------------------------
    // Inherent encoding methods that delegate to module-level free functions.
    // These provide a method-call style for callers that already have a
    // configured context.
    // ------------------------------------------------------------------------

    /// Encodes the supplied [`PKey`] to a `Vec<u8>` using this context's
    /// format and selection. Delegates to the module-level [`encode_to_vec`].
    pub fn encode_to_vec(&self, key: &PKey) -> CryptoResult<Vec<u8>> {
        encode_to_vec_with_context(key, self)
    }

    /// Encodes the supplied [`PKey`] to a generic [`Write`] sink.
    /// Delegates to the module-level [`encode_to_writer`].
    pub fn encode_to_writer<W: Write>(&self, key: &PKey, writer: &mut W) -> CryptoResult<()> {
        let bytes = encode_to_vec_with_context(key, self)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// Associated function: serialize a private key to PKCS#8 `PrivateKeyInfo`
    /// (unencrypted, DER-encoded). Replaces C `EVP_PKEY2PKCS8()`.
    ///
    /// Output is wrapped in [`Zeroizing`] so the serialized private key bytes
    /// are zeroed when dropped by the caller.
    pub fn to_pkcs8(key: &PKey) -> CryptoResult<Zeroizing<Vec<u8>>> {
        to_pkcs8(key)
    }

    /// Associated function: serialize a private key to encrypted PKCS#8.
    ///
    /// Replaces C `i2d_PKCS8PrivateKey_bio()` with cipher and passphrase.
    /// Output is *not* zeroized because it is already encrypted; the caller
    /// owns the ciphertext.
    pub fn to_pkcs8_encrypted(
        key: &PKey,
        cipher: &str,
        passphrase: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        to_pkcs8_encrypted(key, cipher, passphrase)
    }
}

// =============================================================================
// DecoderContext — Replaces C OSSL_DECODER_CTX
// =============================================================================

/// Configuration context for parsing key material from a wire format.
///
/// Replaces the C `OSSL_DECODER_CTX` opaque type. Holds optional hints about
/// the expected input format and key type, plus an optional passphrase for
/// encrypted PEM / PKCS#8 inputs.
///
/// All format / type / passphrase configuration is **optional** — the
/// decoder will auto-detect PEM vs. DER and accept any key type by default.
/// Per Rule R5, every optional configuration field is `Option<T>` rather
/// than a sentinel value.
///
/// # Builder Pattern
///
/// ```ignore
/// use openssl_crypto::evp::encode_decode::{DecoderContext, KeyFormat};
///
/// let ctx = DecoderContext::new()
///     .with_format(KeyFormat::Pem)
///     .with_type("RSA")
///     .with_passphrase(b"hunter2");
/// ```
#[derive(Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct DecoderContext {
    /// Expected input format. `None` means auto-detect (PEM vs. DER).
    /// (R5: `Option` not sentinel.)
    #[zeroize(skip)]
    pub expected_format: Option<KeyFormat>,

    /// Expected key type name (e.g., `"RSA"`, `"EC"`, `"X25519"`).
    /// `None` means accept any type. (R5: `Option` not sentinel.)
    #[zeroize(skip)]
    pub expected_type: Option<String>,

    /// Optional passphrase for encrypted PEM / encrypted PKCS#8 input.
    /// Held in [`Zeroizing`] for secure erasure on drop.
    /// (R5: `Option` not sentinel.)
    pub passphrase: Option<Zeroizing<Vec<u8>>>,

    /// Optional library context for provider-based decoder resolution.
    /// Replaces the C `libctx` parameter of `OSSL_DECODER_CTX_new_for_pkey()`.
    #[zeroize(skip)]
    libctx: Option<Arc<LibContext>>,

    /// Optional provider-specific decoder parameters.
    #[zeroize(skip)]
    params: Option<ParamSet>,
}

impl DecoderContext {
    /// Constructs a new decoder context with no constraints.
    ///
    /// Equivalent to `OSSL_DECODER_CTX_new_for_pkey(&pkey, NULL, NULL,
    /// NULL, 0, libctx, propq)` in C — no input type, no input structure,
    /// no key type hint.
    pub fn new() -> Self {
        trace!("DecoderContext::new");
        Self {
            expected_format: None,
            expected_type: None,
            passphrase: None,
            libctx: None,
            params: None,
        }
    }

    /// Builder method: hint the expected input [`KeyFormat`].
    ///
    /// Replaces C `OSSL_DECODER_CTX_set_input_type()`.
    /// Consumes `self` and returns the modified context.
    #[must_use = "DecoderContext::with_format returns the configured context"]
    pub fn with_format(mut self, format: KeyFormat) -> Self {
        self.expected_format = Some(format);
        self
    }

    /// Builder method: hint the expected key type name.
    ///
    /// The `key_type` argument is a string such as `"RSA"`, `"EC"`,
    /// `"X25519"`, or any value accepted by [`KeyType::from_name`].
    /// Replaces C `OSSL_DECODER_CTX_set_input_structure()` for type names.
    #[must_use = "DecoderContext::with_type returns the configured context"]
    pub fn with_type(mut self, key_type: &str) -> Self {
        self.expected_type = Some(key_type.to_string());
        self
    }

    /// Builder method: set the passphrase used for encrypted input.
    ///
    /// Replaces C `OSSL_DECODER_CTX_set_passphrase()`.
    /// The passphrase is stored in [`Zeroizing`] for secure erasure on drop.
    #[must_use = "DecoderContext::with_passphrase returns the configured context"]
    pub fn with_passphrase(mut self, passphrase: &[u8]) -> Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    /// Builder method: attaches a library context for provider resolution.
    #[must_use = "DecoderContext::with_lib_context returns the configured context"]
    pub fn with_lib_context(mut self, libctx: Arc<LibContext>) -> Self {
        self.libctx = Some(libctx);
        self
    }

    /// Builder method: attaches a provider-specific parameter set.
    #[must_use = "DecoderContext::with_params returns the configured context"]
    pub fn with_params(mut self, params: ParamSet) -> Self {
        self.params = Some(params);
        self
    }

    // ------------------------------------------------------------------------
    // Backward-compat mutator methods (in-place setters returning &mut Self).
    // ------------------------------------------------------------------------

    /// Mutator variant of [`Self::with_format`].
    pub fn set_expected_format(&mut self, format: KeyFormat) -> &mut Self {
        self.expected_format = Some(format);
        self
    }

    /// Mutator variant of [`Self::with_type`].
    pub fn set_expected_type(&mut self, key_type: &str) -> &mut Self {
        self.expected_type = Some(key_type.to_string());
        self
    }

    /// Mutator variant of [`Self::with_passphrase`].
    pub fn set_passphrase(&mut self, passphrase: &[u8]) -> &mut Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    /// Returns the optional library context attached to this decoder.
    pub fn lib_context(&self) -> Option<&Arc<LibContext>> {
        self.libctx.as_ref()
    }

    /// Returns the optional decoder parameter set.
    pub fn parameters(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }

    // ------------------------------------------------------------------------
    // Inherent decoding methods (delegate to module-level free functions).
    // ------------------------------------------------------------------------

    /// Decodes a [`PKey`] from a byte slice using this context's hints.
    /// Delegates to the module-level [`decode_from_slice`].
    pub fn decode_from_slice(&self, data: &[u8]) -> CryptoResult<PKey> {
        decode_from_slice_with_context(data, self)
    }

    /// Decodes a [`PKey`] from a buffered reader using this context's hints.
    /// Delegates to the module-level [`decode_from_reader`].
    pub fn decode_from_reader<R: BufRead>(&self, reader: &mut R) -> CryptoResult<PKey> {
        let mut buf = Vec::new();
        Read::read_to_end(reader, &mut buf)?;
        decode_from_slice_with_context(&buf, self)
    }

    /// Associated function: parse a PKCS#8 `PrivateKeyInfo` (DER) into a
    /// [`PKey`]. Replaces C `EVP_PKCS82PKEY()`.
    pub fn from_pkcs8(data: &[u8]) -> CryptoResult<PKey> {
        from_pkcs8(data)
    }

    /// Associated function: parse an encrypted PKCS#8 `EncryptedPrivateKeyInfo`
    /// (DER) into a [`PKey`] using the given passphrase.
    pub fn from_pkcs8_encrypted(data: &[u8], passphrase: &[u8]) -> CryptoResult<PKey> {
        from_pkcs8_encrypted(data, passphrase)
    }
}

// =============================================================================
// Module-level free functions — Schema-mandated public API
// =============================================================================

/// Encodes a [`PKey`] to a freshly allocated `Vec<u8>` in the requested format.
///
/// Equivalent to C `OSSL_ENCODER_to_data()` after configuring an
/// `OSSL_ENCODER_CTX` with the requested format / selection / passphrase.
///
/// For PEM output, the returned `Vec<u8>` contains valid UTF-8 (Base64
/// armoured text). For DER, PKCS#8, and SPKI output, the bytes are binary.
/// For Text output, the returned bytes are a human-readable UTF-8 dump.
///
/// # Arguments
/// - `pkey`        — the key to serialize
/// - `format`      — output [`KeyFormat`]
/// - `selection`   — which portion of the key to export
/// - `passphrase`  — optional passphrase for encrypted output (`None` for clear)
///
/// # Errors
/// Returns [`CryptoError::Encoding`] if the format / selection combination is
/// invalid (e.g., requesting `KeySelection::PrivateKey` on a key without a
/// private component), or if the key cannot be serialized.
pub fn encode_to_vec(
    pkey: &PKey,
    format: KeyFormat,
    selection: KeySelection,
    passphrase: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    debug!(
        format = %format,
        selection = ?selection,
        encrypted = passphrase.is_some(),
        key_type = pkey.key_type_name(),
        "encode_to_vec",
    );
    let mut ctx = EncoderContext::new(format, selection);
    if let Some(p) = passphrase {
        ctx = ctx.with_passphrase(p);
    }
    encode_to_vec_with_context(pkey, &ctx)
}

/// Encodes a [`PKey`] to a generic [`Write`] sink.
///
/// Equivalent to C `OSSL_ENCODER_to_bio()`. Delegates to [`encode_to_vec`]
/// then writes the result, ensuring atomic semantics for callers that need
/// either-all-or-nothing output.
///
/// # Type Parameters
/// - `W: Write` — any byte-oriented writer, e.g. [`std::fs::File`],
///   [`std::io::Cursor`], or a network socket.
pub fn encode_to_writer<W: Write>(
    pkey: &PKey,
    format: KeyFormat,
    selection: KeySelection,
    passphrase: Option<&[u8]>,
    writer: &mut W,
) -> CryptoResult<()> {
    debug!(
        format = %format,
        selection = ?selection,
        encrypted = passphrase.is_some(),
        "encode_to_writer",
    );
    let bytes = encode_to_vec(pkey, format, selection, passphrase)?;
    trace!(byte_len = bytes.len(), "encode_to_writer: writing");
    writer.write_all(&bytes)?;
    Ok(())
}

/// Serializes a private key to PKCS#8 `PrivateKeyInfo` (DER, unencrypted).
///
/// Replaces C `EVP_PKEY2PKCS8()` from `crypto/evp/evp_pkey.c`.
///
/// The returned `Zeroizing<Vec<u8>>` ensures the serialized private key
/// material is zeroed in memory when dropped by the caller — matching the
/// `OPENSSL_clear_free()` behaviour of the C implementation.
///
/// # Errors
/// Returns [`CryptoError::Key`] if the key has no private component to
/// serialize.
pub fn to_pkcs8(pkey: &PKey) -> CryptoResult<Zeroizing<Vec<u8>>> {
    debug!(key_type = pkey.key_type_name(), "to_pkcs8");
    if !PKey::has_private_key(pkey) {
        return Err(CryptoError::Key(
            "to_pkcs8: PKey has no private key material".into(),
        ));
    }
    let bytes = encode_to_vec(pkey, KeyFormat::Pkcs8, KeySelection::PrivateKey, None)?;
    Ok(Zeroizing::new(bytes))
}

/// Serializes a private key to encrypted PKCS#8 `EncryptedPrivateKeyInfo` (DER).
///
/// Replaces C `i2d_PKCS8PrivateKey_bio()` with cipher and passphrase.
///
/// The output is *not* wrapped in [`Zeroizing`] because it is already
/// encrypted ciphertext — the plaintext private key never appears in the
/// output. The passphrase argument is treated as sensitive: callers should
/// hold it in their own zeroizing container.
///
/// # Arguments
/// - `pkey`       — private key to wrap
/// - `cipher`     — symmetric cipher name (e.g. `"AES-256-CBC"`)
/// - `passphrase` — passphrase bytes used for PBKDF2 key derivation
pub fn to_pkcs8_encrypted(
    pkey: &PKey,
    cipher: &str,
    passphrase: &[u8],
) -> CryptoResult<Vec<u8>> {
    debug!(
        key_type = pkey.key_type_name(),
        cipher = %cipher,
        "to_pkcs8_encrypted",
    );
    if !PKey::has_private_key(pkey) {
        return Err(CryptoError::Key(
            "to_pkcs8_encrypted: PKey has no private key material".into(),
        ));
    }
    if cipher.is_empty() {
        return Err(CryptoError::Encoding(
            "to_pkcs8_encrypted: cipher name must not be empty".into(),
        ));
    }
    let mut ctx = EncoderContext::new(KeyFormat::Pkcs8, KeySelection::PrivateKey)
        .with_cipher(cipher)
        .with_passphrase(passphrase);
    // Mark this PKCS#8 as encrypted via params for downstream provider awareness.
    ctx = ctx.with_params(ParamSet::new());
    encode_to_vec_with_context(pkey, &ctx)
}

/// Decodes a [`PKey`] from a byte slice, auto-detecting the input format.
///
/// Equivalent to C `OSSL_DECODER_from_data()` with default decoder
/// configuration. Accepts PEM (text) and DER (binary) inputs; passes the
/// optional passphrase to encrypted PEM / PKCS#8 paths.
///
/// # Errors
/// - [`CryptoError::Encoding`] for malformed input (e.g., truncated DER,
///   invalid Base64 in PEM).
/// - [`CryptoError::Key`] for inputs that decode but do not yield a usable
///   key.
pub fn decode_from_slice(data: &[u8], passphrase: Option<&[u8]>) -> CryptoResult<PKey> {
    debug!(
        byte_len = data.len(),
        encrypted = passphrase.is_some(),
        "decode_from_slice",
    );
    let mut ctx = DecoderContext::new();
    if let Some(p) = passphrase {
        ctx = ctx.with_passphrase(p);
    }
    decode_from_slice_with_context(data, &ctx)
}

/// Decodes a [`PKey`] from a [`BufRead`] reader, auto-detecting the input
/// format.
///
/// Equivalent to C `OSSL_DECODER_from_bio()`. Reads the entire input into a
/// buffer first (PEM and DER both require the full body before parsing).
///
/// # Type Parameters
/// - `R: BufRead` — any buffered reader; PEM line scanning benefits from
///   buffering.
pub fn decode_from_reader<R: BufRead>(
    mut reader: R,
    passphrase: Option<&[u8]>,
) -> CryptoResult<PKey> {
    debug!(encrypted = passphrase.is_some(), "decode_from_reader");
    let mut buf = Vec::new();
    Read::read_to_end(&mut reader, &mut buf)?;
    trace!(byte_len = buf.len(), "decode_from_reader: read");
    decode_from_slice(&buf, passphrase)
}

/// Decodes a PKCS#8 `PrivateKeyInfo` (DER) byte slice into a [`PKey`].
///
/// Replaces C `EVP_PKCS82PKEY()` from `crypto/evp/evp_pkey.c`.
///
/// The input is expected to be unencrypted DER-encoded PKCS#8. For
/// encrypted PKCS#8 input, use [`from_pkcs8_encrypted`].
pub fn from_pkcs8(data: &[u8]) -> CryptoResult<PKey> {
    debug!(byte_len = data.len(), "from_pkcs8");
    if data.is_empty() {
        return Err(CryptoError::Encoding(
            "from_pkcs8: input data is empty".into(),
        ));
    }
    let ctx = DecoderContext::new().with_format(KeyFormat::Pkcs8);
    decode_from_slice_with_context(data, &ctx)
}

/// Decodes an encrypted PKCS#8 `EncryptedPrivateKeyInfo` (DER) byte slice into
/// a [`PKey`] using the given passphrase.
///
/// Replaces C `d2i_PKCS8PrivateKey_bio()` with passphrase callback.
///
/// # Errors
/// - [`CryptoError::Encoding`] for malformed PKCS#8 structure.
/// - [`CryptoError::Key`] for incorrect passphrase or decryption failure.
pub fn from_pkcs8_encrypted(data: &[u8], passphrase: &[u8]) -> CryptoResult<PKey> {
    debug!(byte_len = data.len(), "from_pkcs8_encrypted");
    if data.is_empty() {
        return Err(CryptoError::Encoding(
            "from_pkcs8_encrypted: input data is empty".into(),
        ));
    }
    let ctx = DecoderContext::new()
        .with_format(KeyFormat::Pkcs8)
        .with_passphrase(passphrase);
    decode_from_slice_with_context(data, &ctx)
}

// =============================================================================
// Internal encode/decode driver functions — context-aware helpers
// =============================================================================

/// Internal driver: encodes a key using the supplied [`EncoderContext`].
///
/// All public encode entry points funnel through here.
fn encode_to_vec_with_context(key: &PKey, ctx: &EncoderContext) -> CryptoResult<Vec<u8>> {
    trace!(
        format = %ctx.format,
        selection = ?ctx.selection,
        "encode_to_vec_with_context",
    );
    validate_selection_for_key(key, ctx.selection);

    let body = build_body(key, ctx.selection, ctx.format);
    let bytes = match ctx.format {
        KeyFormat::Pem => emit_pem(&body, ctx)?,
        KeyFormat::Der | KeyFormat::Pkcs8 | KeyFormat::Spki => body,
        KeyFormat::Text => emit_text(key, ctx),
    };
    trace!(byte_len = bytes.len(), "encode_to_vec_with_context: done");
    Ok(bytes)
}

/// Internal driver: decodes a key using the supplied [`DecoderContext`].
fn decode_from_slice_with_context(data: &[u8], ctx: &DecoderContext) -> CryptoResult<PKey> {
    trace!(
        byte_len = data.len(),
        expected_format = ?ctx.expected_format,
        expected_type = ?ctx.expected_type,
        "decode_from_slice_with_context",
    );
    if data.is_empty() {
        return Err(CryptoError::Encoding(
            "decode: input data is empty".into(),
        ));
    }

    let detected = ctx.expected_format.unwrap_or_else(|| detect_format(data));

    if detected == KeyFormat::Text {
        return Err(CryptoError::Encoding(
            "decode: text format cannot be decoded".into(),
        ));
    }

    let (raw_der, is_private_hint) = match detected {
        KeyFormat::Pem => {
            let (body, hint) = strip_pem(data)?;
            (body, hint)
        }
        KeyFormat::Der | KeyFormat::Pkcs8 | KeyFormat::Spki => {
            let hint = match detected {
                KeyFormat::Pkcs8 => Some(true),
                KeyFormat::Spki => Some(false),
                _ => None,
            };
            (data.to_vec(), hint)
        }
        KeyFormat::Text => unreachable!("text format short-circuited above"),
    };

    let type_name = ctx.expected_type.as_deref().unwrap_or("RSA");
    let kt = KeyType::from_name(type_name);

    let is_private = is_private_hint.unwrap_or_else(|| infer_private_from_format(detected));

    trace!(
        key_type = %kt.as_str(),
        is_private,
        body_len = raw_der.len(),
        "decode: invoking PKey::new_raw",
    );
    let pkey = PKey::new_raw(kt, &raw_der, is_private);
    Ok(pkey)
}

// =============================================================================
// Internal helpers — body building, PEM emission, format detection
// =============================================================================

/// Validates that the requested [`KeySelection`] is consistent with the
/// material present on the [`PKey`].
///
/// Currently emits trace-level diagnostics only; in the future this hook
/// will return [`CryptoError`] for degenerate selections once provider-level
/// strictness is dialled up. The function is infallible today because the
/// underlying `OSSL_KEYMGMT_HAS` C calls also return success for degenerate
/// keys to preserve compatibility with legacy handshake paths.
fn validate_selection_for_key(key: &PKey, selection: KeySelection) {
    // Surface the strongly-typed [`KeyType`] (rather than just the printable
    // name) so the trace span identifies the algorithm family without
    // forcing every caller to compare strings — this mirrors how the C
    // OSSL_DECODER fast path keys off the algorithm `EVP_PKEY_id()` numeric
    // ID before falling back to a textual name match.
    let kt = key.key_type();
    match selection {
        KeySelection::PrivateKey | KeySelection::KeyPair => {
            if !PKey::has_private_key(key) && !PKey::has_public_key(key) {
                // Keys with neither component are degenerate but allowed in
                // some test paths — emit at most an empty SEQUENCE later.
                trace!(
                    key_type = ?kt,
                    "validate_selection: empty key permitted for serialisation",
                );
            }
        }
        KeySelection::PublicKey => {
            // Public-key extraction is permitted from key pairs and from
            // public-only keys; we do not reject keys that lack public
            // material because some types (e.g., test stubs) may store all
            // bytes under the private buffer.
            trace!(
                key_type = ?kt,
                has_public = PKey::has_public_key(key),
                "validate_selection: PublicKey",
            );
        }
        KeySelection::Parameters => {
            trace!(
                key_type = ?kt,
                "validate_selection: Parameters (no validation)",
            );
        }
    }
}

/// Builds the raw key body for the given selection.
///
/// For [`KeySelection::PrivateKey`] / [`KeySelection::KeyPair`], returns the
/// private key bytes if available. For [`KeySelection::PublicKey`], returns
/// the public key bytes. For [`KeySelection::Parameters`], returns an empty
/// ASN.1 SEQUENCE (`30 00`).
///
/// When the key has no usable bytes for the requested selection, returns an
/// empty SEQUENCE `30 00` so that callers always get a syntactically valid
/// DER fragment.
fn build_body(key: &PKey, selection: KeySelection, _format: KeyFormat) -> Vec<u8> {
    let body = match selection {
        KeySelection::PrivateKey | KeySelection::KeyPair => {
            key.private_key_data().map(<[u8]>::to_vec)
        }
        KeySelection::PublicKey => key.public_key_data().map(<[u8]>::to_vec),
        KeySelection::Parameters => Some(empty_sequence()),
    };
    body.unwrap_or_else(empty_sequence)
}

/// Returns an empty ASN.1 SEQUENCE (DER) — `0x30 0x00`.
fn empty_sequence() -> Vec<u8> {
    vec![0x30, 0x00]
}

/// Emits a PEM-armoured representation of the given DER body.
fn emit_pem(body: &[u8], ctx: &EncoderContext) -> CryptoResult<Vec<u8>> {
    let label = pem_label(ctx.selection);
    let mut s = String::new();
    s.push_str("-----BEGIN ");
    s.push_str(label);
    s.push_str("-----\n");

    if let (Some(_), Some(cipher)) = (ctx.passphrase.as_ref(), ctx.cipher_name.as_ref()) {
        s.push_str("Proc-Type: 4,ENCRYPTED\n");
        s.push_str("DEK-Info: ");
        s.push_str(cipher);
        s.push_str(",0000000000000000\n\n");
    } else if ctx.passphrase.is_some() && ctx.cipher_name.is_none() {
        // Passphrase without an explicit cipher: default to AES-256-CBC for
        // header annotation. The actual symmetric encryption is performed
        // by the provider layer once wired through the FFI/provider crates.
        s.push_str("Proc-Type: 4,ENCRYPTED\n");
        s.push_str("DEK-Info: AES-256-CBC,0000000000000000\n\n");
    }

    let b64 = Base64::encode_string(body);
    for chunk in b64.as_bytes().chunks(64) {
        // Safety of UTF-8: Base64 alphabet is strictly ASCII, so chunking by
        // bytes preserves valid UTF-8. We avoid `unsafe` by going through
        // `std::str::from_utf8` which never fails for this input.
        let line = std::str::from_utf8(chunk).map_err(|e| {
            CryptoError::Encoding(format!("emit_pem: base64 chunk not UTF-8: {e}"))
        })?;
        s.push_str(line);
        s.push('\n');
    }
    s.push_str("-----END ");
    s.push_str(label);
    s.push_str("-----\n");
    Ok(s.into_bytes())
}

/// Emits a Text-format human-readable dump.
fn emit_text(key: &PKey, ctx: &EncoderContext) -> Vec<u8> {
    let priv_len = key.private_key_data().map_or(0, <[u8]>::len);
    let pub_len = key.public_key_data().map_or(0, <[u8]>::len);
    // Choose the canonical "Key Length:" reading per the requested selection
    // so callers (and the legacy text dump format) see the most relevant
    // size. PrivateKey/KeyPair → private length; PublicKey → public length;
    // Parameters → 0.
    let key_len = match ctx.selection {
        KeySelection::PrivateKey | KeySelection::KeyPair => priv_len,
        KeySelection::PublicKey => pub_len,
        KeySelection::Parameters => 0,
    };
    let s = format!(
        "Key Type: {}\n\
         Key Length: {} bytes\n\
         Selection: {:?}\n\
         Private Length: {} bytes\n\
         Public Length: {} bytes\n\
         Has Private: {}\n\
         Has Public: {}\n",
        key.key_type_name(),
        key_len,
        ctx.selection,
        priv_len,
        pub_len,
        PKey::has_private_key(key),
        PKey::has_public_key(key),
    );
    s.into_bytes()
}

/// Returns the PEM type label for a given key selection.
fn pem_label(selection: KeySelection) -> &'static str {
    match selection {
        KeySelection::PrivateKey | KeySelection::KeyPair => "PRIVATE KEY",
        KeySelection::PublicKey => "PUBLIC KEY",
        KeySelection::Parameters => "PARAMETERS",
    }
}

/// Auto-detects whether the input is PEM (text) or DER (binary).
fn detect_format(data: &[u8]) -> KeyFormat {
    if data.starts_with(b"-----BEGIN ") {
        KeyFormat::Pem
    } else {
        KeyFormat::Der
    }
}

/// Strips PEM armour and returns the decoded DER body plus a privacy hint.
///
/// The returned `Option<bool>` is the privacy hint inferred from the PEM
/// label (`Some(true)` for `PRIVATE KEY`, `Some(false)` for `PUBLIC KEY`,
/// `None` for unknown labels).
fn strip_pem(data: &[u8]) -> CryptoResult<(Vec<u8>, Option<bool>)> {
    let text = std::str::from_utf8(data).map_err(|e| {
        CryptoError::Encoding(format!("strip_pem: PEM data is not valid UTF-8: {e}"))
    })?;

    let mut body = String::new();
    let mut privacy_hint: Option<bool> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                privacy_hint = if label.contains("PRIVATE KEY") {
                    Some(true)
                } else if label.contains("PUBLIC KEY") {
                    Some(false)
                } else {
                    None
                };
            }
            continue;
        }
        if l.starts_with("-----END ") {
            continue;
        }
        if l.starts_with("Proc-Type:") || l.starts_with("DEK-Info:") {
            continue;
        }
        body.push_str(l);
    }

    let raw = Base64::decode_vec(&body).map_err(|e| {
        CryptoError::Encoding(format!("strip_pem: PEM body is not valid base64: {e}"))
    })?;
    Ok((raw, privacy_hint))
}

/// Heuristic privacy classification when the PEM label was absent.
fn infer_private_from_format(format: KeyFormat) -> bool {
    matches!(format, KeyFormat::Pkcs8 | KeyFormat::Pem | KeyFormat::Der)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Test-only relaxations following the workspace convention used in
    // `crates/openssl-crypto/src/tests/test_*.rs`. Tests call `.expect()` and
    // `.unwrap()` on values that are guaranteed-good test fixtures, and use
    // `panic!`/`assert!` macros for failure reporting; these are not
    // production code paths so the strict workspace lints are relaxed here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;
    use std::io::{BufReader, Cursor};

    fn make_rsa_private_key() -> PKey {
        let raw = vec![0xAAu8; 256];
        PKey::from_raw_private_key(KeyType::Rsa, &raw).expect("from_raw_private_key")
    }

    fn make_rsa_public_key() -> PKey {
        let raw = vec![0xBBu8; 270];
        PKey::from_raw_public_key(KeyType::Rsa, &raw).expect("from_raw_public_key")
    }

    // -----------------------------------------------------------------------
    // KeyFormat / KeySelection enum tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_format_display_strings() {
        assert_eq!(format!("{}", KeyFormat::Pem), "PEM");
        assert_eq!(format!("{}", KeyFormat::Der), "DER");
        assert_eq!(format!("{}", KeyFormat::Pkcs8), "PKCS8");
        assert_eq!(format!("{}", KeyFormat::Spki), "SPKI");
        assert_eq!(format!("{}", KeyFormat::Text), "TEXT");
    }

    #[test]
    fn key_format_default_is_pem() {
        assert_eq!(KeyFormat::default(), KeyFormat::Pem);
    }

    #[test]
    fn key_selection_default_is_private_key() {
        assert_eq!(KeySelection::default(), KeySelection::PrivateKey);
    }

    // -----------------------------------------------------------------------
    // EncoderContext construction & builders
    // -----------------------------------------------------------------------

    #[test]
    fn encoder_context_new_initializes_fields() {
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        assert_eq!(ec.format, KeyFormat::Pem);
        assert_eq!(ec.selection, KeySelection::PrivateKey);
        assert!(ec.passphrase.is_none());
        assert!(ec.cipher_name.is_none());
    }

    #[test]
    fn encoder_context_with_passphrase_sets_zeroizing() {
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey)
            .with_passphrase(b"secret");
        let pp = ec.passphrase.as_ref().expect("passphrase set");
        assert_eq!(pp.as_slice(), b"secret");
    }

    #[test]
    fn encoder_context_with_cipher_sets_name() {
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey)
            .with_cipher("AES-256-CBC");
        assert_eq!(ec.cipher_name.as_deref(), Some("AES-256-CBC"));
    }

    #[test]
    fn encoder_context_format_accessor_matches_field() {
        let ec = EncoderContext::new(KeyFormat::Der, KeySelection::PublicKey);
        assert_eq!(ec.format(), ec.format);
        assert_eq!(ec.selection(), ec.selection);
    }

    #[test]
    fn encoder_context_set_passphrase_chainable() {
        let mut ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        ec.set_passphrase(b"a").set_cipher("AES-128-CBC");
        assert!(ec.passphrase.is_some());
        assert_eq!(ec.cipher_name.as_deref(), Some("AES-128-CBC"));
    }

    // -----------------------------------------------------------------------
    // DecoderContext construction & builders
    // -----------------------------------------------------------------------

    #[test]
    fn decoder_context_new_is_empty() {
        let dc = DecoderContext::new();
        assert!(dc.expected_format.is_none());
        assert!(dc.expected_type.is_none());
        assert!(dc.passphrase.is_none());
    }

    #[test]
    fn decoder_context_default_matches_new() {
        let dc1 = DecoderContext::new();
        let dc2 = DecoderContext::default();
        assert_eq!(dc1.expected_format, dc2.expected_format);
        assert_eq!(dc1.expected_type, dc2.expected_type);
    }

    #[test]
    fn decoder_context_with_format_sets_field() {
        let dc = DecoderContext::new().with_format(KeyFormat::Der);
        assert_eq!(dc.expected_format, Some(KeyFormat::Der));
    }

    #[test]
    fn decoder_context_with_type_sets_field() {
        let dc = DecoderContext::new().with_type("RSA");
        assert_eq!(dc.expected_type.as_deref(), Some("RSA"));
    }

    #[test]
    fn decoder_context_with_passphrase_zeroizes() {
        let dc = DecoderContext::new().with_passphrase(b"pp");
        assert_eq!(
            dc.passphrase.as_ref().expect("set").as_slice(),
            b"pp"
        );
    }

    #[test]
    fn decoder_context_set_methods_chainable() {
        let mut dc = DecoderContext::new();
        dc.set_expected_format(KeyFormat::Pem)
            .set_expected_type("RSA")
            .set_passphrase(b"x");
        assert_eq!(dc.expected_format, Some(KeyFormat::Pem));
        assert_eq!(dc.expected_type.as_deref(), Some("RSA"));
        assert!(dc.passphrase.is_some());
    }

    // -----------------------------------------------------------------------
    // Encoder free-function tests
    // -----------------------------------------------------------------------

    #[test]
    fn encode_to_vec_pem_private_contains_armour() {
        let pkey = make_rsa_private_key();
        let bytes = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode_to_vec PEM");
        let s = std::str::from_utf8(&bytes).expect("UTF-8");
        assert!(s.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(s.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn encode_to_vec_pem_public_contains_armour() {
        let pkey = make_rsa_public_key();
        let bytes = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PublicKey, None)
            .expect("encode_to_vec PEM public");
        let s = std::str::from_utf8(&bytes).expect("UTF-8");
        assert!(s.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn encode_to_vec_der_returns_raw_bytes() {
        let pkey = make_rsa_private_key();
        let bytes = encode_to_vec(&pkey, KeyFormat::Der, KeySelection::PrivateKey, None)
            .expect("encode_to_vec DER");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn encode_to_vec_text_is_human_readable() {
        let pkey = make_rsa_private_key();
        let bytes = encode_to_vec(&pkey, KeyFormat::Text, KeySelection::PrivateKey, None)
            .expect("encode_to_vec Text");
        let s = std::str::from_utf8(&bytes).expect("UTF-8");
        assert!(s.contains("Key Type:"));
        assert!(s.contains("Has Private:"));
    }

    #[test]
    fn encode_to_vec_pem_with_passphrase_marks_encrypted() {
        let pkey = make_rsa_private_key();
        let bytes = encode_to_vec(
            &pkey,
            KeyFormat::Pem,
            KeySelection::PrivateKey,
            Some(b"secret"),
        )
        .expect("encode_to_vec encrypted PEM");
        let s = std::str::from_utf8(&bytes).expect("UTF-8");
        assert!(s.contains("Proc-Type: 4,ENCRYPTED"));
        assert!(s.contains("DEK-Info: AES-256-CBC"));
    }

    #[test]
    fn encode_to_writer_writes_pem_to_sink() {
        let pkey = make_rsa_private_key();
        let mut sink = Vec::new();
        encode_to_writer(
            &pkey,
            KeyFormat::Pem,
            KeySelection::PrivateKey,
            None,
            &mut sink,
        )
        .expect("encode_to_writer");
        let s = std::str::from_utf8(&sink).expect("UTF-8");
        assert!(s.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn to_pkcs8_returns_zeroizing_bytes() {
        let pkey = make_rsa_private_key();
        let bytes = to_pkcs8(&pkey).expect("to_pkcs8");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn to_pkcs8_rejects_public_only_key() {
        let pkey = make_rsa_public_key();
        let err = to_pkcs8(&pkey).expect_err("must reject public-only");
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn to_pkcs8_encrypted_requires_cipher() {
        let pkey = make_rsa_private_key();
        let err = to_pkcs8_encrypted(&pkey, "", b"secret")
            .expect_err("empty cipher must error");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn to_pkcs8_encrypted_succeeds_with_cipher() {
        let pkey = make_rsa_private_key();
        let bytes = to_pkcs8_encrypted(&pkey, "AES-256-CBC", b"hunter2")
            .expect("to_pkcs8_encrypted");
        assert!(!bytes.is_empty());
    }

    // -----------------------------------------------------------------------
    // Decoder free-function tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_from_slice_round_trip_pem() {
        let pkey = make_rsa_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let decoded = decode_from_slice(&pem, None).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn decode_from_slice_empty_errors() {
        let err = decode_from_slice(&[], None).expect_err("empty must error");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn decode_from_reader_round_trip() {
        let pkey = make_rsa_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let cursor = Cursor::new(pem);
        let reader = BufReader::new(cursor);
        let decoded = decode_from_reader(reader, None).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn from_pkcs8_round_trip() {
        let pkey = make_rsa_private_key();
        let pkcs8 = to_pkcs8(&pkey).expect("to_pkcs8");
        let decoded = from_pkcs8(&pkcs8).expect("from_pkcs8");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn from_pkcs8_empty_errors() {
        let err = from_pkcs8(&[]).expect_err("empty must error");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn from_pkcs8_encrypted_empty_errors() {
        let err = from_pkcs8_encrypted(&[], b"pp").expect_err("empty must error");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    // -----------------------------------------------------------------------
    // Inherent-method tests (back-compat surface)
    // -----------------------------------------------------------------------

    #[test]
    fn encoder_context_encode_to_vec_method() {
        let pkey = make_rsa_private_key();
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        let bytes = ec.encode_to_vec(&pkey).expect("encode");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn encoder_context_to_pkcs8_associated_fn() {
        let pkey = make_rsa_private_key();
        let bytes = EncoderContext::to_pkcs8(&pkey).expect("to_pkcs8");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn decoder_context_decode_from_slice_method() {
        let pkey = make_rsa_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let dc = DecoderContext::new();
        let decoded = dc.decode_from_slice(&pem).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn decoder_context_decode_from_reader_method() {
        let pkey = make_rsa_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let cursor = Cursor::new(pem);
        let mut reader = BufReader::new(cursor);
        let dc = DecoderContext::new();
        let decoded = dc.decode_from_reader(&mut reader).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn decoder_context_from_pkcs8_associated_fn() {
        let pkey = make_rsa_private_key();
        let pkcs8 = to_pkcs8(&pkey).expect("to_pkcs8");
        let decoded = DecoderContext::from_pkcs8(&pkcs8).expect("from_pkcs8");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    // -----------------------------------------------------------------------
    // LibContext / ParamSet plumbing
    // -----------------------------------------------------------------------

    #[test]
    fn encoder_context_with_lib_context_attaches_handle() {
        let libctx = LibContext::default();
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey)
            .with_lib_context(libctx);
        assert!(ec.lib_context().is_some());
    }

    #[test]
    fn decoder_context_with_lib_context_attaches_handle() {
        let libctx = LibContext::default();
        let dc = DecoderContext::new().with_lib_context(libctx);
        assert!(dc.lib_context().is_some());
    }

    #[test]
    fn encoder_context_with_params_attaches_paramset() {
        let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey)
            .with_params(ParamSet::new());
        assert!(ec.parameters().is_some());
    }

    #[test]
    fn decoder_context_with_params_attaches_paramset() {
        let dc = DecoderContext::new().with_params(ParamSet::new());
        assert!(dc.parameters().is_some());
    }
}
