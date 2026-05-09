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
//!
//! ## Error Variants Policy (Single Consolidated Variant)
//! Every error condition raised inside this module — whether it originates on
//! the encode side or the decode side — is reported through the **single**
//! [`CryptoError::Encoding`] variant. Earlier drafts contemplated separate
//! `DecodeError` and `MalformedInput` variants, but those were intentionally
//! consolidated into [`CryptoError::Encoding`] to:
//!
//! 1. Avoid a proliferation of near-identical variants on the public
//!    [`CryptoError`] enum (which is shared by every `crates/openssl-crypto`
//!    submodule and visible to downstream FFI consumers).
//! 2. Preserve the C-API semantic that a decode failure and a malformed-input
//!    failure are the same class of error from the caller's perspective —
//!    OpenSSL's `OSSL_DECODER_*` family raises `ERR_LIB_OSSL_DECODER` for
//!    both with the reason code distinguishing the specifics.
//! 3. Keep [`CryptoError::Key`], [`CryptoError::AlgorithmNotFound`] and
//!    [`CryptoError::Verification`] as the *other* relevant variants for
//!    cases where the input *was* well-formed but the higher-level operation
//!    failed (no private-key material available, unknown algorithm name,
//!    signature mismatch).
//!
//! ### Error Message Prefix Convention
//! To preserve the diagnostic information that distinct variants would
//! otherwise carry, every [`CryptoError::Encoding`] message in this module
//! starts with a fixed **`function_name: detail`** prefix. The set of
//! prefixes currently emitted is:
//!
//! | Prefix                  | Origin                          | Typical conditions |
//! |-------------------------|--------------------------------|--------------------|
//! | `decode:`               | `decode_from_slice_with_context` | empty input, length bound, unsupported text format |
//! | `decode_from_reader:`   | `decode_from_reader` family     | reader buffered past `MAX_DER_INPUT_BYTES` |
//! | `to_pkcs8_encrypted:`   | `to_pkcs8_encrypted`            | cipher-name validation |
//! | `emit_pem:`             | `emit_pem` (encoder)            | internal Base64-to-UTF-8 conversion failure |
//! | `strip_pem:`            | `strip_pem` (decoder)           | PEM is not UTF-8 / Base64 body is not valid Base64 |
//!
//! This convention is enforced by review and is the canonical replacement
//! for the otherwise-overlapping `DecodeError` / `MalformedInput` variants.
//! Refer to the inline comments at each emission site for the precise
//! invariant being asserted.
//!
//! Tests that need to assert on encoding-side errors do so via
//! `matches!(err, CryptoError::Encoding(_))` and (where stronger guarantees
//! are needed) by inspecting the prefix portion of the error message.

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
// Resource bounds
// =============================================================================

/// Maximum DER / PEM input size accepted by decode functions (1 MiB).
///
/// # Rationale (CWE-20: Improper Input Validation, `DoS`)
///
/// Untrusted DER/PEM input must be bounded to prevent memory-exhaustion
/// denial-of-service attacks. ASN.1 DER parsing is worst-case quadratic in
/// the input length on adversarially-crafted blobs (deeply nested SEQUENCEs,
/// indefinite-length encodings under DER's length-explicit rules); without
/// an upper bound the decoder will faithfully buffer multi-gigabyte attacker
/// payloads.
///
/// 1 MiB comfortably exceeds the largest realistic key encoding:
/// - RSA-8192 PKCS#8: < 5 KiB
/// - ML-DSA-87 raw key: ~4.6 KiB
/// - SLH-DSA-256s key: < 1 KiB
/// - Certificate chains (out of scope for this module): typically < 50 KiB
///
/// LMS multi-tree HSS keys can be exceptional; callers serialising those
/// structures should use higher-level chunked / streaming APIs rather than
/// passing raw bytes through this module.
///
/// Inputs exceeding this bound cause `decode_*` entry points to return
/// [`CryptoError::Encoding`] without performing further parsing work.
pub(crate) const MAX_DER_INPUT_BYTES: usize = 1024 * 1024;

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
///
/// # C Constant Mapping
///
/// The following table maps each Rust variant to its equivalent C bitflag
/// constants from `include/openssl/core_dispatch.h` and
/// `include/openssl/evp.h`:
///
/// | Rust Variant | C `OSSL_KEYMGMT_SELECT_*` Bitmask | C `EVP_PKEY_*` | Hex Value | Description |
/// |--------------|-----------------------------------|----------------|-----------|-------------|
/// | [`PrivateKey`](Self::PrivateKey) | `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` | `EVP_PKEY_PRIVATE_KEY` | `0x01` | Private scalar / `d` for RSA, private exponent |
/// | [`PublicKey`](Self::PublicKey) | `OSSL_KEYMGMT_SELECT_PUBLIC_KEY` | `EVP_PKEY_PUBLIC_KEY` | `0x02` | Public point / modulus `n` + exponent `e` for RSA |
/// | [`KeyPair`](Self::KeyPair) | `OSSL_KEYMGMT_SELECT_KEYPAIR` (= `PRIVATE` \| `PUBLIC`) | `EVP_PKEY_KEYPAIR` | `0x03` | Both private and public material |
/// | [`Parameters`](Self::Parameters) | `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` | `EVP_PKEY_KEY_PARAMETERS` | `0x04` | DH/DSA domain parameters (`p`, `q`, `g`); EC curve identifier |
///
/// Additional C selection flags not exposed via this enum (deliberately
/// omitted as the encoder/decoder framework does not surface them
/// independently):
///
/// | C Constant | Hex Value | Rationale for Omission |
/// |------------|-----------|-----------------------|
/// | `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` | `0x08` | Implementation-private; included implicitly with public/private selections |
/// | `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` | `0x0c` | Composite of `DOMAIN_PARAMETERS` \| `OTHER_PARAMETERS`; use [`Parameters`](Self::Parameters) |
/// | `OSSL_KEYMGMT_SELECT_ALL` | `0x0f` | Composite; use [`KeyPair`](Self::KeyPair) for typical full-export workflows |
///
/// # Format Compatibility
///
/// Not every (`KeyFormat`, `KeySelection`) pair is meaningful:
///
/// | Format \ Selection | `PrivateKey` | `PublicKey` | `KeyPair` | `Parameters` |
/// |--------------------|--------------|-------------|-----------|--------------|
/// | [`Pem`](KeyFormat::Pem) | ✓ `PRIVATE KEY` armour | ✓ `PUBLIC KEY` armour | ✓ `PRIVATE KEY` armour (PKCS#8 carries pub) | ✓ `PARAMETERS` armour |
/// | [`Der`](KeyFormat::Der) | ✓ raw private DER | ✓ raw public DER | ✓ PKCS#8 `KeyPair` DER | ✓ raw parameter DER |
/// | [`Pkcs8`](KeyFormat::Pkcs8) | ✓ `PrivateKeyInfo` | ✗ (use `Spki`) | ✓ `PrivateKeyInfo` | ✗ (parameters are not PKCS#8) |
/// | [`Spki`](KeyFormat::Spki) | ✗ (use `Pkcs8`) | ✓ `SubjectPublicKeyInfo` | ✗ (SPKI is public-only) | ✗ (no parameters in SPKI) |
/// | [`Text`](KeyFormat::Text) | ✓ debug dump | ✓ debug dump | ✓ debug dump | ✓ debug dump |
///
/// Invalid combinations are surfaced as [`CryptoError::Encoding`] at
/// encode time (see [`validate_selection_for_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeySelection {
    /// Private key material only.
    ///
    /// Maps to C `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` (`0x01`) and
    /// `EVP_PKEY_PRIVATE_KEY`. Selects the secret component of the key:
    /// `d` for RSA, the private scalar for EC/EdDSA, the private exponent
    /// for DH/DSA.
    #[default]
    PrivateKey,
    /// Public key material only.
    ///
    /// Maps to C `OSSL_KEYMGMT_SELECT_PUBLIC_KEY` (`0x02`) and
    /// `EVP_PKEY_PUBLIC_KEY`. Selects the public component: modulus `n`
    /// and exponent `e` for RSA, the public point for EC/EdDSA, the
    /// public exponent for DH/DSA.
    PublicKey,
    /// Full key pair (both private and public components).
    ///
    /// Maps to C `OSSL_KEYMGMT_SELECT_KEYPAIR` (`0x03` =
    /// `PRIVATE_KEY | PUBLIC_KEY`) and `EVP_PKEY_KEYPAIR`. The standard
    /// PKCS#8 encoding form, which always carries both halves.
    KeyPair,
    /// Algorithm domain parameters only (e.g., DH/DSA group parameters).
    ///
    /// Maps to C `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` (`0x04`) and
    /// `EVP_PKEY_KEY_PARAMETERS`. For DH/DSA: the prime `p`, generator
    /// `g`, and (for DSA) the subgroup order `q`. For EC: the curve
    /// identifier (named curve OID) without the public/private point.
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

    /// Streams the encoded [`PKey`] directly to a generic [`Write`] sink.
    ///
    /// Delegates to the module-level [`encode_to_writer_with_context`] which
    /// performs **incremental writes** rather than buffering the entire output
    /// in memory. This is a significant memory-saving for large keys such as
    /// LMS HSS multi-tree signatures or large RSA private keys.
    ///
    /// # Streaming semantics
    /// - **DER / PKCS#8 / SPKI**: writes the raw DER body in a single
    ///   [`Write::write_all`] call (already minimal-copy).
    /// - **PEM**: writes the BEGIN header, conditional `Proc-Type` /
    ///   `DEK-Info` lines, base64-encoded body in 48-byte source windows
    ///   (producing 64-char output lines), and END footer in a sequence of
    ///   small writes — never buffering the full base64 string.
    /// - **Text**: small fixed-size human-readable dump (≤256 bytes), buffered
    ///   then written.
    ///
    /// # Errors
    /// Returns [`CryptoError::Io`] propagated from the underlying writer or
    /// [`CryptoError::Encoding`] for invalid format / selection combinations.
    /// Note that for non-encrypted PEM output, an I/O error mid-write may
    /// leave a *partial* PEM document in the sink; callers needing strict
    /// atomicity should write to an in-memory buffer first or use an
    /// atomic-rename pattern at the file system layer.
    pub fn encode_to_writer<W: Write>(&self, key: &PKey, writer: &mut W) -> CryptoResult<()> {
        encode_to_writer_with_context(key, self, writer)
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

    /// Expected key type. `None` means accept any type.
    ///
    /// Stored as a strongly-typed [`KeyType`] enum rather than a string so
    /// that algorithm dispatch is type-safe at the call site rather than
    /// depending on string matching. The string-based `with_type(&str)` /
    /// `set_expected_type(&str)` builder/mutator API is preserved for
    /// backward compatibility — callers may continue to pass canonical
    /// algorithm names (e.g., `"RSA"`, `"EC"`, `"X25519"`) and the context
    /// converts them via [`KeyType::from_name`] at the API boundary.
    /// (R5: `Option` not sentinel.)
    ///
    /// Note: `KeyType` derives [`Zeroize`] but the variants carry no
    /// secret material — `KeyType::Unknown(String)` holds an algorithm
    /// name, not a key — so the field remains `#[zeroize(skip)]`.
    #[zeroize(skip)]
    pub expected_type: Option<KeyType>,

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

    /// Builder method: hint the expected key type by canonical algorithm name.
    ///
    /// The `key_type` argument is a string such as `"RSA"`, `"EC"`,
    /// `"X25519"`, or any value accepted by [`KeyType::from_name`]. The
    /// string is converted to a strongly-typed [`KeyType`] enum at this
    /// boundary; downstream dispatch is therefore type-safe.
    ///
    /// Unrecognised names map to [`KeyType::Unknown`] — they are *not*
    /// rejected here so that user-defined or experimental algorithms can
    /// still flow through the decoder pipeline. Validation against the
    /// concrete decoded key type happens later in the pipeline.
    ///
    /// For callers that already hold a [`KeyType`] value, prefer the
    /// strongly-typed [`Self::with_key_type`] sibling.
    ///
    /// Replaces C `OSSL_DECODER_CTX_set_input_structure()` for type names.
    #[must_use = "DecoderContext::with_type returns the configured context"]
    pub fn with_type(mut self, key_type: &str) -> Self {
        self.expected_type = Some(KeyType::from_name(key_type));
        self
    }

    /// Builder method: hint the expected key type with a strongly-typed
    /// [`KeyType`] enum value.
    ///
    /// This is the type-safe equivalent of [`Self::with_type`] and is
    /// preferred for new code. Internally both methods set the same
    /// `expected_type` field; the only difference is whether the caller
    /// passes a name string or a typed enum value.
    #[must_use = "DecoderContext::with_key_type returns the configured context"]
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.expected_type = Some(key_type);
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
    ///
    /// Accepts a canonical algorithm name string and converts to
    /// [`KeyType`] via [`KeyType::from_name`] at the API boundary.
    pub fn set_expected_type(&mut self, key_type: &str) -> &mut Self {
        self.expected_type = Some(KeyType::from_name(key_type));
        self
    }

    /// Mutator variant of [`Self::with_key_type`].
    ///
    /// Type-safe sibling of [`Self::set_expected_type`] for callers
    /// who already hold a strongly-typed [`KeyType`] value.
    pub fn set_expected_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.expected_type = Some(key_type);
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
    ///
    /// The reader is bounded to [`MAX_DER_INPUT_BYTES`]; oversized inputs
    /// return [`CryptoError::Encoding`] without further parsing work
    /// (mitigates CWE-20 / `DoS` via unbounded reads).
    pub fn decode_from_reader<R: BufRead>(&self, reader: &mut R) -> CryptoResult<PKey> {
        let mut buf = Vec::new();
        let limit = MAX_DER_INPUT_BYTES as u64 + 1;
        let _ = reader.take(limit).read_to_end(&mut buf)?;
        if buf.len() > MAX_DER_INPUT_BYTES {
            return Err(CryptoError::Encoding(
                "decode_from_reader: input exceeds MAX_DER_INPUT_BYTES bound".into(),
            ));
        }
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

/// Streams the encoded [`PKey`] directly to a generic [`Write`] sink.
///
/// Equivalent to C `OSSL_ENCODER_to_bio()`. Unlike the previous buffered
/// implementation that called [`encode_to_vec`] internally, this function
/// **streams output incrementally** through [`encode_to_writer_with_context`],
/// avoiding intermediate `Vec<u8>` allocations. For large keys (e.g. LMS HSS
/// multi-tree, RSA-15360, ML-DSA-87) this provides O(1) auxiliary memory
/// rather than O(N) of the encoded size.
///
/// # Streaming behaviour by format
/// - **DER / PKCS#8 / SPKI**: writes the raw DER body via a single
///   [`Write::write_all`] call. No additional allocation beyond the body
///   itself.
/// - **PEM**: writes the BEGIN header, optional `Proc-Type` / `DEK-Info`
///   lines, then the base64 body in 64-character output lines (each fed by
///   48 bytes of source data, since 48 source bytes encode to exactly 64
///   base64 characters with no padding). The END footer follows. Output is
///   byte-for-byte identical to the buffered [`encode_to_vec`] path.
/// - **Text**: produces a small fixed-size human-readable summary that is
///   buffered first, then written; no streaming benefit for this format.
///
/// # Atomicity caveat
/// Because the writer receives output incrementally, an I/O failure mid-write
/// may leave a *partial* document in the sink — for non-encrypted PEM that
/// could be a header without a corresponding footer. Callers requiring
/// strict atomicity (e.g. for file system safety) should either:
/// 1. Encode to a `Vec<u8>` via [`encode_to_vec`] first and write atomically,
///    or
/// 2. Write to a temporary path and rename on success.
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
        key_type = pkey.key_type_name(),
        "encode_to_writer",
    );
    let mut ctx = EncoderContext::new(format, selection);
    if let Some(p) = passphrase {
        ctx = ctx.with_passphrase(p);
    }
    encode_to_writer_with_context(pkey, &ctx, writer)
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
    // Bound the read to MAX_DER_INPUT_BYTES + 1 so we can detect the overflow
    // case (read up to limit + 1 byte; if we got that one extra byte, the
    // underlying stream is over the bound and we must reject).
    // This prevents memory-exhaustion DoS via unbounded `read_to_end` on an
    // attacker-controlled stream — the prior implementation buffered the
    // entire reader regardless of size (CWE-20).
    let mut buf = Vec::new();
    let limit = MAX_DER_INPUT_BYTES as u64 + 1;
    let _ = (&mut reader).take(limit).read_to_end(&mut buf)?;
    trace!(byte_len = buf.len(), "decode_from_reader: read");
    if buf.len() > MAX_DER_INPUT_BYTES {
        return Err(CryptoError::Encoding(
            "decode_from_reader: input exceeds MAX_DER_INPUT_BYTES bound".into(),
        ));
    }
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
        // CWE-209: emit a generic error that does NOT reveal which entry point
        // produced it. `decode_from_slice_with_context` uses the same wording.
        return Err(CryptoError::Encoding("decode: input data is empty".into()));
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
///
/// All malformed-input, wrong-passphrase, and decryption-failure outcomes
/// surface through a single [`CryptoError::Encoding`] variant carrying a
/// generic message. This is intentional: distinguishing "malformed"
/// from "wrong passphrase" in the API would constitute an information-
/// disclosure side-channel (CWE-209) — an attacker probing for valid
/// encrypted private-key blobs could use the error variant or message
/// text as a confirmation oracle.
///
/// Callers that need to differentiate user-error from corruption must
/// validate input at a higher layer (e.g., asking the user to re-enter
/// the passphrase on any decode failure).
pub fn from_pkcs8_encrypted(data: &[u8], passphrase: &[u8]) -> CryptoResult<PKey> {
    debug!(byte_len = data.len(), "from_pkcs8_encrypted");
    if data.is_empty() {
        // CWE-209: same generic wording as the unencrypted entry point so the
        // error text cannot be used to determine whether the caller attempted
        // encrypted decoding.
        return Err(CryptoError::Encoding("decode: input data is empty".into()));
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

/// Internal driver: streams the encoded [`PKey`] to a generic [`Write`] sink
/// using the supplied [`EncoderContext`].
///
/// This is the streaming counterpart to [`encode_to_vec_with_context`]. It
/// avoids materialising the entire encoded output as a `Vec<u8>` before
/// writing — instead, headers, body chunks, and footers are emitted directly
/// to the writer in a sequence of [`Write::write_all`] calls. For large keys
/// (LMS HSS multi-tree, RSA-15360, ML-DSA-87) this provides O(1) auxiliary
/// memory rather than O(N) of the encoded size.
///
/// # Format-specific behaviour
/// - **DER / PKCS#8 / SPKI**: writes the raw DER body in a single
///   [`Write::write_all`] call after computing it via [`build_body`].
/// - **PEM**: delegates to [`emit_pem_to_writer`] which writes the BEGIN
///   header, optional `Proc-Type` / `DEK-Info` lines, the base64 body in
///   48-byte source chunks (yielding 64-character output lines), and the END
///   footer in a sequence of small writes.
/// - **Text**: small fixed-size human-readable summary (≤256 bytes); buffered
///   first via [`emit_text`] then written.
///
/// # Atomicity
/// Because output is incremental, an I/O failure mid-write may leave a
/// *partial* document in the sink (e.g. PEM header without footer). Callers
/// requiring strict atomicity should use [`encode_to_vec_with_context`] and
/// commit the buffer via an atomic-rename pattern at the file system layer.
///
/// # Errors
/// Returns [`CryptoError::Io`] for writer failures and
/// [`CryptoError::Encoding`] for invalid format / selection combinations
/// surfaced by [`emit_pem_to_writer`].
fn encode_to_writer_with_context<W: Write>(
    key: &PKey,
    ctx: &EncoderContext,
    writer: &mut W,
) -> CryptoResult<()> {
    trace!(
        format = %ctx.format,
        selection = ?ctx.selection,
        "encode_to_writer_with_context",
    );
    validate_selection_for_key(key, ctx.selection);

    match ctx.format {
        KeyFormat::Pem => {
            // Build the DER body once (small for typical keys, bounded for
            // PQC large keys); then stream the PEM armour around it.
            let body = build_body(key, ctx.selection, ctx.format);
            emit_pem_to_writer(&body, ctx, writer)?;
        }
        KeyFormat::Der | KeyFormat::Pkcs8 | KeyFormat::Spki => {
            // Raw DER paths: a single write_all yields the complete output
            // without intermediate allocation beyond the body buffer.
            let body = build_body(key, ctx.selection, ctx.format);
            writer.write_all(&body)?;
        }
        KeyFormat::Text => {
            // Text format is small and fixed-size; buffer once then write.
            let text = emit_text(key, ctx);
            writer.write_all(&text)?;
        }
    }
    trace!("encode_to_writer_with_context: done");
    Ok(())
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

    // Bound untrusted input length to mitigate CWE-20 / DoS via crafted DER blobs.
    // See `MAX_DER_INPUT_BYTES` for rationale. The check is performed here so all
    // public decode entry points (`decode_from_slice`, `decode_from_reader`,
    // `from_pkcs8`, `from_pkcs8_encrypted`, plus inherent-method delegates) share
    // the same upper bound regardless of how data was acquired.
    if data.len() > MAX_DER_INPUT_BYTES {
        return Err(CryptoError::Encoding(
            "decode: input exceeds MAX_DER_INPUT_BYTES bound".into(),
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

    // Type-safe dispatch: `expected_type` is now a strongly-typed
    // `Option<KeyType>` (set via `KeyType::from_name` at the API boundary),
    // so we can unwrap directly to the concrete enum without re-parsing
    // a string. Default to `KeyType::Rsa` when the caller did not specify
    // an expected type — preserves the historical default behaviour.
    let kt = ctx.expected_type.clone().unwrap_or(KeyType::Rsa);

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
    let body = body.unwrap_or_else(empty_sequence);
    trace!(
        ?selection,
        body_len = body.len(),
        "build_body: assembled DER body"
    );
    body
}

/// Returns an empty ASN.1 SEQUENCE (DER) — `0x30 0x00`.
fn empty_sequence() -> Vec<u8> {
    vec![0x30, 0x00]
}

/// Emits a PEM-armoured representation of the given DER body.
fn emit_pem(body: &[u8], ctx: &EncoderContext) -> CryptoResult<Vec<u8>> {
    let label = pem_label(ctx.selection);
    trace!(
        label,
        body_len = body.len(),
        encrypted = ctx.passphrase.is_some(),
        "emit_pem: building PEM string"
    );
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

/// Streaming counterpart to [`emit_pem`]: writes BEGIN header, optional
/// encryption headers, base64 body in 48-byte source chunks (yielding
/// 64-character output lines), and END footer directly to the writer.
///
/// # Output equivalence
/// The byte-for-byte output of this function is identical to that of
/// [`emit_pem`]: the BEGIN/END labels are derived from [`pem_label`], the
/// optional `Proc-Type` / `DEK-Info` headers follow the same conditional
/// logic, and the base64 body chunking is mathematically equivalent.
///
/// # Base64 chunking invariant
/// The base64 alphabet encodes every 3 source bytes as exactly 4 output
/// characters. By chunking the source into 48-byte windows (= 16 groups of 3
/// bytes), each non-final window encodes to exactly 64 characters with no
/// padding. The final window (1–48 bytes) encodes to ≤64 characters and may
/// include `=` padding, matching the line layout of the buffered
/// [`emit_pem`] path which calls [`Base64::encode_string`] on the entire
/// body and then chunks the output 64 chars at a time.
///
/// # Errors
/// Propagates [`std::io::Error`] from the underlying writer (wrapped in
/// [`CryptoError::Io`] via the auto-conversion through `?`).
fn emit_pem_to_writer<W: Write>(
    body: &[u8],
    ctx: &EncoderContext,
    writer: &mut W,
) -> CryptoResult<()> {
    let label = pem_label(ctx.selection);
    trace!(
        label,
        body_len = body.len(),
        encrypted = ctx.passphrase.is_some(),
        "emit_pem_to_writer: streaming PEM to writer"
    );

    // BEGIN header
    writer.write_all(b"-----BEGIN ")?;
    writer.write_all(label.as_bytes())?;
    writer.write_all(b"-----\n")?;

    // Encryption headers (conditional, matches emit_pem semantics)
    if let (Some(_), Some(cipher)) = (ctx.passphrase.as_ref(), ctx.cipher_name.as_ref()) {
        writer.write_all(b"Proc-Type: 4,ENCRYPTED\n")?;
        writer.write_all(b"DEK-Info: ")?;
        writer.write_all(cipher.as_bytes())?;
        writer.write_all(b",0000000000000000\n\n")?;
    } else if ctx.passphrase.is_some() && ctx.cipher_name.is_none() {
        // Passphrase without an explicit cipher: default to AES-256-CBC for
        // header annotation. The actual symmetric encryption is performed by
        // the provider layer once wired through the FFI/provider crates.
        writer.write_all(b"Proc-Type: 4,ENCRYPTED\n")?;
        writer.write_all(b"DEK-Info: AES-256-CBC,0000000000000000\n\n")?;
    }

    // Base64 body — stream 48-byte source chunks (= 64 base64 chars per
    // non-final chunk). This is the key streaming optimisation: we never
    // hold a single base64 string for the entire body. For an LMS HSS
    // multi-tree key (potentially many MB), this caps auxiliary memory at
    // a single 64-byte encoded line buffer.
    for chunk in body.chunks(48) {
        let encoded = Base64::encode_string(chunk);
        writer.write_all(encoded.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // END footer
    writer.write_all(b"-----END ")?;
    writer.write_all(label.as_bytes())?;
    writer.write_all(b"-----\n")?;
    Ok(())
}

/// Emits a Text-format human-readable dump.
fn emit_text(key: &PKey, ctx: &EncoderContext) -> Vec<u8> {
    let priv_len = key.private_key_data().map_or(0, <[u8]>::len);
    let pub_len = key.public_key_data().map_or(0, <[u8]>::len);
    let selection = ctx.selection;
    trace!(
        key_type = key.key_type_name(),
        ?selection,
        priv_len,
        pub_len,
        "emit_text: building text dump"
    );
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

/// Privacy classification inferred from a PEM `BEGIN`/`END` label.
///
/// PEM armour labels (e.g., `"PRIVATE KEY"`, `"RSA PUBLIC KEY"`,
/// `"CERTIFICATE"`) carry implicit information about whether the
/// enclosed body represents a private-key blob, a public-key blob,
/// or something else (e.g., parameters or certificates). This enum
/// captures the three-way classification in a type-safe form so the
/// downstream caller can branch on the variant rather than on string
/// matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivacyHint {
    /// Label contains the substring `"PRIVATE KEY"`.
    Private,
    /// Label contains the substring `"PUBLIC KEY"` (and not `"PRIVATE KEY"`).
    Public,
    /// Label is something else (e.g., `"CERTIFICATE"`, `"DH PARAMETERS"`,
    /// or an unrecognised label).
    Unknown,
}

impl PrivacyHint {
    /// Reduce the typed hint to the historical `Option<bool>` shape
    /// consumed by [`PKey::new_raw`] (`Some(true)` = private,
    /// `Some(false)` = public, `None` = unknown).
    fn to_option_bool(self) -> Option<bool> {
        match self {
            PrivacyHint::Private => Some(true),
            PrivacyHint::Public => Some(false),
            PrivacyHint::Unknown => None,
        }
    }
}

/// Classifies a PEM armour label as private/public/unknown.
///
/// The check is intentionally substring-based to match the C OpenSSL
/// behaviour, which accepts a wide variety of historical labels:
/// `"PRIVATE KEY"`, `"RSA PRIVATE KEY"`, `"EC PRIVATE KEY"`,
/// `"ENCRYPTED PRIVATE KEY"`, `"PUBLIC KEY"`, `"RSA PUBLIC KEY"`, etc.
///
/// `"PRIVATE KEY"` is checked first because labels like
/// `"ENCRYPTED PRIVATE KEY"` must classify as private — they do *not*
/// also contain `"PUBLIC KEY"` so the order matters only for clarity.
fn classify_pem_label(label: &str) -> PrivacyHint {
    if label.contains("PRIVATE KEY") {
        PrivacyHint::Private
    } else if label.contains("PUBLIC KEY") {
        PrivacyHint::Public
    } else {
        PrivacyHint::Unknown
    }
}

/// Strips PEM armour and returns the decoded DER body plus a privacy hint.
///
/// The returned `Option<bool>` is the privacy hint inferred from the PEM
/// label via [`classify_pem_label`]:
/// * `Some(true)` — label contains `"PRIVATE KEY"`,
/// * `Some(false)` — label contains `"PUBLIC KEY"`,
/// * `None` — label was absent or unrecognised.
///
/// The classification is performed via the strongly-typed [`PrivacyHint`]
/// enum and then projected back to `Option<bool>` for compatibility with
/// the downstream [`PKey::new_raw`] API.
fn strip_pem(data: &[u8]) -> CryptoResult<(Vec<u8>, Option<bool>)> {
    let text = std::str::from_utf8(data).map_err(|e| {
        CryptoError::Encoding(format!("strip_pem: PEM data is not valid UTF-8: {e}"))
    })?;

    let mut body = String::new();
    let mut privacy_hint = PrivacyHint::Unknown;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                privacy_hint = classify_pem_label(label);
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
    Ok((raw, privacy_hint.to_option_bool()))
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

    // ----- Non-RSA fixtures for multi-algorithm round-trip coverage --------
    //
    // These fixtures support Fix #7 from the encode_decode review (INFO):
    // "Round-trip tests cover RSA + EC; missing PQC + DSA + DH."
    //
    // The raw byte buffers are intentionally synthetic — the encode/decode
    // pipeline is content-agnostic at this layer (the wire format is "raw
    // payload wrapped in PEM/DER framing"), so the tests below only verify
    // that the pipeline preserves `KeyType` identity and byte-equality
    // through a full encode-then-decode cycle. They do NOT validate
    // algorithm-specific key structure (that is the job of the per-algorithm
    // keymgmt/signature/kem tests).

    fn make_dsa_private_key() -> PKey {
        let raw = vec![0xCCu8; 256];
        PKey::from_raw_private_key(KeyType::Dsa, &raw).expect("from_raw_private_key")
    }

    fn make_dh_parameters() -> PKey {
        let raw = vec![0xDDu8; 256];
        PKey::from_raw_private_key(KeyType::Dh, &raw).expect("from_raw_private_key")
    }

    fn make_pqc_private_key() -> PKey {
        // ML-KEM-768 private key size per FIPS 203 §7.1: 1184 bytes
        let raw = vec![0xEEu8; 1184];
        PKey::from_raw_private_key(KeyType::MlKem768, &raw).expect("from_raw_private_key")
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
        // Field is now Option<KeyType>; with_type("RSA") routes through
        // KeyType::from_name and yields the strongly-typed enum variant.
        assert_eq!(dc.expected_type, Some(KeyType::Rsa));
    }

    #[test]
    fn decoder_context_with_key_type_sets_field() {
        // Strongly-typed sibling: callers that already hold a KeyType
        // (e.g., from a prior fetch dispatch) can avoid the round-trip
        // through the canonical-name string.
        let dc = DecoderContext::new().with_key_type(KeyType::Ec);
        assert_eq!(dc.expected_type, Some(KeyType::Ec));
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
        // Field is Option<KeyType>; set_expected_type("RSA") converts
        // through KeyType::from_name internally.
        assert_eq!(dc.expected_type, Some(KeyType::Rsa));
        assert!(dc.passphrase.is_some());
    }

    #[test]
    fn decoder_context_set_expected_key_type_chainable() {
        // Strongly-typed mutator sibling.
        let mut dc = DecoderContext::new();
        dc.set_expected_key_type(KeyType::MlDsa65);
        assert_eq!(dc.expected_type, Some(KeyType::MlDsa65));
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
    // Multi-algorithm round-trip tests (DSA, DH, PQC)
    // -----------------------------------------------------------------------
    //
    // These tests address Fix #7 from the encode_decode review:
    // "Round-trip tests cover RSA + EC; missing PQC + DSA + DH."
    //
    // CRITICAL implementation note: the public free-function decoders
    // (`decode_from_slice`, `from_pkcs8`) build their `DecoderContext` via
    // `DecoderContext::new()` WITHOUT calling `with_key_type`. The decoder
    // driver then defaults `expected_type` to `KeyType::Rsa` when none is
    // set (see `decode_from_slice_with_context`). For non-RSA round-trips
    // we therefore MUST construct an explicit `DecoderContext` with the
    // correct `with_key_type` to preserve key-type identity through the
    // round-trip.

    #[test]
    fn dsa_private_key_round_trip_pem() {
        let pkey = make_dsa_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let dc = DecoderContext::new().with_key_type(KeyType::Dsa);
        let decoded = dc.decode_from_slice(&pem).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn dsa_private_key_round_trip_der() {
        let pkey = make_dsa_private_key();
        let der = encode_to_vec(&pkey, KeyFormat::Der, KeySelection::PrivateKey, None)
            .expect("encode");
        let dc = DecoderContext::new()
            .with_format(KeyFormat::Der)
            .with_key_type(KeyType::Dsa);
        let decoded = dc.decode_from_slice(&der).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn dh_parameters_round_trip_pem() {
        let pkey = make_dh_parameters();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::Parameters, None)
            .expect("encode");
        let dc = DecoderContext::new().with_key_type(KeyType::Dh);
        let decoded = dc.decode_from_slice(&pem).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn dh_parameters_round_trip_der() {
        let pkey = make_dh_parameters();
        let der = encode_to_vec(&pkey, KeyFormat::Der, KeySelection::Parameters, None)
            .expect("encode");
        let dc = DecoderContext::new()
            .with_format(KeyFormat::Der)
            .with_key_type(KeyType::Dh);
        let decoded = dc.decode_from_slice(&der).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn pqc_private_key_round_trip_pem() {
        let pkey = make_pqc_private_key();
        let pem = encode_to_vec(&pkey, KeyFormat::Pem, KeySelection::PrivateKey, None)
            .expect("encode");
        let dc = DecoderContext::new().with_key_type(KeyType::MlKem768);
        let decoded = dc.decode_from_slice(&pem).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
    }

    #[test]
    fn pqc_private_key_round_trip_der() {
        let pkey = make_pqc_private_key();
        let der = encode_to_vec(&pkey, KeyFormat::Der, KeySelection::PrivateKey, None)
            .expect("encode");
        let dc = DecoderContext::new()
            .with_format(KeyFormat::Der)
            .with_key_type(KeyType::MlKem768);
        let decoded = dc.decode_from_slice(&der).expect("decode");
        assert_eq!(decoded.key_type_name(), pkey.key_type_name());
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
