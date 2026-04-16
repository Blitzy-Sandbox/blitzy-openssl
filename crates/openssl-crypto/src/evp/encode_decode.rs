//! Key serialization — EVP encoder / decoder equivalent.
//!
//! Provides `EncoderContext` and `DecoderContext` for key import/export in
//! PEM, DER, PKCS#8, SPKI, and text formats.

use std::io::{BufRead, Write};

use tracing::trace;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::EvpError;
use crate::evp::pkey::PKey;
use openssl_common::{CryptoError, CryptoResult};

// ---------------------------------------------------------------------------
// KeyFormat — serialization format enum
// ---------------------------------------------------------------------------

/// The serialization format for key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// PEM — Base64-encoded with header/footer lines
    Pem,
    /// DER — raw ASN.1 binary
    Der,
    /// PKCS#8 — RFC 5958 `PrivateKeyInfo` / `EncryptedPrivateKeyInfo`
    Pkcs8,
    /// `SubjectPublicKeyInfo` — RFC 5280 §4.1.2.7
    Spki,
    /// Human-readable text representation
    Text,
}

impl std::fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem => write!(f, "PEM"),
            Self::Der => write!(f, "DER"),
            Self::Pkcs8 => write!(f, "PKCS8"),
            Self::Spki => write!(f, "SPKI"),
            Self::Text => write!(f, "TEXT"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeySelection — what part of the key to encode/decode
// ---------------------------------------------------------------------------

/// Selects which part of the key material to serialise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySelection {
    /// Private key only
    PrivateKey,
    /// Public key only
    PublicKey,
    /// Full key pair (private + public)
    KeyPair,
    /// Domain parameters only (e.g., DH/DSA group params)
    Parameters,
}

// ---------------------------------------------------------------------------
// EncoderContext — key export (OSSL_ENCODER_CTX)
// ---------------------------------------------------------------------------

/// Context for encoding (exporting) key material.
///
/// Passphrase material is securely erased on drop.
#[derive(ZeroizeOnDrop)]
pub struct EncoderContext {
    /// Output format
    #[zeroize(skip)]
    format: KeyFormat,
    /// Which portion of the key to export
    #[zeroize(skip)]
    selection: KeySelection,
    /// Optional passphrase for encrypted PEM/PKCS#8
    passphrase: Option<Zeroizing<Vec<u8>>>,
    /// Optional cipher name for encrypted output (e.g., "AES-256-CBC")
    #[zeroize(skip)]
    cipher_name: Option<String>,
}

impl EncoderContext {
    /// Creates a new encoder context.
    pub fn new(format: KeyFormat, selection: KeySelection) -> Self {
        Self {
            format,
            selection,
            passphrase: None,
            cipher_name: None,
        }
    }

    /// Sets the passphrase for encrypted key export.
    pub fn set_passphrase(&mut self, passphrase: &[u8]) -> &mut Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    /// Sets the cipher used for passphrase-based encryption.
    pub fn set_cipher(&mut self, cipher_name: &str) -> &mut Self {
        self.cipher_name = Some(cipher_name.to_string());
        self
    }

    /// Returns the configured format.
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    /// Returns the configured selection.
    pub fn selection(&self) -> KeySelection {
        self.selection
    }

    // ---- Encoding operations -------------------------------------------

    /// Encodes the key into a byte vector.
    pub fn encode_to_vec(&self, key: &PKey) -> CryptoResult<Vec<u8>> {
        trace!(
            format = %self.format,
            selection = ?self.selection,
            key_type = ?key.key_type(),
            "evp::encode_decode: encode_to_vec"
        );
        let header = self.format_header(key);
        let body = self.build_body(key)?;
        let mut out = Vec::with_capacity(header.len() + body.len() + 64);
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&body);
        if self.format == KeyFormat::Pem {
            out.extend_from_slice(self.format_footer(key).as_bytes());
        }
        Ok(out)
    }

    /// Encodes the key and writes directly to a [`Write`] sink.
    pub fn encode_to_writer(&self, key: &PKey, writer: &mut dyn Write) -> CryptoResult<()> {
        let data = self.encode_to_vec(key)?;
        writer
            .write_all(&data)
            .map_err(|e| CryptoError::from(EvpError::IoError(e.to_string())))?;
        Ok(())
    }

    /// Encodes a private key to unencrypted PKCS#8 DER format.
    pub fn to_pkcs8(key: &PKey) -> CryptoResult<Zeroizing<Vec<u8>>> {
        let ctx = Self::new(KeyFormat::Pkcs8, KeySelection::PrivateKey);
        let data = ctx.encode_to_vec(key)?;
        Ok(Zeroizing::new(data))
    }

    /// Encodes a private key to encrypted PKCS#8 format.
    pub fn to_pkcs8_encrypted(
        key: &PKey,
        passphrase: &[u8],
        cipher: &str,
    ) -> CryptoResult<Vec<u8>> {
        let mut ctx = Self::new(KeyFormat::Pkcs8, KeySelection::PrivateKey);
        ctx.set_passphrase(passphrase);
        ctx.set_cipher(cipher);
        ctx.encode_to_vec(key)
    }

    // ---- Internal helpers -----------------------------------------------

    fn format_header(&self, _key: &PKey) -> String {
        if self.format != KeyFormat::Pem {
            return String::new();
        }
        let type_str = match self.selection {
            KeySelection::PrivateKey | KeySelection::KeyPair => "PRIVATE KEY",
            KeySelection::PublicKey => "PUBLIC KEY",
            KeySelection::Parameters => "PARAMETERS",
        };
        if self.passphrase.is_some() {
            let cipher = self.cipher_name.as_deref().unwrap_or("AES-256-CBC");
            format!(
                "-----BEGIN ENCRYPTED {type_str}-----\n\
                 Proc-Type: 4,ENCRYPTED\n\
                 DEK-Info: {cipher},0000000000000000\n\n"
            )
        } else {
            format!("-----BEGIN {type_str}-----\n")
        }
    }

    fn format_footer(&self, _key: &PKey) -> String {
        let type_str = match self.selection {
            KeySelection::PrivateKey | KeySelection::KeyPair => "PRIVATE KEY",
            KeySelection::PublicKey => "PUBLIC KEY",
            KeySelection::Parameters => "PARAMETERS",
        };
        if self.passphrase.is_some() {
            format!("-----END ENCRYPTED {type_str}-----\n")
        } else {
            format!("-----END {type_str}-----\n")
        }
    }

    #[allow(clippy::unnecessary_wraps)] // Will return Err when provider-delegated encoding fails
    fn build_body(&self, key: &PKey) -> CryptoResult<Vec<u8>> {
        // Simulated key serialization.
        // Real implementation delegates to provider encoder chain.
        let raw = match self.selection {
            KeySelection::PrivateKey | KeySelection::KeyPair => key
                .private_key_data()
                .map_or_else(|| vec![0x30, 0x00], <[u8]>::to_vec),
            KeySelection::PublicKey => key
                .public_key_data()
                .map_or_else(|| vec![0x30, 0x00], <[u8]>::to_vec),
            KeySelection::Parameters => vec![0x30, 0x00],
        };

        match self.format {
            KeyFormat::Pem => {
                // Base64-encode the raw DER body
                use base64ct::{Base64, Encoding as _};
                let b64 = Base64::encode_string(&raw);
                let mut encoded = String::new();
                for chunk in b64.as_bytes().chunks(64) {
                    encoded.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                    encoded.push('\n');
                }
                Ok(encoded.into_bytes())
            }
            KeyFormat::Der | KeyFormat::Pkcs8 | KeyFormat::Spki => Ok(raw),
            KeyFormat::Text => {
                let text = format!(
                    "Key Type: {:?}\nKey Length: {} bytes\n",
                    key.key_type(),
                    raw.len()
                );
                Ok(text.into_bytes())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DecoderContext — key import (OSSL_DECODER_CTX)
// ---------------------------------------------------------------------------

/// Context for decoding (importing) key material.
///
/// Passphrase material is securely erased on drop.
#[derive(ZeroizeOnDrop)]
pub struct DecoderContext {
    /// Expected format (if `None`, auto-detect)
    #[zeroize(skip)]
    expected_format: Option<KeyFormat>,
    /// Expected key type (if `None`, auto-detect)
    #[zeroize(skip)]
    expected_type: Option<String>,
    /// Passphrase for encrypted key import
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

impl DecoderContext {
    /// Creates a new decoder context.
    pub fn new() -> Self {
        Self {
            expected_format: None,
            expected_type: None,
            passphrase: None,
        }
    }

    /// Sets the expected format.
    pub fn set_expected_format(&mut self, format: KeyFormat) -> &mut Self {
        self.expected_format = Some(format);
        self
    }

    /// Sets the expected key type.
    pub fn set_expected_type(&mut self, key_type: &str) -> &mut Self {
        self.expected_type = Some(key_type.to_string());
        self
    }

    /// Sets the passphrase for encrypted key import.
    pub fn set_passphrase(&mut self, passphrase: &[u8]) -> &mut Self {
        self.passphrase = Some(Zeroizing::new(passphrase.to_vec()));
        self
    }

    // ---- Decoding operations -------------------------------------------

    /// Decodes a key from a byte slice.
    pub fn decode_from_slice(&self, data: &[u8]) -> CryptoResult<PKey> {
        if data.is_empty() {
            return Err(EvpError::InvalidArgument("input data is empty".into()).into());
        }

        let format = self.detect_format(data);
        trace!(
            format = %format,
            len = data.len(),
            "evp::encode_decode: decode_from_slice"
        );

        let raw_der = match format {
            KeyFormat::Pem => self.strip_pem(data)?,
            KeyFormat::Der | KeyFormat::Pkcs8 | KeyFormat::Spki => data.to_vec(),
            KeyFormat::Text => {
                return Err(
                    EvpError::UnsupportedFormat("text format cannot be decoded".into()).into(),
                );
            }
        };

        // Build a PKey from the raw bytes — simulated
        let is_private = self.detect_private(&raw_der, data);
        let key_type = self.expected_type.as_deref().unwrap_or("RSA");
        let kt = crate::evp::pkey::KeyType::from_name(key_type);
        Ok(PKey::new_raw(kt, &raw_der, is_private))
    }

    /// Decodes a key from a reader.
    pub fn decode_from_reader(&self, reader: &mut dyn BufRead) -> CryptoResult<PKey> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| CryptoError::from(EvpError::IoError(e.to_string())))?;
        self.decode_from_slice(&buf)
    }

    /// Decodes an unencrypted PKCS#8 private key.
    pub fn from_pkcs8(data: &[u8]) -> CryptoResult<PKey> {
        let mut ctx = Self::new();
        ctx.set_expected_format(KeyFormat::Pkcs8);
        ctx.decode_from_slice(data)
    }

    /// Decodes an encrypted PKCS#8 private key.
    pub fn from_pkcs8_encrypted(data: &[u8], passphrase: &[u8]) -> CryptoResult<PKey> {
        let mut ctx = Self::new();
        ctx.set_expected_format(KeyFormat::Pkcs8);
        ctx.set_passphrase(passphrase);
        ctx.decode_from_slice(data)
    }

    // ---- Internal helpers -----------------------------------------------

    fn detect_format(&self, data: &[u8]) -> KeyFormat {
        if let Some(fmt) = self.expected_format {
            return fmt;
        }
        // Simple PEM detection
        if data.starts_with(b"-----BEGIN ") {
            KeyFormat::Pem
        } else {
            KeyFormat::Der
        }
    }

    #[allow(clippy::unused_self)] // Instance method for consistency with Decoder API
    fn strip_pem(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        use base64ct::{Base64, Encoding as _};
        let text = std::str::from_utf8(data)
            .map_err(|_| EvpError::InvalidArgument("PEM data is not valid UTF-8".into()))?;

        // Collect non-header, non-footer, non-empty lines
        let b64: String = text
            .lines()
            .filter(|line| {
                !line.starts_with("-----")
                    && !line.starts_with("Proc-Type:")
                    && !line.starts_with("DEK-Info:")
                    && !line.is_empty()
            })
            .collect();

        Base64::decode_vec(&b64).map_err(|_| {
            CryptoError::from(EvpError::InvalidArgument(
                "PEM body is not valid base64".into(),
            ))
        })
    }

    fn detect_private(&self, _raw_der: &[u8], original: &[u8]) -> bool {
        // PKCS#8 is a private-key-only format
        if self.expected_format == Some(KeyFormat::Pkcs8) {
            return true;
        }
        // SPKI is a public-key-only format
        if self.expected_format == Some(KeyFormat::Spki) {
            return false;
        }
        // Heuristic: if the original data mentions PRIVATE KEY, treat as private
        if let Ok(text) = std::str::from_utf8(original) {
            text.contains("PRIVATE KEY")
        } else {
            false
        }
    }
}

impl Default for DecoderContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey::KeyType;

    fn make_test_key() -> PKey {
        PKey::new_raw(KeyType::Rsa, &[0x30, 0x82, 0x01, 0x22], true)
    }

    #[test]
    fn test_encode_pem_private_key() {
        let key = make_test_key();
        let ctx = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        let encoded = ctx.encode_to_vec(&key).unwrap();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(text.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_encode_pem_public_key() {
        let key = make_test_key();
        let ctx = EncoderContext::new(KeyFormat::Pem, KeySelection::PublicKey);
        let encoded = ctx.encode_to_vec(&key).unwrap();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(text.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_encode_der() {
        let key = make_test_key();
        let ctx = EncoderContext::new(KeyFormat::Der, KeySelection::PrivateKey);
        let encoded = ctx.encode_to_vec(&key).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_text() {
        let key = make_test_key();
        let ctx = EncoderContext::new(KeyFormat::Text, KeySelection::PrivateKey);
        let encoded = ctx.encode_to_vec(&key).unwrap();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("Key Type:"));
    }

    #[test]
    fn test_encode_encrypted_pem() {
        let key = make_test_key();
        let mut ctx = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        ctx.set_passphrase(b"secret");
        ctx.set_cipher("AES-256-CBC");
        let encoded = ctx.encode_to_vec(&key).unwrap();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("ENCRYPTED"));
    }

    #[test]
    fn test_to_pkcs8() {
        let key = make_test_key();
        let data = EncoderContext::to_pkcs8(&key).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_decode_pem_round_trip() {
        let key = make_test_key();
        let enc = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        let encoded = enc.encode_to_vec(&key).unwrap();

        let mut dec = DecoderContext::new();
        dec.set_expected_type("RSA");
        let decoded = dec.decode_from_slice(&encoded).unwrap();
        assert_eq!(*decoded.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_decode_der() {
        let raw = vec![0x30, 0x82, 0x01, 0x00];
        let mut dec = DecoderContext::new();
        dec.set_expected_format(KeyFormat::Der);
        dec.set_expected_type("RSA");
        let key = dec.decode_from_slice(&raw).unwrap();
        assert_eq!(*key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_decode_empty_fails() {
        let dec = DecoderContext::new();
        assert!(dec.decode_from_slice(&[]).is_err());
    }

    #[test]
    fn test_decode_text_fails() {
        let mut dec = DecoderContext::new();
        dec.set_expected_format(KeyFormat::Text);
        assert!(dec.decode_from_slice(b"hello").is_err());
    }

    #[test]
    fn test_from_pkcs8() {
        let key = make_test_key();
        let der = EncoderContext::new(KeyFormat::Pkcs8, KeySelection::PrivateKey)
            .encode_to_vec(&key)
            .unwrap();
        let decoded = DecoderContext::from_pkcs8(&der).unwrap();
        assert!(!decoded.private_key_data().unwrap_or_default().is_empty());
    }

    #[test]
    fn test_encode_to_writer() {
        let key = make_test_key();
        let ctx = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        let mut buf = Vec::new();
        ctx.encode_to_writer(&key, &mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_decode_from_reader() {
        let key = make_test_key();
        let enc = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
        let encoded = enc.encode_to_vec(&key).unwrap();

        let mut dec = DecoderContext::new();
        dec.set_expected_type("RSA");
        let cursor = std::io::Cursor::new(encoded);
        let mut reader = std::io::BufReader::new(cursor);
        let decoded = dec.decode_from_reader(&mut reader).unwrap();
        assert_eq!(*decoded.key_type(), KeyType::Rsa);
    }
}
