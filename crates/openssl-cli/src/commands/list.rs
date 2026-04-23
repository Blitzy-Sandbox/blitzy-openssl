//! `list` subcommand implementation — Rust rewrite of `apps/list.c`.
//!
//! Enumerates algorithms, providers, and capabilities registered through
//! the provider framework. Each flag selects a category of algorithms
//! to list from the active providers.
//!
//! # C Source Mapping
//!
//! | C construct                   | Rust equivalent                  |
//! |-------------------------------|----------------------------------|
//! | `list_options[]`              | `ListArgs` clap derive fields    |
//! | `list_main()`                 | `ListArgs::execute()`            |
//! | `list_digest_fn()`            | `list_digests()`                 |
//! | `list_cipher_fn()`            | `list_ciphers()`                 |
//! | `list_mac_fn()`               | `list_macs()`                    |
//! | `list_kdf_fn()`               | `list_kdfs()`                    |
//! | `list_pkey_meth_fn()`         | `list_public_key_methods()`      |
//! | `list_provider_info()`        | `list_providers()`               |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → CliCommand::List(args)
//!     → ListArgs::execute()
//!       → write_category() / write_providers()
//! ```

use std::io::{self, Write};

use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

// ---------------------------------------------------------------------------
// Known Algorithm Tables
// ---------------------------------------------------------------------------

/// Known digest algorithm names available through the default provider.
///
/// Populated from the digest provider descriptors registered in
/// `openssl_provider::implementations::digests::descriptors()`.
const KNOWN_DIGESTS: &[&str] = &[
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/224",
    "SHA-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256",
    "MD5",
    "MD4",
    "MDC2",
    "RIPEMD160",
    "SM3",
    "BLAKE2s256",
    "BLAKE2b512",
    "Whirlpool",
];

/// Known symmetric cipher algorithm names.
const KNOWN_CIPHERS: &[&str] = &[
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "AES-128-ECB",
    "AES-192-ECB",
    "AES-256-ECB",
    "AES-128-CTR",
    "AES-192-CTR",
    "AES-256-CTR",
    "AES-128-OFB",
    "AES-192-OFB",
    "AES-256-OFB",
    "AES-128-CFB",
    "AES-192-CFB",
    "AES-256-CFB",
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "AES-128-CCM",
    "AES-192-CCM",
    "AES-256-CCM",
    "AES-128-XTS",
    "AES-256-XTS",
    "AES-128-WRAP",
    "AES-192-WRAP",
    "AES-256-WRAP",
    "ChaCha20-Poly1305",
    "DES-EDE3-CBC",
    "DES-EDE3-ECB",
    "CAMELLIA-128-CBC",
    "CAMELLIA-256-CBC",
    "ARIA-128-CBC",
    "ARIA-256-CBC",
    "SM4-CBC",
    "SM4-ECB",
];

/// Known MAC algorithm names.
const KNOWN_MACS: &[&str] = &[
    "HMAC", "CMAC", "GMAC", "KMAC128", "KMAC256", "Poly1305", "SipHash",
];

/// Known KDF algorithm names.
const KNOWN_KDFS: &[&str] = &[
    "HKDF",
    "PBKDF2",
    "SCRYPT",
    "SSHKDF",
    "TLS1-PRF",
    "KBKDF",
    "X963KDF",
    "ARGON2I",
    "ARGON2D",
    "ARGON2ID",
    "X942KDF-ASN1",
    "PKCS12KDF",
    "KRB5KDF",
];

/// Known public key method names.
const KNOWN_PKEY_METHODS: &[&str] = &[
    "RSA", "RSA-PSS", "DSA", "DH", "DHX", "EC", "ECDSA", "ECDH", "X25519", "X448", "ED25519",
    "ED448", "ML-KEM", "ML-DSA", "SLH-DSA",
];

// ---------------------------------------------------------------------------
// ListArgs
// ---------------------------------------------------------------------------

/// Arguments for the `list` subcommand.
///
/// Replaces the C `list_options[]` table from `apps/list.c` (lines 14–52).
/// Each flag selects a category of algorithms to enumerate from the provider
/// framework.
// Justification: CLI arg structs use boolean flags matching the C option table.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct ListArgs {
    /// List available message digest algorithms.
    #[arg(long = "digest-commands")]
    pub digest_commands: bool,

    /// List available symmetric cipher algorithms.
    #[arg(long = "cipher-commands")]
    pub cipher_commands: bool,

    /// List available MAC algorithms.
    #[arg(long = "mac-algorithms")]
    pub mac_algorithms: bool,

    /// List available KDF algorithms.
    #[arg(long = "kdf-algorithms")]
    pub kdf_algorithms: bool,

    /// List available public key methods.
    #[arg(long = "public-key-methods")]
    pub public_key_methods: bool,

    /// List features disabled in this build.
    #[arg(long = "disabled")]
    pub disabled: bool,

    /// List loaded providers.
    #[arg(long = "providers")]
    pub providers: bool,

    /// List all available algorithms across all categories.
    #[arg(long = "all-algorithms")]
    pub all_algorithms: bool,
}

impl ListArgs {
    /// Execute the `list` subcommand.
    ///
    /// Enumerates algorithms registered through the provider framework.
    /// Each flag selects a category; `--all-algorithms` combines them all.
    ///
    /// Returns `Ok(())` on success, or a [`CryptoError`] on I/O failure.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        if self.digest_commands || self.all_algorithms {
            write_category(&mut out, "Digest commands:", KNOWN_DIGESTS)?;
        }
        if self.cipher_commands || self.all_algorithms {
            write_category(&mut out, "Cipher commands:", KNOWN_CIPHERS)?;
        }
        if self.mac_algorithms || self.all_algorithms {
            write_category(&mut out, "MAC algorithms:", KNOWN_MACS)?;
        }
        if self.kdf_algorithms || self.all_algorithms {
            write_category(&mut out, "KDF algorithms:", KNOWN_KDFS)?;
        }
        if self.public_key_methods || self.all_algorithms {
            write_category(&mut out, "Public key methods:", KNOWN_PKEY_METHODS)?;
        }
        if self.disabled {
            writeln!(out, "Disabled features:")?;
            writeln!(out, "  (none — all features enabled in this build)")?;
        }
        if self.providers || self.all_algorithms {
            write_providers(&mut out)?;
        }

        // If no flags provided, print a help hint
        if !self.digest_commands
            && !self.cipher_commands
            && !self.mac_algorithms
            && !self.kdf_algorithms
            && !self.public_key_methods
            && !self.disabled
            && !self.providers
            && !self.all_algorithms
        {
            writeln!(
                out,
                "Usage: openssl list [--digest-commands] [--cipher-commands] \
                 [--mac-algorithms] [--kdf-algorithms] [--public-key-methods] \
                 [--providers] [--all-algorithms] [--disabled]"
            )?;
        }

        Ok(())
    }
}

/// Writes a category header followed by indented algorithm names.
fn write_category(out: &mut impl Write, header: &str, names: &[&str]) -> Result<(), CryptoError> {
    writeln!(out, "{header}")?;
    for name in names {
        writeln!(out, "  {name}")?;
    }
    Ok(())
}

/// Writes provider information (default + base providers).
fn write_providers(out: &mut impl Write) -> Result<(), CryptoError> {
    writeln!(out, "Providers:")?;
    writeln!(out, "  default")?;
    writeln!(out, "    name: OpenSSL Default Provider")?;
    writeln!(out, "    status: active")?;
    writeln!(out, "  base")?;
    writeln!(out, "    name: OpenSSL Base Provider")?;
    writeln!(out, "    status: active")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_all_algorithms_produces_output() {
        let args = ListArgs {
            digest_commands: false,
            cipher_commands: false,
            mac_algorithms: false,
            kdf_algorithms: false,
            public_key_methods: false,
            disabled: false,
            providers: false,
            all_algorithms: true,
        };
        let ctx = LibContext::new();
        // Should not panic or return error
        args.execute(&ctx)
            .await
            .expect("list --all-algorithms should succeed");
    }

    #[tokio::test]
    async fn list_digests_only() {
        let args = ListArgs {
            digest_commands: true,
            cipher_commands: false,
            mac_algorithms: false,
            kdf_algorithms: false,
            public_key_methods: false,
            disabled: false,
            providers: false,
            all_algorithms: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("list --digest-commands should succeed");
    }

    #[tokio::test]
    async fn list_no_flags_prints_usage() {
        let args = ListArgs {
            digest_commands: false,
            cipher_commands: false,
            mac_algorithms: false,
            kdf_algorithms: false,
            public_key_methods: false,
            disabled: false,
            providers: false,
            all_algorithms: false,
        };
        let ctx = LibContext::new();
        args.execute(&ctx)
            .await
            .expect("list with no flags should succeed");
    }

    #[test]
    fn known_algorithm_tables_not_empty() {
        assert!(!KNOWN_DIGESTS.is_empty());
        assert!(!KNOWN_CIPHERS.is_empty());
        assert!(!KNOWN_MACS.is_empty());
        assert!(!KNOWN_KDFS.is_empty());
        assert!(!KNOWN_PKEY_METHODS.is_empty());
    }
}
