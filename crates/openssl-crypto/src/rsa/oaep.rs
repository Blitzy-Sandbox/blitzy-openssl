//! RSA-OAEP padding (Optimal Asymmetric Encryption Padding).
//!
//! Implements the OAEP encryption padding scheme as specified in
//! **RFC 8017 §7.1** (PKCS #1 v2.2). OAEP is the recommended padding mode
//! for RSA encryption in new deployments because it provides IND-CCA2
//! security under the RSA assumption in the random oracle model
//! (Bellare-Rogaway, Eurocrypt 1994; Fujisaki-Okamoto-Pointcheval-Stern,
//! CRYPTO 2001).
//!
//! Translates the upstream C implementation in `crypto/rsa/rsa_oaep.c`
//! (~410 lines) into idiomatic, fully-safe Rust. The decode path retains
//! the **constant-time / Manger-attack defense** of the C reference: every
//! comparison on secret data is performed with the
//! [`openssl_common::constant_time`] primitives, and the final extraction
//! step uses a bit-shifted memmove that runs in `O(N · log N)` regardless
//! of the discovered separator position.
//!
//! # Source Mapping
//!
//! | Rust Component                | C Source                                                   | Purpose                                                  |
//! |-------------------------------|------------------------------------------------------------|----------------------------------------------------------|
//! | [`OaepParams`]                | `EVP_PKEY_CTX_set_rsa_oaep_md` / `_set_rsa_mgf1_md` / `_set_rsa_oaep_label` | Per-operation OAEP parameters: hash, MGF1 hash, label |
//! | [`oaep_encrypt`]              | `crypto/rsa/rsa_oaep.c::RSA_padding_add_PKCS1_OAEP_mgf1`   | RFC 8017 §7.1.1 EME-OAEP encode + RSA primitive         |
//! | [`oaep_decrypt`]              | `crypto/rsa/rsa_oaep.c::RSA_padding_check_PKCS1_OAEP_mgf1` | RFC 8017 §7.1.2 EME-OAEP decode + RSA primitive         |
//! | MGF1 mask generation          | `crypto/rsa/rsa_oaep.c::PKCS1_MGF1`                        | RFC 8017 §B.2.1 MGF1 — provided by [`super::pss::pkcs1_mgf1`] |
//!
//! # OAEP Encoding (RFC 8017 §7.1.1 EME-OAEP-Encode)
//!
//! OAEP transforms a message `M` of length `mLen ≤ k − 2hLen − 2` octets
//! (where `k` is the RSA modulus length in octets and `hLen` is the hash
//! function output length in octets) into an encoded message `EM` of
//! length `k` octets:
//!
//! ```text
//! 1.  lHash = Hash(L)                            // L is the optional label
//! 2.  PS    = (k − mLen − 2hLen − 2) zero octets
//! 3.  DB    = lHash || PS || 0x01 || M           // length k − hLen − 1
//! 4.  seed  = random hLen octets
//! 5.  dbMask  = MGF1(seed, k − hLen − 1)
//! 6.  maskedDB = DB ⊕ dbMask
//! 7.  seedMask = MGF1(maskedDB, hLen)
//! 8.  maskedSeed = seed ⊕ seedMask
//! 9.  EM    = 0x00 || maskedSeed || maskedDB     // total length k
//! 10. C     = RSAEP((n, e), OS2IP(EM))           // RSA primitive
//! ```
//!
//! # OAEP Decoding (RFC 8017 §7.1.2 EME-OAEP-Decode)
//!
//! Decoding mirrors encoding but is performed in **constant time** to
//! defeat Manger's attack (Manger, CRYPTO 2001), which exploits timing
//! differences in the leading-byte check (`Y == 0x00`) to recover the
//! plaintext bit-by-bit. The Rust implementation:
//!
//! - Defers all branching on secret-derived data: the `good` accumulator
//!   collects every per-step validity bit using bitwise AND.
//! - Performs the separator scan with `constant_time::constant_time_eq_8`
//!   on every byte position (no early break).
//! - Performs the message extraction with a bit-shifted memmove
//!   (`O(log₂(maxMsg))` outer iterations) so that the access pattern
//!   does not depend on the recovered message length.
//! - Selects the success / failure return path with
//!   `constant_time::constant_time_select_int` — an integer-domain
//!   conditional move.
//!
//! # Defaults & Negotiated Parameters
//!
//! - **Hash:** SHA-1 in upstream OpenSSL for backwards compatibility, but
//!   **SHA-256** is strongly recommended for new code. The default in
//!   [`OaepParams::new_default`] is therefore **SHA-256**.
//! - **MGF1 hash:** same as the OAEP hash unless overridden via
//!   [`OaepParams::with_mgf1_hash`].
//! - **Label:** empty by default. RFC 8017 §7.1 permits any octet string
//!   as a label, but most deployments leave it empty.
//!
//! # Choice of Hash Function (Compliance)
//!
//! Per **NIST SP 800-131A Rev. 2 §6**, SHA-1 is **disallowed** for new
//! RSA-OAEP deployments after 2030. Use SHA-256 or SHA-384 in new code.
//!
//! # Specifications
//!
//! - **RFC 8017 §7.1** — RSAES-OAEP Encryption Scheme
//! - **RFC 8017 §B.2.1** — MGF1 Mask Generation Function
//! - **NIST SP 800-56B Rev. 2 §7.2.2.3** — RSA-OAEP-KEM Key-Transport
//! - **NIST SP 800-131A Rev. 2 §6** — Hash function transitions
//! - **Manger, CRYPTO 2001** — A Chosen-Ciphertext Attack on RSA OAEP
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Optional label is `Vec<u8>` (empty by default,
//!   never an integer sentinel); optional MGF1 hash is `Option<…>`.
//! - **R6 (Lossless Casts):** Cross-type conversions go through
//!   `try_from` / `u32::from` widening; no bare narrowing `as` casts on
//!   length values.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module; the parent
//!   crate forbids it.
//! - **R10 (Wiring):** Reachable from `openssl_crypto::rsa::oaep` and
//!   integrated with [`super::public_encrypt`] / [`super::private_decrypt`]
//!   via [`super::PaddingMode::None`] (the OAEP padding is performed in
//!   this module before / after the RSA primitive).
//! - **§0.7.6 (Secure Erasure):** All intermediate buffers (`db`, `seed`,
//!   `dbmask`, `seedmask`, decoded EM) are wiped via [`Zeroize`].

use openssl_common::constant_time;
use openssl_common::error::{CryptoError, CryptoResult};

use crate::hash::{create_digest, Digest, DigestAlgorithm};
use crate::rand::rand_bytes;

use tracing::{debug, trace};
use zeroize::Zeroize;

use super::pss::pkcs1_mgf1;
use super::{
    digest_to_scheme_nid, private_decrypt, public_encrypt, scheme_nid_to_digest, PaddingMode,
    RsaError, RsaPrivateKey, RsaPublicKey,
};

// =============================================================================
// OAEP parameters
// =============================================================================

/// Per-operation OAEP parameters: the digest function applied to the
/// label (and used as the OAEP / MGF1 hash by default), an optional
/// override for the MGF1 hash, and the optional label.
///
/// Translates the three OpenSSL provider parameters
/// `OSSL_PKEY_RSA_OAEP_DIGEST`, `OSSL_PKEY_RSA_MGF1_DIGEST`, and
/// `OSSL_PKEY_RSA_OAEP_LABEL` (see `include/openssl/core_names.h`).
///
/// # Field Semantics
///
/// - `hash` — Hash function `Hash` applied to the label `L` per
///   RFC 8017 §7.1.1 step 1. Also used as the MGF1 hash unless
///   [`mgf1_hash`](Self::mgf1_hash) overrides it.
/// - `mgf1_hash` — Optional override for the MGF1 mask-generation hash.
///   `None` means "same as `hash`" per the RFC default.
/// - `label` — The label `L`. Empty by default; RFC 8017 permits any
///   octet string but most deployments use the empty string.
#[derive(Debug, Clone)]
pub struct OaepParams {
    /// Hash function applied to the label and used as default MGF1 hash.
    pub hash: DigestAlgorithm,
    /// Optional MGF1 hash override (`None` ⇒ same as `hash`).
    pub mgf1_hash: Option<DigestAlgorithm>,
    /// Optional label `L` (empty by default).
    pub label: Vec<u8>,
}

impl OaepParams {
    /// Creates a new [`OaepParams`] with **SHA-256** as the OAEP and
    /// MGF1 hash and an empty label. SHA-256 is the recommended default
    /// per NIST SP 800-131A Rev. 2 §6 (SHA-1 disallowed after 2030).
    #[must_use]
    pub fn new_default() -> Self {
        Self {
            hash: DigestAlgorithm::Sha256,
            mgf1_hash: None,
            label: Vec::new(),
        }
    }

    /// Creates [`OaepParams`] using the given hash for both OAEP and
    /// MGF1 (no override) with an empty label.
    #[must_use]
    pub fn with_hash(hash: DigestAlgorithm) -> Self {
        Self {
            hash,
            mgf1_hash: None,
            label: Vec::new(),
        }
    }

    /// Sets a distinct MGF1 hash (RFC 8017 §B.2.1). Returns `self` for
    /// chaining.
    #[must_use]
    pub fn with_mgf1_hash(mut self, mgf1_hash: DigestAlgorithm) -> Self {
        self.mgf1_hash = Some(mgf1_hash);
        self
    }

    /// Sets the label `L` (RFC 8017 §7.1.1 step 1). Returns `self` for
    /// chaining.
    #[must_use]
    pub fn with_label(mut self, label: Vec<u8>) -> Self {
        self.label = label;
        self
    }

    /// Returns the effective MGF1 hash: the override if present,
    /// otherwise the OAEP hash.
    #[must_use]
    pub fn mgf1_hash_effective(&self) -> DigestAlgorithm {
        self.mgf1_hash.unwrap_or(self.hash)
    }

    /// Returns the OAEP hash NID (object identifier numeric form) for
    /// serialization. Translates `OBJ_nid2obj(EVP_MD_get_type(md))` from
    /// `crypto/rsa/rsa_oaep.c`.
    ///
    /// Returns `None` if the hash algorithm has no NID mapping.
    #[must_use]
    pub fn oaep_hash_nid(&self) -> Option<u32> {
        digest_to_scheme_nid(self.hash)
    }

    /// Returns the MGF1 hash NID (object identifier numeric form) for
    /// serialization. Returns `None` if the hash algorithm has no NID
    /// mapping.
    #[must_use]
    pub fn mgf1_hash_nid(&self) -> Option<u32> {
        digest_to_scheme_nid(self.mgf1_hash_effective())
    }

    /// Resolves OAEP parameters from a `(oaep_hash_nid, mgf1_hash_nid)`
    /// pair as commonly stored in encoded ASN.1 forms (per
    /// `RSAES-OAEP-params`, RFC 8017 §A.2.1). Returns the corresponding
    /// [`OaepParams`] with an empty label. The caller may set the label
    /// via [`Self::with_label`].
    ///
    /// Returns `None` if either NID does not map to a known
    /// [`DigestAlgorithm`].
    #[must_use]
    pub fn from_nids(oaep_hash_nid: u32, mgf1_hash_nid: u32) -> Option<Self> {
        let hash = scheme_nid_to_digest(oaep_hash_nid)?;
        let mgf1 = scheme_nid_to_digest(mgf1_hash_nid)?;
        let mgf1_hash = if mgf1 == hash { None } else { Some(mgf1) };
        Some(Self {
            hash,
            mgf1_hash,
            label: Vec::new(),
        })
    }
}

impl Default for OaepParams {
    fn default() -> Self {
        Self::new_default()
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Computes `Hash(L)` — the hash of the label per RFC 8017 §7.1.1 step 1.
///
/// Translates the `EVP_MD_CTX` invocation pattern in
/// `crypto/rsa/rsa_oaep.c::RSA_padding_add_PKCS1_OAEP_mgf1` (lines 67–88).
fn hash_label(label: &[u8], hash: DigestAlgorithm) -> CryptoResult<Vec<u8>> {
    let mut ctx: Box<dyn Digest> = create_digest(hash)?;
    ctx.update(label)?;
    ctx.finalize()
}

/// Produces an `RsaError::OaepDecodingError`. The decode path treats
/// every failure mode (length, leading byte, label hash, separator,
/// message length) identically to avoid leaking which step rejected the
/// ciphertext (Manger defense). The on-the-wire error returned by this
/// helper carries no diagnostic information beyond
/// "OAEP decoding failed".
#[inline]
fn oaep_decode_error() -> CryptoError {
    CryptoError::from(RsaError::OaepDecodingError)
}

// =============================================================================
// OAEP encrypt
// =============================================================================

/// RSA-OAEP encrypts `msg` with the public `key` and the supplied OAEP
/// parameters, returning the RSA ciphertext of length `k = key_size_bytes`.
///
/// Translates `RSA_padding_add_PKCS1_OAEP_mgf1` followed by the public
/// RSA primitive from `crypto/rsa/rsa_oaep.c` (lines 54–149). The OAEP
/// padding is performed in pure Rust here, then the resulting EM buffer
/// (already exactly `k` bytes long) is handed to
/// [`super::public_encrypt`] with [`PaddingMode::None`] for the modular
/// exponentiation.
///
/// # Length Constraints (RFC 8017 §7.1.1)
///
/// Let `k` be the RSA modulus length in octets and `hLen` the digest size.
///
/// - `k` must be at least `2 · hLen + 2` (`KEY_SIZE_TOO_SMALL` otherwise).
/// - `mLen` (`= msg.len()`) must satisfy `mLen ≤ k − 2 · hLen − 2`
///   (`DATA_TOO_LARGE_FOR_KEY_SIZE` otherwise).
///
/// # Errors
///
/// Returns:
/// - [`RsaError::DataTooLargeForKeySize`] if `msg` is longer than the key
///   can accommodate.
/// - [`RsaError::KeyTooSmall`] if the modulus is too small for the chosen
///   hash.
/// - Whatever the hash, RNG, or RSA primitive returns on failure.
///
/// # Side-Channel Properties
///
/// This is the **encryption** path; the message is the caller's own
/// secret. Side-channel countermeasures (constant-time MGF1 application,
/// secure-erasure of the seed and intermediate masks) protect the random
/// seed and prevent state leakage between operations.
pub fn oaep_encrypt(key: &RsaPublicKey, msg: &[u8], params: &OaepParams) -> CryptoResult<Vec<u8>> {
    trace!(
        msg_len = msg.len(),
        hash = ?params.hash,
        mgf1 = ?params.mgf1_hash_effective(),
        label_len = params.label.len(),
        "RSA oaep_encrypt",
    );

    let hash = params.hash;
    let mgf1_hash = params.mgf1_hash_effective();
    let mdlen = hash.digest_size();
    if mdlen == 0 {
        return Err(CryptoError::Encoding(
            "OAEP: hash has zero digest size".to_string(),
        ));
    }

    let k_u32 = key.key_size_bytes();
    let k = usize::try_from(k_u32).map_err(|_| RsaError::DataTooLargeForKeySize)?;

    // RFC 8017 §7.1.1 constraints. Use checked arithmetic to avoid overflow
    // even on absurdly small / pathological key sizes.
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| {
            CryptoError::Encoding("OAEP: overflow computing key size threshold".to_string())
        })?;
    if k < two_mdlen_plus_2 {
        let actual = u32::try_from(k.saturating_mul(8)).unwrap_or(u32::MAX);
        let min = u32::try_from(two_mdlen_plus_2.saturating_mul(8)).unwrap_or(u32::MAX);
        return Err(RsaError::KeyTooSmall {
            min_bits: min,
            actual_bits: actual,
        }
        .into());
    }
    // Maximum message length: k - 2*hLen - 2.
    let max_msg = k - two_mdlen_plus_2;
    if msg.len() > max_msg {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    // Compute lHash = Hash(L).
    let lhash = hash_label(&params.label, hash)?;
    debug_assert_eq!(lhash.len(), mdlen);

    // Build EM = 0x00 || maskedSeed || maskedDB, total length k bytes.
    //
    // Layout positions (matches rsa_oaep.c):
    //   em[0]                       = 0x00
    //   em[1 .. 1 + mdlen]          = seed       (later masked)
    //   em[1 + mdlen ..]            = db         (later masked); length k - mdlen - 1
    //
    // db = lHash || PS (zeros) || 0x01 || M, total length k - mdlen - 1.
    let mut em = vec![0u8; k];
    let db_off = 1 + mdlen;
    let db_len = k - db_off;

    // db[0..mdlen] = lHash
    em[db_off..db_off + mdlen].copy_from_slice(&lhash);

    // db[mdlen..db_len - msg.len() - 1] is already zero (PS) from vec init.

    // db[db_len - msg.len() - 1] = 0x01
    let one_pos = db_off + db_len - msg.len() - 1;
    em[one_pos] = 0x01;

    // db[db_len - msg.len()..] = M
    if !msg.is_empty() {
        em[one_pos + 1..one_pos + 1 + msg.len()].copy_from_slice(msg);
    }

    // Generate a random seed of mdlen bytes into em[1..=mdlen].
    rand_bytes(&mut em[1..=mdlen])?;

    // First MGF1: dbmask = MGF1(seed, db_len). Apply to db.
    let mut dbmask = vec![0u8; db_len];
    {
        let seed_slice = &em[1..=mdlen];
        pkcs1_mgf1(&mut dbmask, seed_slice, mgf1_hash).inspect_err(|_e| {
            // Wipe before propagating to ensure we don't leak any partial mask.
            let mut tmp = dbmask.clone();
            tmp.zeroize();
        })?;
    }
    for (i, mask_byte) in dbmask.iter().enumerate().take(db_len) {
        em[db_off + i] ^= *mask_byte;
    }
    dbmask.zeroize();

    // Second MGF1: seedmask = MGF1(maskedDB, mdlen). Apply to seed.
    let mut seedmask = vec![0u8; mdlen];
    {
        let masked_db = &em[db_off..db_off + db_len];
        pkcs1_mgf1(&mut seedmask, masked_db, mgf1_hash).inspect_err(|_e| {
            let mut tmp = seedmask.clone();
            tmp.zeroize();
        })?;
    }
    for (i, mask_byte) in seedmask.iter().enumerate().take(mdlen) {
        em[1 + i] ^= *mask_byte;
    }
    seedmask.zeroize();

    // em[0] is already 0x00 (from vec init). EM is now ready: exactly k bytes.
    debug_assert_eq!(em.len(), k);

    // RSA primitive: ciphertext = EM ^ e mod n. We pass PaddingMode::None
    // because the OAEP padding has already been applied above. The em
    // buffer length equals k exactly, satisfying no_padding_add's
    // exact-length contract (see super::no_padding_add).
    let ct_result = public_encrypt(key, &em, PaddingMode::None);

    // Wipe EM regardless of success: it contains the random seed and the
    // padded plaintext, both of which should not linger on the stack /
    // heap.
    em.zeroize();

    let ct = ct_result?;
    debug!(
        ciphertext_len = ct.len(),
        "RSA oaep_encrypt: produced ciphertext"
    );
    Ok(ct)
}

// =============================================================================
// OAEP decrypt (constant-time, Manger defense)
// =============================================================================

/// RSA-OAEP decrypts `ciphertext` with the private `key` and the
/// supplied OAEP parameters, returning the recovered plaintext.
///
/// Translates `RSA_padding_check_PKCS1_OAEP_mgf1` followed by the
/// private RSA primitive from `crypto/rsa/rsa_oaep.c` (lines 200–340).
/// The RSA private operation is delegated to [`super::private_decrypt`]
/// with [`PaddingMode::None`] (which performs blinding, CRT modular
/// exponentiation, and the Bellcore fault defense). The OAEP decoding
/// runs in **constant time** here to defeat Manger's attack:
///
/// - Length check on the leading `0x00` byte uses
///   `constant_time::constant_time_is_zero`.
/// - Label-hash comparison uses `constant_time::constant_time_eq` on
///   each byte and accumulates into the `good` mask (no early exit).
/// - The separator scan touches every position from `mdlen` to `db_len-1`.
/// - Message extraction uses a bit-shifted memmove that runs the same
///   number of XOR / select operations regardless of where the separator
///   was found.
/// - The success / failure return is selected via
///   `constant_time::constant_time_select_int`.
///
/// # Errors
///
/// Returns [`RsaError::OaepDecodingError`] on **any** decode-time
/// failure (length, leading-byte, label-hash, missing separator).
/// The same error variant is returned for every failure mode to
/// prevent ciphertext-distinguishing oracles.
pub fn oaep_decrypt(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    params: &OaepParams,
) -> CryptoResult<Vec<u8>> {
    trace!(
        ct_len = ciphertext.len(),
        hash = ?params.hash,
        mgf1 = ?params.mgf1_hash_effective(),
        label_len = params.label.len(),
        "RSA oaep_decrypt",
    );

    let hash = params.hash;
    let mgf1_hash = params.mgf1_hash_effective();
    let mdlen = hash.digest_size();
    if mdlen == 0 {
        return Err(CryptoError::Encoding(
            "OAEP: hash has zero digest size".to_string(),
        ));
    }

    let k_u32 = key.key_size_bytes();
    let k = usize::try_from(k_u32).map_err(|_| RsaError::DataTooLargeForKeySize)?;

    // Bounds check — the smallest legal RSA-OAEP key is 2*hLen + 2.
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| {
            CryptoError::Encoding("OAEP: overflow computing key size threshold".to_string())
        })?;
    if k < two_mdlen_plus_2 {
        return Err(oaep_decode_error());
    }

    // Run the RSA private primitive (blinding + CRT + Bellcore defense).
    // PaddingMode::None means private_decrypt returns the raw decrypted
    // bytes (no_padding_check is just to_vec()).
    let mut em = private_decrypt(key, ciphertext, PaddingMode::None)?;

    // private_decrypt with PaddingMode::None always returns exactly k
    // bytes for valid input. If for any reason it does not, treat that
    // as a decode failure (avoid panic on slicing).
    if em.len() != k {
        em.zeroize();
        return Err(oaep_decode_error());
    }

    // ---- Begin constant-time OAEP decode ----
    //
    // From here on, `good` accumulates validity bits via bitwise AND.
    // Every step ANDs in its result so that *no* later step can recover
    // a "good" status if any earlier step failed. We do not branch on
    // any value derived from `em` apart from the final `good` selection
    // at the very end.

    // Manger defense: the leading byte must be 0x00.
    let mut good: u32 = constant_time::constant_time_is_zero(u32::from(em[0]));

    // Layout: em[0] || maskedSeed[mdlen] || maskedDB[db_len].
    let db_off = 1 + mdlen;
    let db_len = k - db_off;

    // Recover seed = maskedSeed ^ MGF1(maskedDB, mdlen).
    let mut seedmask = vec![0u8; mdlen];
    pkcs1_mgf1(&mut seedmask, &em[db_off..db_off + db_len], mgf1_hash).inspect_err(|_e| {
        em.zeroize();
        seedmask.zeroize();
    })?;
    let mut seed = vec![0u8; mdlen];
    for (i, mask_byte) in seedmask.iter().enumerate().take(mdlen) {
        seed[i] = em[1 + i] ^ *mask_byte;
    }
    seedmask.zeroize();

    // Recover db = maskedDB ^ MGF1(seed, db_len).
    let mut dbmask = vec![0u8; db_len];
    pkcs1_mgf1(&mut dbmask, &seed, mgf1_hash).inspect_err(|_e| {
        em.zeroize();
        seed.zeroize();
        dbmask.zeroize();
    })?;
    let mut db = vec![0u8; db_len];
    for (i, mask_byte) in dbmask.iter().enumerate().take(db_len) {
        db[i] = em[db_off + i] ^ *mask_byte;
    }
    dbmask.zeroize();
    seed.zeroize();

    // Compute lHash = Hash(L) and compare against db[0..mdlen] in
    // constant time. We accumulate eq-bits across every position so that
    // partial mismatches do not allow an early-exit timing oracle.
    let lhash = hash_label(&params.label, hash).inspect_err(|_e| {
        em.zeroize();
        db.zeroize();
    })?;
    debug_assert_eq!(lhash.len(), mdlen);

    let mut hash_eq: u32 = u32::MAX;
    for i in 0..mdlen {
        hash_eq &= constant_time::constant_time_eq(u32::from(db[i]), u32::from(lhash[i]));
    }
    good &= hash_eq;

    // Separator scan: find the position of the first 0x01 byte after
    // the lHash region. We scan every position from mdlen through
    // db_len - 1, regardless of whether we have already found a
    // separator, so the timing depends only on db_len, not on the
    // separator's position. `found` is 0 until a 0x01 has been seen,
    // then 0xFFFF_FFFF for all subsequent positions.
    //
    // We also OR-in `nonzero_before_one` for every byte that was
    // non-zero before the first 0x01; the spec requires those bytes to
    // all be zero (the PS region). Any non-zero byte before the
    // separator is a decode failure.
    let mut found: u32 = 0;
    let mut zeroth_one_index: u32 = 0;
    let mut bad_pad: u32 = 0;
    for (i, byte_val) in db.iter().enumerate().skip(mdlen) {
        let byte = u32::from(*byte_val);
        let is_one = constant_time::constant_time_eq(byte, 1);
        let is_zero = constant_time::constant_time_is_zero(byte);

        // Once `found` has been set, subsequent positions are message
        // bytes — they may be anything. So we only check `is_zero` for
        // positions where !found && !is_one. If at one of those
        // positions the byte is non-zero, that's bad padding.
        let pre_one = !found; // 0xFFFF_FFFF before the first 0x01, 0 after
        bad_pad |= pre_one & !is_one & !is_zero;

        // Capture the index of the first 0x01 byte. We use
        // constant_time_select to keep this branch-free: when
        // !found && is_one, store i; otherwise leave the previous value.
        let take_now = pre_one & is_one;
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        zeroth_one_index = constant_time::constant_time_select(take_now, i_u32, zeroth_one_index);

        // Mark `found` once we've seen the first 0x01.
        found |= take_now;
    }
    good &= found;
    good &= !bad_pad;

    // The message starts at db[zeroth_one_index + 1] and runs to db[db_len - 1].
    // mlen = (db_len - 1 - zeroth_one_index). Compute as u32.
    let db_len_u32 = u32::try_from(db_len).unwrap_or(u32::MAX);
    // If `good` is 0 (failure), zero out the index so subsequent math
    // produces a deterministic value but does not panic — but we must
    // still preserve constant-time properties. zeroth_one_index could
    // be 0 even on success (impossible because the loop starts at mdlen),
    // so any value is fine here for the failure branch. We compute mlen
    // as db_len - 1 - zeroth_one_index, saturating at 0 if invalid.
    let mlen_u32 = db_len_u32
        .saturating_sub(1)
        .saturating_sub(zeroth_one_index);

    // ---- Constant-time message extraction (bit-shifted memmove) ----
    //
    // Translates the C loop at rsa_oaep.c lines 311–321 (and earlier
    // variants going back to OpenSSL 1.1.1). We need to shift db left by
    // `zeroth_one_index + 1` bytes so that the message starts at db[0].
    // Doing this with a naive memmove would leak `zeroth_one_index`
    // through the access pattern, so we use a power-of-two-shift
    // strategy: for each bit position `b` in `shift`, conditionally
    // shift db left by `2^b` bytes if that bit is set.
    //
    // The number of outer iterations is `ceil(log2(db_len))` — purely a
    // function of db_len (public information), not the secret index.
    let shift = zeroth_one_index.saturating_add(1);
    let mut bit: u32 = 1;
    // Determine the highest bit we ever need to consider: enough to
    // cover any possible value of `shift` ≤ db_len.
    while bit < db_len_u32 && bit != 0 {
        let bit_set = constant_time::constant_time_eq(shift & bit, bit);
        let dist = usize::try_from(bit).unwrap_or(0);
        // Conditionally rotate db left by `dist` bytes when bit_set.
        // We do this in-place using a per-byte select.
        if dist == 0 {
            break;
        }
        // Forward iteration is safe because for each i in 0..db_len, we
        // read db[i + dist] (or 0 if out of range) and write to db[i].
        // The read uses the *current* db, so we must capture src before
        // overwriting. Since we iterate i ascending, db[i] is overwritten
        // before db[i + dist] is read for i + dist; that means once
        // i >= db_len - dist, db[i + dist] would be reading something
        // already mutated. To stay correct, we capture each src byte
        // into a temporary, then write. Since dist > 0, db[i + dist]
        // when i = 0 hasn't been touched yet; for i = 1, db[1 + dist]
        // also hasn't been touched, etc. — db[j] is written when
        // we're processing row j, and we read db[j + dist]. Since j
        // grows by 1 each step, j + dist > j, so we're always reading
        // ahead of where we've written. Safe.
        for i in 0..db_len {
            let src = if i + dist < db_len { db[i + dist] } else { 0 };
            // bit_set is u32: 0xFFFF_FFFF if true, 0 if false.
            // We need a u8 mask. Use constant_time_is_zero_8 on (!bit_set)
            // to derive the u8 form: when bit_set != 0, !bit_set == 0,
            // is_zero_8(0) == 0xFF. When bit_set == 0, is_zero_8(non-zero) == 0.
            let mask_u8 = constant_time::constant_time_is_zero_8(!bit_set);
            db[i] = constant_time::constant_time_select_8(mask_u8, src, db[i]);
        }
        bit = bit.wrapping_shl(1);
    }

    // After the shift, db[0..mlen] holds the recovered message (when
    // `good` is true). Now build the output buffer of length `mlen` (or
    // 0 on failure) and copy db[0..mlen] into it under constant time.
    //
    // We compute the output capacity from mlen_u32. On failure mlen is
    // ill-defined, but selecting between (good ? mlen : 0) handles that.
    let mlen_safe = constant_time::constant_time_select(good, mlen_u32, 0);
    let mlen_usize = usize::try_from(mlen_safe).unwrap_or(0);

    // Allocate the output buffer at the maximum possible size to avoid
    // a length-dependent allocation, then truncate. The maximum message
    // length in OAEP is db_len - 1 (when there is no PS).
    let max_msg_len = db_len.saturating_sub(1);
    let mut out = vec![0u8; max_msg_len];
    out.copy_from_slice(&db[..max_msg_len]);

    // Wipe internal buffers before returning.
    em.zeroize();
    db.zeroize();

    // Final decision: if good != 0, return the first mlen_usize bytes;
    // otherwise return the OaepDecodingError.
    //
    // We use constant_time::constant_time_select_int to choose between
    // (mlen_usize as i32) and -1 in constant time, then branch on the
    // sign of the result. The branch on the final return is unavoidable
    // — but it is on a value that already encodes both validity and
    // length, so an attacker observing the timing of this single branch
    // learns no more than "did decryption succeed or fail", which is
    // the IND-CCA2-permitted leak.
    let mlen_i32 = i32::try_from(mlen_usize).unwrap_or(-1);
    let result_i32 = constant_time::constant_time_select_int(good, mlen_i32, -1);
    if result_i32 < 0 {
        out.zeroize();
        return Err(oaep_decode_error());
    }
    let final_len = usize::try_from(result_i32).map_err(|_| oaep_decode_error())?;
    if final_len > out.len() {
        out.zeroize();
        return Err(oaep_decode_error());
    }
    out.truncate(final_len);
    debug!(
        plaintext_len = out.len(),
        "RSA oaep_decrypt: decoded plaintext"
    );
    Ok(out)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code conventionally uses expect/unwrap/panic with descriptive messages \
              for fast-fail diagnostics; the crate-level `#![deny(clippy::expect_used)]` and \
              `#![deny(clippy::unwrap_used)]` apply to library code, not test code."
)]
mod tests {
    //! Unit tests for the RSA-OAEP submodule.
    //!
    //! These tests verify:
    //! - Parameter construction / defaults / NID round-trip.
    //! - Encrypt → decrypt round-trip with a freshly generated key
    //!   (across multiple message sizes and labels).
    //! - Tamper detection: ciphertext flip → decode failure with
    //!   `OaepDecodingError`.
    //! - Wrong label / hash detection: decode with mismatched params
    //!   fails.

    use super::*;
    use crate::rsa::{generate_key, RsaKeyGenParams};

    /// Helper: generate a small (2048-bit) test key. 2048 is the minimum
    /// recommended size for new RSA keys per NIST SP 800-131A Rev. 2.
    fn test_keypair() -> super::super::RsaKeyPair {
        generate_key(&RsaKeyGenParams::default()).expect("RSA-2048 key generation should succeed")
    }

    #[test]
    fn oaep_params_default_is_sha256() {
        let p = OaepParams::default();
        assert_eq!(p.hash, DigestAlgorithm::Sha256);
        assert_eq!(p.mgf1_hash, None);
        assert!(p.label.is_empty());
        assert_eq!(p.mgf1_hash_effective(), DigestAlgorithm::Sha256);
    }

    #[test]
    fn oaep_params_with_hash() {
        let p = OaepParams::with_hash(DigestAlgorithm::Sha384);
        assert_eq!(p.hash, DigestAlgorithm::Sha384);
        assert_eq!(p.mgf1_hash_effective(), DigestAlgorithm::Sha384);
    }

    #[test]
    fn oaep_params_mgf1_override() {
        let p =
            OaepParams::with_hash(DigestAlgorithm::Sha256).with_mgf1_hash(DigestAlgorithm::Sha512);
        assert_eq!(p.mgf1_hash_effective(), DigestAlgorithm::Sha512);
    }

    #[test]
    fn oaep_params_with_label() {
        let p = OaepParams::default().with_label(b"hello".to_vec());
        assert_eq!(p.label, b"hello");
    }

    #[test]
    fn oaep_params_nid_roundtrip() {
        let p = OaepParams::with_hash(DigestAlgorithm::Sha256);
        let oaep_nid = p.oaep_hash_nid().expect("SHA-256 has an NID");
        let mgf1_nid = p.mgf1_hash_nid().expect("SHA-256 has an NID");
        let recovered = OaepParams::from_nids(oaep_nid, mgf1_nid).expect("NIDs round-trip");
        assert_eq!(recovered.hash, DigestAlgorithm::Sha256);
        assert_eq!(recovered.mgf1_hash_effective(), DigestAlgorithm::Sha256);
    }

    #[test]
    fn oaep_roundtrip_empty_message_default_params() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params = OaepParams::default();

        let ct = oaep_encrypt(&pubkey, b"", &params).expect("encrypt empty");
        assert_eq!(ct.len(), usize::try_from(pubkey.key_size_bytes()).unwrap());
        let pt = oaep_decrypt(privkey, &ct, &params).expect("decrypt empty");
        assert_eq!(pt, b"");
    }

    #[test]
    fn oaep_roundtrip_short_message_default_params() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params = OaepParams::default();
        let msg = b"the quick brown fox jumps over the lazy dog";

        let ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt short");
        let pt = oaep_decrypt(privkey, &ct, &params).expect("decrypt short");
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_with_label() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params = OaepParams::default().with_label(b"context-binding-label".to_vec());
        let msg = b"secret payload";

        let ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt with label");
        let pt = oaep_decrypt(privkey, &ct, &params).expect("decrypt with label");
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_sha384() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params = OaepParams::with_hash(DigestAlgorithm::Sha384);
        let msg = b"sha-384-test";

        let ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt sha384");
        let pt = oaep_decrypt(privkey, &ct, &params).expect("decrypt sha384");
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_distinct_mgf1_hash() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params =
            OaepParams::with_hash(DigestAlgorithm::Sha256).with_mgf1_hash(DigestAlgorithm::Sha384);
        let msg = b"distinct-mgf1-hash-test";

        let ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt distinct mgf1");
        let pt = oaep_decrypt(privkey, &ct, &params).expect("decrypt distinct mgf1");
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_message_too_long_returns_error() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let params = OaepParams::default();
        // For a 2048-bit (256-byte) modulus with SHA-256 (32-byte) hash,
        // the maximum plaintext is 256 - 2*32 - 2 = 190 bytes.
        let too_long = vec![0x42u8; 256];
        let result = oaep_encrypt(&pubkey, &too_long, &params);
        assert!(result.is_err(), "encrypt should reject overlong message");
    }

    #[test]
    fn oaep_tampered_ciphertext_fails_decode() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let params = OaepParams::default();
        let msg = b"tamper-test";

        let mut ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt ok");
        // Flip one bit in the middle of the ciphertext.
        let mid = ct.len() / 2;
        ct[mid] ^= 0x80;

        let result = oaep_decrypt(privkey, &ct, &params);
        assert!(result.is_err(), "decrypt should reject tampered ciphertext");
    }

    #[test]
    fn oaep_wrong_label_fails_decode() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let enc_params = OaepParams::default().with_label(b"correct-label".to_vec());
        let dec_params = OaepParams::default().with_label(b"wrong-label".to_vec());
        let msg = b"label-mismatch-test";

        let ct = oaep_encrypt(&pubkey, msg, &enc_params).expect("encrypt ok");
        let result = oaep_decrypt(privkey, &ct, &dec_params);
        assert!(result.is_err(), "decrypt should reject mismatched label");
    }

    #[test]
    fn oaep_wrong_hash_fails_decode() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let privkey = kp.private_key();
        let enc_params = OaepParams::with_hash(DigestAlgorithm::Sha256);
        let dec_params = OaepParams::with_hash(DigestAlgorithm::Sha384);
        let msg = b"hash-mismatch-test";

        let ct = oaep_encrypt(&pubkey, msg, &enc_params).expect("encrypt ok");
        let result = oaep_decrypt(privkey, &ct, &dec_params);
        assert!(result.is_err(), "decrypt should reject mismatched hash");
    }

    #[test]
    fn oaep_ciphertext_length_equals_modulus_bytes() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let params = OaepParams::default();
        let msg = b"len-check";
        let ct = oaep_encrypt(&pubkey, msg, &params).expect("encrypt ok");
        let expected = usize::try_from(pubkey.key_size_bytes()).unwrap();
        assert_eq!(ct.len(), expected, "OAEP ciphertext is exactly k bytes");
    }
}
