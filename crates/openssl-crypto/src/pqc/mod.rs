//! Post-Quantum Cryptography (PQC) module for the OpenSSL Rust workspace.
//!
//! Provides idiomatic Rust implementations of NIST-standardized post-quantum
//! algorithms, translated from the OpenSSL 4.0 C source code under
//! `crypto/ml_kem/`, `crypto/ml_dsa/`, `crypto/slh_dsa/`, and `crypto/lms/`.
//!
//! # Included Algorithms
//!
//! - **ML-KEM** ([`ml_kem`]) — Module-Lattice-Based Key Encapsulation Mechanism
//!   (FIPS 203, August 2024). Provides post-quantum key establishment via the
//!   ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets at NIST security
//!   categories 1, 3, and 5 respectively.
//!
//! - **ML-DSA** ([`ml_dsa`]) — Module-Lattice-Based Digital Signature Algorithm
//!   (FIPS 204). Provides post-quantum digital signatures via the ML-DSA-44,
//!   ML-DSA-65, and ML-DSA-87 parameter sets at NIST security categories 2, 3,
//!   and 5 respectively.
//!
//! - **SLH-DSA** ([`slh_dsa`]) — Stateless Hash-Based Digital Signature Algorithm
//!   (FIPS 205). Provides hash-based post-quantum signatures across all 12
//!   standardised parameter sets, spanning the SHA-2 and SHAKE hash families at
//!   128/192/256-bit security in both slow (`s`) and fast (`f`) variants.
//!
//! - **LMS** ([`lms`]) — Leighton-Micali Hash-Based Signature scheme
//!   (NIST SP 800-208, RFC 8554). **Verification-only** — this matches OpenSSL's
//!   upstream implementation which also provides only verification (no signing
//!   or key generation). Supports all 5 RFC 8554 LMS parameter sets plus 15
//!   SP 800-208 SHAKE-based and SHA-256/192-truncated additions (20 LMS
//!   parameter sets total) and all 16 LM-OTS parameter sets.
//!
//! # Feature Gating
//!
//! The entire `pqc` module is gated behind the `pqc` Cargo feature (enabled by
//! default). This allows constrained builds to exclude the post-quantum
//! algorithms when they are not required:
//!
//! ```toml
//! [dependencies]
//! openssl-crypto = { path = "..", default-features = false, features = ["pqc"] }
//! ```
//!
//! # Unified Algorithm Identifier
//!
//! The [`PqcAlgorithm`] enum provides a single discriminator covering every
//! supported PQC parameter set. It is useful for parameterised provider
//! dispatch, configuration parsing, and error reporting:
//!
//! ```rust
//! use openssl_crypto::pqc::PqcAlgorithm;
//!
//! let alg = PqcAlgorithm::from_name("ML-KEM-768").unwrap();
//! assert_eq!(alg.algorithm_name(), "ML-KEM-768");
//! assert_eq!(alg.security_category(), 3);
//! assert!(alg.is_kem());
//! assert!(!alg.is_signature());
//! assert!(alg.is_fips_approved());
//! ```
//!
//! # Key Material Security
//!
//! All key types in this module (`MlKemKey`, `MlDsaKey`, `SlhDsaKey`, `LmsKey`)
//! implement [`zeroize::ZeroizeOnDrop`] in their respective submodules, ensuring
//! that private key material is securely erased from memory when keys are
//! dropped. This satisfies FIPS 140-3 secure-zeroization requirements.
//!
//! # Standards Conformance
//!
//! - NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard*
//!   (August 2024).
//! - NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard*
//!   (August 2024).
//! - NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard*
//!   (August 2024).
//! - NIST SP 800-208: *Recommendation for Stateful Hash-Based Signature
//!   Schemes* (October 2020).
//! - RFC 8554: *Leighton-Micali Hash-Based Signatures* (April 2019).

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use bitflags::bitflags;
use std::fmt;

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

pub mod ml_kem;
pub mod ml_dsa;
pub mod slh_dsa;
pub mod lms;

// ---------------------------------------------------------------------------
// Re-exports — primary public types from each submodule.
//
// This list mirrors the schema-mandated `members_exposed` for the `pqc`
// module hub. Note that submodule-local types like `KeySelection`,
// `MlDsaSig`, `SlhHashFunc`, `LmsType`, and `LmOtsType` are intentionally
// *not* re-exported here — they remain accessible via `pqc::ml_dsa::*`,
// `pqc::slh_dsa::*`, `pqc::lms::*` to avoid namespace collisions and keep
// the top-level surface focused on the most commonly used types.
// ---------------------------------------------------------------------------

// Re-export groups are separated by blank lines so that rustfmt's
// `reorder_imports` lint does not collapse them into a single
// alphabetically-sorted block — the FIPS-standard ordering
// (ML-KEM → ML-DSA → SLH-DSA → LMS) is deliberate documentation
// matching the submodule declaration order above.

pub use ml_kem::{MlKemKey, MlKemParams, MlKemVariant};

pub use ml_dsa::{MlDsaKey, MlDsaParams, MlDsaVariant};

pub use slh_dsa::{SlhDsaKey, SlhDsaParams, SlhDsaVariant};

pub use lms::{LmOtsParams, LmsKey, LmsParams};

// ---------------------------------------------------------------------------
// PqcAlgorithm — unified algorithm identifier
// ---------------------------------------------------------------------------

/// Enumerates every post-quantum cryptographic algorithm supported by this
/// crate.
///
/// `PqcAlgorithm` provides a single, exhaustive discriminator across the four
/// PQC algorithm families: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA
/// (FIPS 205), and LMS (NIST SP 800-208 / RFC 8554). It is intended for use in
/// configuration parsing, provider dispatch tables, and diagnostic reporting,
/// where a single typed value can identify any PQC parameter set.
///
/// # Naming Convention
///
/// Variant names follow OpenSSL's canonical algorithm-name convention with
/// internal underscores to denote security level + speed (e.g.
/// `SlhDsaSha2_128s` corresponds to the canonical `"SLH-DSA-SHA2-128s"`
/// algorithm name). The trailing `s`/`f` indicate slow (smaller signatures) /
/// fast (larger signatures) parameter sets per FIPS 205. The
/// `non_camel_case_types` lint is allowed so that the trailing `_128s`,
/// `_192f`, etc. suffixes can match the FIPS 205 spelling exactly.
///
/// # NIST Security Categories
///
/// The [`security_category`](Self::security_category) method returns the
/// associated NIST PQC security category as an unsigned integer:
///
/// | Category | Equivalent classical strength       |
/// |----------|-------------------------------------|
/// | 1        | At least as hard as AES-128 KS      |
/// | 2        | At least as hard as SHA-256 col.    |
/// | 3        | At least as hard as AES-192 KS      |
/// | 5        | At least as hard as AES-256 KS      |
///
/// (Category 4 is reserved by NIST and is not used by any current standard.)
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcAlgorithm {
    // -- ML-KEM variants (FIPS 203) ----------------------------------------
    /// ML-KEM-512 — NIST security category 1 (≈128-bit). KEM.
    MlKem512,
    /// ML-KEM-768 — NIST security category 3 (≈192-bit). KEM.
    MlKem768,
    /// ML-KEM-1024 — NIST security category 5 (≈256-bit). KEM.
    MlKem1024,

    // -- ML-DSA variants (FIPS 204) ----------------------------------------
    /// ML-DSA-44 — NIST security category 2 (≈128-bit). Digital signature.
    MlDsa44,
    /// ML-DSA-65 — NIST security category 3 (≈192-bit). Digital signature.
    MlDsa65,
    /// ML-DSA-87 — NIST security category 5 (≈256-bit). Digital signature.
    MlDsa87,

    // -- SLH-DSA 128-bit variants (FIPS 205) -------------------------------
    /// SLH-DSA-SHA2-128s — slow, SHA-2, NIST category 1. Smaller signatures,
    /// slower keygen/sign.
    SlhDsaSha2_128s,
    /// SLH-DSA-SHAKE-128s — slow, SHAKE, NIST category 1.
    SlhDsaShake_128s,
    /// SLH-DSA-SHA2-128f — fast, SHA-2, NIST category 1. Larger signatures,
    /// faster keygen/sign.
    SlhDsaSha2_128f,
    /// SLH-DSA-SHAKE-128f — fast, SHAKE, NIST category 1.
    SlhDsaShake_128f,

    // -- SLH-DSA 192-bit variants (FIPS 205) -------------------------------
    /// SLH-DSA-SHA2-192s — slow, SHA-2, NIST category 3.
    SlhDsaSha2_192s,
    /// SLH-DSA-SHAKE-192s — slow, SHAKE, NIST category 3.
    SlhDsaShake_192s,
    /// SLH-DSA-SHA2-192f — fast, SHA-2, NIST category 3.
    SlhDsaSha2_192f,
    /// SLH-DSA-SHAKE-192f — fast, SHAKE, NIST category 3.
    SlhDsaShake_192f,

    // -- SLH-DSA 256-bit variants (FIPS 205) -------------------------------
    /// SLH-DSA-SHA2-256s — slow, SHA-2, NIST category 5.
    SlhDsaSha2_256s,
    /// SLH-DSA-SHAKE-256s — slow, SHAKE, NIST category 5.
    SlhDsaShake_256s,
    /// SLH-DSA-SHA2-256f — fast, SHA-2, NIST category 5.
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-256f — fast, SHAKE, NIST category 5.
    SlhDsaShake_256f,

    // -- LMS (NIST SP 800-208 / RFC 8554) ----------------------------------
    /// LMS — Leighton-Micali Hash-Based Signature, **verification only**.
    /// Single algorithm family covering all 20 RFC 8554 / SP 800-208
    /// parameter sets. Not a FIPS standard (SP 800-208 is a Recommendation,
    /// not a FIPS document).
    Lms,
}

impl PqcAlgorithm {
    /// Returns the canonical algorithm-name string for this variant.
    ///
    /// The returned name is the NIST/OpenSSL canonical spelling — e.g.
    /// `"ML-KEM-512"`, `"SLH-DSA-SHAKE-128f"`, `"LMS"`. These names match the
    /// `alg` field of the corresponding `*_PARAMS` table in the upstream C
    /// source (e.g. `crypto/ml_dsa/ml_dsa_params.c` and
    /// `crypto/slh_dsa/slh_params.c`).
    ///
    /// The returned string slice has `'static` lifetime — it is a string
    /// literal embedded in the binary, never an owned buffer.
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",

            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",

            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Self::SlhDsaShake_128s => "SLH-DSA-SHAKE-128s",
            Self::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Self::SlhDsaShake_128f => "SLH-DSA-SHAKE-128f",

            Self::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Self::SlhDsaShake_192s => "SLH-DSA-SHAKE-192s",
            Self::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Self::SlhDsaShake_192f => "SLH-DSA-SHAKE-192f",

            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            Self::SlhDsaShake_256s => "SLH-DSA-SHAKE-256s",
            Self::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Self::SlhDsaShake_256f => "SLH-DSA-SHAKE-256f",

            Self::Lms => "LMS",
        }
    }

    /// Returns the NIST PQC security category for this variant.
    ///
    /// The categories are defined by NIST as:
    /// - **1** — at least as hard to break as AES-128 key search
    /// - **2** — at least as hard as a SHA-256 collision search
    /// - **3** — at least as hard as AES-192 key search
    /// - **5** — at least as hard as AES-256 key search
    ///
    /// Category 4 is reserved and currently unused by any standardised
    /// algorithm.
    ///
    /// LMS returns category `5` because, in its strongest commonly-deployed
    /// configuration (SHA-256 with `n = 32`), it offers ≥256-bit collision
    /// resistance comparable to AES-256.
    #[must_use]
    // The match is intentionally structured by FIPS standard family
    // (ML-KEM / ML-DSA / SLH-DSA / LMS) rather than by category number, so
    // that each arm directly mirrors the source FIPS specification table
    // and can be cross-referenced with FIPS 203 §4.1, FIPS 204 §4 Table 1,
    // and FIPS 205 §11 Table 2. Merging arms with identical right-hand
    // sides (as `clippy::match_same_arms` would suggest) would obscure
    // this per-standard structure and make spec compliance harder to
    // audit. The duplication is therefore deliberate documentation, not
    // accidental redundancy.
    #[allow(clippy::match_same_arms)]
    pub fn security_category(&self) -> u32 {
        match self {
            // ML-KEM mappings — see FIPS 203 §4.1.
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,

            // ML-DSA mappings — see FIPS 204 §4 Table 1.
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,

            // SLH-DSA mappings — see FIPS 205 §11 Table 2.
            Self::SlhDsaSha2_128s
            | Self::SlhDsaShake_128s
            | Self::SlhDsaSha2_128f
            | Self::SlhDsaShake_128f => 1,
            Self::SlhDsaSha2_192s
            | Self::SlhDsaShake_192s
            | Self::SlhDsaSha2_192f
            | Self::SlhDsaShake_192f => 3,
            Self::SlhDsaSha2_256s
            | Self::SlhDsaShake_256s
            | Self::SlhDsaSha2_256f
            | Self::SlhDsaShake_256f => 5,

            // LMS — strongest configuration ≈ AES-256 strength.
            Self::Lms => 5,
        }
    }

    /// Returns `true` if the algorithm is a Key Encapsulation Mechanism (KEM).
    ///
    /// In the current standardised PQC algorithm set, only the ML-KEM variants
    /// (FIPS 203) are KEMs. Signature schemes return `false`.
    #[must_use]
    pub fn is_kem(&self) -> bool {
        matches!(self, Self::MlKem512 | Self::MlKem768 | Self::MlKem1024)
    }

    /// Returns `true` if the algorithm is a digital-signature scheme.
    ///
    /// All ML-DSA, SLH-DSA, and LMS variants are signature schemes; the
    /// ML-KEM variants are KEMs and return `false`.
    ///
    /// `is_kem()` and `is_signature()` are mutually exclusive — every
    /// `PqcAlgorithm` is exactly one of the two.
    #[must_use]
    pub fn is_signature(&self) -> bool {
        !self.is_kem()
    }

    /// Looks up a `PqcAlgorithm` by its canonical name.
    ///
    /// The lookup is **case-insensitive**: `"ml-kem-512"`, `"ML-KEM-512"`,
    /// and `"Ml-Kem-512"` all return `Some(PqcAlgorithm::MlKem512)`. Returns
    /// [`None`] when no algorithm matches.
    ///
    /// Per Rule R5 (nullability over sentinels), this function returns
    /// `Option<Self>` rather than a sentinel value such as `None`/`-1`/`0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::pqc::PqcAlgorithm;
    ///
    /// assert_eq!(
    ///     PqcAlgorithm::from_name("ML-DSA-65"),
    ///     Some(PqcAlgorithm::MlDsa65),
    /// );
    /// assert_eq!(
    ///     PqcAlgorithm::from_name("slh-dsa-shake-256f"),
    ///     Some(PqcAlgorithm::SlhDsaShake_256f),
    /// );
    /// assert_eq!(PqcAlgorithm::from_name("not-a-real-algorithm"), None);
    /// ```
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        // Iterate over the (canonical-name, variant) tuple list and perform
        // a case-insensitive ASCII comparison against each entry. The list
        // is small (19 entries) so linear scan is more than fast enough.
        for (canonical, alg) in NAME_TABLE {
            if canonical.eq_ignore_ascii_case(name) {
                return Some(*alg);
            }
        }
        None
    }

    /// Returns `true` if the algorithm is approved by a NIST FIPS standard.
    ///
    /// FIPS-approved algorithms are those defined by FIPS 203, FIPS 204, and
    /// FIPS 205 — i.e. ML-KEM, ML-DSA, and SLH-DSA respectively.
    ///
    /// LMS (NIST SP 800-208 / RFC 8554) is *not* defined by a FIPS standard
    /// but rather by a NIST Special Publication, so this function returns
    /// `false` for `PqcAlgorithm::Lms`. Note that LMS is nonetheless
    /// FIPS 140-3 *acceptable* via SP 800-208 referenced from FIPS 140-3
    /// implementation guidance — the distinction here is whether the
    /// algorithm is itself a FIPS standard.
    #[must_use]
    pub fn is_fips_approved(&self) -> bool {
        // LMS is defined by NIST SP 800-208 / RFC 8554, *not* by a FIPS
        // standard, so it is the sole non-FIPS variant in this enum. All
        // ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205)
        // variants are FIPS-approved. Encoding the rule as "everything
        // except LMS" rather than enumerating the 18 FIPS variants keeps
        // the function correct-by-construction: any future PQC variant
        // added to `PqcAlgorithm` will default to FIPS-approved unless
        // explicitly excluded here, which matches NIST's standardisation
        // direction (the next standardised PQC algorithms are expected
        // to ship as FIPS 206+).
        !matches!(self, Self::Lms)
    }
}

/// Canonical-name to [`PqcAlgorithm`] lookup table used by
/// [`PqcAlgorithm::from_name`] and [`pqc_algorithm_for_name`].
///
/// The table is exhaustive: it contains exactly one entry for each variant
/// of `PqcAlgorithm`, in the same order as the enum declaration. The
/// canonical names match the strings returned by
/// [`PqcAlgorithm::algorithm_name`].
const NAME_TABLE: &[(&str, PqcAlgorithm)] = &[
    ("ML-KEM-512", PqcAlgorithm::MlKem512),
    ("ML-KEM-768", PqcAlgorithm::MlKem768),
    ("ML-KEM-1024", PqcAlgorithm::MlKem1024),
    ("ML-DSA-44", PqcAlgorithm::MlDsa44),
    ("ML-DSA-65", PqcAlgorithm::MlDsa65),
    ("ML-DSA-87", PqcAlgorithm::MlDsa87),
    ("SLH-DSA-SHA2-128s", PqcAlgorithm::SlhDsaSha2_128s),
    ("SLH-DSA-SHAKE-128s", PqcAlgorithm::SlhDsaShake_128s),
    ("SLH-DSA-SHA2-128f", PqcAlgorithm::SlhDsaSha2_128f),
    ("SLH-DSA-SHAKE-128f", PqcAlgorithm::SlhDsaShake_128f),
    ("SLH-DSA-SHA2-192s", PqcAlgorithm::SlhDsaSha2_192s),
    ("SLH-DSA-SHAKE-192s", PqcAlgorithm::SlhDsaShake_192s),
    ("SLH-DSA-SHA2-192f", PqcAlgorithm::SlhDsaSha2_192f),
    ("SLH-DSA-SHAKE-192f", PqcAlgorithm::SlhDsaShake_192f),
    ("SLH-DSA-SHA2-256s", PqcAlgorithm::SlhDsaSha2_256s),
    ("SLH-DSA-SHAKE-256s", PqcAlgorithm::SlhDsaShake_256s),
    ("SLH-DSA-SHA2-256f", PqcAlgorithm::SlhDsaSha2_256f),
    ("SLH-DSA-SHAKE-256f", PqcAlgorithm::SlhDsaShake_256f),
    ("LMS", PqcAlgorithm::Lms),
];

impl fmt::Display for PqcAlgorithm {
    /// Writes the canonical algorithm name (as returned by
    /// [`PqcAlgorithm::algorithm_name`]) to the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.algorithm_name())
    }
}

// ---------------------------------------------------------------------------
// KeySelection — typed key-component selector flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Selection flags identifying which key component(s) an operation
    /// applies to.
    ///
    /// `KeySelection` is the cross-algorithm replacement for OpenSSL's
    /// `OSSL_KEYMGMT_SELECT_*` defines (`select_pub_key`, `select_priv_key`,
    /// `select_keypair`). It is used by key-management operations that may
    /// affect either the public component, the private component, or both —
    /// for example `MlDsaKey::dup`, `SlhDsaKey::pairwise_check`, and
    /// `LmsKey::is_valid`.
    ///
    /// The struct provides the standard bitflags methods automatically:
    /// [`bits`](Self::bits), [`contains`](Self::contains),
    /// [`is_empty`](Self::is_empty), and [`is_all`](Self::is_all).
    ///
    /// # Compatibility With OpenSSL Constants
    ///
    /// | OpenSSL `#define`                       | Rust `KeySelection`         |
    /// |-----------------------------------------|-----------------------------|
    /// | `OSSL_KEYMGMT_SELECT_PUBLIC_KEY` (0x01) | [`KeySelection::PUBLIC`]    |
    /// | `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`(0x02) | [`KeySelection::PRIVATE`]   |
    /// | `OSSL_KEYMGMT_SELECT_KEYPAIR` (0x03)    | [`KeySelection::ALL`]       |
    ///
    /// (The OpenSSL constants `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` and
    /// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` are not represented here as no
    /// PQC algorithm in this crate uses them.)
    ///
    /// # Example
    ///
    /// ```
    /// use openssl_crypto::pqc::KeySelection;
    ///
    /// let sel = KeySelection::PUBLIC | KeySelection::PRIVATE;
    /// assert!(sel.contains(KeySelection::PUBLIC));
    /// assert!(sel.contains(KeySelection::PRIVATE));
    /// assert_eq!(sel, KeySelection::ALL);
    /// assert!(sel.is_all());
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeySelection: u32 {
        /// Public-key components only (e.g. ML-KEM `ek`, ML-DSA `t1`/`rho`,
        /// SLH-DSA `PK.seed`/`PK.root`, LMS `pub`).
        const PUBLIC = 0x01;
        /// Private-key components only (e.g. ML-KEM `dk`, ML-DSA `s1`/`s2`/
        /// `t0`/`K`, SLH-DSA `SK.seed`/`SK.prf`).
        const PRIVATE = 0x02;
        /// Both public and private components — the union of `PUBLIC` and
        /// `PRIVATE`. Equivalent to OpenSSL's
        /// `OSSL_KEYMGMT_SELECT_KEYPAIR`.
        const ALL = Self::PUBLIC.bits() | Self::PRIVATE.bits();
    }
}

// ---------------------------------------------------------------------------
// Top-level convenience: pqc_algorithm_for_name
// ---------------------------------------------------------------------------

/// Looks up a `PqcAlgorithm` by canonical name across all PQC submodules.
///
/// This is the top-level convenience function that delegates to each PQC
/// submodule's parameter-table lookup in turn (`ml_kem`, `ml_dsa`, `slh_dsa`)
/// as a fast path, then falls back to the unified [`NAME_TABLE`]-based
/// case-insensitive lookup performed by [`PqcAlgorithm::from_name`]. The
/// fast-path delegation ensures the algorithm-name table maintained in
/// `mod.rs` stays consistent with the per-submodule parameter tables: any
/// canonical name reachable through a submodule must round-trip through this
/// function.
///
/// Like [`PqcAlgorithm::from_name`] this function is **case-insensitive**:
/// `"ml-kem-512"` and `"ML-KEM-512"` both yield `Some(PqcAlgorithm::MlKem512)`.
///
/// Per Rule R5 (nullability over sentinels), this returns `Option<_>` rather
/// than a sentinel value.
///
/// # Examples
///
/// ```
/// use openssl_crypto::pqc::{pqc_algorithm_for_name, PqcAlgorithm};
///
/// assert_eq!(
///     pqc_algorithm_for_name("ML-KEM-1024"),
///     Some(PqcAlgorithm::MlKem1024),
/// );
/// assert_eq!(
///     pqc_algorithm_for_name("LMS"),
///     Some(PqcAlgorithm::Lms),
/// );
/// assert_eq!(pqc_algorithm_for_name("nonexistent"), None);
/// ```
#[must_use]
pub fn pqc_algorithm_for_name(name: &str) -> Option<PqcAlgorithm> {
    // ---- Fast path: delegate to each submodule's case-sensitive lookup -
    //
    // The submodule helpers (`ml_kem_params_get_by_name`,
    // `ml_dsa_params_get_by_name`, `slh_dsa_params_get`) all use exact
    // string match against their canonical names. When the caller provides
    // the canonical spelling we satisfy the request without consulting the
    // top-level table.

    if let Some(params) = ml_kem::ml_kem_params_get_by_name(name) {
        return Some(match params.variant {
            MlKemVariant::MlKem512 => PqcAlgorithm::MlKem512,
            MlKemVariant::MlKem768 => PqcAlgorithm::MlKem768,
            MlKemVariant::MlKem1024 => PqcAlgorithm::MlKem1024,
        });
    }

    if let Some(params) = ml_dsa::ml_dsa_params_get_by_name(name) {
        return Some(match params.variant {
            MlDsaVariant::MlDsa44 => PqcAlgorithm::MlDsa44,
            MlDsaVariant::MlDsa65 => PqcAlgorithm::MlDsa65,
            MlDsaVariant::MlDsa87 => PqcAlgorithm::MlDsa87,
        });
    }

    if let Some(params) = slh_dsa::slh_dsa_params_get(name) {
        return Some(match params.variant {
            SlhDsaVariant::Sha2_128s => PqcAlgorithm::SlhDsaSha2_128s,
            SlhDsaVariant::Shake_128s => PqcAlgorithm::SlhDsaShake_128s,
            SlhDsaVariant::Sha2_128f => PqcAlgorithm::SlhDsaSha2_128f,
            SlhDsaVariant::Shake_128f => PqcAlgorithm::SlhDsaShake_128f,
            SlhDsaVariant::Sha2_192s => PqcAlgorithm::SlhDsaSha2_192s,
            SlhDsaVariant::Shake_192s => PqcAlgorithm::SlhDsaShake_192s,
            SlhDsaVariant::Sha2_192f => PqcAlgorithm::SlhDsaSha2_192f,
            SlhDsaVariant::Shake_192f => PqcAlgorithm::SlhDsaShake_192f,
            SlhDsaVariant::Sha2_256s => PqcAlgorithm::SlhDsaSha2_256s,
            SlhDsaVariant::Shake_256s => PqcAlgorithm::SlhDsaShake_256s,
            SlhDsaVariant::Sha2_256f => PqcAlgorithm::SlhDsaSha2_256f,
            SlhDsaVariant::Shake_256f => PqcAlgorithm::SlhDsaShake_256f,
        });
    }

    // ---- Slow path: case-insensitive unified lookup ---------------------
    //
    // Falls back to [`PqcAlgorithm::from_name`] which performs a
    // case-insensitive scan over [`NAME_TABLE`]. This branch covers the
    // bare `"LMS"` name (which has no case-sensitive submodule lookup
    // because LMS has 20 parameter sets compressed into the single
    // `PqcAlgorithm::Lms` discriminant) plus any case-insensitive matches
    // that the case-sensitive submodule helpers above did not catch.
    PqcAlgorithm::from_name(name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `PqcAlgorithm::algorithm_name` value must be the canonical
    /// upper-cased OpenSSL spelling, matching the C source tables.
    #[test]
    fn algorithm_names_are_canonical() {
        assert_eq!(PqcAlgorithm::MlKem512.algorithm_name(), "ML-KEM-512");
        assert_eq!(PqcAlgorithm::MlKem768.algorithm_name(), "ML-KEM-768");
        assert_eq!(PqcAlgorithm::MlKem1024.algorithm_name(), "ML-KEM-1024");

        assert_eq!(PqcAlgorithm::MlDsa44.algorithm_name(), "ML-DSA-44");
        assert_eq!(PqcAlgorithm::MlDsa65.algorithm_name(), "ML-DSA-65");
        assert_eq!(PqcAlgorithm::MlDsa87.algorithm_name(), "ML-DSA-87");

        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_128s.algorithm_name(),
            "SLH-DSA-SHA2-128s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_128s.algorithm_name(),
            "SLH-DSA-SHAKE-128s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_128f.algorithm_name(),
            "SLH-DSA-SHA2-128f"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_128f.algorithm_name(),
            "SLH-DSA-SHAKE-128f"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_192s.algorithm_name(),
            "SLH-DSA-SHA2-192s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_192s.algorithm_name(),
            "SLH-DSA-SHAKE-192s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_192f.algorithm_name(),
            "SLH-DSA-SHA2-192f"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_192f.algorithm_name(),
            "SLH-DSA-SHAKE-192f"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_256s.algorithm_name(),
            "SLH-DSA-SHA2-256s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_256s.algorithm_name(),
            "SLH-DSA-SHAKE-256s"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaSha2_256f.algorithm_name(),
            "SLH-DSA-SHA2-256f"
        );
        assert_eq!(
            PqcAlgorithm::SlhDsaShake_256f.algorithm_name(),
            "SLH-DSA-SHAKE-256f"
        );

        assert_eq!(PqcAlgorithm::Lms.algorithm_name(), "LMS");
    }

    /// Verify that every NIST security category mapping matches the upstream
    /// C parameter tables exactly.
    #[test]
    fn security_categories_match_fips_specs() {
        // FIPS 203 — ML-KEM.
        assert_eq!(PqcAlgorithm::MlKem512.security_category(), 1);
        assert_eq!(PqcAlgorithm::MlKem768.security_category(), 3);
        assert_eq!(PqcAlgorithm::MlKem1024.security_category(), 5);

        // FIPS 204 — ML-DSA (matches `ml_dsa_params.c`).
        assert_eq!(PqcAlgorithm::MlDsa44.security_category(), 2);
        assert_eq!(PqcAlgorithm::MlDsa65.security_category(), 3);
        assert_eq!(PqcAlgorithm::MlDsa87.security_category(), 5);

        // FIPS 205 — SLH-DSA (matches `slh_params.c`).
        for v in [
            PqcAlgorithm::SlhDsaSha2_128s,
            PqcAlgorithm::SlhDsaShake_128s,
            PqcAlgorithm::SlhDsaSha2_128f,
            PqcAlgorithm::SlhDsaShake_128f,
        ] {
            assert_eq!(v.security_category(), 1, "{v:?}");
        }
        for v in [
            PqcAlgorithm::SlhDsaSha2_192s,
            PqcAlgorithm::SlhDsaShake_192s,
            PqcAlgorithm::SlhDsaSha2_192f,
            PqcAlgorithm::SlhDsaShake_192f,
        ] {
            assert_eq!(v.security_category(), 3, "{v:?}");
        }
        for v in [
            PqcAlgorithm::SlhDsaSha2_256s,
            PqcAlgorithm::SlhDsaShake_256s,
            PqcAlgorithm::SlhDsaSha2_256f,
            PqcAlgorithm::SlhDsaShake_256f,
        ] {
            assert_eq!(v.security_category(), 5, "{v:?}");
        }

        // LMS — strongest deployment ≈ AES-256.
        assert_eq!(PqcAlgorithm::Lms.security_category(), 5);
    }

    /// `is_kem()` returns `true` exactly for the three ML-KEM variants;
    /// `is_signature()` is its complement.
    #[test]
    fn kem_versus_signature_partition() {
        let kems = [
            PqcAlgorithm::MlKem512,
            PqcAlgorithm::MlKem768,
            PqcAlgorithm::MlKem1024,
        ];
        for alg in kems {
            assert!(alg.is_kem(), "{alg:?} should be a KEM");
            assert!(!alg.is_signature(), "{alg:?} should not be a signature");
        }

        // All other variants must be signatures, never KEMs.
        for &(_, alg) in NAME_TABLE.iter() {
            if kems.contains(&alg) {
                continue;
            }
            assert!(!alg.is_kem(), "{alg:?} should not be a KEM");
            assert!(alg.is_signature(), "{alg:?} should be a signature");
        }
    }

    /// `from_name` must perform case-insensitive matching and round-trip
    /// every canonical name.
    #[test]
    fn from_name_round_trip() {
        // Every canonical name must look itself up.
        for &(canonical, alg) in NAME_TABLE.iter() {
            assert_eq!(
                PqcAlgorithm::from_name(canonical),
                Some(alg),
                "canonical lookup failed for {canonical}"
            );
            // And uppercase, lowercase, and mixed must also work.
            assert_eq!(
                PqcAlgorithm::from_name(&canonical.to_lowercase()),
                Some(alg),
            );
            assert_eq!(
                PqcAlgorithm::from_name(&canonical.to_uppercase()),
                Some(alg),
            );
        }
    }

    /// Unknown names must return `None`, never panic, never a sentinel.
    #[test]
    fn from_name_unknown_returns_none() {
        assert_eq!(PqcAlgorithm::from_name(""), None);
        assert_eq!(PqcAlgorithm::from_name("ML-KEM"), None);
        assert_eq!(PqcAlgorithm::from_name("RSA-2048"), None);
        assert_eq!(PqcAlgorithm::from_name("Falcon-512"), None);
        assert_eq!(PqcAlgorithm::from_name("ML-KEM-2048"), None);
    }

    /// FIPS 203/204/205 algorithms are FIPS-approved; LMS (SP 800-208) is
    /// not.
    #[test]
    fn fips_approval_status() {
        // FIPS 203 — ML-KEM.
        assert!(PqcAlgorithm::MlKem512.is_fips_approved());
        assert!(PqcAlgorithm::MlKem768.is_fips_approved());
        assert!(PqcAlgorithm::MlKem1024.is_fips_approved());

        // FIPS 204 — ML-DSA.
        assert!(PqcAlgorithm::MlDsa44.is_fips_approved());
        assert!(PqcAlgorithm::MlDsa65.is_fips_approved());
        assert!(PqcAlgorithm::MlDsa87.is_fips_approved());

        // FIPS 205 — SLH-DSA (all 12 parameter sets).
        let slh_variants = [
            PqcAlgorithm::SlhDsaSha2_128s,
            PqcAlgorithm::SlhDsaShake_128s,
            PqcAlgorithm::SlhDsaSha2_128f,
            PqcAlgorithm::SlhDsaShake_128f,
            PqcAlgorithm::SlhDsaSha2_192s,
            PqcAlgorithm::SlhDsaShake_192s,
            PqcAlgorithm::SlhDsaSha2_192f,
            PqcAlgorithm::SlhDsaShake_192f,
            PqcAlgorithm::SlhDsaSha2_256s,
            PqcAlgorithm::SlhDsaShake_256s,
            PqcAlgorithm::SlhDsaSha2_256f,
            PqcAlgorithm::SlhDsaShake_256f,
        ];
        for v in slh_variants {
            assert!(v.is_fips_approved(), "{v:?} should be FIPS approved");
        }

        // SP 800-208 — LMS is *not* a FIPS standard.
        assert!(!PqcAlgorithm::Lms.is_fips_approved());
    }

    /// `Display` must emit the canonical name (`{}` formatter).
    #[test]
    fn display_emits_canonical_name() {
        assert_eq!(format!("{}", PqcAlgorithm::MlKem768), "ML-KEM-768");
        assert_eq!(
            format!("{}", PqcAlgorithm::SlhDsaShake_192f),
            "SLH-DSA-SHAKE-192f"
        );
        assert_eq!(format!("{}", PqcAlgorithm::Lms), "LMS");
    }

    /// `KeySelection` exposes the standard `bitflags` API surface.
    #[test]
    fn key_selection_basic_invariants() {
        // Empty selection.
        let empty = KeySelection::empty();
        assert!(empty.is_empty());
        assert!(!empty.contains(KeySelection::PUBLIC));
        assert!(!empty.contains(KeySelection::PRIVATE));
        assert_eq!(empty.bits(), 0);

        // PUBLIC only.
        let pub_only = KeySelection::PUBLIC;
        assert!(!pub_only.is_empty());
        assert!(pub_only.contains(KeySelection::PUBLIC));
        assert!(!pub_only.contains(KeySelection::PRIVATE));
        assert!(!pub_only.is_all());
        assert_eq!(pub_only.bits(), 0x01);

        // PRIVATE only.
        let priv_only = KeySelection::PRIVATE;
        assert!(!priv_only.is_empty());
        assert!(!priv_only.contains(KeySelection::PUBLIC));
        assert!(priv_only.contains(KeySelection::PRIVATE));
        assert!(!priv_only.is_all());
        assert_eq!(priv_only.bits(), 0x02);

        // ALL.
        let both = KeySelection::ALL;
        assert!(!both.is_empty());
        assert!(both.contains(KeySelection::PUBLIC));
        assert!(both.contains(KeySelection::PRIVATE));
        assert!(both.is_all());
        assert_eq!(both.bits(), 0x03);

        // Bitwise composition.
        assert_eq!(
            KeySelection::PUBLIC | KeySelection::PRIVATE,
            KeySelection::ALL
        );
    }

    /// `pqc_algorithm_for_name` must agree with `PqcAlgorithm::from_name` for
    /// every canonical algorithm name and return `None` for unknown names.
    #[test]
    fn pqc_algorithm_for_name_round_trip() {
        for &(canonical, expected) in NAME_TABLE.iter() {
            assert_eq!(
                pqc_algorithm_for_name(canonical),
                Some(expected),
                "lookup failed for {canonical}",
            );
        }

        // Case-insensitivity for the LMS branch (special-cased).
        assert_eq!(pqc_algorithm_for_name("lms"), Some(PqcAlgorithm::Lms));
        assert_eq!(pqc_algorithm_for_name("Lms"), Some(PqcAlgorithm::Lms));

        // Unknown names → None.
        assert_eq!(pqc_algorithm_for_name(""), None);
        assert_eq!(pqc_algorithm_for_name("ML-KEM-2048"), None);
        assert_eq!(pqc_algorithm_for_name("Hopefully-Not-Real"), None);
    }

    /// The `NAME_TABLE` must contain exactly 19 entries, one per
    /// `PqcAlgorithm` variant.
    #[test]
    fn name_table_is_exhaustive() {
        assert_eq!(
            NAME_TABLE.len(),
            19,
            "PqcAlgorithm has 3 ML-KEM + 3 ML-DSA + 12 SLH-DSA + 1 LMS = 19 variants",
        );
    }

    /// The re-exports declared at the top of the module must remain
    /// type-resolvable.
    #[test]
    fn reexports_are_accessible() {
        // These compile-time references keep the re-exports honest: if a
        // submodule renames or removes one of these types, the test ceases
        // to compile.
        let _ = std::mem::size_of::<MlKemVariant>();
        let _ = std::mem::size_of::<MlKemParams>();
        let _ = std::mem::size_of::<MlKemKey>();

        let _ = std::mem::size_of::<MlDsaVariant>();
        let _ = std::mem::size_of::<MlDsaParams>();
        let _ = std::mem::size_of::<MlDsaKey>();

        let _ = std::mem::size_of::<SlhDsaVariant>();
        let _ = std::mem::size_of::<SlhDsaParams>();
        let _ = std::mem::size_of::<SlhDsaKey>();

        let _ = std::mem::size_of::<LmsParams>();
        let _ = std::mem::size_of::<LmsKey>();
        let _ = std::mem::size_of::<LmOtsParams>();
    }
}
