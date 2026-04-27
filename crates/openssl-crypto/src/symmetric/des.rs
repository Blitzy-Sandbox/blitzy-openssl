//! DES and Triple-DES (3DES-EDE) block cipher implementations.
//!
//! Provides the Data Encryption Standard (DES) 64-bit block cipher and its
//! Triple-DES (3DES-EDE2 / EDE3) variants. Single DES is considered **broken**
//! (56-bit effective key space, demonstrably breakable by brute force) and is
//! provided ONLY for legacy compatibility. Triple-DES (3DES) provides ~112-bit
//! effective security but is substantially slower than AES.
//!
//! ## Source Mapping
//!
//! | Rust Type / Function | C Source File(s) | Notes |
//! |----------------------|------------------|-------|
//! | [`Des`]              | `crypto/des/des_enc.c` (block primitive), `crypto/des/set_key.c` (key schedule) | Single-DES |
//! | [`TripleDes`]        | `crypto/des/ecb3_enc.c`, `crypto/des/des_enc.c` (`DES_encrypt3`/`DES_decrypt3`) | EDE2/EDE3 |
//! | `DesKeySchedule`     | `crypto/des/set_key.c` (`DES_set_key*`, `DES_is_weak_key`) | 16 round subkey pairs |
//! | `DES_SPTRANS`        | `crypto/des/spr.h` | 8×64 precomputed S-box/P-permutation table |
//! | `DES_SKB`            | `crypto/des/set_key.c` (`des_skb`) | 8×64 PC-1/PC-2 key schedule tables |
//! | `des_cbc_encrypt`    | `crypto/des/ncbc_enc.c` | Delegates to generic [`cbc_encrypt`](crate::symmetric::cbc_encrypt) |
//! | `triple_des_cbc_encrypt` | `crypto/des/cbc_enc.c` (3DES CBC) | Delegates to generic [`cbc_encrypt`](crate::symmetric::cbc_encrypt) |
//!
//! ## Security Warning
//!
//! - **Single DES is BROKEN.** Use [`crate::symmetric::aes::Aes`] instead.
//! - **3DES (Triple-DES) is acceptable only for legacy interoperability.**
//!   It has known practical attacks (Sweet32 birthday attack) for long sessions
//!   and is being phased out by NIST SP 800-131A.
//! - The implementation performs **constant-time weak-key detection** using
//!   [`subtle::ConstantTimeEq`] to prevent timing side-channel leaks during key
//!   validation.
//!
//! ## Security Notice — Cache-Timing Side Channel
//!
//! This implementation is the pure-safe-Rust **table-driven reference path**
//! translating `crypto/des/spr.h` (`DES_SPTRANS`) and `crypto/des/set_key.c`
//! (`DES_SKB`). The table-driven approach is **not constant-time on cache-
//! equipped CPUs**:
//!
//! | Site | Table | Lookups per block | Lookups per encryption |
//! |------|-------|-------------------|------------------------|
//! | `d_encrypt_round` (Feistel round) | `DES_SPTRANS` | 8 × 16 rounds = 128 | 128 (DES) / 384 (3DES) |
//! | DES key schedule (`des_set_key`)    | `DES_SKB`     | up to 64 per key   | once per key load |
//!
//! Each indexed lookup `DES_SPTRANS[i][idx]` and `DES_SKB[i][idx]` is a
//! *secret-derived* index — the index `idx` is a function of either the round
//! state and round subkey (Feistel) or the raw key bytes (key schedule). On
//! any CPU with a data cache, the cache-line access pattern reveals which
//! 64-byte (or implementation-dependent) line was touched, leaking bits of
//! the indexed byte to a co-resident attacker (Bernstein 2005,
//! Tromer–Osvik–Shamir 2010).
//!
//! ### Threat model
//!
//! - **Co-resident attacker** on the same CPU package (multi-tenant cloud,
//!   browser sandbox, hostile OS process): high — measurable through Flush+
//!   Reload, Prime+Probe, or Evict+Reload.
//! - **Remote network attacker**: medium — feasible when wall-clock timing
//!   variance from cache misses leaks across the network in long-lived
//!   sessions (Sweet32 amplifies this for 3DES specifically).
//! - **Standalone host with no co-tenant**: low.
//!
//! ### Recommended remediations (none in this codebase yet)
//!
//! 1. Hardware DES is rare; modern CPUs do not provide DES instructions.
//!    The recommended action for new systems is **migration off DES/3DES
//!    entirely** — use [`crate::symmetric::aes::Aes`].
//! 2. For codebases that cannot migrate immediately, consider bitsliced
//!    DES (Biham 1997, Matsui 2006) — out of scope for this reference
//!    path, which prioritizes bit-exact correspondence with upstream
//!    OpenSSL `crypto/des/`.
//!
//! Until DES is fully removed, the cache-timing residual is **DOCUMENTED
//! BUT UNRESOLVED**. See `BENCHMARK_REPORT.md` and AAP §0.7.5 (Perlasm
//! Assembly Strategy).
//!
//! ## Feature Flag Gating
//!
//! The entire `des` module is gated behind the `des` Cargo feature flag.
//! Unlike the `legacy` module, the `des` feature **IS** enabled by default
//! per AAP §0.6.1 to preserve API and feature parity with existing FFI
//! consumers that link against legacy DES code paths during the C→Rust
//! migration window. New deployments **SHOULD** opt out.
//!
//! ### Gating Mechanism
//!
//! ```toml
//! # crates/openssl-crypto/Cargo.toml
//! [features]
//! default = [
//!     "ec", "rsa", "dh", "dsa",
//!     "aes", "sha", "chacha", "des",  # <-- des is in default per AAP §0.6.1
//!     "pqc",
//!     "hpke", "cms", "ocsp", "ct",
//!     "cmp", "ts",
//! ]
//! des = []  # DES/3DES legacy cipher (replaces OPENSSL_NO_DES)
//! ```
//!
//! ```rust,ignore
//! // crates/openssl-crypto/src/symmetric/mod.rs
//! #[cfg(feature = "des")]
//! pub mod des;
//!
//! #[cfg(feature = "des")]
//! pub use des::{Des, TripleDes};
//! ```
//!
//! ### Recommended Opt-Out
//!
//! For new deployments — particularly those running in multi-tenant cloud
//! environments where co-resident cache-timing attacks are credible, or
//! where compliance with NIST SP 800-131A 3DES phase-out is required —
//! disable the `des` feature explicitly:
//!
//! ```text
//! # Build with everything default EXCEPT des:
//! cargo build --no-default-features \
//!     --features "ec,rsa,dh,dsa,aes,sha,chacha,pqc,hpke,cms,ocsp,ct,cmp,ts"
//!
//! # Or in a downstream Cargo.toml:
//! [dependencies]
//! openssl-crypto = { version = "0.1.0",
//!                    default-features = false,
//!                    features = ["ec", "rsa", "aes", "sha", "chacha", "pqc"] }
//! ```
//!
//! When the feature is disabled, the entire `des` module — `Des`, `TripleDes`,
//! `DesKeySchedule`, `DES_SPTRANS`, `DES_SKB`, and the round/key-schedule
//! helpers — is excluded from the build, eliminating both the cache-timing
//! attack surface and the binary footprint of the static tables.
//!
//! ### Rationale: Default-On Per AAP §0.6.1, Not "Always Available"
//!
//! 1. **API parity preservation** — Existing FFI consumers expect
//!    `EVP_des_*` / `DES_*` symbols to be present on the default build.
//!    Removing them from default would break existing C callers linking
//!    through `openssl-ffi` and violate AAP §0.3.2 "Existing FFI consumer
//!    breakage" preservation requirement.
//!
//! 2. **Migration window** — During the active C→Rust migration phase,
//!    test suites and interop benchmarks reference DES vectors. Default-
//!    disabling DES would cause widespread regression-test failures in
//!    downstream consumers.
//!
//! 3. **Future trajectory** — A future major version (post-migration) is
//!    expected to flip this feature OFF in default and require explicit
//!    opt-in, mirroring the `legacy` feature posture. This is documented
//!    in the workspace `Cargo.toml` security commentary above
//!    `[features]`.
//!
//! 4. **Compile-time elimination on opt-out** — When the `des` feature is
//!    OFF, every cache-timing-vulnerable code path in this file is
//!    excluded from compilation. There is no runtime check; the
//!    elimination is fully static.
//!
//! ### Cross-References
//!
//! - **`crates/openssl-crypto/Cargo.toml`** — `[features]` section,
//!   `des = []` declaration with security commentary and opt-out
//!   instructions.
//! - **`crates/openssl-crypto/src/symmetric/mod.rs`** — `#[cfg]`-gated
//!   module declaration and re-exports.
//! - **`symmetric/aes.rs`** — Sibling module; AES is also default-on per
//!   AAP §0.6.1 with its own cache-timing notice.
//! - **`symmetric/legacy.rs`** — Sibling module; the `legacy` feature is
//!   opt-in (NOT in default) — contrast with the AAP §0.6.1 design
//!   decision documented above.
//! - **Group B #5 commit `e60b4ef65f`** — Per-table SECURITY blocks at
//!   `DES_SPTRANS` / `DES_SKB` declaration sites and round-function call
//!   sites.
//! - **Group B #6 commit (this file)** — Feature-flag gating documentation.
//!
//! ## Key Material Security
//!
//! All structures holding DES key material (`DesKeySchedule`, `Des`,
//! `TripleDes`) derive [`Zeroize`] and `ZeroizeOnDrop` to ensure round
//! subkeys and key bytes are securely erased from memory when dropped. This
//! replaces the C `OPENSSL_cleanse()` call pattern per AAP §0.7.6.
//!
//! ## Rule Compliance
//!
//! | Rule | Enforcement |
//! |------|-------------|
//! | R5 (No sentinels) | All fallible operations return [`CryptoResult<T>`]. |
//! | R6 (Lossless casts) | Byte↔word via `u32::from_le_bytes` / `to_le_bytes`; S-box indices masked before cast. |
//! | R8 (No unsafe) | Zero `unsafe` blocks — bounds-guaranteed by `& 0x3f` masking on S-box lookups. |
//! | R9 (Warning-free) | All public items documented; no `#[allow]` suppressions. |

use crate::symmetric::{cbc_encrypt, BlockSize, CipherAlgorithm, CipherDirection, SymmetricCipher};
use openssl_common::{CommonError, CryptoError, CryptoResult};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// DES block size in bytes (64 bits).
const DES_BLOCK_BYTES: usize = 8;

/// DES key size in bytes (64 bits with 8 parity bits, 56-bit effective).
const DES_KEY_BYTES: usize = 8;

/// Triple-DES EDE2 key size (16 bytes: K1 || K2, K3 = K1).
const TDES_EDE2_KEY_BYTES: usize = 16;

/// Triple-DES EDE3 key size (24 bytes: K1 || K2 || K3).
const TDES_EDE3_KEY_BYTES: usize = 24;

/// Number of DES Feistel rounds.
const DES_ROUNDS: usize = 16;

// =============================================================================
// DES_SPTRANS — Precomputed S-box / P-permutation table
// =============================================================================
//
// Each entry fuses one of the 8 DES S-boxes (6-bit input → 4-bit output) with
// the subsequent P-permutation, yielding a 32-bit output that is XOR-combined
// by the Feistel round. The table is pre-rotated 1 bit right (Richard
// Outerbridge optimization) to align with the `r.rotate_left(3)` pre-rotation
// applied at the start of `des_encrypt1`/`des_encrypt2`.
//
// Source: `crypto/des/spr.h` (verbatim from upstream OpenSSL, unchanged
// since 1995). 512 constants (8 × 64).
//
// SECURITY (cache-timing): Lookups `DES_SPTRANS[i][idx]` use a *secret-
// derived* `idx` — the 6-bit S-box input formed from the round subkey
// XOR with the expanded right half. The cache-line access pattern leaks
// bits of `idx` to a co-resident attacker. With 8 lookups per Feistel
// round × 16 rounds = 128 secret-indexed reads per DES block, and
// 384 reads per 3DES block, the leak surface is substantial. See module-
// level "Security Notice — Cache-Timing Side Channel" for the full
// threat model and the lack of a hardware/bitsliced backend in this
// reference path.

/// Fused S-box + P-permutation lookup table (8 nibbles × 64 entries).
///
/// # Security (cache-timing)
///
/// Indexed by *secret-derived* round-state bytes. Cache-line access
/// pattern leaks bits of the index. See the SECURITY block above and
/// the module-level "Security Notice — Cache-Timing Side Channel".
const DES_SPTRANS: [[u32; 64]; 8] = [
    // nibble 0
    [
        0x0208_0800,
        0x0008_0000,
        0x0200_0002,
        0x0208_0802,
        0x0200_0000,
        0x0008_0802,
        0x0008_0002,
        0x0200_0002,
        0x0008_0802,
        0x0208_0800,
        0x0208_0000,
        0x0000_0802,
        0x0200_0802,
        0x0200_0000,
        0x0000_0000,
        0x0008_0002,
        0x0008_0000,
        0x0000_0002,
        0x0200_0800,
        0x0008_0800,
        0x0208_0802,
        0x0208_0000,
        0x0000_0802,
        0x0200_0800,
        0x0000_0002,
        0x0000_0800,
        0x0008_0800,
        0x0208_0002,
        0x0000_0800,
        0x0200_0802,
        0x0208_0002,
        0x0000_0000,
        0x0000_0000,
        0x0208_0802,
        0x0200_0800,
        0x0008_0002,
        0x0208_0800,
        0x0008_0000,
        0x0000_0802,
        0x0200_0800,
        0x0208_0002,
        0x0000_0800,
        0x0008_0800,
        0x0200_0002,
        0x0008_0802,
        0x0000_0002,
        0x0200_0002,
        0x0208_0000,
        0x0208_0802,
        0x0008_0800,
        0x0208_0000,
        0x0200_0802,
        0x0200_0000,
        0x0000_0802,
        0x0008_0002,
        0x0000_0000,
        0x0008_0000,
        0x0200_0000,
        0x0200_0802,
        0x0208_0800,
        0x0000_0002,
        0x0208_0002,
        0x0000_0800,
        0x0008_0802,
    ],
    // nibble 1
    [
        0x4010_8010,
        0x0000_0000,
        0x0010_8000,
        0x4010_0000,
        0x4000_0010,
        0x0000_8010,
        0x4000_8000,
        0x0010_8000,
        0x0000_8000,
        0x4010_0010,
        0x0000_0010,
        0x4000_8000,
        0x0010_0010,
        0x4010_8000,
        0x4010_0000,
        0x0000_0010,
        0x0010_0000,
        0x4000_8010,
        0x4010_0010,
        0x0000_8000,
        0x0010_8010,
        0x4000_0000,
        0x0000_0000,
        0x0010_0010,
        0x4000_8010,
        0x0010_8010,
        0x4010_8000,
        0x4000_0010,
        0x4000_0000,
        0x0010_0000,
        0x0000_8010,
        0x4010_8010,
        0x0010_0010,
        0x4010_8000,
        0x4000_8000,
        0x0010_8010,
        0x4010_8010,
        0x0010_0010,
        0x4000_0010,
        0x0000_0000,
        0x4000_0000,
        0x0000_8010,
        0x0010_0000,
        0x4010_0010,
        0x0000_8000,
        0x4000_0000,
        0x0010_8010,
        0x4000_8010,
        0x4010_8000,
        0x0000_8000,
        0x0000_0000,
        0x4000_0010,
        0x0000_0010,
        0x4010_8010,
        0x0010_8000,
        0x4010_0000,
        0x4010_0010,
        0x0010_0000,
        0x0000_8010,
        0x4000_8000,
        0x4000_8010,
        0x0000_0010,
        0x4010_0000,
        0x0010_8000,
    ],
    // nibble 2
    [
        0x0400_0001,
        0x0404_0100,
        0x0000_0100,
        0x0400_0101,
        0x0004_0001,
        0x0400_0000,
        0x0400_0101,
        0x0004_0100,
        0x0400_0100,
        0x0004_0000,
        0x0404_0000,
        0x0000_0001,
        0x0404_0101,
        0x0000_0101,
        0x0000_0001,
        0x0404_0001,
        0x0000_0000,
        0x0004_0001,
        0x0404_0100,
        0x0000_0100,
        0x0000_0101,
        0x0404_0101,
        0x0004_0000,
        0x0400_0001,
        0x0404_0001,
        0x0400_0100,
        0x0004_0101,
        0x0404_0000,
        0x0004_0100,
        0x0000_0000,
        0x0400_0000,
        0x0004_0101,
        0x0404_0100,
        0x0000_0100,
        0x0000_0001,
        0x0004_0000,
        0x0000_0101,
        0x0004_0001,
        0x0404_0000,
        0x0400_0101,
        0x0000_0000,
        0x0404_0100,
        0x0004_0100,
        0x0404_0001,
        0x0004_0001,
        0x0400_0000,
        0x0404_0101,
        0x0000_0001,
        0x0004_0101,
        0x0400_0001,
        0x0400_0000,
        0x0404_0101,
        0x0004_0000,
        0x0400_0100,
        0x0400_0101,
        0x0004_0100,
        0x0400_0100,
        0x0000_0000,
        0x0404_0001,
        0x0000_0101,
        0x0400_0001,
        0x0004_0101,
        0x0000_0100,
        0x0404_0000,
    ],
    // nibble 3
    [
        0x0040_1008,
        0x1000_1000,
        0x0000_0008,
        0x1040_1008,
        0x0000_0000,
        0x1040_0000,
        0x1000_1008,
        0x0040_0008,
        0x1040_1000,
        0x1000_0008,
        0x1000_0000,
        0x0000_1008,
        0x1000_0008,
        0x0040_1008,
        0x0040_0000,
        0x1000_0000,
        0x1040_0008,
        0x0040_1000,
        0x0000_1000,
        0x0000_0008,
        0x0040_1000,
        0x1000_1008,
        0x1040_0000,
        0x0000_1000,
        0x0000_1008,
        0x0000_0000,
        0x0040_0008,
        0x1040_1000,
        0x1000_1000,
        0x1040_0008,
        0x1040_1008,
        0x0040_0000,
        0x1040_0008,
        0x0000_1008,
        0x0040_0000,
        0x1000_0008,
        0x0040_1000,
        0x1000_1000,
        0x0000_0008,
        0x1040_0000,
        0x1000_1008,
        0x0000_0000,
        0x0000_1000,
        0x0040_0008,
        0x0000_0000,
        0x1040_0008,
        0x1040_1000,
        0x0000_1000,
        0x1000_0000,
        0x1040_1008,
        0x0040_1008,
        0x0040_0000,
        0x1040_1008,
        0x0000_0008,
        0x1000_1000,
        0x0040_1008,
        0x0040_0008,
        0x0040_1000,
        0x1040_0000,
        0x1000_1008,
        0x0000_1008,
        0x1000_0000,
        0x1000_0008,
        0x1040_1000,
    ],
    // nibble 4
    [
        0x0800_0000,
        0x0001_0000,
        0x0000_0400,
        0x0801_0420,
        0x0801_0020,
        0x0800_0400,
        0x0001_0420,
        0x0801_0000,
        0x0001_0000,
        0x0000_0020,
        0x0800_0020,
        0x0001_0400,
        0x0800_0420,
        0x0801_0020,
        0x0801_0400,
        0x0000_0000,
        0x0001_0400,
        0x0800_0000,
        0x0001_0020,
        0x0000_0420,
        0x0800_0400,
        0x0001_0420,
        0x0000_0000,
        0x0800_0020,
        0x0000_0020,
        0x0800_0420,
        0x0801_0420,
        0x0001_0020,
        0x0801_0000,
        0x0000_0400,
        0x0000_0420,
        0x0801_0400,
        0x0801_0400,
        0x0800_0420,
        0x0001_0020,
        0x0801_0000,
        0x0001_0000,
        0x0000_0020,
        0x0800_0020,
        0x0800_0400,
        0x0800_0000,
        0x0001_0400,
        0x0801_0420,
        0x0000_0000,
        0x0001_0420,
        0x0800_0000,
        0x0000_0400,
        0x0001_0020,
        0x0800_0420,
        0x0000_0400,
        0x0000_0000,
        0x0801_0420,
        0x0801_0020,
        0x0801_0400,
        0x0000_0420,
        0x0001_0000,
        0x0001_0400,
        0x0801_0020,
        0x0800_0400,
        0x0000_0420,
        0x0000_0020,
        0x0001_0420,
        0x0801_0000,
        0x0800_0020,
    ],
    // nibble 5
    [
        0x8000_0040,
        0x0020_0040,
        0x0000_0000,
        0x8020_2000,
        0x0020_0040,
        0x0000_2000,
        0x8000_2040,
        0x0020_0000,
        0x0000_2040,
        0x8020_2040,
        0x0020_2000,
        0x8000_0000,
        0x8000_2000,
        0x8000_0040,
        0x8020_0000,
        0x0020_2040,
        0x0020_0000,
        0x8000_2040,
        0x8020_0040,
        0x0000_0000,
        0x0000_2000,
        0x0000_0040,
        0x8020_2000,
        0x8020_0040,
        0x8020_2040,
        0x8020_0000,
        0x8000_0000,
        0x0000_2040,
        0x0000_0040,
        0x0020_2000,
        0x0020_2040,
        0x8000_2000,
        0x0000_2040,
        0x8000_0000,
        0x8000_2000,
        0x0020_2040,
        0x8020_2000,
        0x0020_0040,
        0x0000_0000,
        0x8000_2000,
        0x8000_0000,
        0x0000_2000,
        0x8020_0040,
        0x0020_0000,
        0x0020_0040,
        0x8020_2040,
        0x0020_2000,
        0x0000_0040,
        0x8020_2040,
        0x0020_2000,
        0x0020_0000,
        0x8000_2040,
        0x8000_0040,
        0x8020_0000,
        0x0020_2040,
        0x0000_0000,
        0x0000_2000,
        0x8000_0040,
        0x8000_2040,
        0x8020_2000,
        0x8020_0000,
        0x0000_2040,
        0x0000_0040,
        0x8020_0040,
    ],
    // nibble 6
    [
        0x0000_4000,
        0x0000_0200,
        0x0100_0200,
        0x0100_0004,
        0x0100_4204,
        0x0000_4004,
        0x0000_4200,
        0x0000_0000,
        0x0100_0000,
        0x0100_0204,
        0x0000_0204,
        0x0100_4000,
        0x0000_0004,
        0x0100_4200,
        0x0100_4000,
        0x0000_0204,
        0x0100_0204,
        0x0000_4000,
        0x0000_4004,
        0x0100_4204,
        0x0000_0000,
        0x0100_0200,
        0x0100_0004,
        0x0000_4200,
        0x0100_4004,
        0x0000_4204,
        0x0100_4200,
        0x0000_0004,
        0x0000_4204,
        0x0100_4004,
        0x0000_0200,
        0x0100_0000,
        0x0000_4204,
        0x0100_4000,
        0x0100_4004,
        0x0000_0204,
        0x0000_4000,
        0x0000_0200,
        0x0100_0000,
        0x0100_4004,
        0x0100_0204,
        0x0000_4204,
        0x0000_4200,
        0x0000_0000,
        0x0000_0200,
        0x0100_0004,
        0x0000_0004,
        0x0100_0200,
        0x0000_0000,
        0x0100_0204,
        0x0100_0200,
        0x0000_4200,
        0x0000_0204,
        0x0000_4000,
        0x0100_4204,
        0x0100_0000,
        0x0100_4200,
        0x0000_0004,
        0x0000_4004,
        0x0100_4204,
        0x0100_0004,
        0x0100_4200,
        0x0100_4000,
        0x0000_4004,
    ],
    // nibble 7
    [
        0x2080_0080,
        0x2082_0000,
        0x0002_0080,
        0x0000_0000,
        0x2002_0000,
        0x0080_0080,
        0x2080_0000,
        0x2082_0080,
        0x0000_0080,
        0x2000_0000,
        0x0082_0000,
        0x0002_0080,
        0x0082_0080,
        0x2002_0080,
        0x2000_0080,
        0x2080_0000,
        0x0002_0000,
        0x0082_0080,
        0x0080_0080,
        0x2002_0000,
        0x2082_0080,
        0x2000_0080,
        0x0000_0000,
        0x0082_0000,
        0x2000_0000,
        0x0080_0000,
        0x2002_0080,
        0x2080_0080,
        0x0080_0000,
        0x0002_0000,
        0x2082_0000,
        0x0000_0080,
        0x0080_0000,
        0x0002_0000,
        0x2000_0080,
        0x2082_0080,
        0x0002_0080,
        0x2000_0000,
        0x0000_0000,
        0x0082_0000,
        0x2080_0080,
        0x2002_0080,
        0x2002_0000,
        0x0080_0080,
        0x2082_0000,
        0x0000_0080,
        0x0080_0080,
        0x2002_0000,
        0x2082_0080,
        0x0080_0000,
        0x2080_0000,
        0x2000_0080,
        0x0082_0000,
        0x0002_0080,
        0x2002_0080,
        0x2080_0000,
        0x0000_0080,
        0x2082_0000,
        0x0082_0080,
        0x0000_0000,
        0x2000_0000,
        0x2080_0080,
        0x0002_0000,
        0x0082_0080,
    ],
];

// -------------------------------------------------------------------------------------------------
// DES_SKB key-schedule tables (from `crypto/des/set_key.c`).
//
// These eight 64-entry tables implement the combined PC-1 permutation and PC-2 sub-key extraction
// for the DES key schedule. Each subtable looks up a 6-bit group of bits from the shifted
// `c` or `d` halves and returns the corresponding contribution to a 48-bit round sub-key (packed
// into two 32-bit words as described in the `set_key_unchecked` function below).
//
// Sub-tables 0..=3 process bits from the `c` half (upper 28 bits of PC-1 output) and sub-tables
// 4..=7 process bits from the `d` half. The mapping matches FIPS 46-3 and the classic
// Outerbridge/Biham-Shamir key-schedule optimisation.
//
// SECURITY (cache-timing): Indices into `DES_SKB[i]` are *secret-derived*
// 6-bit slices of the raw key bytes (after PC-1). Each key load performs
// up to 64 secret-indexed reads (8 subtables × 8 indices over 16 round
// shifts). The cache-line access pattern leaks bits of the indexed key
// material to a co-resident attacker. This leak is per-key-load (not
// per-block), so its impact is bounded by key-rotation frequency, but it
// remains a concrete vulnerability when long-lived keys are reused. See
// the module-level "Security Notice — Cache-Timing Side Channel" for the
// threat model and the lack of a hardware/bitsliced backend.
// -------------------------------------------------------------------------------------------------

/// Combined PC-1/PC-2 key-schedule lookup tables (8 tables × 64 entries).
///
/// Translated verbatim from `des_skb` in `crypto/des/set_key.c`.
///
/// # Security (cache-timing)
///
/// Indexed by *secret-derived* 6-bit groups of the PC-1-permuted key
/// halves. Cache-line access pattern leaks bits of the indexed key bytes.
/// See SECURITY block above and module-level "Security Notice —
/// Cache-Timing Side Channel".
const DES_SKB: [[u32; 64]; 8] = [
    // DES_SKB[0] — for C bits 1, 2, 3, 4, 5, 6.
    [
        0x0000_0000,
        0x0000_0010,
        0x2000_0000,
        0x2000_0010,
        0x0001_0000,
        0x0001_0010,
        0x2001_0000,
        0x2001_0010,
        0x0000_0800,
        0x0000_0810,
        0x2000_0800,
        0x2000_0810,
        0x0001_0800,
        0x0001_0810,
        0x2001_0800,
        0x2001_0810,
        0x0000_0020,
        0x0000_0030,
        0x2000_0020,
        0x2000_0030,
        0x0001_0020,
        0x0001_0030,
        0x2001_0020,
        0x2001_0030,
        0x0000_0820,
        0x0000_0830,
        0x2000_0820,
        0x2000_0830,
        0x0001_0820,
        0x0001_0830,
        0x2001_0820,
        0x2001_0830,
        0x0008_0000,
        0x0008_0010,
        0x2008_0000,
        0x2008_0010,
        0x0009_0000,
        0x0009_0010,
        0x2009_0000,
        0x2009_0010,
        0x0008_0800,
        0x0008_0810,
        0x2008_0800,
        0x2008_0810,
        0x0009_0800,
        0x0009_0810,
        0x2009_0800,
        0x2009_0810,
        0x0008_0020,
        0x0008_0030,
        0x2008_0020,
        0x2008_0030,
        0x0009_0020,
        0x0009_0030,
        0x2009_0020,
        0x2009_0030,
        0x0008_0820,
        0x0008_0830,
        0x2008_0820,
        0x2008_0830,
        0x0009_0820,
        0x0009_0830,
        0x2009_0820,
        0x2009_0830,
    ],
    // DES_SKB[1] — for C bits 7, 8, 10, 11, 12, 13.
    [
        0x0000_0000,
        0x0200_0000,
        0x0000_2000,
        0x0200_2000,
        0x0020_0000,
        0x0220_0000,
        0x0020_2000,
        0x0220_2000,
        0x0000_0004,
        0x0200_0004,
        0x0000_2004,
        0x0200_2004,
        0x0020_0004,
        0x0220_0004,
        0x0020_2004,
        0x0220_2004,
        0x0000_0400,
        0x0200_0400,
        0x0000_2400,
        0x0200_2400,
        0x0020_0400,
        0x0220_0400,
        0x0020_2400,
        0x0220_2400,
        0x0000_0404,
        0x0200_0404,
        0x0000_2404,
        0x0200_2404,
        0x0020_0404,
        0x0220_0404,
        0x0020_2404,
        0x0220_2404,
        0x1000_0000,
        0x1200_0000,
        0x1000_2000,
        0x1200_2000,
        0x1020_0000,
        0x1220_0000,
        0x1020_2000,
        0x1220_2000,
        0x1000_0004,
        0x1200_0004,
        0x1000_2004,
        0x1200_2004,
        0x1020_0004,
        0x1220_0004,
        0x1020_2004,
        0x1220_2004,
        0x1000_0400,
        0x1200_0400,
        0x1000_2400,
        0x1200_2400,
        0x1020_0400,
        0x1220_0400,
        0x1020_2400,
        0x1220_2400,
        0x1000_0404,
        0x1200_0404,
        0x1000_2404,
        0x1200_2404,
        0x1020_0404,
        0x1220_0404,
        0x1020_2404,
        0x1220_2404,
    ],
    // DES_SKB[2] — for C bits 14, 15, 16, 17, 19, 20.
    [
        0x0000_0000,
        0x0000_0001,
        0x0004_0000,
        0x0004_0001,
        0x0100_0000,
        0x0100_0001,
        0x0104_0000,
        0x0104_0001,
        0x0000_0002,
        0x0000_0003,
        0x0004_0002,
        0x0004_0003,
        0x0100_0002,
        0x0100_0003,
        0x0104_0002,
        0x0104_0003,
        0x0000_0200,
        0x0000_0201,
        0x0004_0200,
        0x0004_0201,
        0x0100_0200,
        0x0100_0201,
        0x0104_0200,
        0x0104_0201,
        0x0000_0202,
        0x0000_0203,
        0x0004_0202,
        0x0004_0203,
        0x0100_0202,
        0x0100_0203,
        0x0104_0202,
        0x0104_0203,
        0x0800_0000,
        0x0800_0001,
        0x0804_0000,
        0x0804_0001,
        0x0900_0000,
        0x0900_0001,
        0x0904_0000,
        0x0904_0001,
        0x0800_0002,
        0x0800_0003,
        0x0804_0002,
        0x0804_0003,
        0x0900_0002,
        0x0900_0003,
        0x0904_0002,
        0x0904_0003,
        0x0800_0200,
        0x0800_0201,
        0x0804_0200,
        0x0804_0201,
        0x0900_0200,
        0x0900_0201,
        0x0904_0200,
        0x0904_0201,
        0x0800_0202,
        0x0800_0203,
        0x0804_0202,
        0x0804_0203,
        0x0900_0202,
        0x0900_0203,
        0x0904_0202,
        0x0904_0203,
    ],
    // DES_SKB[3] — for C bits 21, 23, 24, 26, 27, 28.
    [
        0x0000_0000,
        0x0010_0000,
        0x0000_0100,
        0x0010_0100,
        0x0000_0008,
        0x0010_0008,
        0x0000_0108,
        0x0010_0108,
        0x0000_1000,
        0x0010_1000,
        0x0000_1100,
        0x0010_1100,
        0x0000_1008,
        0x0010_1008,
        0x0000_1108,
        0x0010_1108,
        0x0400_0000,
        0x0410_0000,
        0x0400_0100,
        0x0410_0100,
        0x0400_0008,
        0x0410_0008,
        0x0400_0108,
        0x0410_0108,
        0x0400_1000,
        0x0410_1000,
        0x0400_1100,
        0x0410_1100,
        0x0400_1008,
        0x0410_1008,
        0x0400_1108,
        0x0410_1108,
        0x0002_0000,
        0x0012_0000,
        0x0002_0100,
        0x0012_0100,
        0x0002_0008,
        0x0012_0008,
        0x0002_0108,
        0x0012_0108,
        0x0002_1000,
        0x0012_1000,
        0x0002_1100,
        0x0012_1100,
        0x0002_1008,
        0x0012_1008,
        0x0002_1108,
        0x0012_1108,
        0x0402_0000,
        0x0412_0000,
        0x0402_0100,
        0x0412_0100,
        0x0402_0008,
        0x0412_0008,
        0x0402_0108,
        0x0412_0108,
        0x0402_1000,
        0x0412_1000,
        0x0402_1100,
        0x0412_1100,
        0x0402_1008,
        0x0412_1008,
        0x0402_1108,
        0x0412_1108,
    ],
    // DES_SKB[4] — for D bits 1, 2, 3, 4, 5, 6.
    [
        0x0000_0000,
        0x1000_0000,
        0x0001_0000,
        0x1001_0000,
        0x0000_0004,
        0x1000_0004,
        0x0001_0004,
        0x1001_0004,
        0x2000_0000,
        0x3000_0000,
        0x2001_0000,
        0x3001_0000,
        0x2000_0004,
        0x3000_0004,
        0x2001_0004,
        0x3001_0004,
        0x0010_0000,
        0x1010_0000,
        0x0011_0000,
        0x1011_0000,
        0x0010_0004,
        0x1010_0004,
        0x0011_0004,
        0x1011_0004,
        0x2010_0000,
        0x3010_0000,
        0x2011_0000,
        0x3011_0000,
        0x2010_0004,
        0x3010_0004,
        0x2011_0004,
        0x3011_0004,
        0x0000_1000,
        0x1000_1000,
        0x0001_1000,
        0x1001_1000,
        0x0000_1004,
        0x1000_1004,
        0x0001_1004,
        0x1001_1004,
        0x2000_1000,
        0x3000_1000,
        0x2001_1000,
        0x3001_1000,
        0x2000_1004,
        0x3000_1004,
        0x2001_1004,
        0x3001_1004,
        0x0010_1000,
        0x1010_1000,
        0x0011_1000,
        0x1011_1000,
        0x0010_1004,
        0x1010_1004,
        0x0011_1004,
        0x1011_1004,
        0x2010_1000,
        0x3010_1000,
        0x2011_1000,
        0x3011_1000,
        0x2010_1004,
        0x3010_1004,
        0x2011_1004,
        0x3011_1004,
    ],
    // DES_SKB[5] — for D bits 8, 9, 11, 12, 13, 14.
    [
        0x0000_0000,
        0x0800_0000,
        0x0000_0008,
        0x0800_0008,
        0x0000_0400,
        0x0800_0400,
        0x0000_0408,
        0x0800_0408,
        0x0002_0000,
        0x0802_0000,
        0x0002_0008,
        0x0802_0008,
        0x0002_0400,
        0x0802_0400,
        0x0002_0408,
        0x0802_0408,
        0x0000_0001,
        0x0800_0001,
        0x0000_0009,
        0x0800_0009,
        0x0000_0401,
        0x0800_0401,
        0x0000_0409,
        0x0800_0409,
        0x0002_0001,
        0x0802_0001,
        0x0002_0009,
        0x0802_0009,
        0x0002_0401,
        0x0802_0401,
        0x0002_0409,
        0x0802_0409,
        0x0200_0000,
        0x0A00_0000,
        0x0200_0008,
        0x0A00_0008,
        0x0200_0400,
        0x0A00_0400,
        0x0200_0408,
        0x0A00_0408,
        0x0202_0000,
        0x0A02_0000,
        0x0202_0008,
        0x0A02_0008,
        0x0202_0400,
        0x0A02_0400,
        0x0202_0408,
        0x0A02_0408,
        0x0200_0001,
        0x0A00_0001,
        0x0200_0009,
        0x0A00_0009,
        0x0200_0401,
        0x0A00_0401,
        0x0200_0409,
        0x0A00_0409,
        0x0202_0001,
        0x0A02_0001,
        0x0202_0009,
        0x0A02_0009,
        0x0202_0401,
        0x0A02_0401,
        0x0202_0409,
        0x0A02_0409,
    ],
    // DES_SKB[6] — for D bits 16, 17, 18, 19, 20, 21.
    [
        0x0000_0000,
        0x0000_0100,
        0x0008_0000,
        0x0008_0100,
        0x0100_0000,
        0x0100_0100,
        0x0108_0000,
        0x0108_0100,
        0x0000_0010,
        0x0000_0110,
        0x0008_0010,
        0x0008_0110,
        0x0100_0010,
        0x0100_0110,
        0x0108_0010,
        0x0108_0110,
        0x0020_0000,
        0x0020_0100,
        0x0028_0000,
        0x0028_0100,
        0x0120_0000,
        0x0120_0100,
        0x0128_0000,
        0x0128_0100,
        0x0020_0010,
        0x0020_0110,
        0x0028_0010,
        0x0028_0110,
        0x0120_0010,
        0x0120_0110,
        0x0128_0010,
        0x0128_0110,
        0x0000_0200,
        0x0000_0300,
        0x0008_0200,
        0x0008_0300,
        0x0100_0200,
        0x0100_0300,
        0x0108_0200,
        0x0108_0300,
        0x0000_0210,
        0x0000_0310,
        0x0008_0210,
        0x0008_0310,
        0x0100_0210,
        0x0100_0310,
        0x0108_0210,
        0x0108_0310,
        0x0020_0200,
        0x0020_0300,
        0x0028_0200,
        0x0028_0300,
        0x0120_0200,
        0x0120_0300,
        0x0128_0200,
        0x0128_0300,
        0x0020_0210,
        0x0020_0310,
        0x0028_0210,
        0x0028_0310,
        0x0120_0210,
        0x0120_0310,
        0x0128_0210,
        0x0128_0310,
    ],
    // DES_SKB[7] — for D bits 22, 23, 24, 25, 27, 28.
    [
        0x0000_0000,
        0x0400_0000,
        0x0004_0000,
        0x0404_0000,
        0x0000_0002,
        0x0400_0002,
        0x0004_0002,
        0x0404_0002,
        0x0000_2000,
        0x0400_2000,
        0x0004_2000,
        0x0404_2000,
        0x0000_2002,
        0x0400_2002,
        0x0004_2002,
        0x0404_2002,
        0x0000_0020,
        0x0400_0020,
        0x0004_0020,
        0x0404_0020,
        0x0000_0022,
        0x0400_0022,
        0x0004_0022,
        0x0404_0022,
        0x0000_2020,
        0x0400_2020,
        0x0004_2020,
        0x0404_2020,
        0x0000_2022,
        0x0400_2022,
        0x0004_2022,
        0x0404_2022,
        0x0000_0800,
        0x0400_0800,
        0x0004_0800,
        0x0404_0800,
        0x0000_0802,
        0x0400_0802,
        0x0004_0802,
        0x0404_0802,
        0x0000_2800,
        0x0400_2800,
        0x0004_2800,
        0x0404_2800,
        0x0000_2802,
        0x0400_2802,
        0x0004_2802,
        0x0404_2802,
        0x0000_0820,
        0x0400_0820,
        0x0004_0820,
        0x0404_0820,
        0x0000_0822,
        0x0400_0822,
        0x0004_0822,
        0x0404_0822,
        0x0000_2820,
        0x0400_2820,
        0x0004_2820,
        0x0404_2820,
        0x0000_2822,
        0x0400_2822,
        0x0004_2822,
        0x0404_2822,
    ],
];

// -------------------------------------------------------------------------------------------------
// Odd-parity lookup table (from `crypto/des/set_key.c`).
//
// Used by `DesKeySchedule::set_odd_parity` to impose the canonical DES odd-parity convention on
// user-supplied key bytes: each byte's low-order (LSB) parity bit is flipped as needed so that
// the total number of set bits in the byte is odd.
// -------------------------------------------------------------------------------------------------

/// 256-entry odd-parity fix-up table translated from `odd_parity` in `crypto/des/set_key.c`.
const ODD_PARITY: [u8; 256] = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25,
    26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49,
    50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73,
    74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97,
    98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117,
    117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134,
    137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155,
    155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173,
    174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193,
    193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211,
    213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230,
    230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248,
    251, 251, 253, 253, 254, 254,
];

// -------------------------------------------------------------------------------------------------
// Weak and semi-weak DES keys (from `crypto/des/set_key.c`).
//
// The DES block cipher has 4 "weak" keys and 12 "semi-weak" keys that make the encryption
// structurally predictable or self-inverting. `DesKeySchedule::is_weak_key` rejects these keys
// using a constant-time comparison via the `subtle` crate (see §0.7.6 of the AAP).
// -------------------------------------------------------------------------------------------------

/// 16 weak and semi-weak DES keys rejected by `DesKeySchedule::set_key`.
///
/// Translated verbatim from `weak_keys` in `crypto/des/set_key.c`. Entries 0..=3 are weak keys;
/// entries 4..=15 are semi-weak keys (6 pairs).
const WEAK_KEYS: [[u8; DES_KEY_BYTES]; 16] = [
    // Weak keys (4): every round subkey is identical, making `E_k(E_k(m)) == m`.
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    // Semi-weak keys (12, six complementary pairs):
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

// -------------------------------------------------------------------------------------------------
// DES key-schedule rotation schedule (from `crypto/des/set_key.c`).
//
// The C source expresses the DES round shift amounts indirectly via `shifts2` — a table whose
// entry at index `i` selects either a 1-bit (value 0) or a 2-bit (value 1) left rotation of the
// `c`/`d` halves when computing the sub-key for round `i`. The schedule is
// `{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}` per FIPS 46-3; the `shifts2` table thus
// implements this by selecting between two alternative rotation widths.
// -------------------------------------------------------------------------------------------------

/// Selects between 1-bit (value `0`) and 2-bit (value `1`) left rotations per DES round.
///
/// Translated verbatim from `shifts2` in `crypto/des/set_key.c`.
const SHIFTS2: [u8; DES_ROUNDS] = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];

// =============================================================================
// Helper functions: safe masked indexing
// =============================================================================

/// Extracts a 6-bit S-box index from a `u32` by right-shifting and masking.
///
/// The mask `& 0x3F` guarantees the result fits in 6 bits (0..=63), so the
/// subsequent cast to `usize` is always lossless regardless of the original
/// `u32` value. This is the sanctioned pattern for indexing `DES_SPTRANS` and
/// `DES_SKB` tables without triggering `clippy::cast_possible_truncation`
/// (rule R6).
#[inline]
fn sbox_idx(x: u32, shift: u32) -> usize {
    ((x >> shift) & 0x3F) as usize
}

/// Extracts a low-6-bit S-box index from a `u32`.
#[inline]
fn sbox_idx_lo(x: u32) -> usize {
    (x & 0x3F) as usize
}

// =============================================================================
// Permutation helpers
// =============================================================================
//
// The DES Initial Permutation (IP) and Final Permutation (FP) are implemented
// with Eli Biham's "bit-slicing" technique (see §27.3 of Applied Cryptography
// 2nd ed.). The `perm_op` primitive applies a single XOR-swap pattern that
// moves one bit of the left half into a particular position in the right half
// (or vice versa) — composing multiple `perm_op` calls yields the full IP or
// FP permutation without lookup tables.
//
// Source: `crypto/des/des_local.h` — `PERM_OP(a, b, t, n, m)` macro.

/// Applies one step of the IP/FP permutation (the classic DES `PERM_OP` macro).
///
/// Conceptually: extract the bits selected by `mask` from `a` (after shifting
/// `b` right by `n`), XOR them into `b`, and then XOR the same bits shifted
/// left by `n` back into `a`. This is the atomic building block of both IP
/// and FP.
#[inline]
fn perm_op(a: &mut u32, b: &mut u32, n: u32, mask: u32) {
    let t = ((*a >> n) ^ *b) & mask;
    *b ^= t;
    *a ^= t << n;
}

/// Applies the DES Initial Permutation (IP) to a pair of half-words.
///
/// Translated from the `IP` macro in `crypto/des/des_local.h`. The IP is a
/// fixed bit permutation that reorders the 64 input bits; it is its own
/// structural inverse in the sense that `FP ∘ IP = id` (the [`fp_permutation`]
/// function below implements the inverse).
#[inline]
fn ip_permutation(l: &mut u32, r: &mut u32) {
    perm_op(r, l, 4, 0x0f0f_0f0f);
    perm_op(l, r, 16, 0x0000_ffff);
    perm_op(r, l, 2, 0x3333_3333);
    perm_op(l, r, 8, 0x00ff_00ff);
    perm_op(r, l, 1, 0x5555_5555);
}

/// Applies the DES Final Permutation (FP) to a pair of half-words.
///
/// Translated from the `FP` macro in `crypto/des/des_local.h`. Inverts
/// [`ip_permutation`] exactly.
#[inline]
fn fp_permutation(l: &mut u32, r: &mut u32) {
    perm_op(l, r, 1, 0x5555_5555);
    perm_op(r, l, 8, 0x00ff_00ff);
    perm_op(l, r, 2, 0x3333_3333);
    perm_op(r, l, 16, 0x0000_ffff);
    perm_op(l, r, 4, 0x0f0f_0f0f);
}

/// Applies one half-rotation helper used in `DES_set_key_unchecked`.
///
/// Translated from the `HPERM_OP` macro in `crypto/des/set_key.c`:
///
/// ```text
/// #define HPERM_OP(a, t, n, m) ((t) = ((((a) << (16 - (n))) ^ (a)) & (m)),
///     (a) = (a) ^ (t) ^ (t >> (16 - (n))))
/// ```
///
/// The C macro takes `n` as a signed integer (always called with `n = -2`
/// in `set_key.c`), so the effective shift width `16 - n` = `18`. To avoid
/// any ambiguity we accept the `shift` width directly. The call sites in
/// [`DesKeySchedule::set_key_unchecked`] pass `18` to match the C source
/// exactly.
#[inline]
fn hperm_op(a: &mut u32, shift: u32, mask: u32) {
    let t = ((*a << shift) ^ *a) & mask;
    *a = *a ^ t ^ (t >> shift);
}

// =============================================================================
// DES block primitive — single-block encrypt/decrypt without IP/FP
// =============================================================================

/// Single-block DES Feistel core operating on a pre-permuted `(l, r)` pair.
///
/// Translated from `DES_encrypt2` in `crypto/des/des_enc.c`. The caller is
/// responsible for applying the Initial Permutation (before) and Final
/// Permutation (after). This function is used for the inner two stages of
/// 3DES-EDE to avoid wasteful intermediate IP/FP inversions that would
/// cancel out.
///
/// The `encrypt` flag selects the sub-key iteration order (0..16 for
/// encryption, 15..=0 for decryption).
fn des_block_core(l: &mut u32, r: &mut u32, schedule: &DesKeySchedule, encrypt: bool) {
    // Outerbridge pre-rotation: compensates for the 1-bit pre-rotation baked
    // into the DES_SPTRANS lookup table (rotate right 29 ≡ rotate left 3).
    *r = r.rotate_left(3);
    *l = l.rotate_left(3);

    let subkeys = &schedule.subkeys;

    if encrypt {
        // Rounds 0..16 forward.
        for i in 0..8 {
            let ki_a = subkeys[2 * i];
            let ki_b = subkeys[2 * i + 1];
            d_encrypt_round(l, *r, ki_a);
            d_encrypt_round(r, *l, ki_b);
        }
    } else {
        // Rounds 15..=0 reverse.
        for i in (0..8).rev() {
            let ki_b = subkeys[2 * i + 1];
            let ki_a = subkeys[2 * i];
            d_encrypt_round(l, *r, ki_b);
            d_encrypt_round(r, *l, ki_a);
        }
    }

    // Outerbridge post-rotation: inverse of the pre-rotation above.
    *l = l.rotate_right(3);
    *r = r.rotate_right(3);
}

/// One DES Feistel round: `l ^= F(r, subkey)` using the eight S-box lookups.
///
/// Translated from the `D_ENCRYPT` macro in `crypto/des/des_local.h`. The
/// subkey pair `[ka, kb]` encodes the 48-bit round sub-key; `ka` XORs into
/// the "even" S-box lookups and `kb` into the "odd" ones (after a 4-bit
/// right-rotation per `D_ENCRYPT`).
///
/// # Security (cache-timing)
///
/// This function is the **principal cache-timing-vulnerable site of DES**.
/// It performs 8 secret-indexed `DES_SPTRANS[i][..]` lookups per call. With
/// 16 invocations per DES block (one per Feistel round), each block
/// induces 128 secret-indexed table reads. Triple-DES (3DES-EDE3) triples
/// this to 384 reads/block.
///
/// The indices `sbox_idx(u, ..)` and `sbox_idx(t, ..)` are 6-bit slices
/// of `r ^ subkey[0]` (and a 4-bit-rotated `r ^ subkey[1]`), where `r` is
/// the right-half round state and `subkey` carries 48 bits of the secret
/// round key. The cache-line access pattern of these 128 reads leaks
/// state bits to a co-resident attacker (Bernstein 2005,
/// Tromer–Osvik–Shamir 2010 — same threat model as AES T-tables).
///
/// **No constant-time backend exists in this codebase.** Modern CPUs do
/// not provide DES instructions, so a hardware path comparable to AES-NI
/// is unavailable. Bitsliced DES (Biham 1997, Matsui 2006) is the only
/// known constant-time software approach but is out of scope for this
/// reference path. The recommended action is **migration off DES/3DES**;
/// see [`crate::symmetric::aes::Aes`].
///
/// See module-level "Security Notice — Cache-Timing Side Channel".
#[inline]
fn d_encrypt_round(l: &mut u32, r: u32, subkey: [u32; 2]) {
    let u = r ^ subkey[0];
    let t = (r ^ subkey[1]).rotate_right(4);

    *l ^= DES_SPTRANS[0][sbox_idx(u, 2)]
        ^ DES_SPTRANS[2][sbox_idx(u, 10)]
        ^ DES_SPTRANS[4][sbox_idx(u, 18)]
        ^ DES_SPTRANS[6][sbox_idx(u, 26)]
        ^ DES_SPTRANS[1][sbox_idx(t, 2)]
        ^ DES_SPTRANS[3][sbox_idx(t, 10)]
        ^ DES_SPTRANS[5][sbox_idx(t, 18)]
        ^ DES_SPTRANS[7][sbox_idx(t, 26)];
}

// =============================================================================
// DES single-block with IP/FP (full block cipher operation)
// =============================================================================

/// Encrypts or decrypts a single 8-byte DES block in place.
///
/// Translated from `DES_encrypt1` in `crypto/des/des_enc.c`. Applies the
/// Initial Permutation, runs 16 Feistel rounds using the supplied sub-keys
/// (forward for `encrypt=true`, reverse for `encrypt=false`), and applies
/// the Final Permutation. Note the register swap in the C source:
/// the C code loads `r = data[0]; l = data[1]` and stores `data[0] = l;
/// data[1] = r` after the FP, so FP is called with its arguments swapped.
fn des_block_encrypt(block: &mut [u8; DES_BLOCK_BYTES], schedule: &DesKeySchedule, encrypt: bool) {
    // Load two little-endian 32-bit words (matches C `c2l` macro).
    let mut r = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let mut l = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);

    // Initial Permutation.
    ip_permutation(&mut r, &mut l);

    // Feistel core (operates without IP/FP; performs the 16 rounds only).
    des_block_core(&mut l, &mut r, schedule, encrypt);

    // Final Permutation — note the R/L swap relative to C's `FP(r, l)` call.
    fp_permutation(&mut r, &mut l);

    // Store back with register swap (matches C `l2c(l, out); l2c(r, out)`).
    block[0..4].copy_from_slice(&l.to_le_bytes());
    block[4..8].copy_from_slice(&r.to_le_bytes());
}

// =============================================================================
// Triple-DES EDE: encrypt3 / decrypt3
// =============================================================================

/// Triple-DES EDE encryption: `E_k3 ∘ D_k2 ∘ E_k1`.
///
/// Translated from `DES_encrypt3` in `crypto/des/des_enc.c`:
///
/// ```c
/// l = data[0]; r = data[1];
/// IP(l, r);
/// data[0] = l; data[1] = r;
/// DES_encrypt2(data, ks1, DES_ENCRYPT);
/// DES_encrypt2(data, ks2, DES_DECRYPT);
/// DES_encrypt2(data, ks3, DES_ENCRYPT);
/// l = data[0]; r = data[1];
/// FP(r, l);
/// data[0] = l; data[1] = r;
/// ```
///
/// Each `DES_encrypt2` call loads `r_int = data[0], l_int = data[1]` at
/// entry and stores `data[0] = ROTATE(l_int, 3), data[1] = ROTATE(r_int, 3)`
/// on exit. This causes an implicit "slot swap" per stage. We avoid the
/// intermediate store/load by alternating the argument order on calls to
/// [`des_block_core`] so that its `(l, r)` parameters always match C's
/// `(l_int, r_int)` = `(data[1], data[0])` at the start of each stage.
///
/// Note the Rust local variable naming is `r = data[0], l = data[1]`,
/// which matches C's `DES_encrypt1` convention but is the OPPOSITE of C's
/// `DES_encrypt3` convention (`l = data[0], r = data[1]`). After the three
/// stages, the slot meanings have net-swapped once relative to the start:
/// the first-word slot `data[0]` now lives in Rust's `l`, and the
/// second-word slot `data[1]` lives in Rust's `r`. Therefore the final
/// `FP(r, l)` call in C — positionally `FP(data[1], data[0])` — must be
/// rendered in Rust as `fp_permutation(&mut r, &mut l)` because our `r`
/// now holds `data[1]` and our `l` now holds `data[0]`.
fn tdes_block_encrypt(
    block: &mut [u8; DES_BLOCK_BYTES],
    ks1: &DesKeySchedule,
    ks2: &DesKeySchedule,
    ks3: &DesKeySchedule,
) {
    // Load: `r = data[0]` (first word), `l = data[1]` (second word).
    let mut r = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let mut l = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);

    // Outer IP — matches C's `IP(l, r)` positionally = `IP(data[0], data[1])`.
    // Our `r` holds data[0] and our `l` holds data[1], so pass `(r, l)`.
    ip_permutation(&mut r, &mut l);

    // Stage 1: E with ks1. `des_block_core(l_param, r_param, ...)` treats
    // its first param as `l_int` and second as `r_int`. C's DES_encrypt2
    // has `l_int = data[1]` and `r_int = data[0]`, so pass `(l, r)` since
    // currently our `l` = data[1] and our `r` = data[0].
    des_block_core(&mut l, &mut r, ks1, true);
    // Slot semantics now swapped: data[0] lives in `l`, data[1] in `r`.

    // Stage 2: D with ks2. Currently data[1] = our `r`, data[0] = our `l`.
    // We need l_param = l_int = data[1] = our `r`, so swap arg order.
    des_block_core(&mut r, &mut l, ks2, false);
    // Slot semantics swapped again: back to data[0] = `r`, data[1] = `l`.

    // Stage 3: E with ks3. data[1] = our `l`, data[0] = our `r`. Pass (l, r).
    des_block_core(&mut l, &mut r, ks3, true);
    // Slot semantics swapped once more: data[0] = `l`, data[1] = `r`.

    // Outer FP — C calls `FP(r, l)` positionally = `FP(data[1], data[0])`.
    // After the three stages, data[1] lives in our `r` and data[0] lives
    // in our `l`, so we pass `(r, l)` to match C's positional argument
    // order. The output lands in the corresponding registers: our `r` is
    // modified via FP's `l_param` pathway and our `l` via FP's `r_param`
    // pathway, so after FP our `l` still represents data[0] and our `r`
    // still represents data[1].
    fp_permutation(&mut r, &mut l);

    // Store: `data[0] = l` (first word), `data[1] = r` (second word).
    block[0..4].copy_from_slice(&l.to_le_bytes());
    block[4..8].copy_from_slice(&r.to_le_bytes());
}

/// Triple-DES EDE decryption: `D_k1 ∘ E_k2 ∘ D_k3`.
///
/// Translated from `DES_decrypt3` in `crypto/des/des_enc.c`:
///
/// ```c
/// l = data[0]; r = data[1];
/// IP(l, r);
/// data[0] = l; data[1] = r;
/// DES_encrypt2(data, ks3, DES_DECRYPT);
/// DES_encrypt2(data, ks2, DES_ENCRYPT);
/// DES_encrypt2(data, ks1, DES_DECRYPT);
/// l = data[0]; r = data[1];
/// FP(r, l);
/// data[0] = l; data[1] = r;
/// ```
///
/// Structurally identical to [`tdes_block_encrypt`] modulo key order and
/// direction per stage. The slot-swap bookkeeping and the outer
/// `FP(r, l)` → Rust `fp_permutation(&mut r, &mut l)` translation follows
/// the same derivation — see the encrypt function's doc comment for
/// details.
fn tdes_block_decrypt(
    block: &mut [u8; DES_BLOCK_BYTES],
    ks1: &DesKeySchedule,
    ks2: &DesKeySchedule,
    ks3: &DesKeySchedule,
) {
    // Load: `r = data[0]` (first word), `l = data[1]` (second word).
    let mut r = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let mut l = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);

    // Outer IP — matches C's `IP(l, r)` with l = data[0] = our `r`.
    ip_permutation(&mut r, &mut l);

    // Stage 1: D with ks3.
    des_block_core(&mut l, &mut r, ks3, false);
    // Stage 2: E with ks2 (swap arg order — slot semantics swapped after
    // stage 1, so data[1] = our `r` and data[0] = our `l`).
    des_block_core(&mut r, &mut l, ks2, true);
    // Stage 3: D with ks1 (slot semantics swap again — now data[0] = `l`,
    // data[1] = `r`).
    des_block_core(&mut l, &mut r, ks1, false);

    // Outer FP — after three stages, data[0] lives in our `l` and data[1]
    // in our `r`. C's positional `FP(r, l)` = `FP(data[1], data[0])` must
    // be rendered as `fp_permutation(&mut r, &mut l)` because our `r`
    // holds data[1] and our `l` holds data[0].
    fp_permutation(&mut r, &mut l);

    // Store: `data[0] = l` (first word), `data[1] = r` (second word).
    block[0..4].copy_from_slice(&l.to_le_bytes());
    block[4..8].copy_from_slice(&r.to_le_bytes());
}

// ---------------------------------------------------------------------------
// DES key schedule
// ---------------------------------------------------------------------------

/// DES key schedule holding 16 round sub-keys derived from an 8-byte key.
///
/// Each entry of `subkeys[i]` is a pair of 32-bit words `[ki_a, ki_b]` that
/// are consumed by the per-round Feistel function `d_encrypt_round`.
///
/// This struct corresponds to the C `DES_key_schedule` type defined in
/// `include/openssl/des.h` and populated by `DES_set_key_unchecked` in
/// `crypto/des/set_key.c`.
///
/// All key material is zeroed on drop via [`ZeroizeOnDrop`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DesKeySchedule {
    /// Round sub-keys, 16 rounds × 2 words.
    pub(crate) subkeys: [[u32; 2]; DES_ROUNDS],
}

impl DesKeySchedule {
    /// Applies the FIPS 46-3 odd-parity correction to each byte of `key`
    /// in place.
    ///
    /// Each output byte has an odd number of set bits. Translates
    /// `DES_set_odd_parity` in `crypto/des/set_key.c`.
    pub fn set_odd_parity(key: &mut [u8; DES_KEY_BYTES]) {
        for b in key.iter_mut() {
            *b = ODD_PARITY[usize::from(*b)];
        }
    }

    /// Returns `true` iff every byte of `key` already has odd parity.
    ///
    /// Translates `DES_check_key_parity` in `crypto/des/set_key.c`.
    pub fn check_key_parity(key: &[u8; DES_KEY_BYTES]) -> bool {
        for &b in key {
            if ODD_PARITY[usize::from(b)] != b {
                return false;
            }
        }
        true
    }

    /// Returns `true` iff `key` is one of the 16 known weak or semi-weak DES
    /// keys catalogued in FIPS 74 Appendix A.
    ///
    /// Uses constant-time comparison via [`subtle::ConstantTimeEq`] to avoid
    /// timing side channels when validating user-supplied keys. Translates
    /// `DES_is_weak_key` in `crypto/des/set_key.c`.
    pub fn is_weak_key(key: &[u8; DES_KEY_BYTES]) -> bool {
        // Accumulate a constant-time OR of all equality results. If any weak
        // key matches, `is_weak` becomes `1` in constant time regardless of
        // which entry matched or its position.
        let mut is_weak: Choice = Choice::from(0u8);
        for entry in &WEAK_KEYS {
            is_weak |= key.ct_eq(entry);
        }
        bool::from(is_weak)
    }

    /// Expands an 8-byte DES key into 16 round sub-keys without performing
    /// parity or weak-key checks.
    ///
    /// Translates `DES_set_key_unchecked` in `crypto/des/set_key.c`.
    /// Implements PC-1 (via `PERM_OP`/`HPERM_OP` macros), the 16-round
    /// rotation schedule (`SHIFTS2`), and PC-2 (via the `DES_SKB` tables).
    ///
    /// This routine is intended for legacy interoperability where callers
    /// knowingly use keys that would be rejected by [`Self::set_key`].
    /// Prefer [`Self::set_key`] for all new code.
    pub fn set_key_unchecked(key: &[u8; DES_KEY_BYTES]) -> Self {
        // Load the key as two little-endian 32-bit halves. The C `c2l`
        // macro in `des_local.h` reads bytes low-to-high, so `from_le_bytes`
        // is the exact byte-order equivalent.
        let mut c = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let mut d = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);

        // PC-1 permutation expressed as a sequence of `PERM_OP` / `HPERM_OP`
        // macro invocations, verbatim from `DES_set_key_unchecked`.
        //
        // The two `HPERM_OP` calls use `n = -2` in the C source, so the
        // effective shift width is `16 - (-2) = 18`. See `hperm_op` docs.
        perm_op(&mut d, &mut c, 4, 0x0f0f_0f0f);
        hperm_op(&mut c, 18, 0xcccc_0000);
        hperm_op(&mut d, 18, 0xcccc_0000);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);
        perm_op(&mut c, &mut d, 8, 0x00ff_00ff);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);

        // Final PC-1 fix-up: re-shuffle `d` and fold high nibble of `c`
        // into `d`, then mask both halves to 28 bits.
        d = ((d & 0x0000_00ff) << 16)
            | (d & 0x0000_ff00)
            | ((d & 0x00ff_0000) >> 16)
            | ((c & 0xf000_0000) >> 4);
        c &= 0x0fff_ffff;

        let mut subkeys = [[0u32; 2]; DES_ROUNDS];

        for (i, shift) in SHIFTS2.iter().enumerate() {
            // Rotate the 28-bit `c` and `d` halves by the per-round amount.
            // Note: we cannot use `u32::rotate_*` because these are 28-bit
            // (not 32-bit) rotations; we must mask back to 28 bits after.
            if *shift != 0 {
                c = (c >> 2) | (c << 26);
                d = (d >> 2) | (d << 26);
            } else {
                c = (c >> 1) | (c << 27);
                d = (d >> 1) | (d << 27);
            }
            c &= 0x0fff_ffff;
            d &= 0x0fff_ffff;

            // PC-2 permutation implemented via the `DES_SKB` lookup tables.
            // Each term selects 6 bits of `c` or `d` and fetches a
            // precomputed contribution to the 48-bit sub-key. All indices
            // are masked with `0x3f` before the `as usize` cast to
            // guarantee they fit in 6 bits (R6 — Lossless Numeric Casts).
            let s: u32 = DES_SKB[0][sbox_idx_lo(c)]
                | DES_SKB[1][((((c >> 6) & 0x03) | ((c >> 7) & 0x3c)) & 0x3f) as usize]
                | DES_SKB[2][((((c >> 13) & 0x0f) | ((c >> 14) & 0x30)) & 0x3f) as usize]
                | DES_SKB[3][((((c >> 20) & 0x01) | ((c >> 21) & 0x06) | ((c >> 22) & 0x38)) & 0x3f)
                    as usize];

            let t: u32 = DES_SKB[4][sbox_idx_lo(d)]
                | DES_SKB[5][((((d >> 7) & 0x03) | ((d >> 8) & 0x3c)) & 0x3f) as usize]
                | DES_SKB[6][sbox_idx(d, 15)]
                | DES_SKB[7][((((d >> 21) & 0x0f) | ((d >> 22) & 0x30)) & 0x3f) as usize];

            // Pack the two 32-bit sub-key halves and apply the final
            // rotation (`ROTATE` is a right-rotation in C; 30 == left 2
            // and 26 == left 6).
            let t2 = (t << 16) | (s & 0x0000_ffff);
            subkeys[i][0] = t2.rotate_left(2);
            let t2 = (s >> 16) | (t & 0xffff_0000);
            subkeys[i][1] = t2.rotate_left(6);
        }

        // Best-effort zeroization of sensitive local state. Values go out
        // of scope anyway, but zeroing ensures no residual stack copy.
        c = 0;
        d = 0;
        let _ = (c, d);

        Self { subkeys }
    }

    /// Expands an 8-byte DES key into 16 round sub-keys, rejecting keys
    /// that fail the parity check or that match one of the 16 known
    /// weak/semi-weak keys.
    ///
    /// Translates `DES_set_key_checked` in `crypto/des/set_key.c`, which
    /// returns `-1` for parity errors and `-2` for weak keys. This Rust
    /// version maps both failures to [`CryptoError::Key`] with a
    /// descriptive message.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if:
    /// * any byte of `key` does not have odd parity, or
    /// * `key` is a weak or semi-weak key.
    pub fn set_key(key: &[u8; DES_KEY_BYTES]) -> CryptoResult<Self> {
        if !Self::check_key_parity(key) {
            return Err(CryptoError::Key(
                "DES key has invalid parity (FIPS 46-3 requires odd parity)".to_string(),
            ));
        }
        if Self::is_weak_key(key) {
            return Err(CryptoError::Key(
                "DES key is a known weak or semi-weak key".to_string(),
            ));
        }
        Ok(Self::set_key_unchecked(key))
    }

    /// Encrypts a single 8-byte DES block in place using this pre-expanded
    /// sub-key schedule.
    ///
    /// This is a thin wrapper over the internal `des_block_encrypt` routine,
    /// exposed to support algorithms (such as MDC2 in `crate::hash::legacy`)
    /// that derive DES keys on the fly via [`Self::set_key_unchecked`] and
    /// therefore cannot use the weak-key-rejecting [`Des::new`] constructor.
    ///
    /// Translates the `DES_encrypt1(&block, &schedule, DES_ENCRYPT)` call
    /// pattern from `crypto/mdc2/mdc2dgst.c`.
    pub fn encrypt_block(&self, block: &mut [u8; DES_BLOCK_BYTES]) {
        des_block_encrypt(block, self, true);
    }
}

// ---------------------------------------------------------------------------
// Single DES (LEGACY — provided for compatibility only)
// ---------------------------------------------------------------------------

/// Single-DES block cipher (64-bit block, 56-bit effective key).
///
/// # Security
///
/// **Single DES is broken.** Its 56-bit key space was exhausted in practice
/// in the 1990s. This type exists solely for decryption of legacy data and
/// interoperability with legacy systems.
///
/// Use [`TripleDes`] (or, preferably, `crate::symmetric::aes::Aes`) for all
/// new work.
///
/// # Key Validation
///
/// [`Self::new`] rejects keys that fail odd-parity or that match one of the
/// 16 known weak/semi-weak keys. To bypass these checks (for legacy
/// interop), build the schedule directly with
/// [`DesKeySchedule::set_key_unchecked`].
///
/// # Zeroization
///
/// The embedded [`DesKeySchedule`] is zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Des {
    schedule: DesKeySchedule,
}

impl Des {
    /// Builds a single-DES instance from an 8-byte key.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Common`] wrapping [`CommonError::InvalidArgument`]
    ///   if `key.len() != 8`.
    /// * [`CryptoError::Key`] if the key fails parity or is a weak key
    ///   (see [`DesKeySchedule::set_key`]).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let key_len = key.len();
        let key_arr: &[u8; DES_KEY_BYTES] = key.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "DES key must be {DES_KEY_BYTES} bytes, got {key_len}"
            )))
        })?;
        let schedule = DesKeySchedule::set_key(key_arr)?;
        Ok(Self { schedule })
    }

    /// Encrypts an 8-byte block in place.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] if `block.len() != 8`.
    pub fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; DES_BLOCK_BYTES] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "DES encrypt_block: expected {DES_BLOCK_BYTES}-byte block, got {block_len}"
            )))
        })?;
        des_block_encrypt(arr, &self.schedule, true);
        Ok(())
    }

    /// Decrypts an 8-byte block in place.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] if `block.len() != 8`.
    pub fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; DES_BLOCK_BYTES] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "DES decrypt_block: expected {DES_BLOCK_BYTES}-byte block, got {block_len}"
            )))
        })?;
        des_block_encrypt(arr, &self.schedule, false);
        Ok(())
    }
}

impl SymmetricCipher for Des {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        Des::encrypt_block(self, block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        Des::decrypt_block(self, block)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Des
    }
}

// ---------------------------------------------------------------------------
// Triple-DES (3DES-EDE2 / 3DES-EDE3)
// ---------------------------------------------------------------------------

/// Triple-DES (3DES-EDE) block cipher.
///
/// Implements the three-key (EDE3) and two-key (EDE2, with `K3 = K1`)
/// variants defined by NIST SP 800-67:
///
/// * **EDE3** — 24-byte key split into `K1 || K2 || K3`. Encryption is
///   `C = E_K3(D_K2(E_K1(P)))`.
/// * **EDE2** — 16-byte key split into `K1 || K2`; internally `K3 = K1`.
///
/// # Security
///
/// 3DES is deprecated by NIST for new designs (SP 800-131A). It provides
/// at most 112 bits of security and is significantly slower than AES. Use
/// `crate::symmetric::aes::Aes` for new work; this type exists for legacy
/// interop (e.g. legacy PKCS #12 files, older VPN deployments).
///
/// # Zeroization
///
/// All three embedded key schedules are zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TripleDes {
    ks1: DesKeySchedule,
    ks2: DesKeySchedule,
    ks3: DesKeySchedule,
}

impl TripleDes {
    /// Builds a 3DES instance from a 16-byte (EDE2) or 24-byte (EDE3) key.
    ///
    /// For EDE2 the third sub-key schedule is derived from the first half of
    /// the input, i.e. `K3 = K1`.
    ///
    /// Unlike [`Des::new`], this routine does **not** enforce parity or
    /// weak-key checks on the individual 8-byte key components, because the
    /// FIPS 46-3 weak-key pathology does not reduce 3DES's effective
    /// security below the design target in the same way it does for single
    /// DES. Callers that require parity correction should call
    /// [`DesKeySchedule::set_odd_parity`] on each 8-byte sub-key first.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] if `key.len()` is neither 16 nor 24.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            TDES_EDE2_KEY_BYTES => {
                // EDE2: K1 = key[0..8], K2 = key[8..16], K3 = K1.
                let mut k1_buf = [0u8; DES_KEY_BYTES];
                let mut k2_buf = [0u8; DES_KEY_BYTES];
                k1_buf.copy_from_slice(&key[0..DES_KEY_BYTES]);
                k2_buf.copy_from_slice(&key[DES_KEY_BYTES..TDES_EDE2_KEY_BYTES]);
                let ks1 = DesKeySchedule::set_key_unchecked(&k1_buf);
                let ks2 = DesKeySchedule::set_key_unchecked(&k2_buf);
                let ks3 = DesKeySchedule::set_key_unchecked(&k1_buf);
                k1_buf.zeroize();
                k2_buf.zeroize();
                Ok(Self { ks1, ks2, ks3 })
            }
            TDES_EDE3_KEY_BYTES => {
                // EDE3: three independent 8-byte sub-keys.
                let mut k1_buf = [0u8; DES_KEY_BYTES];
                let mut k2_buf = [0u8; DES_KEY_BYTES];
                let mut k3_buf = [0u8; DES_KEY_BYTES];
                k1_buf.copy_from_slice(&key[0..DES_KEY_BYTES]);
                k2_buf.copy_from_slice(&key[DES_KEY_BYTES..2 * DES_KEY_BYTES]);
                k3_buf.copy_from_slice(&key[2 * DES_KEY_BYTES..TDES_EDE3_KEY_BYTES]);
                let ks1 = DesKeySchedule::set_key_unchecked(&k1_buf);
                let ks2 = DesKeySchedule::set_key_unchecked(&k2_buf);
                let ks3 = DesKeySchedule::set_key_unchecked(&k3_buf);
                k1_buf.zeroize();
                k2_buf.zeroize();
                k3_buf.zeroize();
                Ok(Self { ks1, ks2, ks3 })
            }
            n => Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "Triple-DES key must be {TDES_EDE2_KEY_BYTES} (EDE2) or \
                 {TDES_EDE3_KEY_BYTES} (EDE3) bytes, got {n}"
            )))),
        }
    }

    /// Encrypts an 8-byte block in place using 3DES-EDE.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] if `block.len() != 8`.
    pub fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; DES_BLOCK_BYTES] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "3DES encrypt_block: expected {DES_BLOCK_BYTES}-byte block, got {block_len}"
            )))
        })?;
        tdes_block_encrypt(arr, &self.ks1, &self.ks2, &self.ks3);
        Ok(())
    }

    /// Decrypts an 8-byte block in place using 3DES-EDE.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] if `block.len() != 8`.
    pub fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; DES_BLOCK_BYTES] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "3DES decrypt_block: expected {DES_BLOCK_BYTES}-byte block, got {block_len}"
            )))
        })?;
        tdes_block_decrypt(arr, &self.ks1, &self.ks2, &self.ks3);
        Ok(())
    }
}

impl SymmetricCipher for TripleDes {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        TripleDes::encrypt_block(self, block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        TripleDes::decrypt_block(self, block)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::TripleDes
    }
}

// ---------------------------------------------------------------------------
// CBC mode wrappers
// ---------------------------------------------------------------------------

/// Encrypts or decrypts `data` with single DES in CBC mode.
///
/// Delegates to the generic [`cbc_encrypt`] engine in the parent module,
/// which applies PKCS#7 padding on encryption and strips it on decryption.
///
/// This replaces the family of C routines in `crypto/des/ncbc_enc.c`,
/// `cbc_enc.c`, `pcbc_enc.c`, and `xcbc_enc.c`. Partial-block handling
/// from the C API is replaced by uniform PKCS#7 padding per the parent
/// module contract.
///
/// # Parameters
///
/// * `cipher` — an initialised [`Des`] instance (key-schedule already built)
/// * `data` — plaintext (for encrypt) or ciphertext (for decrypt)
/// * `iv` — 8-byte initialisation vector
/// * `direction` — [`CipherDirection::Encrypt`] or [`CipherDirection::Decrypt`]
///
/// # Errors
///
/// Returns the error propagated from [`cbc_encrypt`], typically
/// [`CryptoError::Common`] for malformed inputs or invalid padding on
/// decryption.
pub fn des_cbc_encrypt(
    cipher: &Des,
    data: &[u8],
    iv: &[u8; DES_BLOCK_BYTES],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    cbc_encrypt(cipher, data, &iv[..], direction)
}

/// Encrypts or decrypts `data` with 3DES-EDE in CBC mode.
///
/// Delegates to the generic [`cbc_encrypt`] engine in the parent module.
/// Replaces `DES_ede3_cbc_encrypt` in `crypto/des/ede_cbcm_enc.c` and its
/// cousin `DES_ede2_cbc_encrypt`.
///
/// # Parameters
///
/// * `cipher` — an initialised [`TripleDes`] instance
/// * `data` — plaintext (for encrypt) or ciphertext (for decrypt)
/// * `iv` — 8-byte initialisation vector
/// * `direction` — [`CipherDirection::Encrypt`] or [`CipherDirection::Decrypt`]
///
/// # Errors
///
/// Returns the error propagated from [`cbc_encrypt`].
pub fn triple_des_cbc_encrypt(
    cipher: &TripleDes,
    data: &[u8],
    iv: &[u8; DES_BLOCK_BYTES],
    direction: CipherDirection,
) -> CryptoResult<Vec<u8>> {
    cbc_encrypt(cipher, data, &iv[..], direction)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // A key with odd parity and NOT in the weak key list.
    // Source: the canonical DES test-vector key used widely in the
    // literature (Stinson, Applied Cryptography).
    const GOOD_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

    // 0xEF has parity 7 (odd). 0xF0 has parity 4 (even) — invalid for DES.
    const BAD_PARITY_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF0];

    #[test]
    fn odd_parity_table_is_idempotent() {
        // Applying the odd-parity table to any byte yields a byte that is
        // already odd, so a second application is a no-op.
        let mut key = [0x00u8, 0x01, 0x02, 0x03, 0x80, 0xFE, 0xFF, 0x7F];
        DesKeySchedule::set_odd_parity(&mut key);
        let once = key;
        DesKeySchedule::set_odd_parity(&mut key);
        assert_eq!(once, key, "odd-parity table must be idempotent");
        assert!(DesKeySchedule::check_key_parity(&key));
    }

    #[test]
    fn check_key_parity_distinguishes_good_and_bad_keys() {
        assert!(DesKeySchedule::check_key_parity(&GOOD_KEY));
        assert!(!DesKeySchedule::check_key_parity(&BAD_PARITY_KEY));
    }

    #[test]
    fn is_weak_key_detects_known_weak_keys() {
        // The first two entries of WEAK_KEYS are the canonical weak keys
        // (all-0-parity and all-1-parity). Check a handful more to exercise
        // the full 16-element table.
        for weak in WEAK_KEYS.iter() {
            assert!(
                DesKeySchedule::is_weak_key(weak),
                "{weak:02X?} should be detected as weak"
            );
        }
    }

    #[test]
    fn is_weak_key_accepts_good_keys() {
        assert!(!DesKeySchedule::is_weak_key(&GOOD_KEY));
        assert!(!DesKeySchedule::is_weak_key(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        ]));
    }

    #[test]
    fn set_key_rejects_bad_parity() {
        // NOTE: `DesKeySchedule` intentionally does NOT implement `Debug`
        // (to prevent accidental logging of key material). We therefore
        // match on the full `Result` pattern instead of `.unwrap_err()`.
        let r = DesKeySchedule::set_key(&BAD_PARITY_KEY);
        assert!(matches!(r, Err(CryptoError::Key(_))), "expected Key error");
    }

    #[test]
    fn set_key_rejects_weak_key() {
        let r = DesKeySchedule::set_key(&WEAK_KEYS[0]);
        assert!(matches!(r, Err(CryptoError::Key(_))));
    }

    #[test]
    fn set_key_unchecked_accepts_weak_key() {
        // set_key_unchecked is the "escape hatch" for legacy interop:
        // it must NOT reject weak keys. Smoke test: construction succeeds.
        let _schedule = DesKeySchedule::set_key_unchecked(&WEAK_KEYS[0]);
    }

    #[test]
    fn des_new_rejects_wrong_length() {
        // `Des` intentionally does not implement `Debug`, so we match on
        // the `Result` rather than unwrapping the error.
        let r = Des::new(&[0u8; 7]);
        assert!(matches!(
            r,
            Err(CryptoError::Common(CommonError::InvalidArgument(_)))
        ));
        let r = Des::new(&[0u8; 9]);
        assert!(matches!(
            r,
            Err(CryptoError::Common(CommonError::InvalidArgument(_)))
        ));
    }

    #[test]
    fn des_new_rejects_bad_parity() {
        assert!(Des::new(&BAD_PARITY_KEY).is_err());
    }

    #[test]
    fn des_new_rejects_weak_key() {
        assert!(Des::new(&WEAK_KEYS[0]).is_err());
    }

    #[test]
    fn des_encrypt_decrypt_roundtrip() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let original = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let mut block = original;
        Des::encrypt_block(&des, &mut block).unwrap();
        assert_ne!(block, original, "encryption must change the block");
        Des::decrypt_block(&des, &mut block).unwrap();
        assert_eq!(block, original, "decrypt(encrypt(x)) must equal x");
    }

    #[test]
    fn des_block_length_validation() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let mut short = [0u8; 7];
        assert!(Des::encrypt_block(&des, &mut short).is_err());
        let mut long = [0u8; 9];
        assert!(Des::decrypt_block(&des, &mut long).is_err());
    }

    #[test]
    fn des_kat_fips81_now_is_t() {
        // FIPS 81 Appendix C known-answer vector:
        //   Key:       0x0123456789ABCDEF
        //   Plaintext: 0x4E6F772069732074 ("Now is t" ASCII)
        //   Ciphertext: 0x3FA40E8A984D4815
        let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&key).unwrap();
        let mut block = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
        Des::encrypt_block(&des, &mut block).unwrap();
        assert_eq!(
            block,
            [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15],
            "DES(0x0123456789ABCDEF, \"Now is t\") != 0x3FA40E8A984D4815"
        );
    }

    #[test]
    fn des_kat_roundtrip_decrypt() {
        // Inverse of `des_kat_fips81_now_is_t`.
        let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&key).unwrap();
        let mut block = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];
        Des::decrypt_block(&des, &mut block).unwrap();
        assert_eq!(block, [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74]);
    }

    #[test]
    fn des_symmetric_cipher_trait() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let as_trait: &dyn SymmetricCipher = &des;
        assert_eq!(as_trait.block_size(), BlockSize::Block64);
        assert_eq!(as_trait.algorithm(), CipherAlgorithm::Des);
        let mut block = [0u8; 8];
        as_trait.encrypt_block(&mut block).unwrap();
        as_trait.decrypt_block(&mut block).unwrap();
        assert_eq!(block, [0u8; 8]);
    }

    #[test]
    fn triple_des_new_rejects_wrong_length() {
        // `TripleDes` intentionally does not implement `Debug`, so we
        // match on the full `Result` pattern.
        let cases = [0usize, 7, 8, 15, 17, 20, 23, 25, 32];
        for n in cases {
            let key = vec![0u8; n];
            let r = TripleDes::new(&key);
            assert!(
                matches!(r, Err(CryptoError::Common(CommonError::InvalidArgument(_)))),
                "expected InvalidArgument for {n}-byte key"
            );
        }
    }

    #[test]
    fn triple_des_ede3_roundtrip() {
        // Three independent 8-byte sub-keys.
        let mut key = [0u8; TDES_EDE3_KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            // Generate odd-parity bytes deterministically so the sub-keys
            // pass parity checks if anyone were to invoke them.
            let seed = u8::try_from((i * 17) & 0xFF).unwrap();
            *b = ODD_PARITY[usize::from(seed)];
        }
        let tdes = TripleDes::new(&key).unwrap();
        let original = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut block = original;
        TripleDes::encrypt_block(&tdes, &mut block).unwrap();
        assert_ne!(
            block, original,
            "3DES-EDE3 encryption must change the block"
        );
        TripleDes::decrypt_block(&tdes, &mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn triple_des_ede2_roundtrip() {
        // Two independent 8-byte sub-keys (K3 = K1 internally).
        let key1 = [0x13u8, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let key2 = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let mut key = [0u8; TDES_EDE2_KEY_BYTES];
        key[0..8].copy_from_slice(&key1);
        key[8..16].copy_from_slice(&key2);
        let tdes = TripleDes::new(&key).unwrap();
        let original = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut block = original;
        TripleDes::encrypt_block(&tdes, &mut block).unwrap();
        assert_ne!(block, original);
        TripleDes::decrypt_block(&tdes, &mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn triple_des_with_identical_keys_matches_des() {
        // When K1 = K2 = K3, the 3DES encrypt becomes:
        //   C = E_K1(D_K1(E_K1(P))) = E_K1(P)
        // So the ciphertext must exactly match single-DES output.
        let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&key).unwrap();
        let mut tdes_key = [0u8; TDES_EDE3_KEY_BYTES];
        tdes_key[0..8].copy_from_slice(&key);
        tdes_key[8..16].copy_from_slice(&key);
        tdes_key[16..24].copy_from_slice(&key);
        let tdes = TripleDes::new(&tdes_key).unwrap();

        let original = [0x4Eu8, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
        let mut des_out = original;
        let mut tdes_out = original;
        Des::encrypt_block(&des, &mut des_out).unwrap();
        TripleDes::encrypt_block(&tdes, &mut tdes_out).unwrap();
        assert_eq!(
            des_out, tdes_out,
            "3DES with K1=K2=K3 must produce same ciphertext as single DES"
        );
    }

    #[test]
    fn triple_des_symmetric_cipher_trait() {
        let mut key = [0u8; TDES_EDE3_KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            let seed = u8::try_from(i).unwrap();
            *b = ODD_PARITY[usize::from(seed)];
        }
        let tdes = TripleDes::new(&key).unwrap();
        let as_trait: &dyn SymmetricCipher = &tdes;
        assert_eq!(as_trait.block_size(), BlockSize::Block64);
        assert_eq!(as_trait.algorithm(), CipherAlgorithm::TripleDes);
    }

    #[test]
    fn des_cbc_roundtrip() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let iv = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let plaintext = b"This text is exactly thirty-two.";
        assert_eq!(plaintext.len(), 32);
        let ct = des_cbc_encrypt(&des, plaintext, &iv, CipherDirection::Encrypt).unwrap();
        // Encryption must change the data; PKCS#7 pads to next block boundary
        // (here: +8 bytes because input length is a multiple of the block size).
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        assert_eq!(ct.len(), 32 + DES_BLOCK_BYTES);
        let pt = des_cbc_encrypt(&des, &ct, &iv, CipherDirection::Decrypt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn des_cbc_partial_length() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let iv = [0u8; 8];
        // 13 bytes → padded to 16 after PKCS#7 padding
        let plaintext = b"lucky-13-text";
        assert_eq!(plaintext.len(), 13);
        let ct = des_cbc_encrypt(&des, plaintext, &iv, CipherDirection::Encrypt).unwrap();
        assert_eq!(ct.len(), 16);
        let pt = des_cbc_encrypt(&des, &ct, &iv, CipherDirection::Decrypt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn triple_des_cbc_roundtrip_ede3() {
        let mut key = [0u8; TDES_EDE3_KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            let seed = u8::try_from((i * 31 + 7) & 0xFF).unwrap();
            *b = ODD_PARITY[usize::from(seed)];
        }
        let tdes = TripleDes::new(&key).unwrap();
        let iv = [0x55u8; 8];
        let plaintext = b"Triple-DES CBC test payload!";
        let ct = triple_des_cbc_encrypt(&tdes, plaintext, &iv, CipherDirection::Encrypt).unwrap();
        let pt = triple_des_cbc_encrypt(&tdes, &ct, &iv, CipherDirection::Decrypt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn triple_des_cbc_roundtrip_ede2() {
        let mut key = [0u8; TDES_EDE2_KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            let seed = u8::try_from((i * 23 + 3) & 0xFF).unwrap();
            *b = ODD_PARITY[usize::from(seed)];
        }
        let tdes = TripleDes::new(&key).unwrap();
        let iv = [0xAAu8; 8];
        let plaintext = b"EDE2 mode CBC data";
        let ct = triple_des_cbc_encrypt(&tdes, plaintext, &iv, CipherDirection::Encrypt).unwrap();
        let pt = triple_des_cbc_encrypt(&tdes, &ct, &iv, CipherDirection::Decrypt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn key_schedule_clone_preserves_subkeys() {
        let ks1 = DesKeySchedule::set_key_unchecked(&GOOD_KEY);
        let ks2 = ks1.clone();
        assert_eq!(ks1.subkeys, ks2.subkeys);
    }

    #[test]
    fn empty_input_cbc_encrypts_to_one_padding_block() {
        let des = Des::new(&GOOD_KEY).unwrap();
        let iv = [0u8; 8];
        let ct = des_cbc_encrypt(&des, &[], &iv, CipherDirection::Encrypt).unwrap();
        // PKCS#7 always adds at least one full block of padding.
        assert_eq!(ct.len(), DES_BLOCK_BYTES);
        let pt = des_cbc_encrypt(&des, &ct, &iv, CipherDirection::Decrypt).unwrap();
        assert!(pt.is_empty());
    }
}
