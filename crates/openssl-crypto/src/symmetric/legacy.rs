//! Legacy symmetric cipher implementations for the OpenSSL Rust workspace.
//!
//! This module provides the block/stream cipher primitives that the modern
//! OpenSSL ecosystem classifies as **legacy** — retained for backward
//! compatibility with older protocols and data formats but **not recommended**
//! for any new design. Each cipher is a faithful translation of the original
//! C implementation from the source repository.
//!
//! ## Provided Ciphers
//!
//! | Rust Type   | Block (bytes) | Key (bytes) | Rounds | Notes |
//! |-------------|:-:|:-:|:-:|---|
//! | [`Blowfish`] | 8  | 1–56       | 16 Feistel | 448-bit max key, pi-derived tables |
//! | [`Cast5`]    | 8  | 5–16       | 12/16      | CAST-128, 3-way round triad |
//! | [`Idea`]     | 8  | 16         | 8 + out    | Multiplication mod 0x10001 |
//! | [`Seed`]     | 16 | 16         | 16 Feistel | Korean national standard, KC constants |
//! | [`Rc2`]      | 8  | 1–128 (≤1024 bits) | 16 MIX + 2 MASH | Pi-table permutation |
//! | [`Rc4`]      | —  | 1–256      | —          | **Stream** cipher (KSA/PRGA) |
//! | [`Rc5`]      | 8  | 0–255      | 8 / 12 / 16 | Data-dependent rotations |
//! | [`Camellia`] | 16 | 16, 24, 32 | 18 / 24    | FL/FL^-1 layer, SIGMA constants |
//! | [`Aria`]     | 16 | 16, 24, 32 | 12 / 14 / 16 | Korean national standard |
//! | [`Sm4`]      | 16 | 16         | 32         | Chinese national standard |
//!
//! ## Source Mapping
//!
//! | Rust Type  | C Source Directory | Key Files |
//! |------------|--------------------|-----------|
//! | `Blowfish` | `crypto/bf/`       | `bf_enc.c`, `bf_skey.c`, `bf_pi.h` |
//! | `Cast5`    | `crypto/cast/`     | `c_enc.c`, `c_skey.c`, `cast_s.h` |
//! | `Idea`     | `crypto/idea/`     | `i_cbc.c`, `i_skey.c`, `idea_local.h` |
//! | `Seed`     | `crypto/seed/`     | `seed.c`, `seed_local.h` |
//! | `Rc2`      | `crypto/rc2/`      | `rc2_cbc.c`, `rc2_skey.c` |
//! | `Rc4`      | `crypto/rc4/`      | `rc4_enc.c`, `rc4_skey.c` |
//! | `Rc5`      | `crypto/rc5/`      | `rc5_enc.c`, `rc5_skey.c` |
//! | `Camellia` | `crypto/camellia/` | `camellia.c`, `cmll_misc.c` |
//! | `Aria`     | `crypto/aria/`     | `aria.c` |
//! | `Sm4`      | `crypto/sm4/`      | `sm4.c` |
//!
//! ## Security Warning
//!
//! - **These ciphers are LEGACY.** Do not use them for new deployments.
//! - RC4 has known biases and must never be used for new traffic.
//! - Single-DES-sized (64-bit) block ciphers (Blowfish, CAST5, IDEA, RC2, RC5)
//!   are vulnerable to Sweet32 birthday attacks for long-lived sessions.
//! - Camellia, ARIA, SM4 are modern in design but included here for locale-
//!   specific standardization compatibility. Prefer AES for interoperability.
//!
//! ## Security Notice — Cache-Timing Side Channel
//!
//! The implementations in this module are pure-safe-Rust **table-driven**
//! translations of the upstream C reference paths. Every round function
//! performs S-box or P-table lookups whose **indices depend on secret key
//! material and/or secret intermediate state**. On modern CPUs these
//! data-dependent memory accesses induce **cache-line-resident observable
//! side channels**: an attacker co-resident on the same core (e.g., another
//! process, VM, or hyper-thread) can measure cache-hit/miss timing and
//! recover bits of the key or state.
//!
//! This class of vulnerability was first demonstrated against AES by
//! Bernstein (2005, "Cache-timing attacks on AES") and Tromer, Osvik, and
//! Shamir (2010, "Efficient Cache Attacks on AES, and Countermeasures",
//! J. Cryptology). The same attack pattern applies identically to every
//! software S-box lookup in this module.
//!
//! ### Per-Cipher Leakage Profile
//!
//! | Cipher    | Vulnerable Site(s)                         | Lookups / Block                 |
//! |-----------|--------------------------------------------|----------------------------------|
//! | Blowfish  | F-function (S0/S1/S2/S3 tables)            | 4 × 16 rounds = 64              |
//! | CAST5     | Round function (CAST_S{0..3} tables)       | 4 × {12,16} rounds = 48 or 64   |
//! | IDEA      | **No table lookup** — uses arithmetic mul  | 0 (not cache-timing vulnerable) |
//! | SEED      | Round F-function (SEED_SS0..3 tables)      | 4 × 16 rounds = 64              |
//! | ARIA      | `aria_sl1`/`aria_sl2` (ARIA_SB1..4)        | 16 × {12,14,16} rounds           |
//! | Camellia  | Round function (SBOX1_1110/2_0222/...)     | 8 × {18,24} rounds = 144 or 192 |
//! | SM4       | Round function (SM4_SBOX_T0..3)            | 4 × 32 rounds = 128             |
//! | RC2       | Key schedule (RC2_KEY_TABLE, pi bytes)     | KEY-byte-indexed on setup       |
//! | RC4       | PRGA state permutation (S-array)           | Data-dependent swap each byte   |
//! | RC5       | **No table lookup** — data-dep. rotation   | 0 (but rotation amount is secret) |
//!
//! ### Threat Model and Mitigations
//!
//! - **Co-resident attacker (local / cloud multi-tenant):** HIGH risk for
//!   all table-driven ciphers in this module. Flush+Reload and Prime+Probe
//!   attacks recover keys in minutes to hours.
//! - **Remote network attacker:** LOWER direct risk (network noise masks
//!   cache-line timing), but amplified for 64-bit-block ciphers (Blowfish,
//!   CAST5, RC2, RC5) that already suffer from Sweet32 birthday-bound
//!   collision vulnerabilities for long sessions (RFC 7457).
//! - **Deployment hardening:** The only effective countermeasures are
//!   (a) **migrate off these legacy ciphers** — prefer AES-GCM or
//!   ChaCha20-Poly1305, (b) pin the process/VM to dedicated cores to
//!   prevent cache co-residency, and (c) for ciphers where a bitsliced or
//!   constant-time implementation exists in literature (most notably
//!   bitsliced DES by Biham 1997 for 64-bit ciphers), implement one.
//!   No such implementation is provided in this crate — it is out of scope
//!   per AAP §0.7.5 Perlasm Assembly Strategy.
//!
//! This residual vulnerability is **DOCUMENTED BUT UNRESOLVED**. Callers
//! who require cache-timing resistance **MUST NOT** use the ciphers in this
//! module with secret keys on shared hardware. See `BENCHMARK_REPORT.md`
//! for the trade-off analysis and `UNSAFE_AUDIT.md` for the broader
//! side-channel posture of the workspace.
//!
//! ## Key Material Security
//!
//! Every cipher struct derives [`Zeroize`] and [`ZeroizeOnDrop`] from the
//! [`zeroize`] crate, so round keys, expanded P-arrays, S-boxes, permutation
//! state (RC4), and round schedules are securely wiped from memory when the
//! cipher instance is dropped. This replaces the C `OPENSSL_cleanse()` call
//! pattern per AAP §0.7.6.
//!
//! ## Rule Compliance
//!
//! | Rule | Enforcement |
//! |------|-------------|
//! | R5 (No sentinels)   | All fallible operations return [`CryptoResult<T>`]. |
//! | R6 (Lossless casts) | Byte ↔ word via `u32::from_be_bytes` / `u32::from_le_bytes` / `to_*_bytes`; S-box indices masked with `& 0xff` before cast. |
//! | R8 (No unsafe)      | Zero `unsafe` blocks — enforced crate-wide by `#![forbid(unsafe_code)]`. |
//! | R9 (Warning-free)   | All public items documented; no `#[allow]` suppressions. |

use crate::symmetric::{BlockSize, CipherAlgorithm, StreamCipher, SymmetricCipher};
use openssl_common::{CommonError, CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Shared helpers
// =============================================================================

/// Validate that a mutable byte slice matches the cipher's block size.
///
/// Returns [`CryptoError::Common`] with [`CommonError::InvalidArgument`] on
/// length mismatch, mirroring the trait contract documented on
/// [`SymmetricCipher::encrypt_block`].
fn check_block(block: &[u8], expected: usize, name: &str) -> CryptoResult<()> {
    if block.len() != expected {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "{name} requires {expected}-byte block, got {}",
            block.len()
        ))));
    }
    Ok(())
}

/// Read a 32-bit big-endian word at the given byte offset of `src`.
///
/// The caller guarantees `src.len() >= offset + 4`.
#[inline]
fn load_u32_be(src: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&src[offset..offset + 4]);
    u32::from_be_bytes(buf)
}

/// Write a 32-bit big-endian word to the given byte offset of `dst`.
///
/// The caller guarantees `dst.len() >= offset + 4`.
#[inline]
fn store_u32_be(dst: &mut [u8], offset: usize, value: u32) {
    dst[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

// =============================================================================
// Blowfish
// =============================================================================
// Translated from `crypto/bf/` (Bruce Schneier, 1993).
// Structures and algorithm mirror `BF_set_key`, `BF_encrypt`, `BF_decrypt`.
// The key schedule derives both the 18-word P-array and the four 256-word
// S-boxes from the binary expansion of π mixed with the user-supplied key.
// =============================================================================

/// Number of Feistel rounds in Blowfish.
const BF_ROUNDS: usize = 16;

/// Blowfish minimum key length in bytes (translated from the OpenSSL public
/// API which rejects zero-length keys).
const BF_KEY_MIN: usize = 1;

/// Blowfish maximum meaningful key length in bytes: `(BF_ROUNDS + 2) * 4 = 72`.
/// The OpenSSL API clamps at this value per `bf_skey.c`.
const BF_KEY_MAX: usize = (BF_ROUNDS + 2) * 4;

// -----------------------------------------------------------------------------
// Blowfish initial tables (binary expansion of π)
// -----------------------------------------------------------------------------

/// Initial Blowfish P-array: first 18 words of the fractional part of π.
/// Translated from `crypto/bf/bf_pi.h` (`bf_init` P sub-array).
const BF_P_INIT: [u32; 18] = [
    0x243f_6a88,
    0x85a3_08d3,
    0x1319_8a2e,
    0x0370_7344,
    0xa409_3822,
    0x299f_31d0,
    0x082e_fa98,
    0xec4e_6c89,
    0x4528_21e6,
    0x38d0_1377,
    0xbe54_66cf,
    0x34e9_0c6c,
    0xc0ac_29b7,
    0xc97c_50dd,
    0x3f84_d5b5,
    0xb547_0917,
    0x9216_d5d9,
    0x8979_fb1b,
];

/// Initial Blowfish S-boxes: four arrays of 256 words each, derived from π.
/// Translated from `crypto/bf/bf_pi.h` (`bf_init` S sub-arrays).
const BF_S_INIT: [[u32; 256]; 4] = [
    [
        0xd131_0ba6,
        0x98df_b5ac,
        0x2ffd_72db,
        0xd01a_dfb7,
        0xb8e1_afed,
        0x6a26_7e96,
        0xba7c_9045,
        0xf12c_7f99,
        0x24a1_9947,
        0xb391_6cf7,
        0x0801_f2e2,
        0x858e_fc16,
        0x6369_20d8,
        0x7157_4e69,
        0xa458_fea3,
        0xf493_3d7e,
        0x0d95_748f,
        0x728e_b658,
        0x718b_cd58,
        0x8215_4aee,
        0x7b54_a41d,
        0xc25a_59b5,
        0x9c30_d539,
        0x2af2_6013,
        0xc5d1_b023,
        0x2860_85f0,
        0xca41_7918,
        0xb8db_38ef,
        0x8e79_dcb0,
        0x603a_180e,
        0x6c9e_0e8b,
        0xb01e_8a3e,
        0xd715_77c1,
        0xbd31_4b27,
        0x78af_2fda,
        0x5560_5c60,
        0xe655_25f3,
        0xaa55_ab94,
        0x5748_9862,
        0x63e8_1440,
        0x55ca_396a,
        0x2aab_10b6,
        0xb4cc_5c34,
        0x1141_e8ce,
        0xa154_86af,
        0x7c72_e993,
        0xb3ee_1411,
        0x636f_bc2a,
        0x2ba9_c55d,
        0x7418_31f6,
        0xce5c_3e16,
        0x9b87_931e,
        0xafd6_ba33,
        0x6c24_cf5c,
        0x7a32_5381,
        0x2895_8677,
        0x3b8f_4898,
        0x6b4b_b9af,
        0xc4bf_e81b,
        0x6628_2193,
        0x61d8_09cc,
        0xfb21_a991,
        0x487c_ac60,
        0x5dec_8032,
        0xef84_5d5d,
        0xe985_75b1,
        0xdc26_2302,
        0xeb65_1b88,
        0x2389_3e81,
        0xd396_acc5,
        0x0f6d_6ff3,
        0x83f4_4239,
        0x2e0b_4482,
        0xa484_2004,
        0x69c8_f04a,
        0x9e1f_9b5e,
        0x21c6_6842,
        0xf6e9_6c9a,
        0x670c_9c61,
        0xabd3_88f0,
        0x6a51_a0d2,
        0xd854_2f68,
        0x960f_a728,
        0xab51_33a3,
        0x6eef_0b6c,
        0x137a_3be4,
        0xba3b_f050,
        0x7efb_2a98,
        0xa1f1_651d,
        0x39af_0176,
        0x66ca_593e,
        0x8243_0e88,
        0x8cee_8619,
        0x456f_9fb4,
        0x7d84_a5c3,
        0x3b8b_5ebe,
        0xe06f_75d8,
        0x85c1_2073,
        0x401a_449f,
        0x56c1_6aa6,
        0x4ed3_aa62,
        0x363f_7706,
        0x1bfe_df72,
        0x429b_023d,
        0x37d0_d724,
        0xd00a_1248,
        0xdb0f_ead3,
        0x49f1_c09b,
        0x0753_72c9,
        0x8099_1b7b,
        0x25d4_79d8,
        0xf6e8_def7,
        0xe3fe_501a,
        0xb679_4c3b,
        0x976c_e0bd,
        0x04c0_06ba,
        0xc1a9_4fb6,
        0x409f_60c4,
        0x5e5c_9ec2,
        0x196a_2463,
        0x68fb_6faf,
        0x3e6c_53b5,
        0x1339_b2eb,
        0x3b52_ec6f,
        0x6dfc_511f,
        0x9b30_952c,
        0xcc81_4544,
        0xaf5e_bd09,
        0xbee3_d004,
        0xde33_4afd,
        0x660f_2807,
        0x192e_4bb3,
        0xc0cb_a857,
        0x45c8_740f,
        0xd20b_5f39,
        0xb9d3_fbdb,
        0x5579_c0bd,
        0x1a60_320a,
        0xd6a1_00c6,
        0x402c_7279,
        0x679f_25fe,
        0xfb1f_a3cc,
        0x8ea5_e9f8,
        0xdb32_22f8,
        0x3c75_16df,
        0xfd61_6b15,
        0x2f50_1ec8,
        0xad05_52ab,
        0x323d_b5fa,
        0xfd23_8760,
        0x5331_7b48,
        0x3e00_df82,
        0x9e5c_57bb,
        0xca6f_8ca0,
        0x1a87_562e,
        0xdf17_69db,
        0xd542_a8f6,
        0x287e_ffc3,
        0xac67_32c6,
        0x8c4f_5573,
        0x695b_27b0,
        0xbbca_58c8,
        0xe1ff_a35d,
        0xb8f0_11a0,
        0x10fa_3d98,
        0xfd21_83b8,
        0x4afc_b56c,
        0x2dd1_d35b,
        0x9a53_e479,
        0xb6f8_4565,
        0xd28e_49bc,
        0x4bfb_9790,
        0xe1dd_f2da,
        0xa4cb_7e33,
        0x62fb_1341,
        0xcee4_c6e8,
        0xef20_cada,
        0x3677_4c01,
        0xd07e_9efe,
        0x2bf1_1fb4,
        0x95db_da4d,
        0xae90_9198,
        0xeaad_8e71,
        0x6b93_d5a0,
        0xd08e_d1d0,
        0xafc7_25e0,
        0x8e3c_5b2f,
        0x8e75_94b7,
        0x8ff6_e2fb,
        0xf212_2b64,
        0x8888_b812,
        0x900d_f01c,
        0x4fad_5ea0,
        0x688f_c31c,
        0xd1cf_f191,
        0xb3a8_c1ad,
        0x2f2f_2218,
        0xbe0e_1777,
        0xea75_2dfe,
        0x8b02_1fa1,
        0xe5a0_cc0f,
        0xb56f_74e8,
        0x18ac_f3d6,
        0xce89_e299,
        0xb4a8_4fe0,
        0xfd13_e0b7,
        0x7cc4_3b81,
        0xd2ad_a8d9,
        0x165f_a266,
        0x8095_7705,
        0x93cc_7314,
        0x211a_1477,
        0xe6ad_2065,
        0x77b5_fa86,
        0xc754_42f5,
        0xfb9d_35cf,
        0xebcd_af0c,
        0x7b3e_89a0,
        0xd641_1bd3,
        0xae1e_7e49,
        0x0025_0e2d,
        0x2071_b35e,
        0x2268_00bb,
        0x57b8_e0af,
        0x2464_369b,
        0xf009_b91e,
        0x5563_911d,
        0x59df_a6aa,
        0x78c1_4389,
        0xd95a_537f,
        0x207d_5ba2,
        0x02e5_b9c5,
        0x8326_0376,
        0x6295_cfa9,
        0x11c8_1968,
        0x4e73_4a41,
        0xb347_2dca,
        0x7b14_a94a,
        0x1b51_0052,
        0x9a53_2915,
        0xd60f_573f,
        0xbc9b_c6e4,
        0x2b60_a476,
        0x81e6_7400,
        0x08ba_6fb5,
        0x571b_e91f,
        0xf296_ec6b,
        0x2a0d_d915,
        0xb663_6521,
        0xe7b9_f9b6,
        0xff34_052e,
        0xc585_5664,
        0x53b0_2d5d,
        0xa99f_8fa1,
        0x08ba_4799,
        0x6e85_076a,
    ],
    [
        0x4b7a_70e9,
        0xb5b3_2944,
        0xdb75_092e,
        0xc419_2623,
        0xad6e_a6b0,
        0x49a7_df7d,
        0x9cee_60b8,
        0x8fed_b266,
        0xecaa_8c71,
        0x699a_17ff,
        0x5664_526c,
        0xc2b1_9ee1,
        0x1936_02a5,
        0x7509_4c29,
        0xa059_1340,
        0xe418_3a3e,
        0x3f54_989a,
        0x5b42_9d65,
        0x6b8f_e4d6,
        0x99f7_3fd6,
        0xa1d2_9c07,
        0xefe8_30f5,
        0x4d2d_38e6,
        0xf025_5dc1,
        0x4cdd_2086,
        0x8470_eb26,
        0x6382_e9c6,
        0x021e_cc5e,
        0x0968_6b3f,
        0x3eba_efc9,
        0x3c97_1814,
        0x6b6a_70a1,
        0x687f_3584,
        0x52a0_e286,
        0xb79c_5305,
        0xaa50_0737,
        0x3e07_841c,
        0x7fde_ae5c,
        0x8e7d_44ec,
        0x5716_f2b8,
        0xb03a_da37,
        0xf050_0c0d,
        0xf01c_1f04,
        0x0200_b3ff,
        0xae0c_f51a,
        0x3cb5_74b2,
        0x2583_7a58,
        0xdc09_21bd,
        0xd191_13f9,
        0x7ca9_2ff6,
        0x9432_4773,
        0x22f5_4701,
        0x3ae5_e581,
        0x37c2_dadc,
        0xc8b5_7634,
        0x9af3_dda7,
        0xa944_6146,
        0x0fd0_030e,
        0xecc8_c73e,
        0xa475_1e41,
        0xe238_cd99,
        0x3bea_0e2f,
        0x3280_bba1,
        0x183e_b331,
        0x4e54_8b38,
        0x4f6d_b908,
        0x6f42_0d03,
        0xf60a_04bf,
        0x2cb8_1290,
        0x2497_7c79,
        0x5679_b072,
        0xbcaf_89af,
        0xde9a_771f,
        0xd993_0810,
        0xb38b_ae12,
        0xdccf_3f2e,
        0x5512_721f,
        0x2e6b_7124,
        0x501a_dde6,
        0x9f84_cd87,
        0x7a58_4718,
        0x7408_da17,
        0xbc9f_9abc,
        0xe94b_7d8c,
        0xec7a_ec3a,
        0xdb85_1dfa,
        0x6309_4366,
        0xc464_c3d2,
        0xef1c_1847,
        0x3215_d908,
        0xdd43_3b37,
        0x24c2_ba16,
        0x12a1_4d43,
        0x2a65_c451,
        0x5094_0002,
        0x133a_e4dd,
        0x71df_f89e,
        0x1031_4e55,
        0x81ac_77d6,
        0x5f11_199b,
        0x0435_56f1,
        0xd7a3_c76b,
        0x3c11_183b,
        0x5924_a509,
        0xf28f_e6ed,
        0x97f1_fbfa,
        0x9eba_bf2c,
        0x1e15_3c6e,
        0x86e3_4570,
        0xeae9_6fb1,
        0x860e_5e0a,
        0x5a3e_2ab3,
        0x771f_e71c,
        0x4e3d_06fa,
        0x2965_dcb9,
        0x99e7_1d0f,
        0x803e_89d6,
        0x5266_c825,
        0x2e4c_c978,
        0x9c10_b36a,
        0xc615_0eba,
        0x94e2_ea78,
        0xa5fc_3c53,
        0x1e0a_2df4,
        0xf2f7_4ea7,
        0x361d_2b3d,
        0x1939_260f,
        0x19c2_7960,
        0x5223_a708,
        0xf713_12b6,
        0xebad_fe6e,
        0xeac3_1f66,
        0xe3bc_4595,
        0xa67b_c883,
        0xb17f_37d1,
        0x018c_ff28,
        0xc332_ddef,
        0xbe6c_5aa5,
        0x6558_2185,
        0x68ab_9802,
        0xeece_a50f,
        0xdb2f_953b,
        0x2aef_7dad,
        0x5b6e_2f84,
        0x1521_b628,
        0x2907_6170,
        0xecdd_4775,
        0x619f_1510,
        0x13cc_a830,
        0xeb61_bd96,
        0x0334_fe1e,
        0xaa03_63cf,
        0xb573_5c90,
        0x4c70_a239,
        0xd59e_9e0b,
        0xcbaa_de14,
        0xeecc_86bc,
        0x6062_2ca7,
        0x9cab_5cab,
        0xb2f3_846e,
        0x648b_1eaf,
        0x19bd_f0ca,
        0xa023_69b9,
        0x655a_bb50,
        0x4068_5a32,
        0x3c2a_b4b3,
        0x319e_e9d5,
        0xc021_b8f7,
        0x9b54_0b19,
        0x875f_a099,
        0x95f7_997e,
        0x623d_7da8,
        0xf837_889a,
        0x97e3_2d77,
        0x11ed_935f,
        0x1668_1281,
        0x0e35_8829,
        0xc7e6_1fd6,
        0x96de_dfa1,
        0x7858_ba99,
        0x57f5_84a5,
        0x1b22_7263,
        0x9b83_c3ff,
        0x1ac2_4696,
        0xcdb3_0aeb,
        0x532e_3054,
        0x8fd9_48e4,
        0x6dbc_3128,
        0x58eb_f2ef,
        0x34c6_ffea,
        0xfe28_ed61,
        0xee7c_3c73,
        0x5d4a_14d9,
        0xe864_b7e3,
        0x4210_5d14,
        0x203e_13e0,
        0x45ee_e2b6,
        0xa3aa_abea,
        0xdb6c_4f15,
        0xfacb_4fd0,
        0xc742_f442,
        0xef6a_bbb5,
        0x654f_3b1d,
        0x41cd_2105,
        0xd81e_799e,
        0x8685_4dc7,
        0xe44b_476a,
        0x3d81_6250,
        0xcf62_a1f2,
        0x5b8d_2646,
        0xfc88_83a0,
        0xc1c7_b6a3,
        0x7f15_24c3,
        0x69cb_7492,
        0x4784_8a0b,
        0x5692_b285,
        0x095b_bf00,
        0xad19_489d,
        0x1462_b174,
        0x2382_0e00,
        0x5842_8d2a,
        0x0c55_f5ea,
        0x1dad_f43e,
        0x233f_7061,
        0x3372_f092,
        0x8d93_7e41,
        0xd65f_ecf1,
        0x6c22_3bdb,
        0x7cde_3759,
        0xcbee_7460,
        0x4085_f2a7,
        0xce77_326e,
        0xa607_8084,
        0x19f8_509e,
        0xe8ef_d855,
        0x61d9_9735,
        0xa969_a7aa,
        0xc50c_06c2,
        0x5a04_abfc,
        0x800b_cadc,
        0x9e44_7a2e,
        0xc345_3484,
        0xfdd5_6705,
        0x0e1e_9ec9,
        0xdb73_dbd3,
        0x1055_88cd,
        0x675f_da79,
        0xe367_4340,
        0xc5c4_3465,
        0x713e_38d8,
        0x3d28_f89e,
        0xf16d_ff20,
        0x153e_21e7,
        0x8fb0_3d4a,
        0xe6e3_9f2b,
        0xdb83_adf7,
    ],
    [
        0xe93d_5a68,
        0x9481_40f7,
        0xf64c_261c,
        0x9469_2934,
        0x4115_20f7,
        0x7602_d4f7,
        0xbcf4_6b2e,
        0xd4a2_0068,
        0xd408_2471,
        0x3320_f46a,
        0x43b7_d4b7,
        0x5000_61af,
        0x1e39_f62e,
        0x9724_4546,
        0x1421_4f74,
        0xbf8b_8840,
        0x4d95_fc1d,
        0x96b5_91af,
        0x70f4_ddd3,
        0x66a0_2f45,
        0xbfbc_09ec,
        0x03bd_9785,
        0x7fac_6dd0,
        0x31cb_8504,
        0x96eb_27b3,
        0x55fd_3941,
        0xda25_47e6,
        0xabca_0a9a,
        0x2850_7825,
        0x5304_29f4,
        0x0a2c_86da,
        0xe9b6_6dfb,
        0x68dc_1462,
        0xd748_6900,
        0x680e_c0a4,
        0x27a1_8dee,
        0x4f3f_fea2,
        0xe887_ad8c,
        0xb58c_e006,
        0x7af4_d6b6,
        0xaace_1e7c,
        0xd337_5fec,
        0xce78_a399,
        0x406b_2a42,
        0x20fe_9e35,
        0xd9f3_85b9,
        0xee39_d7ab,
        0x3b12_4e8b,
        0x1dc9_faf7,
        0x4b6d_1856,
        0x26a3_6631,
        0xeae3_97b2,
        0x3a6e_fa74,
        0xdd5b_4332,
        0x6841_e7f7,
        0xca78_20fb,
        0xfb0a_f54e,
        0xd8fe_b397,
        0x4540_56ac,
        0xba48_9527,
        0x5553_3a3a,
        0x2083_8d87,
        0xfe6b_a9b7,
        0xd096_954b,
        0x55a8_67bc,
        0xa115_9a58,
        0xcca9_2963,
        0x99e1_db33,
        0xa62a_4a56,
        0x3f31_25f9,
        0x5ef4_7e1c,
        0x9029_317c,
        0xfdf8_e802,
        0x0427_2f70,
        0x80bb_155c,
        0x0528_2ce3,
        0x95c1_1548,
        0xe4c6_6d22,
        0x48c1_133f,
        0xc70f_86dc,
        0x07f9_c9ee,
        0x4104_1f0f,
        0x4047_79a4,
        0x5d88_6e17,
        0x325f_51eb,
        0xd59b_c0d1,
        0xf2bc_c18f,
        0x4111_3564,
        0x257b_7834,
        0x602a_9c60,
        0xdff8_e8a3,
        0x1f63_6c1b,
        0x0e12_b4c2,
        0x02e1_329e,
        0xaf66_4fd1,
        0xcad1_8115,
        0x6b23_95e0,
        0x333e_92e1,
        0x3b24_0b62,
        0xeebe_b922,
        0x85b2_a20e,
        0xe6ba_0d99,
        0xde72_0c8c,
        0x2da2_f728,
        0xd012_7845,
        0x95b7_94fd,
        0x647d_0862,
        0xe7cc_f5f0,
        0x5449_a36f,
        0x877d_48fa,
        0xc39d_fd27,
        0xf33e_8d1e,
        0x0a47_6341,
        0x992e_ff74,
        0x3a6f_6eab,
        0xf4f8_fd37,
        0xa812_dc60,
        0xa1eb_ddf8,
        0x991b_e14c,
        0xdb6e_6b0d,
        0xc67b_5510,
        0x6d67_2c37,
        0x2765_d43b,
        0xdcd0_e804,
        0xf129_0dc7,
        0xcc00_ffa3,
        0xb539_0f92,
        0x690f_ed0b,
        0x667b_9ffb,
        0xcedb_7d9c,
        0xa091_cf0b,
        0xd915_5ea3,
        0xbb13_2f88,
        0x515b_ad24,
        0x7b94_79bf,
        0x763b_d6eb,
        0x3739_2eb3,
        0xcc11_5979,
        0x8026_e297,
        0xf42e_312d,
        0x6842_ada7,
        0xc66a_2b3b,
        0x1275_4ccc,
        0x782e_f11c,
        0x6a12_4237,
        0xb792_51e7,
        0x06a1_bbe6,
        0x4bfb_6350,
        0x1a6b_1018,
        0x11ca_edfa,
        0x3d25_bdd8,
        0xe2e1_c3c9,
        0x4442_1659,
        0x0a12_1386,
        0xd90c_ec6e,
        0xd5ab_ea2a,
        0x64af_674e,
        0xda86_a85f,
        0xbebf_e988,
        0x64e4_c3fe,
        0x9dbc_8057,
        0xf0f7_c086,
        0x6078_7bf8,
        0x6003_604d,
        0xd1fd_8346,
        0xf638_1fb0,
        0x7745_ae04,
        0xd736_fccc,
        0x8342_6b33,
        0xf01e_ab71,
        0xb080_4187,
        0x3c00_5e5f,
        0x77a0_57be,
        0xbde8_ae24,
        0x5546_4299,
        0xbf58_2e61,
        0x4e58_f48f,
        0xf2dd_fda2,
        0xf474_ef38,
        0x8789_bdc2,
        0x5366_f9c3,
        0xc8b3_8e74,
        0xb475_f255,
        0x46fc_d9b9,
        0x7aeb_2661,
        0x8b1d_df84,
        0x846a_0e79,
        0x915f_95e2,
        0x466e_598e,
        0x20b4_5770,
        0x8cd5_5591,
        0xc902_de4c,
        0xb90b_ace1,
        0xbb82_05d0,
        0x11a8_6248,
        0x7574_a99e,
        0xb77f_19b6,
        0xe0a9_dc09,
        0x662d_09a1,
        0xc432_4633,
        0xe85a_1f02,
        0x09f0_be8c,
        0x4a99_a025,
        0x1d6e_fe10,
        0x1ab9_3d1d,
        0x0ba5_a4df,
        0xa186_f20f,
        0x2868_f169,
        0xdcb7_da83,
        0x5739_06fe,
        0xa1e2_ce9b,
        0x4fcd_7f52,
        0x5011_5e01,
        0xa706_83fa,
        0xa002_b5c4,
        0x0de6_d027,
        0x9af8_8c27,
        0x773f_8641,
        0xc360_4c06,
        0x61a8_06b5,
        0xf017_7a28,
        0xc0f5_86e0,
        0x0060_58aa,
        0x30dc_7d62,
        0x11e6_9ed7,
        0x2338_ea63,
        0x53c2_dd94,
        0xc2c2_1634,
        0xbbcb_ee56,
        0x90bc_b6de,
        0xebfc_7da1,
        0xce59_1d76,
        0x6f05_e409,
        0x4b7c_0188,
        0x3972_0a3d,
        0x7c92_7c24,
        0x86e3_725f,
        0x724d_9db9,
        0x1ac1_5bb4,
        0xd39e_b8fc,
        0xed54_5578,
        0x08fc_a5b5,
        0xd83d_7cd3,
        0x4dad_0fc4,
        0x1e50_ef5e,
        0xb161_e6f8,
        0xa285_14d9,
        0x6c51_133c,
        0x6fd5_c7e7,
        0x56e1_4ec4,
        0x362a_bfce,
        0xddc6_c837,
        0xd79a_3234,
        0x9263_8212,
        0x670e_fa8e,
        0x4060_00e0,
    ],
    [
        0x3a39_ce37,
        0xd3fa_f5cf,
        0xabc2_7737,
        0x5ac5_2d1b,
        0x5cb0_679e,
        0x4fa3_3742,
        0xd382_2740,
        0x99bc_9bbe,
        0xd511_8e9d,
        0xbf0f_7315,
        0xd62d_1c7e,
        0xc700_c47b,
        0xb78c_1b6b,
        0x21a1_9045,
        0xb26e_b1be,
        0x6a36_6eb4,
        0x5748_ab2f,
        0xbc94_6e79,
        0xc6a3_76d2,
        0x6549_c2c8,
        0x530f_f8ee,
        0x468d_de7d,
        0xd573_0a1d,
        0x4cd0_4dc6,
        0x2939_bbdb,
        0xa9ba_4650,
        0xac95_26e8,
        0xbe5e_e304,
        0xa1fa_d5f0,
        0x6a2d_519a,
        0x63ef_8ce2,
        0x9a86_ee22,
        0xc089_c2b8,
        0x4324_2ef6,
        0xa51e_03aa,
        0x9cf2_d0a4,
        0x83c0_61ba,
        0x9be9_6a4d,
        0x8fe5_1550,
        0xba64_5bd6,
        0x2826_a2f9,
        0xa73a_3ae1,
        0x4ba9_9586,
        0xef55_62e9,
        0xc72f_efd3,
        0xf752_f7da,
        0x3f04_6f69,
        0x77fa_0a59,
        0x80e4_a915,
        0x87b0_8601,
        0x9b09_e6ad,
        0x3b3e_e593,
        0xe990_fd5a,
        0x9e34_d797,
        0x2cf0_b7d9,
        0x022b_8b51,
        0x96d5_ac3a,
        0x017d_a67d,
        0xd1cf_3ed6,
        0x7c7d_2d28,
        0x1f9f_25cf,
        0xadf2_b89b,
        0x5ad6_b472,
        0x5a88_f54c,
        0xe029_ac71,
        0xe019_a5e6,
        0x47b0_acfd,
        0xed93_fa9b,
        0xe8d3_c48d,
        0x283b_57cc,
        0xf8d5_6629,
        0x7913_2e28,
        0x785f_0191,
        0xed75_6055,
        0xf796_0e44,
        0xe3d3_5e8c,
        0x1505_6dd4,
        0x88f4_6dba,
        0x03a1_6125,
        0x0564_f0bd,
        0xc3eb_9e15,
        0x3c90_57a2,
        0x9727_1aec,
        0xa93a_072a,
        0x1b3f_6d9b,
        0x1e63_21f5,
        0xf59c_66fb,
        0x26dc_f319,
        0x7533_d928,
        0xb155_fdf5,
        0x0356_3482,
        0x8aba_3cbb,
        0x2851_7711,
        0xc20a_d9f8,
        0xabcc_5167,
        0xccad_925f,
        0x4de8_1751,
        0x3830_dc8e,
        0x379d_5862,
        0x9320_f991,
        0xea7a_90c2,
        0xfb3e_7bce,
        0x5121_ce64,
        0x774f_be32,
        0xa8b6_e37e,
        0xc329_3d46,
        0x48de_5369,
        0x6413_e680,
        0xa2ae_0810,
        0xdd6d_b224,
        0x6985_2dfd,
        0x0907_2166,
        0xb39a_460a,
        0x6445_c0dd,
        0x586c_decf,
        0x1c20_c8ae,
        0x5bbe_f7dd,
        0x1b58_8d40,
        0xccd2_017f,
        0x6bb4_e3bb,
        0xdda2_6a7e,
        0x3a59_ff45,
        0x3e35_0a44,
        0xbcb4_cdd5,
        0x72ea_cea8,
        0xfa64_84bb,
        0x8d66_12ae,
        0xbf3c_6f47,
        0xd29b_e463,
        0x542f_5d9e,
        0xaec2_771b,
        0xf64e_6370,
        0x740e_0d8d,
        0xe75b_1357,
        0xf872_1671,
        0xaf53_7d5d,
        0x4040_cb08,
        0x4eb4_e2cc,
        0x34d2_466a,
        0x0115_af84,
        0xe1b0_0428,
        0x9598_3a1d,
        0x06b8_9fb4,
        0xce6e_a048,
        0x6f3f_3b82,
        0x3520_ab82,
        0x011a_1d4b,
        0x2772_27f8,
        0x6115_60b1,
        0xe793_3fdc,
        0xbb3a_792b,
        0x3445_25bd,
        0xa088_39e1,
        0x51ce_794b,
        0x2f32_c9b7,
        0xa01f_bac9,
        0xe01c_c87e,
        0xbcc7_d1f6,
        0xcf01_11c3,
        0xa1e8_aac7,
        0x1a90_8749,
        0xd44f_bd9a,
        0xd0da_decb,
        0xd50a_da38,
        0x0339_c32a,
        0xc691_3667,
        0x8df9_317c,
        0xe0b1_2b4f,
        0xf79e_59b7,
        0x43f5_bb3a,
        0xf2d5_19ff,
        0x27d9_459c,
        0xbf97_222c,
        0x15e6_fc2a,
        0x0f91_fc71,
        0x9b94_1525,
        0xfae5_9361,
        0xceb6_9ceb,
        0xc2a8_6459,
        0x12ba_a8d1,
        0xb6c1_075e,
        0xe305_6a0c,
        0x10d2_5065,
        0xcb03_a442,
        0xe0ec_6e0e,
        0x1698_db3b,
        0x4c98_a0be,
        0x3278_e964,
        0x9f1f_9532,
        0xe0d3_92df,
        0xd3a0_342b,
        0x8971_f21e,
        0x1b0a_7441,
        0x4ba3_348c,
        0xc5be_7120,
        0xc376_32d8,
        0xdf35_9f8d,
        0x9b99_2f2e,
        0xe60b_6f47,
        0x0fe3_f11d,
        0xe54c_da54,
        0x1eda_d891,
        0xce62_79cf,
        0xcd3e_7e6f,
        0x1618_b166,
        0xfd2c_1d05,
        0x848f_d2c5,
        0xf6fb_2299,
        0xf523_f357,
        0xa632_7623,
        0x93a8_3531,
        0x56cc_cd02,
        0xacf0_8162,
        0x5a75_ebb5,
        0x6e16_3697,
        0x88d2_73cc,
        0xde96_6292,
        0x81b9_49d0,
        0x4c50_901b,
        0x71c6_5614,
        0xe6c6_c7bd,
        0x327a_140a,
        0x45e1_d006,
        0xc3f2_7b9a,
        0xc9aa_53fd,
        0x62a8_0f00,
        0xbb25_bfe2,
        0x35bd_d2f6,
        0x7112_6905,
        0xb204_0222,
        0xb6cb_cf7c,
        0xcd76_9c2b,
        0x5311_3ec0,
        0x1640_e3d3,
        0x38ab_bd60,
        0x2547_adf0,
        0xba38_209c,
        0xf746_ce76,
        0x77af_a1c5,
        0x2075_6060,
        0x85cb_fe4e,
        0x8ae8_8dd8,
        0x7aaa_f9b0,
        0x4cf9_aa7e,
        0x1948_c25c,
        0x02fb_8a8c,
        0x01c3_6ae4,
        0xd6eb_e1f9,
        0x90d4_f869,
        0xa65c_dea0,
        0x3f09_252d,
        0xc208_e69f,
        0xb74e_6132,
        0xce77_e25b,
        0x578f_dfe3,
        0x3ac3_72e6,
    ],
];

// -----------------------------------------------------------------------------
// Blowfish struct and implementation
// -----------------------------------------------------------------------------

/// Blowfish block cipher (64-bit block, variable 1–56 byte key).
///
/// Mirrors the C `BF_KEY` structure from `crypto/bf/bf_local.h`:
/// ```c
/// typedef struct bf_key_st {
///     BF_LONG P[BF_ROUNDS + 2];
///     BF_LONG S[4 * 256];
/// } BF_KEY;
/// ```
///
/// The struct retains the expanded P-array and the four S-boxes. Key material
/// is wiped from memory when the instance is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Blowfish {
    /// Expanded P-array (18 × 32-bit subkeys).
    p: [u32; BF_ROUNDS + 2],
    /// Four S-boxes (4 × 256 × 32 bits).
    s: [[u32; 256]; 4],
}

impl Blowfish {
    /// Round function `F` from `crypto/bf/bf_local.h` (`BF_ENC` macro).
    ///
    /// Computes `((S0[B3] + S1[B2]) XOR S2[B1]) + S3[B0]` in wrapping u32.
    ///
    /// # Security (cache-timing)
    ///
    /// This is the **principal cache-timing-vulnerable site** of Blowfish
    /// encryption and decryption. The four byte-indexed lookups into
    /// `self.s[0..=3]` use **secret-derived indices** (`b0..b3` are bytes of
    /// `x`, which mixes the round subkey with the opposite half of the
    /// Feistel state). Each S-box is 256 × 32-bit = 1024 bytes — large
    /// enough to span multiple cache lines on any modern CPU, so the
    /// cache-line residency of each access leaks information about the
    /// indexed byte.
    ///
    /// Per block: **4 lookups × 16 Feistel rounds = 64 secret-indexed S-box
    /// reads** through both `encrypt_words` and `decrypt_words`. During the
    /// key schedule (`Blowfish::new`), the initial S-boxes are encrypted in
    /// place, triggering the same lookup pattern on the **expanded key
    /// material** — leakage scope is therefore both per-block AND per-key.
    ///
    /// No constant-time software path is provided for Blowfish in this
    /// crate; no hardware acceleration exists for Blowfish on any
    /// commodity CPU. The only effective mitigation is to **migrate off
    /// Blowfish** to AES-GCM or ChaCha20-Poly1305. Additionally, Blowfish
    /// is a **64-bit-block cipher** and therefore vulnerable to Sweet32
    /// birthday attacks (RFC 7457) for long-lived sessions.
    ///
    /// See the module-level *Security Notice — Cache-Timing Side Channel*
    /// for the full threat model and the Bernstein 2005 /
    /// Tromer-Osvik-Shamir 2010 references.
    #[inline]
    fn f(&self, x: u32) -> u32 {
        let b0 = (x & 0xff) as usize;
        let b1 = ((x >> 8) & 0xff) as usize;
        let b2 = ((x >> 16) & 0xff) as usize;
        let b3 = ((x >> 24) & 0xff) as usize;
        (self.s[0][b3].wrapping_add(self.s[1][b2]) ^ self.s[2][b1]).wrapping_add(self.s[3][b0])
    }

    /// Encrypt one 64-bit block presented as two 32-bit words `[l, r]`.
    ///
    /// Translates the `BF_encrypt` function from `crypto/bf/bf_enc.c`. Sixteen
    /// Feistel rounds mix the halves through the `F` function under P[0..15],
    /// then the halves are whitened with P[16] and P[17] and swapped.
    fn encrypt_words(&self, l: &mut u32, r: &mut u32) {
        let mut xl = *l;
        let mut xr = *r;

        xl ^= self.p[0];
        for i in (1..=BF_ROUNDS).step_by(2) {
            xr ^= self.f(xl) ^ self.p[i];
            xl ^= self.f(xr) ^ self.p[i + 1];
        }
        xr ^= self.p[BF_ROUNDS + 1];

        // Output swap: (l, r) = (xr, xl).
        *l = xr;
        *r = xl;
    }

    /// Decrypt one 64-bit block presented as two 32-bit words `[l, r]`.
    ///
    /// Translates `BF_decrypt` from `crypto/bf/bf_enc.c`: the P-array is
    /// consumed in reverse order.
    fn decrypt_words(&self, l: &mut u32, r: &mut u32) {
        let mut xl = *l;
        let mut xr = *r;

        xl ^= self.p[BF_ROUNDS + 1];
        let mut i = BF_ROUNDS;
        while i >= 2 {
            xr ^= self.f(xl) ^ self.p[i];
            xl ^= self.f(xr) ^ self.p[i - 1];
            i -= 2;
        }
        xr ^= self.p[0];

        *l = xr;
        *r = xl;
    }

    /// Construct a new Blowfish cipher from a user-supplied key.
    ///
    /// Translates `BF_set_key` from `crypto/bf/bf_skey.c`:
    ///
    /// 1. Copy the π-derived P and S initial values.
    /// 2. XOR key bytes (cyclically) as 32-bit words into the P-array.
    /// 3. Iteratively encrypt the zero block and use the output to replace
    ///    successive pairs of entries in P and S, generating 521 encryptions
    ///    in total.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] when `key` is empty or longer than
    /// `BF_KEY_MAX` (72 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.is_empty() || key.len() < BF_KEY_MIN {
            return Err(CryptoError::Key(format!(
                "Blowfish key must be {BF_KEY_MIN}–{BF_KEY_MAX} bytes, got {}",
                key.len()
            )));
        }
        // OpenSSL clamps longer keys to BF_KEY_MAX rather than rejecting; we
        // replicate that behaviour exactly so the cipher interoperates with
        // the reference implementation.
        let effective_len = key.len().min(BF_KEY_MAX);

        let mut bf = Blowfish {
            p: BF_P_INIT,
            s: BF_S_INIT,
        };

        // XOR cyclic key bytes into the P-array as 32-bit words.
        let mut ki = 0usize;
        for i in 0..(BF_ROUNDS + 2) {
            let mut word: u32 = 0;
            for _ in 0..4 {
                word = (word << 8) | u32::from(key[ki]);
                ki = (ki + 1) % effective_len;
            }
            bf.p[i] ^= word;
        }

        // Iteratively encrypt the zero vector to overwrite P and then S.
        let mut l: u32 = 0;
        let mut r: u32 = 0;

        let mut i = 0usize;
        while i < BF_ROUNDS + 2 {
            bf.encrypt_words(&mut l, &mut r);
            bf.p[i] = l;
            bf.p[i + 1] = r;
            i += 2;
        }

        for s_box in 0..4 {
            let mut j = 0usize;
            while j < 256 {
                bf.encrypt_words(&mut l, &mut r);
                bf.s[s_box][j] = l;
                bf.s[s_box][j + 1] = r;
                j += 2;
            }
        }

        Ok(bf)
    }
}

impl SymmetricCipher for Blowfish {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "Blowfish")?;
        let mut l = load_u32_be(block, 0);
        let mut r = load_u32_be(block, 4);
        self.encrypt_words(&mut l, &mut r);
        store_u32_be(block, 0, l);
        store_u32_be(block, 4, r);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "Blowfish")?;
        let mut l = load_u32_be(block, 0);
        let mut r = load_u32_be(block, 4);
        self.decrypt_words(&mut l, &mut r);
        store_u32_be(block, 0, l);
        store_u32_be(block, 4, r);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Blowfish
    }
}

// -----------------------------------------------------------------------------
// CAST-128 / CAST5 (RFC 2144)
// -----------------------------------------------------------------------------

/// Maximum CAST5 key length (RFC 2144 permits 40–128 bits, i.e. 5–16 bytes).
const CAST_KEY_MAX: usize = 16;
/// Minimum CAST5 key length.
const CAST_KEY_MIN: usize = 5;
/// CAST5 short-key threshold: keys ≤10 bytes use 12-round variant.
const CAST_SHORT_KEY_MAX: usize = 10;

const CAST_S0: [u32; 256] = [
    0x30fb_40d4,
    0x9fa0_ff0b,
    0x6bec_cd2f,
    0x3f25_8c7a,
    0x1e21_3f2f,
    0x9c00_4dd3,
    0x6003_e540,
    0xcf9f_c949,
    0xbfd4_af27,
    0x88bb_bdb5,
    0xe203_4090,
    0x98d0_9675,
    0x6e63_a0e0,
    0x15c3_61d2,
    0xc2e7_661d,
    0x22d4_ff8e,
    0x2868_3b6f,
    0xc07f_d059,
    0xff23_79c8,
    0x775f_50e2,
    0x43c3_40d3,
    0xdf2f_8656,
    0x887c_a41a,
    0xa2d2_bd2d,
    0xa1c9_e0d6,
    0x346c_4819,
    0x61b7_6d87,
    0x2254_0f2f,
    0x2abe_32e1,
    0xaa54_166b,
    0x2256_8e3a,
    0xa2d3_41d0,
    0x66db_40c8,
    0xa784_392f,
    0x004d_ff2f,
    0x2db9_d2de,
    0x9794_3fac,
    0x4a97_c1d8,
    0x5276_44b7,
    0xb5f4_37a7,
    0xb82c_baef,
    0xd751_d159,
    0x6ff7_f0ed,
    0x5a09_7a1f,
    0x827b_68d0,
    0x90ec_f52e,
    0x22b0_c054,
    0xbc8e_5935,
    0x4b6d_2f7f,
    0x50bb_64a2,
    0xd266_4910,
    0xbee5_812d,
    0xb733_2290,
    0xe93b_159f,
    0xb48e_e411,
    0x4bff_345d,
    0xfd45_c240,
    0xad31_973f,
    0xc4f6_d02e,
    0x55fc_8165,
    0xd5b1_caad,
    0xa1ac_2dae,
    0xa2d4_b76d,
    0xc19b_0c50,
    0x8822_40f2,
    0x0c6e_4f38,
    0xa4e4_bfd7,
    0x4f5b_a272,
    0x564c_1d2f,
    0xc59c_5319,
    0xb949_e354,
    0xb046_69fe,
    0xb1b6_ab8a,
    0xc713_58dd,
    0x6385_c545,
    0x110f_935d,
    0x5753_8ad5,
    0x6a39_0493,
    0xe63d_37e0,
    0x2a54_f6b3,
    0x3a78_7d5f,
    0x6276_a0b5,
    0x19a6_fcdf,
    0x7a42_206a,
    0x29f9_d4d5,
    0xf61b_1891,
    0xbb72_275e,
    0xaa50_8167,
    0x3890_1091,
    0xc6b5_05eb,
    0x84c7_cb8c,
    0x2ad7_5a0f,
    0x874a_1427,
    0xa2d1_936b,
    0x2ad2_86af,
    0xaa56_d291,
    0xd789_4360,
    0x425c_750d,
    0x93b3_9e26,
    0x1871_84c9,
    0x6c00_b32d,
    0x73e2_bb14,
    0xa0be_bc3c,
    0x5462_3779,
    0x6445_9eab,
    0x3f32_8b82,
    0x7718_cf82,
    0x59a2_cea6,
    0x04ee_002e,
    0x89fe_78e6,
    0x3fab_0950,
    0x325f_f6c2,
    0x8138_3f05,
    0x6963_c5c8,
    0x76cb_5ad6,
    0xd499_74c9,
    0xca18_0dcf,
    0x3807_82d5,
    0xc7fa_5cf6,
    0x8ac3_1511,
    0x35e7_9e13,
    0x47da_91d0,
    0xf40f_9086,
    0xa7e2_419e,
    0x3136_6241,
    0x051e_f495,
    0xaa57_3b04,
    0x4a80_5d8d,
    0x5483_00d0,
    0x0032_2a3c,
    0xbf64_cddf,
    0xba57_a68e,
    0x75c6_372b,
    0x50af_d341,
    0xa7c1_3275,
    0x915a_0bf5,
    0x6b54_bfab,
    0x2b0b_1426,
    0xab4c_c9d7,
    0x449c_cd82,
    0xf7fb_f265,
    0xab85_c5f3,
    0x1b55_db94,
    0xaad4_e324,
    0xcfa4_bd3f,
    0x2dea_a3e2,
    0x9e20_4d02,
    0xc8bd_25ac,
    0xeadf_55b3,
    0xd5bd_9e98,
    0xe312_31b2,
    0x2ad5_ad6c,
    0x9543_29de,
    0xadbe_4528,
    0xd871_0f69,
    0xaa51_c90f,
    0xaa78_6bf6,
    0x2251_3f1e,
    0xaa51_a79b,
    0x2ad3_44cc,
    0x7b5a_41f0,
    0xd37c_fbad,
    0x1b06_9505,
    0x41ec_e491,
    0xb4c3_32e6,
    0x0322_68d4,
    0xc960_0acc,
    0xce38_7e6d,
    0xbf6b_b16c,
    0x6a70_fb78,
    0x0d03_d9c9,
    0xd4df_39de,
    0xe010_63da,
    0x4736_f464,
    0x5ad3_28d8,
    0xb347_cc96,
    0x75bb_0fc3,
    0x9851_1bfb,
    0x4ffb_cc35,
    0xb58b_cf6a,
    0xe11f_0abc,
    0xbfc5_fe4a,
    0xa70a_ec10,
    0xac39_570a,
    0x3f04_442f,
    0x6188_b153,
    0xe039_7a2e,
    0x5727_cb79,
    0x9ceb_418f,
    0x1cac_d68d,
    0x2ad3_7c96,
    0x0175_cb9d,
    0xc69d_ff09,
    0xc75b_65f0,
    0xd9db_40d8,
    0xec0e_7779,
    0x4744_ead4,
    0xb11c_3274,
    0xdd24_cb9e,
    0x7e1c_54bd,
    0xf011_44f9,
    0xd224_0eb1,
    0x9675_b3fd,
    0xa3ac_3755,
    0xd47c_27af,
    0x51c8_5f4d,
    0x5690_7596,
    0xa5bb_15e6,
    0x5803_04f0,
    0xca04_2cf1,
    0x011a_37ea,
    0x8dbf_aadb,
    0x35ba_3e4a,
    0x3526_ffa0,
    0xc37b_4d09,
    0xbc30_6ed9,
    0x98a5_2666,
    0x5648_f725,
    0xff5e_569d,
    0x0ced_63d0,
    0x7c63_b2cf,
    0x700b_45e1,
    0xd5ea_50f1,
    0x85a9_2872,
    0xaf1f_bda7,
    0xd423_4870,
    0xa787_0bf3,
    0x2d3b_4d79,
    0x42e0_4198,
    0x0cd0_ede7,
    0x2647_0db8,
    0xf881_814c,
    0x474d_6ad7,
    0x7c0c_5e5c,
    0xd123_1959,
    0x381b_7298,
    0xf5d2_f4db,
    0xab83_8653,
    0x6e2f_1e23,
    0x8371_9c9e,
    0xbd91_e046,
    0x9a56_456e,
    0xdc39_200c,
    0x20c8_c571,
    0x962b_da1c,
    0xe1e6_96ff,
    0xb141_ab08,
    0x7cca_89b9,
    0x1a69_e783,
    0x02cc_4843,
    0xa2f7_c579,
    0x429e_f47d,
    0x427b_169c,
    0x5ac9_f049,
    0xdd8f_0f00,
    0x5c81_65bf,
];

const CAST_S1: [u32; 256] = [
    0x1f20_1094,
    0xef0b_a75b,
    0x69e3_cf7e,
    0x393f_4380,
    0xfe61_cf7a,
    0xeec5_207a,
    0x5588_9c94,
    0x72fc_0651,
    0xada7_ef79,
    0x4e1d_7235,
    0xd55a_63ce,
    0xde04_36ba,
    0x99c4_30ef,
    0x5f0c_0794,
    0x18dc_db7d,
    0xa1d6_eff3,
    0xa0b5_2f7b,
    0x59e8_3605,
    0xee15_b094,
    0xe9ff_d909,
    0xdc44_0086,
    0xef94_4459,
    0xba83_ccb3,
    0xe0c3_cdfb,
    0xd1da_4181,
    0x3b09_2ab1,
    0xf997_f1c1,
    0xa5e6_cf7b,
    0x0142_0ddb,
    0xe4e7_ef5b,
    0x25a1_ff41,
    0xe180_f806,
    0x1fc4_1080,
    0x179b_ee7a,
    0xd37a_c6a9,
    0xfe58_30a4,
    0x98de_8b7f,
    0x77e8_3f4e,
    0x7992_9269,
    0x24fa_9f7b,
    0xe113_c85b,
    0xacc4_0083,
    0xd750_3525,
    0xf7ea_615f,
    0x6214_3154,
    0x0d55_4b63,
    0x5d68_1121,
    0xc866_c359,
    0x3d63_cf73,
    0xcee2_34c0,
    0xd4d8_7e87,
    0x5c67_2b21,
    0x071f_6181,
    0x39f7_627f,
    0x361e_3084,
    0xe4eb_573b,
    0x602f_64a4,
    0xd63a_cd9c,
    0x1bbc_4635,
    0x9e81_032d,
    0x2701_f50c,
    0x9984_7ab4,
    0xa0e3_df79,
    0xba6c_f38c,
    0x1084_3094,
    0x2537_a95e,
    0xf46f_6ffe,
    0xa1ff_3b1f,
    0x208c_fb6a,
    0x8f45_8c74,
    0xd9e0_a227,
    0x4ec7_3a34,
    0xfc88_4f69,
    0x3e4d_e8df,
    0xef0e_0088,
    0x3559_648d,
    0x8a45_388c,
    0x1d80_4366,
    0x721d_9bfd,
    0xa586_84bb,
    0xe825_6333,
    0x844e_8212,
    0x128d_8098,
    0xfed3_3fb4,
    0xce28_0ae1,
    0x27e1_9ba5,
    0xd5a6_c252,
    0xe497_54bd,
    0xc5d6_55dd,
    0xeb66_7064,
    0x7784_0b4d,
    0xa1b6_a801,
    0x84db_26a9,
    0xe0b5_6714,
    0x21f0_43b7,
    0xe5d0_5860,
    0x54f0_3084,
    0x066f_f472,
    0xa31a_a153,
    0xdadc_4755,
    0xb562_5dbf,
    0x6856_1be6,
    0x83ca_6b94,
    0x2d6e_d23b,
    0xeccf_01db,
    0xa6d3_d0ba,
    0xb680_3d5c,
    0xaf77_a709,
    0x33b4_a34c,
    0x397b_c8d6,
    0x5ee2_2b95,
    0x5f0e_5304,
    0x81ed_6f61,
    0x20e7_4364,
    0xb45e_1378,
    0xde18_639b,
    0x881c_a122,
    0xb967_26d1,
    0x8049_a7e8,
    0x22b7_da7b,
    0x5e55_2d25,
    0x5272_d237,
    0x79d2_951c,
    0xc60d_894c,
    0x488c_b402,
    0x1ba4_fe5b,
    0xa4b0_9f6b,
    0x1ca8_15cf,
    0xa20c_3005,
    0x8871_df63,
    0xb9de_2fcb,
    0x0cc6_c9e9,
    0x0bee_ff53,
    0xe321_4517,
    0xb454_2835,
    0x9f63_293c,
    0xee41_e729,
    0x6e1d_2d7c,
    0x5004_5286,
    0x1e66_85f3,
    0xf334_01c6,
    0x30a2_2c95,
    0x31a7_0850,
    0x6093_0f13,
    0x73f9_8417,
    0xa126_9859,
    0xec64_5c44,
    0x52c8_77a9,
    0xcdff_33a6,
    0xa02b_1741,
    0x7cba_d9a2,
    0x2180_036f,
    0x50d9_9c08,
    0xcb3f_4861,
    0xc26b_d765,
    0x64a3_f6ab,
    0x8034_2676,
    0x25a7_5e7b,
    0xe4e6_d1fc,
    0x20c7_10e6,
    0xcdf0_b680,
    0x1784_4d3b,
    0x31ee_f84d,
    0x7e08_24e4,
    0x2ccb_49eb,
    0x846a_3bae,
    0x8ff7_7888,
    0xee5d_60f6,
    0x7af7_5673,
    0x2fdd_5cdb,
    0xa116_31c1,
    0x30f6_6f43,
    0xb3fa_ec54,
    0x157f_d7fa,
    0xef85_79cc,
    0xd152_de58,
    0xdb2f_fd5e,
    0x8f32_ce19,
    0x306a_f97a,
    0x02f0_3ef8,
    0x9931_9ad5,
    0xc242_fa0f,
    0xa7e3_ebb0,
    0xc68e_4906,
    0xb8da_230c,
    0x8082_3028,
    0xdcde_f3c8,
    0xd35f_b171,
    0x088a_1bc8,
    0xbec0_c560,
    0x61a3_c9e8,
    0xbca8_f54d,
    0xc72f_effa,
    0x2282_2e99,
    0x82c5_70b4,
    0xd8d9_4e89,
    0x8b1c_34bc,
    0x301e_16e6,
    0x273b_e979,
    0xb0ff_eaa6,
    0x61d9_b8c6,
    0x00b2_4869,
    0xb7ff_ce3f,
    0x08dc_283b,
    0x43da_f65a,
    0xf7e1_9798,
    0x7619_b72f,
    0x8f1c_9ba4,
    0xdc86_37a0,
    0x16a7_d3b1,
    0x9fc3_93b7,
    0xa713_6eeb,
    0xc6bc_c63e,
    0x1a51_3742,
    0xef68_28bc,
    0x5203_65d6,
    0x2d6a_77ab,
    0x3527_ed4b,
    0x821f_d216,
    0x095c_6e2e,
    0xdb92_f2fb,
    0x5eea_29cb,
    0x1458_92f5,
    0x9158_4f7f,
    0x5483_697b,
    0x2667_a8cc,
    0x8519_6048,
    0x8c4b_acea,
    0x8338_60d4,
    0x0d23_e0f9,
    0x6c38_7e8a,
    0x0ae6_d249,
    0xb284_600c,
    0xd835_731d,
    0xdcb1_c647,
    0xac4c_56ea,
    0x3ebd_81b3,
    0x230e_abb0,
    0x6438_bc87,
    0xf0b5_b1fa,
    0x8f5e_a2b3,
    0xfc18_4642,
    0x0a03_6b7a,
    0x4fb0_89bd,
    0x649d_a589,
    0xa345_415e,
    0x5c03_8323,
    0x3e5d_3bb9,
    0x43d7_9572,
    0x7e6d_d07c,
    0x06df_df1e,
    0x6c6c_c4ef,
    0x7160_a539,
    0x73bf_be70,
    0x8387_7605,
    0x4523_ecf1,
];

const CAST_S2: [u32; 256] = [
    0x8def_c240,
    0x25fa_5d9f,
    0xeb90_3dbf,
    0xe810_c907,
    0x4760_7fff,
    0x369f_e44b,
    0x8c1f_c644,
    0xaece_ca90,
    0xbeb1_f9bf,
    0xeefb_caea,
    0xe8cf_1950,
    0x51df_07ae,
    0x920e_8806,
    0xf0ad_0548,
    0xe13c_8d83,
    0x9270_10d5,
    0x1110_7d9f,
    0x0764_7db9,
    0xb2e3_e4d4,
    0x3d4f_285e,
    0xb9af_a820,
    0xfade_82e0,
    0xa067_268b,
    0x8272_792e,
    0x553f_b2c0,
    0x489a_e22b,
    0xd4ef_9794,
    0x125e_3fbc,
    0x21ff_fcee,
    0x825b_1bfd,
    0x9255_c5ed,
    0x1257_a240,
    0x4e1a_8302,
    0xbae0_7fff,
    0x5282_46e7,
    0x8e57_140e,
    0x3373_f7bf,
    0x8c9f_8188,
    0xa6fc_4ee8,
    0xc982_b5a5,
    0xa8c0_1db7,
    0x579f_c264,
    0x6709_4f31,
    0xf2bd_3f5f,
    0x40ff_f7c1,
    0x1fb7_8dfc,
    0x8e6b_d2c1,
    0x437b_e59b,
    0x99b0_3dbf,
    0xb5db_c64b,
    0x638d_c0e6,
    0x5581_9d99,
    0xa197_c81c,
    0x4a01_2d6e,
    0xc588_4a28,
    0xccc3_6f71,
    0xb843_c213,
    0x6c07_43f1,
    0x8309_893c,
    0x0fed_dd5f,
    0x2f7f_e850,
    0xd7c0_7f7e,
    0x0250_7fbf,
    0x5afb_9a04,
    0xa747_d2d0,
    0x1651_192e,
    0xaf70_bf3e,
    0x58c3_1380,
    0x5f98_302e,
    0x727c_c3c4,
    0x0a0f_b402,
    0x0f7f_ef82,
    0x8c96_fdad,
    0x5d2c_2aae,
    0x8ee9_9a49,
    0x50da_88b8,
    0x8427_f4a0,
    0x1eac_5790,
    0x796f_b449,
    0x8252_dc15,
    0xefbd_7d9b,
    0xa672_597d,
    0xada8_40d8,
    0x45f5_4504,
    0xfa5d_7403,
    0xe83e_c305,
    0x4f91_751a,
    0x9256_69c2,
    0x23ef_e941,
    0xa903_f12e,
    0x6027_0df2,
    0x0276_e4b6,
    0x94fd_6574,
    0x9279_85b2,
    0x8276_dbcb,
    0x0277_8176,
    0xf8af_918d,
    0x4e48_f79e,
    0x8f61_6ddf,
    0xe29d_840e,
    0x842f_7d83,
    0x340c_e5c8,
    0x96bb_b682,
    0x93b4_b148,
    0xef30_3cab,
    0x984f_af28,
    0x779f_af9b,
    0x92dc_560d,
    0x224d_1e20,
    0x8437_aa88,
    0x7d29_dc96,
    0x2756_d3dc,
    0x8b90_7cee,
    0xb51f_d240,
    0xe7c0_7ce3,
    0xe566_b4a1,
    0xc3e9_615e,
    0x3cf8_209d,
    0x6094_d1e3,
    0xcd9c_a341,
    0x5c76_460e,
    0x00ea_983b,
    0xd4d6_7881,
    0xfd47_572c,
    0xf76c_edd9,
    0xbda8_229c,
    0x127d_adaa,
    0x438a_074e,
    0x1f97_c090,
    0x081b_db8a,
    0x93a0_7ebe,
    0xb938_ca15,
    0x97b0_3cff,
    0x3dc2_c0f8,
    0x8d1a_b2ec,
    0x6438_0e51,
    0x68cc_7bfb,
    0xd90f_2788,
    0x1249_0181,
    0x5de5_ffd4,
    0xdd7e_f86a,
    0x76a2_e214,
    0xb9a4_0368,
    0x925d_958f,
    0x4b39_fffa,
    0xba39_aee9,
    0xa4ff_d30b,
    0xfaf7_933b,
    0x6d49_8623,
    0x193c_bcfa,
    0x2762_7545,
    0x825c_f47a,
    0x61bd_8ba0,
    0xd11e_42d1,
    0xcead_04f4,
    0x127e_a392,
    0x1042_8db7,
    0x8272_a972,
    0x9270_c4a8,
    0x127d_e50b,
    0x285b_a1c8,
    0x3c62_f44f,
    0x35c0_eaa5,
    0xe805_d231,
    0x4289_29fb,
    0xb4fc_df82,
    0x4fb6_6a53,
    0x0e7d_c15b,
    0x1f08_1fab,
    0x1086_18ae,
    0xfcfd_086d,
    0xf9ff_2889,
    0x694b_cc11,
    0x236a_5cae,
    0x12de_ca4d,
    0x2c3f_8cc5,
    0xd2d0_2dfe,
    0xf8ef_5896,
    0xe4cf_52da,
    0x9515_5b67,
    0x494a_488c,
    0xb9b6_a80c,
    0x5c8f_82bc,
    0x89d3_6b45,
    0x3a60_9437,
    0xec00_c9a9,
    0x4471_5253,
    0x0a87_4b49,
    0xd773_bc40,
    0x7c34_671c,
    0x0271_7ef6,
    0x4feb_5536,
    0xa2d0_2fff,
    0xd2bf_60c4,
    0xd43f_03c0,
    0x50b4_ef6d,
    0x0747_8cd1,
    0x006e_1888,
    0xa2e5_3f55,
    0xb9e6_d4bc,
    0xa204_8016,
    0x9757_3833,
    0xd720_7d67,
    0xde0f_8f3d,
    0x72f8_7b33,
    0xabcc_4f33,
    0x7688_c55d,
    0x7b00_a6b0,
    0x947b_0001,
    0x5700_75d2,
    0xf9bb_88f8,
    0x8942_019e,
    0x4264_a5ff,
    0x8563_02e0,
    0x72db_d92b,
    0xee97_1b69,
    0x6ea2_2fde,
    0x5f08_ae2b,
    0xaf7a_616d,
    0xe5c9_8767,
    0xcf1f_ebd2,
    0x61ef_c8c2,
    0xf1ac_2571,
    0xcc82_39c2,
    0x6721_4cb8,
    0xb1e5_83d1,
    0xb7dc_3e62,
    0x7f10_bdce,
    0xf90a_5c38,
    0x0ff0_443d,
    0x606e_6dc6,
    0x6054_3a49,
    0x5727_c148,
    0x2be9_8a1d,
    0x8ab4_1738,
    0x20e1_be24,
    0xaf96_da0f,
    0x6845_8425,
    0x9983_3be5,
    0x600d_457d,
    0x282f_9350,
    0x8334_b362,
    0xd91d_1120,
    0x2b6d_8da0,
    0x642b_1e31,
    0x9c30_5a00,
    0x52bc_e688,
    0x1b03_588a,
    0xf7ba_efd5,
    0x4142_ed9c,
    0xa431_5c11,
    0x8332_3ec5,
    0xdfef_4636,
    0xa133_c501,
    0xe9d3_531c,
    0xee35_3783,
];

const CAST_S3: [u32; 256] = [
    0x9db3_0420,
    0x1fb6_e9de,
    0xa7be_7bef,
    0xd273_a298,
    0x4a4f_7bdb,
    0x64ad_8c57,
    0x8551_0443,
    0xfa02_0ed1,
    0x7e28_7aff,
    0xe60f_b663,
    0x095f_35a1,
    0x79eb_f120,
    0xfd05_9d43,
    0x6497_b7b1,
    0xf364_1f63,
    0x241e_4adf,
    0x2814_7f5f,
    0x4fa2_b8cd,
    0xc943_0040,
    0x0cc3_2220,
    0xfdd3_0b30,
    0xc0a5_374f,
    0x1d2d_00d9,
    0x2414_7b15,
    0xee4d_111a,
    0x0fca_5167,
    0x71ff_904c,
    0x2d19_5ffe,
    0x1a05_645f,
    0x0c13_fefe,
    0x081b_08ca,
    0x0517_0121,
    0x8053_0100,
    0xe83e_5efe,
    0xac9a_f4f8,
    0x7fe7_2701,
    0xd2b8_ee5f,
    0x06df_4261,
    0xbb9e_9b8a,
    0x7293_ea25,
    0xce84_ffdf,
    0xf571_8801,
    0x3dd6_4b04,
    0xa26f_263b,
    0x7ed4_8400,
    0x547e_ebe6,
    0x446d_4ca0,
    0x6cf3_d6f5,
    0x2649_abdf,
    0xaea0_c7f5,
    0x3633_8cc1,
    0x503f_7e93,
    0xd377_2061,
    0x11b6_38e1,
    0x7250_0e03,
    0xf80e_b2bb,
    0xabe0_502e,
    0xec8d_77de,
    0x5797_1e81,
    0xe14f_6746,
    0xc933_5400,
    0x6920_318f,
    0x081d_bb99,
    0xffc3_04a5,
    0x4d35_1805,
    0x7f3d_5ce3,
    0xa6c8_66c6,
    0x5d5b_cca9,
    0xdaec_6fea,
    0x9f92_6f91,
    0x9f46_222f,
    0x3991_467d,
    0xa5bf_6d8e,
    0x1143_c44f,
    0x4395_8302,
    0xd021_4eeb,
    0x0220_83b8,
    0x3fb6_180c,
    0x18f8_931e,
    0x2816_58e6,
    0x2648_6e3e,
    0x8bd7_8a70,
    0x7477_e4c1,
    0xb506_e07c,
    0xf32d_0a25,
    0x7909_8b02,
    0xe4ea_bb81,
    0x2812_3b23,
    0x69de_ad38,
    0x1574_ca16,
    0xdf87_1b62,
    0x211c_40b7,
    0xa51a_9ef9,
    0x0014_377b,
    0x041e_8ac8,
    0x0911_4003,
    0xbd59_e4d2,
    0xe3d1_56d5,
    0x4fe8_76d5,
    0x2f91_a340,
    0x557b_e8de,
    0x00ea_e4a7,
    0x0ce5_c2ec,
    0x4db4_bba6,
    0xe756_bdff,
    0xdd33_69ac,
    0xec17_b035,
    0x0657_2327,
    0x99af_c8b0,
    0x56c8_c391,
    0x6b65_811c,
    0x5e14_6119,
    0x6e85_cb75,
    0xbe07_c002,
    0xc232_5577,
    0x893f_f4ec,
    0x5bbf_c92d,
    0xd0ec_3b25,
    0xb780_1ab7,
    0x8d6d_3b24,
    0x20c7_63ef,
    0xc366_a5fc,
    0x9c38_2880,
    0x0ace_3205,
    0xaac9_548a,
    0xeca1_d7c7,
    0x041a_fa32,
    0x1d16_625a,
    0x6701_902c,
    0x9b75_7a54,
    0x31d4_77f7,
    0x9126_b031,
    0x36cc_6fdb,
    0xc70b_8b46,
    0xd9e6_6a48,
    0x56e5_5a79,
    0x026a_4ceb,
    0x5243_7eff,
    0x2f8f_76b4,
    0x0df9_80a5,
    0x8674_cde3,
    0xedda_04eb,
    0x17a9_be04,
    0x2c18_f4df,
    0xb774_7f9d,
    0xab2a_f7b4,
    0xefc3_4d20,
    0x2e09_6b7c,
    0x1741_a254,
    0xe5b6_a035,
    0x213d_42f6,
    0x2c1c_7c26,
    0x61c2_f50f,
    0x6552_daf9,
    0xd2c2_31f8,
    0x2513_0f69,
    0xd816_7fa2,
    0x0418_f2c8,
    0x001a_96a6,
    0x0d15_26ab,
    0x6331_5c21,
    0x5e0a_72ec,
    0x49ba_fefd,
    0x1879_08d9,
    0x8d0d_bd86,
    0x3111_70a7,
    0x3e9b_640c,
    0xcc3e_10d7,
    0xd5ca_d3b6,
    0x0cae_c388,
    0xf730_01e1,
    0x6c72_8aff,
    0x71ea_e2a1,
    0x1f9a_f36e,
    0xcfcb_d12f,
    0xc1de_8417,
    0xac07_be6b,
    0xcb44_a1d8,
    0x8b9b_0f56,
    0x0139_88c3,
    0xb1c5_2fca,
    0xb4be_31cd,
    0xd878_2806,
    0x12a3_a4e2,
    0x6f7d_e532,
    0x58fd_7eb6,
    0xd01e_e900,
    0x24ad_ffc2,
    0xf499_0fc5,
    0x9711_aac5,
    0x001d_7b95,
    0x82e5_e7d2,
    0x1098_73f6,
    0x0061_3096,
    0xc32d_9521,
    0xada1_21ff,
    0x2990_8415,
    0x7fbb_977f,
    0xaf9e_b3db,
    0x29c9_ed2a,
    0x5ce2_a465,
    0xa730_f32c,
    0xd0aa_3fe8,
    0x8a5c_c091,
    0xd49e_2ce7,
    0x0ce4_54a9,
    0xd60a_cd86,
    0x015f_1919,
    0x7707_9103,
    0xdea0_3af6,
    0x78a8_565e,
    0xdee3_56df,
    0x21f0_5cbe,
    0x8b75_e387,
    0xb3c5_0651,
    0xb8a5_c3ef,
    0xd8ee_b6d2,
    0xe523_be77,
    0xc215_4529,
    0x2f69_efdf,
    0xafe6_7afb,
    0xf470_c4b2,
    0xf3e0_eb5b,
    0xd6cc_9876,
    0x39e4_460c,
    0x1fda_8538,
    0x1987_832f,
    0xca00_7367,
    0xa991_44f8,
    0x296b_299e,
    0x492f_c295,
    0x9266_beab,
    0xb567_6e69,
    0x9bd3_ddda,
    0xdf7e_052f,
    0xdb25_701c,
    0x1b5e_51ee,
    0xf653_24e6,
    0x6afc_e36c,
    0x0316_cc04,
    0x8644_213e,
    0xb7dc_59d0,
    0x7965_291f,
    0xccd6_fd43,
    0x4182_3979,
    0x932b_cdf6,
    0xb657_c34d,
    0x4edf_d282,
    0x7ae5_290c,
    0x3cb9_536b,
    0x851e_20fe,
    0x9833_557e,
    0x13ec_f0b0,
    0xd3ff_b372,
    0x3f85_c5c1,
    0x0aef_7ed2,
];

const CAST_S4: [u32; 256] = [
    0x7ec9_0c04,
    0x2c6e_74b9,
    0x9b0e_66df,
    0xa633_7911,
    0xb86a_7fff,
    0x1dd3_58f5,
    0x44dd_9d44,
    0x1731_167f,
    0x08fb_f1fa,
    0xe7f5_11cc,
    0xd205_1b00,
    0x735a_ba00,
    0x2ab7_22d8,
    0x3863_81cb,
    0xacf6_243a,
    0x69be_fd7a,
    0xe6a2_e77f,
    0xf0c7_20cd,
    0xc449_4816,
    0xccf5_c180,
    0x3885_1640,
    0x15b0_a848,
    0xe68b_18cb,
    0x4caa_deff,
    0x5f48_0a01,
    0x0412_b2aa,
    0x2598_14fc,
    0x41d0_efe2,
    0x4e40_b48d,
    0x248e_b6fb,
    0x8dba_1cfe,
    0x41a9_9b02,
    0x1a55_0a04,
    0xba8f_65cb,
    0x7251_f4e7,
    0x95a5_1725,
    0xc106_ecd7,
    0x97a5_980a,
    0xc539_b9aa,
    0x4d79_fe6a,
    0xf2f3_f763,
    0x68af_8040,
    0xed0c_9e56,
    0x11b4_958b,
    0xe1eb_5a88,
    0x8709_e6b0,
    0xd7e0_7156,
    0x4e29_fea7,
    0x6366_e52d,
    0x02d1_c000,
    0xc4ac_8e05,
    0x9377_f571,
    0x0c05_372a,
    0x5785_35f2,
    0x2261_be02,
    0xd642_a0c9,
    0xdf13_a280,
    0x74b5_5bd2,
    0x6821_99c0,
    0xd421_e5ec,
    0x53fb_3ce8,
    0xc8ad_edb3,
    0x28a8_7fc9,
    0x3d95_9981,
    0x5c1f_f900,
    0xfe38_d399,
    0x0c4e_ff0b,
    0x0624_07ea,
    0xaa2f_4fb1,
    0x4fb9_6976,
    0x90c7_9505,
    0xb0a8_a774,
    0xef55_a1ff,
    0xe59c_a2c2,
    0xa6b6_2d27,
    0xe66a_4263,
    0xdf65_001f,
    0x0ec5_0966,
    0xdfdd_55bc,
    0x29de_0655,
    0x911e_739a,
    0x17af_8975,
    0x32c7_911c,
    0x89f8_9468,
    0x0d01_e980,
    0x5247_55f4,
    0x03b6_3cc9,
    0x0cc8_44b2,
    0xbcf3_f0aa,
    0x87ac_36e9,
    0xe53a_7426,
    0x01b3_d82b,
    0x1a9e_7449,
    0x64ee_2d7e,
    0xcddb_b1da,
    0x01c9_4910,
    0xb868_bf80,
    0x0d26_f3fd,
    0x9342_ede7,
    0x04a5_c284,
    0x6367_37b6,
    0x50f5_b616,
    0xf247_66e3,
    0x8eca_36c1,
    0x136e_05db,
    0xfef1_8391,
    0xfb88_7a37,
    0xd6e7_f7d4,
    0xc7fb_7dc9,
    0x3063_fcdf,
    0xb6f5_89de,
    0xec29_41da,
    0x26e4_6695,
    0xb756_6419,
    0xf654_efc5,
    0xd08d_58b7,
    0x4892_5401,
    0xc1ba_cb7f,
    0xe5ff_550f,
    0xb608_3049,
    0x5bb5_d0e8,
    0x87d7_2e5a,
    0xab6a_6ee1,
    0x223a_66ce,
    0xc62b_f3cd,
    0x9e08_85f9,
    0x68cb_3e47,
    0x086c_010f,
    0xa21d_e820,
    0xd18b_69de,
    0xf3f6_5777,
    0xfa02_c3f6,
    0x407e_dac3,
    0xcbb3_d550,
    0x1793_084d,
    0xb0d7_0eba,
    0x0ab3_78d5,
    0xd951_fb0c,
    0xded7_da56,
    0x4124_bbe4,
    0x94ca_0b56,
    0x0f57_55d1,
    0xe0e1_e56e,
    0x6184_b5be,
    0x580a_249f,
    0x94f7_4bc0,
    0xe327_888e,
    0x9f7b_5561,
    0xc3dc_0280,
    0x0568_7715,
    0x646c_6bd7,
    0x4490_4db3,
    0x66b4_f0a3,
    0xc0f1_648a,
    0x697e_d5af,
    0x49e9_2ff6,
    0x309e_374f,
    0x2cb6_356a,
    0x8580_8573,
    0x4991_f840,
    0x76f0_ae02,
    0x083b_e84d,
    0x2842_1c9a,
    0x4448_9406,
    0x736e_4cb8,
    0xc109_2910,
    0x8bc9_5fc6,
    0x7d86_9cf4,
    0x134f_616f,
    0x2e77_118d,
    0xb31b_2be1,
    0xaa90_b472,
    0x3ca5_d717,
    0x7d16_1bba,
    0x9cad_9010,
    0xaf46_2ba2,
    0x9fe4_59d2,
    0x45d3_4559,
    0xd9f2_da13,
    0xdbc6_5487,
    0xf3e4_f94e,
    0x176d_486f,
    0x097c_13ea,
    0x631d_a5c7,
    0x445f_7382,
    0x1756_83f4,
    0xcdc6_6a97,
    0x70be_0288,
    0xb3cd_cf72,
    0x6e5d_d2f3,
    0x2093_6079,
    0x459b_80a5,
    0xbe60_e2db,
    0xa9c2_3101,
    0xeba5_315c,
    0x224e_42f2,
    0x1c5c_1572,
    0xf672_1b2c,
    0x1ad2_fff3,
    0x8c25_404e,
    0x324e_d72f,
    0x4067_b7fd,
    0x0523_138e,
    0x5ca3_bc78,
    0xdc0f_d66e,
    0x7592_2283,
    0x784d_6b17,
    0x58eb_b16e,
    0x4409_4f85,
    0x3f48_1d87,
    0xfcfe_ae7b,
    0x77b5_ff76,
    0x8c23_02bf,
    0xaaf4_7556,
    0x5f46_b02a,
    0x2b09_2801,
    0x3d38_f5f7,
    0x0ca8_1f36,
    0x52af_4a8a,
    0x66d5_e7c0,
    0xdf3b_0874,
    0x9505_5110,
    0x1b5a_d7a8,
    0xf61e_d5ad,
    0x6cf6_e479,
    0x2075_8184,
    0xd0ce_fa65,
    0x88f7_be58,
    0x4a04_6826,
    0x0ff6_f8f3,
    0xa09c_7f70,
    0x5346_aba0,
    0x5ce9_6c28,
    0xe176_eda3,
    0x6bac_307f,
    0x3768_29d2,
    0x8536_0fa9,
    0x17e3_fe2a,
    0x24b7_9767,
    0xf5a9_6b20,
    0xd6cd_2595,
    0x68ff_1ebf,
    0x7555_442c,
    0xf19f_06be,
    0xf9e0_659a,
    0xeeb9_491d,
    0x3401_0718,
    0xbb30_cab8,
    0xe822_fe15,
    0x8857_0983,
    0x750e_6249,
    0xda62_7e55,
    0x5e76_ffa8,
    0xb153_4546,
    0x6d47_de08,
    0xefe9_e7d4,
];

const CAST_S5: [u32; 256] = [
    0xf6fa_8f9d,
    0x2cac_6ce1,
    0x4ca3_4867,
    0xe233_7f7c,
    0x95db_08e7,
    0x0168_43b4,
    0xeced_5cbc,
    0x3255_53ac,
    0xbf9f_0960,
    0xdfa1_e2ed,
    0x83f0_579d,
    0x63ed_86b9,
    0x1ab6_a6b8,
    0xde5e_be39,
    0xf38f_f732,
    0x8989_b138,
    0x33f1_4961,
    0xc019_37bd,
    0xf506_c6da,
    0xe462_5e7e,
    0xa308_ea99,
    0x4e23_e33c,
    0x79cb_d7cc,
    0x48a1_4367,
    0xa314_9619,
    0xfec9_4bd5,
    0xa114_174a,
    0xeaa0_1866,
    0xa084_db2d,
    0x09a8_486f,
    0xa888_614a,
    0x2900_af98,
    0x0166_5991,
    0xe199_2863,
    0xc8f3_0c60,
    0x2e78_ef3c,
    0xd0d5_1932,
    0xcf0f_ec14,
    0xf7ca_07d2,
    0xd0a8_2072,
    0xfd41_197e,
    0x9305_a6b0,
    0xe86b_e3da,
    0x74be_d3cd,
    0x372d_a53c,
    0x4c7f_4448,
    0xdab5_d440,
    0x6dba_0ec3,
    0x0839_19a7,
    0x9fba_eed9,
    0x49db_cfb0,
    0x4e67_0c53,
    0x5c3d_9c01,
    0x64bd_b941,
    0x2c0e_636a,
    0xba7d_d9cd,
    0xea6f_7388,
    0xe70b_c762,
    0x35f2_9adb,
    0x5c4c_dd8d,
    0xf0d4_8d8c,
    0xb881_53e2,
    0x08a1_9866,
    0x1ae2_eac8,
    0x284c_af89,
    0xaa92_8223,
    0x9334_be53,
    0x3b3a_21bf,
    0x1643_4be3,
    0x9aea_3906,
    0xefe8_c36e,
    0xf890_cdd9,
    0x8022_6dae,
    0xc340_a4a3,
    0xdf7e_9c09,
    0xa694_a807,
    0x5b7c_5ecc,
    0x221d_b3a6,
    0x9a69_a02f,
    0x6881_8a54,
    0xceb2_296f,
    0x53c0_843a,
    0xfe89_3655,
    0x25bf_e68a,
    0xb462_8abc,
    0xcf22_2ebf,
    0x25ac_6f48,
    0xa9a9_9387,
    0x53bd_db65,
    0xe76f_fbe7,
    0xe967_fd78,
    0x0ba9_3563,
    0x8e34_2bc1,
    0xe8a1_1be9,
    0x4980_740d,
    0xc808_7dfc,
    0x8de4_bf99,
    0xa111_01a0,
    0x7fd3_7975,
    0xda5a_26c0,
    0xe81f_994f,
    0x9528_cd89,
    0xfd33_9fed,
    0xb878_34bf,
    0x5f04_456d,
    0x2225_8698,
    0xc9c4_c83b,
    0x2dc1_56be,
    0x4f62_8daa,
    0x57f5_5ec5,
    0xe222_0abe,
    0xd291_6ebf,
    0x4ec7_5b95,
    0x24f2_c3c0,
    0x42d1_5d99,
    0xcd0d_7fa0,
    0x7b6e_27ff,
    0xa8dc_8af0,
    0x7345_c106,
    0xf41e_232f,
    0x3516_2386,
    0xe6ea_8926,
    0x3333_b094,
    0x157e_c6f2,
    0x372b_74af,
    0x6925_73e4,
    0xe9a9_d848,
    0xf316_0289,
    0x3a62_ef1d,
    0xa787_e238,
    0xf3a5_f676,
    0x7436_4853,
    0x2095_1063,
    0x4576_698d,
    0xb6fa_d407,
    0x592a_f950,
    0x36f7_3523,
    0x4cfb_6e87,
    0x7da4_cec0,
    0x6c15_2daa,
    0xcb03_96a8,
    0xc50d_fe5d,
    0xfcd7_07ab,
    0x0921_c42f,
    0x89df_f0bb,
    0x5fe2_be78,
    0x448f_4f33,
    0x7546_13c9,
    0x2b05_d08d,
    0x48b9_d585,
    0xdc04_9441,
    0xc809_8f9b,
    0x7ded_e786,
    0xc39a_3373,
    0x4241_0005,
    0x6a09_1751,
    0x0ef3_c8a6,
    0x8900_72d6,
    0x2820_7682,
    0xa9a9_f7be,
    0xbf32_679d,
    0xd45b_5b75,
    0xb353_fd00,
    0xcbb0_e358,
    0x830f_220a,
    0x1f8f_b214,
    0xd372_cf08,
    0xcc3c_4a13,
    0x8cf6_3166,
    0x061c_87be,
    0x88c9_8f88,
    0x6062_e397,
    0x47cf_8e7a,
    0xb6c8_5283,
    0x3cc2_acfb,
    0x3fc0_6976,
    0x4e8f_0252,
    0x64d8_314d,
    0xda38_70e3,
    0x1e66_5459,
    0xc109_08f0,
    0x5130_21a5,
    0x6c5b_68b7,
    0x822f_8aa0,
    0x3007_cd3e,
    0x7471_9eef,
    0xdc87_2681,
    0x0733_40d4,
    0x7e43_2fd9,
    0x0c5e_c241,
    0x8809_286c,
    0xf592_d891,
    0x08a9_30f6,
    0x957e_f305,
    0xb7fb_ffbd,
    0xc266_e96f,
    0x6fe4_ac98,
    0xb173_ecc0,
    0xbc60_b42a,
    0x9534_98da,
    0xfba1_ae12,
    0x2d4b_d736,
    0x0f25_faab,
    0xa4f3_fceb,
    0xe296_9123,
    0x257f_0c3d,
    0x9348_af49,
    0x3614_00bc,
    0xe881_6f4a,
    0x3814_f200,
    0xa3f9_4043,
    0x9c7a_54c2,
    0xbc70_4f57,
    0xda41_e7f9,
    0xc25a_d33a,
    0x54f4_a084,
    0xb17f_5505,
    0x5935_7cbe,
    0xedbd_15c8,
    0x7f97_c5ab,
    0xba5a_c7b5,
    0xb6f6_deaf,
    0x3a47_9c3a,
    0x5302_da25,
    0x653d_7e6a,
    0x5426_8d49,
    0x51a4_77ea,
    0x5017_d55b,
    0xd7d2_5d88,
    0x4413_6c76,
    0x0404_a8c8,
    0xb8e5_a121,
    0xb81a_928a,
    0x60ed_5869,
    0x97c5_5b96,
    0xeaec_991b,
    0x2993_5913,
    0x01fd_b7f1,
    0x088e_8dfa,
    0x9ab6_f6f5,
    0x3b4c_bf9f,
    0x4a5d_e3ab,
    0xe605_1d35,
    0xa0e1_d855,
    0xd36b_4cf1,
    0xf544_edeb,
    0xb0e9_3524,
    0xbebb_8fbd,
    0xa2d7_62cf,
    0x49c9_2f54,
    0x38b5_f331,
    0x7128_a454,
    0x4839_2905,
    0xa65b_1db8,
    0x851c_97bd,
    0xd675_cf2f,
];

const CAST_S6: [u32; 256] = [
    0x85e0_4019,
    0x332b_f567,
    0x662d_bfff,
    0xcfc6_5693,
    0x2a8d_7f6f,
    0xab9b_c912,
    0xde60_08a1,
    0x2028_da1f,
    0x0227_bce7,
    0x4d64_2916,
    0x18fa_c300,
    0x50f1_8b82,
    0x2cb2_cb11,
    0xb232_e75c,
    0x4b36_95f2,
    0xb287_07de,
    0xa05f_bcf6,
    0xcd41_81e9,
    0xe150_210c,
    0xe24e_f1bd,
    0xb168_c381,
    0xfde4_e789,
    0x5c79_b0d8,
    0x1e8b_fd43,
    0x4d49_5001,
    0x38be_4341,
    0x913c_ee1d,
    0x92a7_9c3f,
    0x0897_66be,
    0xbaee_adf4,
    0x1286_becf,
    0xb6ea_cb19,
    0x2660_c200,
    0x7565_bde4,
    0x6424_1f7a,
    0x8248_dca9,
    0xc3b3_ad66,
    0x2813_6086,
    0x0bd8_dfa8,
    0x356d_1cf2,
    0x1077_89be,
    0xb3b2_e9ce,
    0x0502_aa8f,
    0x0bc0_351e,
    0x166b_f52a,
    0xeb12_ff82,
    0xe348_6911,
    0xd34d_7516,
    0x4e7b_3aff,
    0x5f43_671b,
    0x9cf6_e037,
    0x4981_ac83,
    0x3342_66ce,
    0x8c93_41b7,
    0xd0d8_54c0,
    0xcb3a_6c88,
    0x47bc_2829,
    0x4725_ba37,
    0xa66a_d22b,
    0x7ad6_1f1e,
    0x0c5c_bafa,
    0x4437_f107,
    0xb6e7_9962,
    0x42d2_d816,
    0x0a96_1288,
    0xe1a5_c06e,
    0x1374_9e67,
    0x72fc_081a,
    0xb1d1_39f7,
    0xf958_3745,
    0xcf19_df58,
    0xbec3_f756,
    0xc06e_ba30,
    0x0721_1b24,
    0x45c2_8829,
    0xc95e_317f,
    0xbc8e_c511,
    0x38bc_46e9,
    0xc6e6_fa14,
    0xbae8_584a,
    0xad4e_bc46,
    0x468f_508b,
    0x7829_435f,
    0xf124_183b,
    0x821d_ba9f,
    0xaff6_0ff4,
    0xea2c_4e6d,
    0x16e3_9264,
    0x9254_4a8b,
    0x009b_4fc3,
    0xaba6_8ced,
    0x9ac9_6f78,
    0x06a5_b79a,
    0xb285_6e6e,
    0x1aec_3ca9,
    0xbe83_8688,
    0x0e08_04e9,
    0x55f1_be56,
    0xe7e5_363b,
    0xb3a1_f25d,
    0xf7de_bb85,
    0x61fe_033c,
    0x1674_6233,
    0x3c03_4c28,
    0xda6d_0c74,
    0x79aa_c56c,
    0x3ce4_e1ad,
    0x51f0_c802,
    0x98f8_f35a,
    0x1626_a49f,
    0xeed8_2b29,
    0x1d38_2fe3,
    0x0c4f_b99a,
    0xbb32_5778,
    0x3ec6_d97b,
    0x6e77_a6a9,
    0xcb65_8b5c,
    0xd452_30c7,
    0x2bd1_408b,
    0x60c0_3eb7,
    0xb906_8d78,
    0xa337_54f4,
    0xf430_c87d,
    0xc8a7_1302,
    0xb96d_8c32,
    0xebd4_e7be,
    0xbe8b_9d2d,
    0x7979_fb06,
    0xe722_5308,
    0x8b75_cf77,
    0x11ef_8da4,
    0xe083_c858,
    0x8d6b_786f,
    0x5a63_17a6,
    0xfa5c_f7a0,
    0x5dda_0033,
    0xf28e_bfb0,
    0xf5b9_c310,
    0xa0ea_c280,
    0x08b9_767a,
    0xa3d9_d2b0,
    0x79d3_4217,
    0x021a_718d,
    0x9ac6_336a,
    0x2711_fd60,
    0x4380_50e3,
    0x0699_08a8,
    0x3d7f_edc4,
    0x826d_2bef,
    0x4eeb_8476,
    0x488d_cf25,
    0x36c9_d566,
    0x28e7_4e41,
    0xc261_0aca,
    0x3d49_a9cf,
    0xbae3_b9df,
    0xb65f_8de6,
    0x92ae_af64,
    0x3ac7_d5e6,
    0x9ea8_0509,
    0xf22b_017d,
    0xa417_3f70,
    0xdd1e_16c3,
    0x15e0_d7f9,
    0x50b1_b887,
    0x2b9f_4fd5,
    0x625a_ba82,
    0x6a01_7962,
    0x2ec0_1b9c,
    0x1548_8aa9,
    0xd716_e740,
    0x4005_5a2c,
    0x93d2_9a22,
    0xe32d_bf9a,
    0x0587_45b9,
    0x3453_dc1e,
    0xd699_296e,
    0x496c_ff6f,
    0x1c9f_4986,
    0xdfe2_ed07,
    0xb872_42d1,
    0x19de_7eae,
    0x053e_561a,
    0x15ad_6f8c,
    0x6662_6c1c,
    0x7154_c24c,
    0xea08_2b2a,
    0x93eb_2939,
    0x17dc_b0f0,
    0x58d4_f2ae,
    0x9ea2_94fb,
    0x52cf_564c,
    0x9883_fe66,
    0x2ec4_0581,
    0x7639_53c3,
    0x01d6_692e,
    0xd3a0_c108,
    0xa1e7_160e,
    0xe4f2_dfa6,
    0x693e_d285,
    0x7490_4698,
    0x4c2b_0edd,
    0x4f75_7656,
    0x5d39_3378,
    0xa132_234f,
    0x3d32_1c5d,
    0xc3f5_e194,
    0x4b26_9301,
    0xc79f_022f,
    0x3c99_7e7e,
    0x5e4f_9504,
    0x3ffa_fbbd,
    0x76f7_ad0e,
    0x2966_93f4,
    0x3d1f_ce6f,
    0xc61e_45be,
    0xd3b5_ab34,
    0xf72b_f9b7,
    0x1b04_34c0,
    0x4e72_b567,
    0x5592_a33d,
    0xb522_9301,
    0xcfd2_a87f,
    0x60ae_b767,
    0x1814_386b,
    0x30bc_c33d,
    0x38a0_c07d,
    0xfd16_06f2,
    0xc363_519b,
    0x589d_d390,
    0x5479_f8e6,
    0x1cb8_d647,
    0x97fd_61a9,
    0xea77_59f4,
    0x2d57_539d,
    0x569a_58cf,
    0xe84e_63ad,
    0x462e_1b78,
    0x6580_f87e,
    0xf381_7914,
    0x91da_55f4,
    0x40a2_30f3,
    0xd198_8f35,
    0xb6e3_18d2,
    0x3ffa_50bc,
    0x3d40_f021,
    0xc3c0_bdae,
    0x4958_c24c,
    0x518f_36b2,
    0x84b1_d370,
    0x0fed_ce83,
    0x878d_dada,
    0xf2a2_79c7,
    0x94e0_1be8,
    0x9071_6f4b,
    0x954b_8aa3,
];

const CAST_S7: [u32; 256] = [
    0xe216_300d,
    0xbbdd_fffc,
    0xa7eb_dabd,
    0x3564_8095,
    0x7789_f8b7,
    0xe6c1_121b,
    0x0e24_1600,
    0x052c_e8b5,
    0x11a9_cfb0,
    0xe595_2f11,
    0xece7_990a,
    0x9386_d174,
    0x2a42_931c,
    0x76e3_8111,
    0xb12d_ef3a,
    0x37dd_ddfc,
    0xde9a_deb1,
    0x0a0c_c32c,
    0xbe19_7029,
    0x84a0_0940,
    0xbb24_3a0f,
    0xb4d1_37cf,
    0xb44e_79f0,
    0x049e_edfd,
    0x0b15_a15d,
    0x480d_3168,
    0x8bbb_de5a,
    0x669d_ed42,
    0xc7ec_e831,
    0x3f8f_95e7,
    0x72df_191b,
    0x7580_330d,
    0x9407_4251,
    0x5c7d_cdfa,
    0xabbe_6d63,
    0xaa40_2164,
    0xb301_d40a,
    0x02e7_d1ca,
    0x5357_1dae,
    0x7a31_82a2,
    0x12a8_ddec,
    0xfdaa_335d,
    0x176f_43e8,
    0x71fb_46d4,
    0x3812_9022,
    0xce94_9ad4,
    0xb847_69ad,
    0x965b_d862,
    0x82f3_d055,
    0x66fb_9767,
    0x15b8_0b4e,
    0x1d5b_47a0,
    0x4cfd_e06f,
    0xc28e_c4b8,
    0x57e8_726e,
    0x647a_78fc,
    0x9986_5d44,
    0x608b_d593,
    0x6c20_0e03,
    0x39dc_5ff6,
    0x5d0b_00a3,
    0xae63_aff2,
    0x7e8b_d632,
    0x7010_8c0c,
    0xbbd3_5049,
    0x2998_df04,
    0x980c_f42a,
    0x9b6d_f491,
    0x9e7e_dd53,
    0x0691_8548,
    0x58cb_7e07,
    0x3b74_ef2e,
    0x522f_ffb1,
    0xd247_08cc,
    0x1c7e_27cd,
    0xa4eb_215b,
    0x3cf1_d2e2,
    0x19b4_7a38,
    0x424f_7618,
    0x3585_6039,
    0x9d17_dee7,
    0x27eb_35e6,
    0xc9af_f67b,
    0x36ba_f5b8,
    0x09c4_67cd,
    0xc189_10b1,
    0xe11d_bf7b,
    0x06cd_1af8,
    0x7170_c608,
    0x2d5e_3354,
    0xd4de_495a,
    0x64c6_d006,
    0xbcc0_c62c,
    0x3dd0_0db3,
    0x708f_8f34,
    0x77d5_1b42,
    0x264f_620f,
    0x24b8_d2bf,
    0x15c1_b79e,
    0x46a5_2564,
    0xf8d7_e54e,
    0x3e37_8160,
    0x7895_cda5,
    0x859c_15a5,
    0xe645_9788,
    0xc37b_c75f,
    0xdb07_ba0c,
    0x0676_a3ab,
    0x7f22_9b1e,
    0x3184_2e7b,
    0x2425_9fd7,
    0xf8be_f472,
    0x835f_fcb8,
    0x6df4_c1f2,
    0x96f5_b195,
    0xfd0a_f0fc,
    0xb0fe_134c,
    0xe250_6d3d,
    0x4f9b_12ea,
    0xf215_f225,
    0xa223_736f,
    0x9fb4_c428,
    0x25d0_4979,
    0x34c7_13f8,
    0xc461_8187,
    0xea7a_6e98,
    0x7cd1_6efc,
    0x1436_876c,
    0xf154_4107,
    0xbede_ee14,
    0x56e9_af27,
    0xa04a_a441,
    0x3cf7_c899,
    0x92ec_bae6,
    0xdd67_016d,
    0x1516_82eb,
    0xa842_eedf,
    0xfdba_60b4,
    0xf190_7b75,
    0x20e3_030f,
    0x24d8_c29e,
    0xe139_673b,
    0xefa6_3fb8,
    0x7187_3054,
    0xb6f2_cf3b,
    0x9f32_6442,
    0xcb15_a4cc,
    0xb01a_4504,
    0xf1e4_7d8d,
    0x844a_1be5,
    0xbae7_dfdc,
    0x42cb_da70,
    0xcd7d_ae0a,
    0x57e8_5b7a,
    0xd53f_5af6,
    0x20cf_4d8c,
    0xcea4_d428,
    0x79d1_30a4,
    0x3486_ebfb,
    0x33d3_cddc,
    0x7785_3b53,
    0x37ef_fcb5,
    0xc506_8778,
    0xe580_b3e6,
    0x4e68_b8f4,
    0xc5c8_b37e,
    0x0d80_9ea2,
    0x398f_eb7c,
    0x132a_4f94,
    0x43b7_950e,
    0x2fee_7d1c,
    0x2236_13bd,
    0xdd06_caa2,
    0x37df_932b,
    0xc424_8289,
    0xacf3_ebc3,
    0x5715_f6b7,
    0xef34_78dd,
    0xf267_616f,
    0xc148_cbe4,
    0x9052_815e,
    0x5e41_0fab,
    0xb48a_2465,
    0x2eda_7fa4,
    0xe87b_40e4,
    0xe98e_a084,
    0x5889_e9e1,
    0xefd3_90fc,
    0xdd07_d35b,
    0xdb48_5694,
    0x38d7_e5b2,
    0x5772_0101,
    0x730e_debc,
    0x5b64_3113,
    0x9491_7e4f,
    0x503c_2fba,
    0x646f_1282,
    0x7523_d24a,
    0xe077_9695,
    0xf9c1_7a8f,
    0x7a5b_2121,
    0xd187_b896,
    0x2926_3a4d,
    0xba51_0cdf,
    0x81f4_7c9f,
    0xad11_63ed,
    0xea7b_5965,
    0x1a00_726e,
    0x1140_3092,
    0x00da_6d77,
    0x4a0c_dd61,
    0xad1f_4603,
    0x605b_dfb0,
    0x9eed_c364,
    0x22eb_e6a8,
    0xcee7_d28a,
    0xa0e7_36a0,
    0x5564_a6b9,
    0x1085_3209,
    0xc7eb_8f37,
    0x2de7_05ca,
    0x8951_570f,
    0xdf09_822b,
    0xbd69_1a6c,
    0xaa12_e4f2,
    0x8745_1c0f,
    0xe0f6_a27a,
    0x3ada_4819,
    0x4cf1_764f,
    0x0d77_1c2b,
    0x67cd_b156,
    0x350d_8384,
    0x5938_fa0f,
    0x4239_9ef3,
    0x3699_7b07,
    0x0e84_093d,
    0x4aa9_3e61,
    0x8360_d87b,
    0x1fa9_8b0c,
    0x1149_382c,
    0xe976_25a5,
    0x0614_d1b7,
    0x0e25_244b,
    0x0c76_8347,
    0x589e_8d82,
    0x0d20_59d1,
    0xa466_bb1e,
    0xf8da_0a82,
    0x04f1_9130,
    0xba6e_4ec0,
    0x9926_5164,
    0x1ee7_230d,
    0x50b2_ad80,
    0xeaee_6801,
    0x8db2_a283,
    0xea8b_f59e,
];

/// CAST-128 / CAST5 cipher (64-bit block, 40–128-bit key).
///
/// Translates the C `CAST_KEY` structure from `crypto/cast/cast_local.h`.
/// When the supplied key is 10 bytes or shorter, only 12 rounds are
/// performed (per RFC 2144 §2.6); full-length keys use 16 rounds.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Cast5 {
    /// Expanded schedule of 32 subkey words (`Km[0..15]` interleaved with
    /// `Kr[0..15]` rotation amounts).
    data: [u32; 32],
    /// `true` when the user-supplied key length ≤ 10 bytes.
    short_key: bool,
}

impl Cast5 {
    /// Perform one CAST5 round of the inner `E_CAST` transform.
    ///
    /// `km` is the masking subkey (`data[n*2]`), `kr` is the rotation amount
    /// (`data[n*2+1]`), `r` is the round's right half, and `op` selects the
    /// triad `(OP1, OP2, OP3)` according to the position in the three-round
    /// cycle. `op % 3 == 0` uses `(+, ^, -)`, `op % 3 == 1` uses `(^, -, +)`,
    /// `op % 3 == 2` uses `(-, +, ^)`. The return value is `XORed` into `L`.
    ///
    /// The parameter and local names (`km`, `kr`, `r`, `op`, `t`, `a`, `b`,
    /// `c`, `d`) mirror the `E_CAST` macro notation in RFC 2144 §2.2 and
    /// `crypto/cast/cast_local.h`; keeping them short preserves the direct
    /// correspondence with the reference implementation.
    ///
    /// # Security (cache-timing)
    ///
    /// This is the **principal cache-timing-vulnerable site** of CAST5
    /// encryption and decryption. Each round performs **4 secret-indexed
    /// lookups** into `CAST_S0..CAST_S3` (each S-box is 256 × 32-bit =
    /// 1024 bytes, spanning multiple cache lines). The byte indices
    /// `(t >> 24) & 0xff`, `(t >> 16) & 0xff`, `(t >> 8) & 0xff`, and
    /// `t & 0xff` are derived from `t = km OP r` (or a rotation thereof)
    /// which **mixes the round subkey with the opposite half of the
    /// Feistel state** — both secret.
    ///
    /// Additionally, the data-dependent rotation `t.rotate_left(kr & 0x1f)`
    /// uses a **secret 5-bit rotation amount** drawn from the round subkey
    /// (`data[n*2+1]`). While Rust's `u32::rotate_left` is implemented as a
    /// constant-time instruction on all supported targets (x86_64 ROL,
    /// aarch64 ROR/equivalent), older literature (e.g., Kocher 1996)
    /// warns that variable-count shifts may not be constant-time on every
    /// microarchitecture. The S-box lookup leakage dominates in practice.
    ///
    /// Per block: **4 lookups × 12 or 16 Feistel rounds = 48 or 64
    /// secret-indexed CAST_S reads** via `encrypt_halves`/`decrypt_halves`.
    /// CAST5 is additionally a **64-bit-block cipher** (Sweet32 vulnerable
    /// for long sessions, RFC 7457).
    ///
    /// The key schedule (`Cast5::new`) also performs CAST_S4..CAST_S7
    /// lookups on key bytes; see `CAST_S4..CAST_S7` declarations. No
    /// constant-time software path is provided; no hardware acceleration
    /// exists for CAST5. Only mitigation: **migrate off CAST5** to
    /// AES-GCM or ChaCha20-Poly1305.
    ///
    /// See the module-level *Security Notice — Cache-Timing Side Channel*
    /// for the full threat model.
    #[inline]
    #[allow(clippy::many_single_char_names)]
    fn e_cast(km: u32, kr: u32, r: u32, op: u8) -> u32 {
        // All arithmetic is modulo 2^32 (wrapping) because the C code masks
        // with 0xffffffff at every step.
        let (t0, t1, t2) = match op % 3 {
            0 => {
                let t = km.wrapping_add(r);
                let t = t.rotate_left(kr & 0x1f);
                let a = CAST_S0[((t >> 8) & 0xff) as usize];
                let b = CAST_S1[(t & 0xff) as usize];
                let c = CAST_S2[((t >> 24) & 0xff) as usize];
                let d = CAST_S3[((t >> 16) & 0xff) as usize];
                // (+, ^, -): ((a + b) ^ c) - d -- but note the final operator
                //            is the same as OP1. For op%3==0 this is (+).
                // Expansion in C: L ^= (((a OP2 b) OP3 c) OP1 d)
                // For (OP1,OP2,OP3) = (+,^,-): L ^= (((a ^ b) - c) + d)
                (a ^ b, c, d)
            }
            1 => {
                let t = km ^ r;
                let t = t.rotate_left(kr & 0x1f);
                let a = CAST_S0[((t >> 8) & 0xff) as usize];
                let b = CAST_S1[(t & 0xff) as usize];
                let c = CAST_S2[((t >> 24) & 0xff) as usize];
                let d = CAST_S3[((t >> 16) & 0xff) as usize];
                // (^, -, +): (((a - b) + c) ^ d)
                (a.wrapping_sub(b), c, d)
            }
            _ => {
                let t = km.wrapping_sub(r);
                let t = t.rotate_left(kr & 0x1f);
                let a = CAST_S0[((t >> 8) & 0xff) as usize];
                let b = CAST_S1[(t & 0xff) as usize];
                let c = CAST_S2[((t >> 24) & 0xff) as usize];
                let d = CAST_S3[((t >> 16) & 0xff) as usize];
                // (-, +, ^): (((a + b) ^ c) - d)
                (a.wrapping_add(b), c, d)
            }
        };
        match op % 3 {
            0 => t0.wrapping_sub(t1).wrapping_add(t2),
            1 => t0.wrapping_add(t1) ^ t2,
            _ => (t0 ^ t1).wrapping_sub(t2),
        }
    }

    /// Encrypt two 32-bit halves in place (`CAST_encrypt` from `c_enc.c`).
    // `(n % 3) as u8` is provably lossless: `n` iterates in `0..16`, so
    // `n % 3` ∈ {0, 1, 2} and always fits in a `u8`.
    #[allow(clippy::cast_possible_truncation)]
    fn encrypt_halves(&self, l: &mut u32, r: &mut u32) {
        let k = &self.data;
        // Rounds 0..11 alternate L and R as operand.
        for n in 0..12 {
            let km = k[n * 2];
            let kr = k[n * 2 + 1];
            if n % 2 == 0 {
                *l ^= Self::e_cast(km, kr, *r, (n % 3) as u8);
            } else {
                *r ^= Self::e_cast(km, kr, *l, (n % 3) as u8);
            }
        }
        if !self.short_key {
            for n in 12..16 {
                let km = k[n * 2];
                let kr = k[n * 2 + 1];
                if n % 2 == 0 {
                    *l ^= Self::e_cast(km, kr, *r, (n % 3) as u8);
                } else {
                    *r ^= Self::e_cast(km, kr, *l, (n % 3) as u8);
                }
            }
        }

        // Output swap: data[1] = l, data[0] = r.
        core::mem::swap(l, r);
    }

    /// Decrypt two 32-bit halves in place (`CAST_decrypt` from `c_enc.c`).
    ///
    /// The C `CAST_decrypt` runs the round macros in reverse with SWAPPED
    /// (L, R) argument order relative to `CAST_encrypt`: where encrypt at
    /// round `n` uses `E_CAST(n, k, l, r, ...)` for even `n` (target=l) and
    /// `E_CAST(n, k, r, l, ...)` for odd `n` (target=r), decrypt inverts the
    /// targets so even `n` targets `r` and odd `n` targets `l`. This is
    /// equivalent to taking advantage of the output half-swap used by encrypt
    /// — the ciphertext is stored with (L, R) swapped, so processing it in
    /// place requires inverted targets.
    // `(n % 3) as u8` is provably lossless: `n` iterates in `0..16`, so
    // `n % 3` ∈ {0, 1, 2} and always fits in a `u8`.
    #[allow(clippy::cast_possible_truncation)]
    fn decrypt_halves(&self, l: &mut u32, r: &mut u32) {
        let k = &self.data;
        if !self.short_key {
            for n in (12..16).rev() {
                let km = k[n * 2];
                let kr = k[n * 2 + 1];
                if n % 2 == 0 {
                    *r ^= Self::e_cast(km, kr, *l, (n % 3) as u8);
                } else {
                    *l ^= Self::e_cast(km, kr, *r, (n % 3) as u8);
                }
            }
        }
        for n in (0..12).rev() {
            let km = k[n * 2];
            let kr = k[n * 2 + 1];
            if n % 2 == 0 {
                *r ^= Self::e_cast(km, kr, *l, (n % 3) as u8);
            } else {
                *l ^= Self::e_cast(km, kr, *r, (n % 3) as u8);
            }
        }
        core::mem::swap(l, r);
    }

    /// Derive the 32-entry subkey schedule from a user key.
    ///
    /// Port of `CAST_set_key` from `crypto/cast/c_skey.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key` is shorter than
    /// [`CAST_KEY_MIN`] or longer than [`CAST_KEY_MAX`].
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        // Helper: expand a 32-bit word `l` into Z[n/4] = l and z[n..n+3] (big-endian).
        // Byte extraction via `& 0xff` and a right shift produces values in [0, 255],
        // which always fit in `u8`; the cast is therefore lossless.
        #[allow(clippy::cast_possible_truncation)]
        fn cast_exp(l: u32, words: &mut [u32; 4], bytes: &mut [u8; 16], n: usize) {
            words[n / 4] = l;
            bytes[n + 3] = (l & 0xff) as u8;
            bytes[n + 2] = ((l >> 8) & 0xff) as u8;
            bytes[n + 1] = ((l >> 16) & 0xff) as u8;
            bytes[n] = ((l >> 24) & 0xff) as u8;
        }

        if key.len() < CAST_KEY_MIN || key.len() > CAST_KEY_MAX {
            return Err(CryptoError::Key(format!(
                "CAST5 key must be {CAST_KEY_MIN}–{CAST_KEY_MAX} bytes, got {}",
                key.len()
            )));
        }
        let short_key = key.len() <= CAST_SHORT_KEY_MAX;

        // Byte arrays x[], z[] and temporary word arrays X[], Z[], mirroring
        // the C implementation exactly.
        let mut x: [u8; 16] = [0; 16];
        x[..key.len()].copy_from_slice(key);
        let mut z: [u8; 16] = [0; 16];
        let mut x_words: [u32; 4] = [0; 4];
        let mut z_words: [u32; 4] = [0; 4];
        let mut k_buf: [u32; 32] = [0; 32];

        for (i, word) in x_words.iter_mut().enumerate() {
            *word = (u32::from(x[i * 4]) << 24)
                | (u32::from(x[i * 4 + 1]) << 16)
                | (u32::from(x[i * 4 + 2]) << 8)
                | u32::from(x[i * 4 + 3]);
        }

        // The loop runs exactly twice — first to populate k[0..15], then k[16..31].
        for pass in 0..2 {
            let offset = pass * 16;

            // --- First z update block ---
            let l = x_words[0]
                ^ CAST_S4[x[13] as usize]
                ^ CAST_S5[x[15] as usize]
                ^ CAST_S6[x[12] as usize]
                ^ CAST_S7[x[14] as usize]
                ^ CAST_S6[x[8] as usize];
            cast_exp(l, &mut z_words, &mut z, 0);
            let l = x_words[2]
                ^ CAST_S4[z[0] as usize]
                ^ CAST_S5[z[2] as usize]
                ^ CAST_S6[z[1] as usize]
                ^ CAST_S7[z[3] as usize]
                ^ CAST_S7[x[10] as usize];
            cast_exp(l, &mut z_words, &mut z, 4);
            let l = x_words[3]
                ^ CAST_S4[z[7] as usize]
                ^ CAST_S5[z[6] as usize]
                ^ CAST_S6[z[5] as usize]
                ^ CAST_S7[z[4] as usize]
                ^ CAST_S4[x[9] as usize];
            cast_exp(l, &mut z_words, &mut z, 8);
            let l = x_words[1]
                ^ CAST_S4[z[10] as usize]
                ^ CAST_S5[z[9] as usize]
                ^ CAST_S6[z[11] as usize]
                ^ CAST_S7[z[8] as usize]
                ^ CAST_S5[x[11] as usize];
            cast_exp(l, &mut z_words, &mut z, 12);

            k_buf[offset] = CAST_S4[z[8] as usize]
                ^ CAST_S5[z[9] as usize]
                ^ CAST_S6[z[7] as usize]
                ^ CAST_S7[z[6] as usize]
                ^ CAST_S4[z[2] as usize];
            k_buf[offset + 1] = CAST_S4[z[10] as usize]
                ^ CAST_S5[z[11] as usize]
                ^ CAST_S6[z[5] as usize]
                ^ CAST_S7[z[4] as usize]
                ^ CAST_S5[z[6] as usize];
            k_buf[offset + 2] = CAST_S4[z[12] as usize]
                ^ CAST_S5[z[13] as usize]
                ^ CAST_S6[z[3] as usize]
                ^ CAST_S7[z[2] as usize]
                ^ CAST_S6[z[9] as usize];
            k_buf[offset + 3] = CAST_S4[z[14] as usize]
                ^ CAST_S5[z[15] as usize]
                ^ CAST_S6[z[1] as usize]
                ^ CAST_S7[z[0] as usize]
                ^ CAST_S7[z[12] as usize];

            // --- First x update block ---
            let l = z_words[2]
                ^ CAST_S4[z[5] as usize]
                ^ CAST_S5[z[7] as usize]
                ^ CAST_S6[z[4] as usize]
                ^ CAST_S7[z[6] as usize]
                ^ CAST_S6[z[0] as usize];
            cast_exp(l, &mut x_words, &mut x, 0);
            let l = z_words[0]
                ^ CAST_S4[x[0] as usize]
                ^ CAST_S5[x[2] as usize]
                ^ CAST_S6[x[1] as usize]
                ^ CAST_S7[x[3] as usize]
                ^ CAST_S7[z[2] as usize];
            cast_exp(l, &mut x_words, &mut x, 4);
            let l = z_words[1]
                ^ CAST_S4[x[7] as usize]
                ^ CAST_S5[x[6] as usize]
                ^ CAST_S6[x[5] as usize]
                ^ CAST_S7[x[4] as usize]
                ^ CAST_S4[z[1] as usize];
            cast_exp(l, &mut x_words, &mut x, 8);
            let l = z_words[3]
                ^ CAST_S4[x[10] as usize]
                ^ CAST_S5[x[9] as usize]
                ^ CAST_S6[x[11] as usize]
                ^ CAST_S7[x[8] as usize]
                ^ CAST_S5[z[3] as usize];
            cast_exp(l, &mut x_words, &mut x, 12);

            k_buf[offset + 4] = CAST_S4[x[3] as usize]
                ^ CAST_S5[x[2] as usize]
                ^ CAST_S6[x[12] as usize]
                ^ CAST_S7[x[13] as usize]
                ^ CAST_S4[x[8] as usize];
            k_buf[offset + 5] = CAST_S4[x[1] as usize]
                ^ CAST_S5[x[0] as usize]
                ^ CAST_S6[x[14] as usize]
                ^ CAST_S7[x[15] as usize]
                ^ CAST_S5[x[13] as usize];
            k_buf[offset + 6] = CAST_S4[x[7] as usize]
                ^ CAST_S5[x[6] as usize]
                ^ CAST_S6[x[8] as usize]
                ^ CAST_S7[x[9] as usize]
                ^ CAST_S6[x[3] as usize];
            k_buf[offset + 7] = CAST_S4[x[5] as usize]
                ^ CAST_S5[x[4] as usize]
                ^ CAST_S6[x[10] as usize]
                ^ CAST_S7[x[11] as usize]
                ^ CAST_S7[x[7] as usize];

            // --- Second z update block ---
            let l = x_words[0]
                ^ CAST_S4[x[13] as usize]
                ^ CAST_S5[x[15] as usize]
                ^ CAST_S6[x[12] as usize]
                ^ CAST_S7[x[14] as usize]
                ^ CAST_S6[x[8] as usize];
            cast_exp(l, &mut z_words, &mut z, 0);
            let l = x_words[2]
                ^ CAST_S4[z[0] as usize]
                ^ CAST_S5[z[2] as usize]
                ^ CAST_S6[z[1] as usize]
                ^ CAST_S7[z[3] as usize]
                ^ CAST_S7[x[10] as usize];
            cast_exp(l, &mut z_words, &mut z, 4);
            let l = x_words[3]
                ^ CAST_S4[z[7] as usize]
                ^ CAST_S5[z[6] as usize]
                ^ CAST_S6[z[5] as usize]
                ^ CAST_S7[z[4] as usize]
                ^ CAST_S4[x[9] as usize];
            cast_exp(l, &mut z_words, &mut z, 8);
            let l = x_words[1]
                ^ CAST_S4[z[10] as usize]
                ^ CAST_S5[z[9] as usize]
                ^ CAST_S6[z[11] as usize]
                ^ CAST_S7[z[8] as usize]
                ^ CAST_S5[x[11] as usize];
            cast_exp(l, &mut z_words, &mut z, 12);

            k_buf[offset + 8] = CAST_S4[z[3] as usize]
                ^ CAST_S5[z[2] as usize]
                ^ CAST_S6[z[12] as usize]
                ^ CAST_S7[z[13] as usize]
                ^ CAST_S4[z[9] as usize];
            k_buf[offset + 9] = CAST_S4[z[1] as usize]
                ^ CAST_S5[z[0] as usize]
                ^ CAST_S6[z[14] as usize]
                ^ CAST_S7[z[15] as usize]
                ^ CAST_S5[z[12] as usize];
            k_buf[offset + 10] = CAST_S4[z[7] as usize]
                ^ CAST_S5[z[6] as usize]
                ^ CAST_S6[z[8] as usize]
                ^ CAST_S7[z[9] as usize]
                ^ CAST_S6[z[2] as usize];
            k_buf[offset + 11] = CAST_S4[z[5] as usize]
                ^ CAST_S5[z[4] as usize]
                ^ CAST_S6[z[10] as usize]
                ^ CAST_S7[z[11] as usize]
                ^ CAST_S7[z[6] as usize];

            // --- Second x update block ---
            let l = z_words[2]
                ^ CAST_S4[z[5] as usize]
                ^ CAST_S5[z[7] as usize]
                ^ CAST_S6[z[4] as usize]
                ^ CAST_S7[z[6] as usize]
                ^ CAST_S6[z[0] as usize];
            cast_exp(l, &mut x_words, &mut x, 0);
            let l = z_words[0]
                ^ CAST_S4[x[0] as usize]
                ^ CAST_S5[x[2] as usize]
                ^ CAST_S6[x[1] as usize]
                ^ CAST_S7[x[3] as usize]
                ^ CAST_S7[z[2] as usize];
            cast_exp(l, &mut x_words, &mut x, 4);
            let l = z_words[1]
                ^ CAST_S4[x[7] as usize]
                ^ CAST_S5[x[6] as usize]
                ^ CAST_S6[x[5] as usize]
                ^ CAST_S7[x[4] as usize]
                ^ CAST_S4[z[1] as usize];
            cast_exp(l, &mut x_words, &mut x, 8);
            let l = z_words[3]
                ^ CAST_S4[x[10] as usize]
                ^ CAST_S5[x[9] as usize]
                ^ CAST_S6[x[11] as usize]
                ^ CAST_S7[x[8] as usize]
                ^ CAST_S5[z[3] as usize];
            cast_exp(l, &mut x_words, &mut x, 12);

            k_buf[offset + 12] = CAST_S4[x[8] as usize]
                ^ CAST_S5[x[9] as usize]
                ^ CAST_S6[x[7] as usize]
                ^ CAST_S7[x[6] as usize]
                ^ CAST_S4[x[3] as usize];
            k_buf[offset + 13] = CAST_S4[x[10] as usize]
                ^ CAST_S5[x[11] as usize]
                ^ CAST_S6[x[5] as usize]
                ^ CAST_S7[x[4] as usize]
                ^ CAST_S5[x[7] as usize];
            k_buf[offset + 14] = CAST_S4[x[12] as usize]
                ^ CAST_S5[x[13] as usize]
                ^ CAST_S6[x[3] as usize]
                ^ CAST_S7[x[2] as usize]
                ^ CAST_S6[x[8] as usize];
            k_buf[offset + 15] = CAST_S4[x[14] as usize]
                ^ CAST_S5[x[15] as usize]
                ^ CAST_S6[x[1] as usize]
                ^ CAST_S7[x[0] as usize]
                ^ CAST_S7[x[13] as usize];
        }

        // Interleave into the final schedule: data[i*2] = Km, data[i*2+1] = Kr.
        let mut data = [0u32; 32];
        for i in 0..16 {
            data[i * 2] = k_buf[i];
            data[i * 2 + 1] = k_buf[i + 16].wrapping_add(16) & 0x1f;
        }

        // Scrub temporary arrays that contained key material.
        x.zeroize();
        z.zeroize();
        x_words.zeroize();
        z_words.zeroize();
        k_buf.zeroize();

        Ok(Cast5 { data, short_key })
    }
}

impl SymmetricCipher for Cast5 {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "CAST5")?;
        let mut l = load_u32_be(block, 0);
        let mut r = load_u32_be(block, 4);
        self.encrypt_halves(&mut l, &mut r);
        store_u32_be(block, 0, l);
        store_u32_be(block, 4, r);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "CAST5")?;
        let mut l = load_u32_be(block, 0);
        let mut r = load_u32_be(block, 4);
        self.decrypt_halves(&mut l, &mut r);
        store_u32_be(block, 0, l);
        store_u32_be(block, 4, r);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Cast5
    }
}

// -----------------------------------------------------------------------------
// IDEA (International Data Encryption Algorithm)
// -----------------------------------------------------------------------------

/// IDEA key size: 16 bytes (128 bits).
const IDEA_KEY_LEN: usize = 16;
/// Total subkeys in the IDEA schedule (9 rows × 6 words).
const IDEA_SCHEDULE_LEN: usize = 54;

/// IDEA cipher (64-bit block, 128-bit key).
///
/// Translates the C `IDEA_KEY_SCHEDULE` structure from
/// `include/openssl/idea.h`. Encryption and decryption schedules are
/// precomputed at construction so block operations are pure lookups.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Idea {
    /// Encryption schedule (54 × 16-bit words, accessed 6 at a time).
    encrypt_data: [u16; IDEA_SCHEDULE_LEN],
    /// Decryption schedule derived via `IDEA_set_decrypt_key`.
    decrypt_data: [u16; IDEA_SCHEDULE_LEN],
}

impl Idea {
    /// Multiplication mod (2^16 + 1) with IDEA's "0 ≡ 2^16" convention.
    ///
    /// Direct port of the `idea_mul` macro from `idea_local.h`.
    #[inline]
    fn idea_mul(a: u16, b: u16) -> u16 {
        let ul = u32::from(a).wrapping_mul(u32::from(b));
        if ul != 0 {
            // r = (L - H) mod (2^16 + 1) with "0 means 2^16" wrapping fix-up.
            let mut r = (ul & 0xffff).wrapping_sub(ul >> 16);
            r = r.wrapping_sub(r >> 16);
            (r & 0xffff) as u16
        } else {
            // Exactly one of a, b encodes the value 2^16; handle via the
            // algebraic identity from the C source.
            (1u32.wrapping_sub(u32::from(a)).wrapping_sub(u32::from(b)) & 0xffff) as u16
        }
    }

    /// Multiplicative inverse modulo 2^16 + 1 (extended Euclidean).
    ///
    /// Port of the `inverse()` static function from `i_skey.c`.
    fn inverse(xin: u16) -> u16 {
        if xin == 0 {
            return 0;
        }
        let mut n1: i64 = 0x1_0001;
        let mut n2: i64 = i64::from(xin);
        let mut b1: i64 = 0;
        let mut b2: i64 = 1;
        loop {
            let r = n1 % n2;
            let q = (n1 - r) / n2;
            if r == 0 {
                if b2 < 0 {
                    b2 += 0x1_0001;
                }
                break;
            }
            n1 = n2;
            n2 = r;
            let t = b2;
            b2 = b1 - q * b2;
            b1 = t;
        }
        // By construction above, `b2 >= 0` (the branch `b2 += 0x1_0001` runs
        // when `b2 < 0`), so `b2 & 0xffff` is always in `[0, 0xffff]`; the
        // `unwrap_or(0)` is therefore unreachable and the fallback value is
        // purely defensive.
        u16::try_from(b2 & 0xffff).unwrap_or(0)
    }

    /// Execute one full 8-round IDEA encryption on a 64-bit block.
    fn block_crypt(schedule: &[u16; IDEA_SCHEDULE_LEN], d: &mut [u32; 2]) {
        // Split input into four 16-bit sub-blocks.
        let mut x1 = ((d[0] >> 16) & 0xffff) as u16;
        let mut x2 = (d[0] & 0xffff) as u16;
        let mut x3 = ((d[1] >> 16) & 0xffff) as u16;
        let mut x4 = (d[1] & 0xffff) as u16;

        let mut p: usize = 0;
        for _ in 0..8 {
            // E_IDEA round:
            x1 = Self::idea_mul(x1, schedule[p]);
            p += 1;
            x2 = x2.wrapping_add(schedule[p]);
            p += 1;
            x3 = x3.wrapping_add(schedule[p]);
            p += 1;
            x4 = Self::idea_mul(x4, schedule[p]);
            p += 1;

            let mut t0 = x1 ^ x3;
            t0 = Self::idea_mul(t0, schedule[p]);
            p += 1;
            let mut t1 = t0.wrapping_add(x2 ^ x4);
            t1 = Self::idea_mul(t1, schedule[p]);
            p += 1;
            t0 = t0.wrapping_add(t1);
            x1 ^= t1;
            x4 ^= t0;
            // Swap middle halves: (x2, x3) = (x3 ^ t1, x2 ^ t0)
            let tmp = x2 ^ t0;
            x2 = x3 ^ t1;
            x3 = tmp;
        }

        // Output transformation (4 subkeys). Note that x2/x3 are swapped here
        // to undo the final round's swap, matching the reference code layout.
        x1 = Self::idea_mul(x1, schedule[p]);
        p += 1;
        let t0 = x3.wrapping_add(schedule[p]);
        p += 1;
        let t1 = x2.wrapping_add(schedule[p]);
        p += 1;
        x4 = Self::idea_mul(x4, schedule[p]);

        d[0] = (u32::from(t0) & 0xffff) | ((u32::from(x1) & 0xffff) << 16);
        d[1] = (u32::from(x4) & 0xffff) | ((u32::from(t1) & 0xffff) << 16);
    }

    /// Derive the IDEA encrypt schedule from a 128-bit user key.
    ///
    /// Port of `IDEA_set_encrypt_key` from `i_skey.c`.
    fn set_encrypt_key(key: &[u8; IDEA_KEY_LEN]) -> [u16; IDEA_SCHEDULE_LEN] {
        let mut kt = [0u16; IDEA_SCHEDULE_LEN];
        // First 8 subkeys are the raw key bytes, big-endian.
        for i in 0..8 {
            kt[i] = (u16::from(key[i * 2]) << 8) | u16::from(key[i * 2 + 1]);
        }
        // Cyclic 25-bit-left-rotation expansion.
        let mut kf_base: usize = 0;
        let mut kt_pos: usize = 8;
        for i in 0..6 {
            let r2 = kt[kf_base + 1];
            let r1 = kt[kf_base + 2];
            kt[kt_pos] = (r2 << 9) | (r1 >> 7);
            kt_pos += 1;
            let r0 = kt[kf_base + 3];
            kt[kt_pos] = (r1 << 9) | (r0 >> 7);
            kt_pos += 1;
            let r1b = kt[kf_base + 4];
            kt[kt_pos] = (r0 << 9) | (r1b >> 7);
            kt_pos += 1;
            let r0b = kt[kf_base + 5];
            kt[kt_pos] = (r1b << 9) | (r0b >> 7);
            kt_pos += 1;
            let r1c = kt[kf_base + 6];
            kt[kt_pos] = (r0b << 9) | (r1c >> 7);
            kt_pos += 1;
            let r0c = kt[kf_base + 7];
            kt[kt_pos] = (r1c << 9) | (r0c >> 7);
            kt_pos += 1;
            let r1d = kt[kf_base];
            if i >= 5 {
                break;
            }
            kt[kt_pos] = (r0c << 9) | (r1d >> 7);
            kt_pos += 1;
            kt[kt_pos] = (r1d << 9) | (r2 >> 7);
            kt_pos += 1;
            kf_base += 8;
        }
        kt
    }

    /// Derive the decrypt schedule from the encrypt schedule.
    ///
    /// Port of `IDEA_set_decrypt_key` from `i_skey.c`.
    fn set_decrypt_key(ek: &[u16; IDEA_SCHEDULE_LEN]) -> [u16; IDEA_SCHEDULE_LEN] {
        let mut dk = [0u16; IDEA_SCHEDULE_LEN];
        // fp starts at ek[48] (the 9th row, i.e. last row) and walks backward
        // in strides of 6. The total walk is 48 = 8 * 6, so fp stays in the
        // range [0, 48] throughout and is naturally a `usize`.
        let mut fp: usize = 48;
        let mut tp: usize = 0;
        for r in 0..9 {
            dk[tp] = Self::inverse(ek[fp]);
            tp += 1;
            // Mask-and-cast is lossless: `wrapping_sub(_) & 0xffff` is always
            // representable in a `u16`.
            #[allow(clippy::cast_possible_truncation)]
            {
                dk[tp] = (0x1_0000u32.wrapping_sub(u32::from(ek[fp + 2])) & 0xffff) as u16;
                tp += 1;
                dk[tp] = (0x1_0000u32.wrapping_sub(u32::from(ek[fp + 1])) & 0xffff) as u16;
                tp += 1;
            }
            dk[tp] = Self::inverse(ek[fp + 3]);
            tp += 1;
            if r == 8 {
                break;
            }
            fp = fp.saturating_sub(6);
            dk[tp] = ek[fp + 4];
            tp += 1;
            dk[tp] = ek[fp + 5];
            tp += 1;
        }
        // Swap dk[1] with dk[2] and dk[49] with dk[50] — matches the final
        // fix-up block in `IDEA_set_decrypt_key`.
        dk.swap(1, 2);
        dk.swap(49, 50);
        dk
    }

    /// Build a new IDEA cipher from a 128-bit (16-byte) key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is not exactly 16 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != IDEA_KEY_LEN {
            return Err(CryptoError::Key(format!(
                "IDEA key must be {IDEA_KEY_LEN} bytes, got {}",
                key.len()
            )));
        }
        let mut k = [0u8; IDEA_KEY_LEN];
        k.copy_from_slice(key);
        let encrypt_data = Self::set_encrypt_key(&k);
        let decrypt_data = Self::set_decrypt_key(&encrypt_data);
        k.zeroize();
        Ok(Idea {
            encrypt_data,
            decrypt_data,
        })
    }
}

impl SymmetricCipher for Idea {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "IDEA")?;
        let mut d = [load_u32_be(block, 0), load_u32_be(block, 4)];
        Self::block_crypt(&self.encrypt_data, &mut d);
        store_u32_be(block, 0, d[0]);
        store_u32_be(block, 4, d[1]);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "IDEA")?;
        let mut d = [load_u32_be(block, 0), load_u32_be(block, 4)];
        Self::block_crypt(&self.decrypt_data, &mut d);
        store_u32_be(block, 0, d[0]);
        store_u32_be(block, 4, d[1]);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Idea
    }
}

// -----------------------------------------------------------------------------
// SEED (Korean Information Security Agency, KS X 1213)
// -----------------------------------------------------------------------------

/// SEED key size: 16 bytes (128 bits).
const SEED_KEY_LEN: usize = 16;
/// SEED block size: 16 bytes (128 bits).
const SEED_BLOCK_LEN: usize = 16;
/// SEED schedule length: 16 rounds × 2 subkeys = 32 u32 words.
const SEED_SCHEDULE_LEN: usize = 32;

// Key schedule constants - golden ratio (from seed.c).
const SEED_KC: [u32; 16] = [
    0x9e37_79b9,
    0x3c6e_f373,
    0x78dd_e6e6,
    0xf1bb_cdcc,
    0xe377_9b99,
    0xc6ef_3733,
    0x8dde_6e67,
    0x1bbc_dccf,
    0x3779_b99e,
    0x6ef3_733c,
    0xdde6_e678,
    0xbbcd_ccf1,
    0x779b_99e3,
    0xef37_33c6,
    0xde6e_678d,
    0xbcdc_cf1b,
];

const SEED_SS: [[u32; 256]; 4] = [
    [
        0x2989_a1a8,
        0x0585_8184,
        0x16c6_d2d4,
        0x13c3_d3d0,
        0x1444_5054,
        0x1d0d_111c,
        0x2c8c_a0ac,
        0x2505_2124,
        0x1d4d_515c,
        0x0343_4340,
        0x1808_1018,
        0x1e0e_121c,
        0x1141_5150,
        0x3ccc_f0fc,
        0x0aca_c2c8,
        0x2343_6360,
        0x2808_2028,
        0x0444_4044,
        0x2000_2020,
        0x1d8d_919c,
        0x20c0_e0e0,
        0x22c2_e2e0,
        0x08c8_c0c8,
        0x1707_1314,
        0x2585_a1a4,
        0x0f8f_838c,
        0x0303_0300,
        0x3b4b_7378,
        0x3b8b_b3b8,
        0x1303_1310,
        0x12c2_d2d0,
        0x2ece_e2ec,
        0x3040_7070,
        0x0c8c_808c,
        0x3f0f_333c,
        0x2888_a0a8,
        0x3202_3230,
        0x1dcd_d1dc,
        0x36c6_f2f4,
        0x3444_7074,
        0x2ccc_e0ec,
        0x1585_9194,
        0x0b0b_0308,
        0x1747_5354,
        0x1c4c_505c,
        0x1b4b_5358,
        0x3d8d_b1bc,
        0x0101_0100,
        0x2404_2024,
        0x1c0c_101c,
        0x3343_7370,
        0x1888_9098,
        0x1000_1010,
        0x0ccc_c0cc,
        0x32c2_f2f0,
        0x19c9_d1d8,
        0x2c0c_202c,
        0x27c7_e3e4,
        0x3242_7270,
        0x0383_8380,
        0x1b8b_9398,
        0x11c1_d1d0,
        0x0686_8284,
        0x09c9_c1c8,
        0x2040_6060,
        0x1040_5050,
        0x2383_a3a0,
        0x2bcb_e3e8,
        0x0d0d_010c,
        0x3686_b2b4,
        0x1e8e_929c,
        0x0f4f_434c,
        0x3787_b3b4,
        0x1a4a_5258,
        0x06c6_c2c4,
        0x3848_7078,
        0x2686_a2a4,
        0x1202_1210,
        0x2f8f_a3ac,
        0x15c5_d1d4,
        0x2141_6160,
        0x03c3_c3c0,
        0x3484_b0b4,
        0x0141_4140,
        0x1242_5250,
        0x3d4d_717c,
        0x0d8d_818c,
        0x0808_0008,
        0x1f0f_131c,
        0x1989_9198,
        0x0000_0000,
        0x1909_1118,
        0x0404_0004,
        0x1343_5350,
        0x37c7_f3f4,
        0x21c1_e1e0,
        0x3dcd_f1fc,
        0x3646_7274,
        0x2f0f_232c,
        0x2707_2324,
        0x3080_b0b0,
        0x0b8b_8388,
        0x0e0e_020c,
        0x2b8b_a3a8,
        0x2282_a2a0,
        0x2e4e_626c,
        0x1383_9390,
        0x0d4d_414c,
        0x2949_6168,
        0x3c4c_707c,
        0x0909_0108,
        0x0a0a_0208,
        0x3f8f_b3bc,
        0x2fcf_e3ec,
        0x33c3_f3f0,
        0x05c5_c1c4,
        0x0787_8384,
        0x1404_1014,
        0x3ece_f2fc,
        0x2444_6064,
        0x1ece_d2dc,
        0x2e0e_222c,
        0x0b4b_4348,
        0x1a0a_1218,
        0x0606_0204,
        0x2101_2120,
        0x2b4b_6368,
        0x2646_6264,
        0x0202_0200,
        0x35c5_f1f4,
        0x1282_9290,
        0x0a8a_8288,
        0x0c0c_000c,
        0x3383_b3b0,
        0x3e4e_727c,
        0x10c0_d0d0,
        0x3a4a_7278,
        0x0747_4344,
        0x1686_9294,
        0x25c5_e1e4,
        0x2606_2224,
        0x0080_8080,
        0x2d8d_a1ac,
        0x1fcf_d3dc,
        0x2181_a1a0,
        0x3000_3030,
        0x3707_3334,
        0x2e8e_a2ac,
        0x3606_3234,
        0x1505_1114,
        0x2202_2220,
        0x3808_3038,
        0x34c4_f0f4,
        0x2787_a3a4,
        0x0545_4144,
        0x0c4c_404c,
        0x0181_8180,
        0x29c9_e1e8,
        0x0484_8084,
        0x1787_9394,
        0x3505_3134,
        0x0bcb_c3c8,
        0x0ece_c2cc,
        0x3c0c_303c,
        0x3141_7170,
        0x1101_1110,
        0x07c7_c3c4,
        0x0989_8188,
        0x3545_7174,
        0x3bcb_f3f8,
        0x1aca_d2d8,
        0x38c8_f0f8,
        0x1484_9094,
        0x1949_5158,
        0x0282_8280,
        0x04c4_c0c4,
        0x3fcf_f3fc,
        0x0949_4148,
        0x3909_3138,
        0x2747_6364,
        0x00c0_c0c0,
        0x0fcf_c3cc,
        0x17c7_d3d4,
        0x3888_b0b8,
        0x0f0f_030c,
        0x0e8e_828c,
        0x0242_4240,
        0x2303_2320,
        0x1181_9190,
        0x2c4c_606c,
        0x1bcb_d3d8,
        0x2484_a0a4,
        0x3404_3034,
        0x31c1_f1f0,
        0x0848_4048,
        0x02c2_c2c0,
        0x2f4f_636c,
        0x3d0d_313c,
        0x2d0d_212c,
        0x0040_4040,
        0x3e8e_b2bc,
        0x3e0e_323c,
        0x3c8c_b0bc,
        0x01c1_c1c0,
        0x2a8a_a2a8,
        0x3a8a_b2b8,
        0x0e4e_424c,
        0x1545_5154,
        0x3b0b_3338,
        0x1ccc_d0dc,
        0x2848_6068,
        0x3f4f_737c,
        0x1c8c_909c,
        0x18c8_d0d8,
        0x0a4a_4248,
        0x1646_5254,
        0x3747_7374,
        0x2080_a0a0,
        0x2dcd_e1ec,
        0x0646_4244,
        0x3585_b1b4,
        0x2b0b_2328,
        0x2545_6164,
        0x3aca_f2f8,
        0x23c3_e3e0,
        0x3989_b1b8,
        0x3181_b1b0,
        0x1f8f_939c,
        0x1e4e_525c,
        0x39c9_f1f8,
        0x26c6_e2e4,
        0x3282_b2b0,
        0x3101_3130,
        0x2aca_e2e8,
        0x2d4d_616c,
        0x1f4f_535c,
        0x24c4_e0e4,
        0x30c0_f0f0,
        0x0dcd_c1cc,
        0x0888_8088,
        0x1606_1214,
        0x3a0a_3238,
        0x1848_5058,
        0x14c4_d0d4,
        0x2242_6260,
        0x2909_2128,
        0x0707_0304,
        0x3303_3330,
        0x28c8_e0e8,
        0x1b0b_1318,
        0x0505_0104,
        0x3949_7178,
        0x1080_9090,
        0x2a4a_6268,
        0x2a0a_2228,
        0x1a8a_9298,
    ],
    [
        0x3838_0830,
        0xe828_c8e0,
        0x2c2d_0d21,
        0xa426_86a2,
        0xcc0f_cfc3,
        0xdc1e_ced2,
        0xb033_83b3,
        0xb838_88b0,
        0xac2f_8fa3,
        0x6020_4060,
        0x5415_4551,
        0xc407_c7c3,
        0x4404_4440,
        0x6c2f_4f63,
        0x682b_4b63,
        0x581b_4b53,
        0xc003_c3c3,
        0x6022_4262,
        0x3033_0333,
        0xb435_85b1,
        0x2829_0921,
        0xa020_80a0,
        0xe022_c2e2,
        0xa427_87a3,
        0xd013_c3d3,
        0x9011_8191,
        0x1011_0111,
        0x0406_0602,
        0x1c1c_0c10,
        0xbc3c_8cb0,
        0x3436_0632,
        0x480b_4b43,
        0xec2f_cfe3,
        0x8808_8880,
        0x6c2c_4c60,
        0xa828_88a0,
        0x1417_0713,
        0xc404_c4c0,
        0x1416_0612,
        0xf434_c4f0,
        0xc002_c2c2,
        0x4405_4541,
        0xe021_c1e1,
        0xd416_c6d2,
        0x3c3f_0f33,
        0x3c3d_0d31,
        0x8c0e_8e82,
        0x9818_8890,
        0x2828_0820,
        0x4c0e_4e42,
        0xf436_c6f2,
        0x3c3e_0e32,
        0xa425_85a1,
        0xf839_c9f1,
        0x0c0d_0d01,
        0xdc1f_cfd3,
        0xd818_c8d0,
        0x282b_0b23,
        0x6426_4662,
        0x783a_4a72,
        0x2427_0723,
        0x2c2f_0f23,
        0xf031_c1f1,
        0x7032_4272,
        0x4002_4242,
        0xd414_c4d0,
        0x4001_4141,
        0xc000_c0c0,
        0x7033_4373,
        0x6427_4763,
        0xac2c_8ca0,
        0x880b_8b83,
        0xf437_c7f3,
        0xac2d_8da1,
        0x8000_8080,
        0x1c1f_0f13,
        0xc80a_cac2,
        0x2c2c_0c20,
        0xa82a_8aa2,
        0x3434_0430,
        0xd012_c2d2,
        0x080b_0b03,
        0xec2e_cee2,
        0xe829_c9e1,
        0x5c1d_4d51,
        0x9414_8490,
        0x1818_0810,
        0xf838_c8f0,
        0x5417_4753,
        0xac2e_8ea2,
        0x0808_0800,
        0xc405_c5c1,
        0x1013_0313,
        0xcc0d_cdc1,
        0x8406_8682,
        0xb839_89b1,
        0xfc3f_cff3,
        0x7c3d_4d71,
        0xc001_c1c1,
        0x3031_0131,
        0xf435_c5f1,
        0x880a_8a82,
        0x682a_4a62,
        0xb031_81b1,
        0xd011_c1d1,
        0x2020_0020,
        0xd417_c7d3,
        0x0002_0202,
        0x2022_0222,
        0x0404_0400,
        0x6828_4860,
        0x7031_4171,
        0x0407_0703,
        0xd81b_cbd3,
        0x9c1d_8d91,
        0x9819_8991,
        0x6021_4161,
        0xbc3e_8eb2,
        0xe426_c6e2,
        0x5819_4951,
        0xdc1d_cdd1,
        0x5011_4151,
        0x9010_8090,
        0xdc1c_ccd0,
        0x981a_8a92,
        0xa023_83a3,
        0xa82b_8ba3,
        0xd010_c0d0,
        0x8001_8181,
        0x0c0f_0f03,
        0x4407_4743,
        0x181a_0a12,
        0xe023_c3e3,
        0xec2c_cce0,
        0x8c0d_8d81,
        0xbc3f_8fb3,
        0x9416_8692,
        0x783b_4b73,
        0x5c1c_4c50,
        0xa022_82a2,
        0xa021_81a1,
        0x6023_4363,
        0x2023_0323,
        0x4c0d_4d41,
        0xc808_c8c0,
        0x9c1e_8e92,
        0x9c1c_8c90,
        0x383a_0a32,
        0x0c0c_0c00,
        0x2c2e_0e22,
        0xb83a_8ab2,
        0x6c2e_4e62,
        0x9c1f_8f93,
        0x581a_4a52,
        0xf032_c2f2,
        0x9012_8292,
        0xf033_c3f3,
        0x4809_4941,
        0x7838_4870,
        0xcc0c_ccc0,
        0x1415_0511,
        0xf83b_cbf3,
        0x7030_4070,
        0x7435_4571,
        0x7c3f_4f73,
        0x3435_0531,
        0x1010_0010,
        0x0003_0303,
        0x6424_4460,
        0x6c2d_4d61,
        0xc406_c6c2,
        0x7434_4470,
        0xd415_c5d1,
        0xb434_84b0,
        0xe82a_cae2,
        0x0809_0901,
        0x7436_4672,
        0x1819_0911,
        0xfc3e_cef2,
        0x4000_4040,
        0x1012_0212,
        0xe020_c0e0,
        0xbc3d_8db1,
        0x0405_0501,
        0xf83a_caf2,
        0x0001_0101,
        0xf030_c0f0,
        0x282a_0a22,
        0x5c1e_4e52,
        0xa829_89a1,
        0x5416_4652,
        0x4003_4343,
        0x8405_8581,
        0x1414_0410,
        0x8809_8981,
        0x981b_8b93,
        0xb030_80b0,
        0xe425_c5e1,
        0x4808_4840,
        0x7839_4971,
        0x9417_8793,
        0xfc3c_ccf0,
        0x1c1e_0e12,
        0x8002_8282,
        0x2021_0121,
        0x8c0c_8c80,
        0x181b_0b13,
        0x5c1f_4f53,
        0x7437_4773,
        0x5414_4450,
        0xb032_82b2,
        0x1c1d_0d11,
        0x2425_0521,
        0x4c0f_4f43,
        0x0000_0000,
        0x4406_4642,
        0xec2d_cde1,
        0x5818_4850,
        0x5012_4252,
        0xe82b_cbe3,
        0x7c3e_4e72,
        0xd81a_cad2,
        0xc809_c9c1,
        0xfc3d_cdf1,
        0x3030_0030,
        0x9415_8591,
        0x6425_4561,
        0x3c3c_0c30,
        0xb436_86b2,
        0xe424_c4e0,
        0xb83b_8bb3,
        0x7c3c_4c70,
        0x0c0e_0e02,
        0x5010_4050,
        0x3839_0931,
        0x2426_0622,
        0x3032_0232,
        0x8404_8480,
        0x6829_4961,
        0x9013_8393,
        0x3437_0733,
        0xe427_c7e3,
        0x2424_0420,
        0xa424_84a0,
        0xc80b_cbc3,
        0x5013_4353,
        0x080a_0a02,
        0x8407_8783,
        0xd819_c9d1,
        0x4c0c_4c40,
        0x8003_8383,
        0x8c0f_8f83,
        0xcc0e_cec2,
        0x383b_0b33,
        0x480a_4a42,
        0xb437_87b3,
    ],
    [
        0xa1a8_2989,
        0x8184_0585,
        0xd2d4_16c6,
        0xd3d0_13c3,
        0x5054_1444,
        0x111c_1d0d,
        0xa0ac_2c8c,
        0x2124_2505,
        0x515c_1d4d,
        0x4340_0343,
        0x1018_1808,
        0x121c_1e0e,
        0x5150_1141,
        0xf0fc_3ccc,
        0xc2c8_0aca,
        0x6360_2343,
        0x2028_2808,
        0x4044_0444,
        0x2020_2000,
        0x919c_1d8d,
        0xe0e0_20c0,
        0xe2e0_22c2,
        0xc0c8_08c8,
        0x1314_1707,
        0xa1a4_2585,
        0x838c_0f8f,
        0x0300_0303,
        0x7378_3b4b,
        0xb3b8_3b8b,
        0x1310_1303,
        0xd2d0_12c2,
        0xe2ec_2ece,
        0x7070_3040,
        0x808c_0c8c,
        0x333c_3f0f,
        0xa0a8_2888,
        0x3230_3202,
        0xd1dc_1dcd,
        0xf2f4_36c6,
        0x7074_3444,
        0xe0ec_2ccc,
        0x9194_1585,
        0x0308_0b0b,
        0x5354_1747,
        0x505c_1c4c,
        0x5358_1b4b,
        0xb1bc_3d8d,
        0x0100_0101,
        0x2024_2404,
        0x101c_1c0c,
        0x7370_3343,
        0x9098_1888,
        0x1010_1000,
        0xc0cc_0ccc,
        0xf2f0_32c2,
        0xd1d8_19c9,
        0x202c_2c0c,
        0xe3e4_27c7,
        0x7270_3242,
        0x8380_0383,
        0x9398_1b8b,
        0xd1d0_11c1,
        0x8284_0686,
        0xc1c8_09c9,
        0x6060_2040,
        0x5050_1040,
        0xa3a0_2383,
        0xe3e8_2bcb,
        0x010c_0d0d,
        0xb2b4_3686,
        0x929c_1e8e,
        0x434c_0f4f,
        0xb3b4_3787,
        0x5258_1a4a,
        0xc2c4_06c6,
        0x7078_3848,
        0xa2a4_2686,
        0x1210_1202,
        0xa3ac_2f8f,
        0xd1d4_15c5,
        0x6160_2141,
        0xc3c0_03c3,
        0xb0b4_3484,
        0x4140_0141,
        0x5250_1242,
        0x717c_3d4d,
        0x818c_0d8d,
        0x0008_0808,
        0x131c_1f0f,
        0x9198_1989,
        0x0000_0000,
        0x1118_1909,
        0x0004_0404,
        0x5350_1343,
        0xf3f4_37c7,
        0xe1e0_21c1,
        0xf1fc_3dcd,
        0x7274_3646,
        0x232c_2f0f,
        0x2324_2707,
        0xb0b0_3080,
        0x8388_0b8b,
        0x020c_0e0e,
        0xa3a8_2b8b,
        0xa2a0_2282,
        0x626c_2e4e,
        0x9390_1383,
        0x414c_0d4d,
        0x6168_2949,
        0x707c_3c4c,
        0x0108_0909,
        0x0208_0a0a,
        0xb3bc_3f8f,
        0xe3ec_2fcf,
        0xf3f0_33c3,
        0xc1c4_05c5,
        0x8384_0787,
        0x1014_1404,
        0xf2fc_3ece,
        0x6064_2444,
        0xd2dc_1ece,
        0x222c_2e0e,
        0x4348_0b4b,
        0x1218_1a0a,
        0x0204_0606,
        0x2120_2101,
        0x6368_2b4b,
        0x6264_2646,
        0x0200_0202,
        0xf1f4_35c5,
        0x9290_1282,
        0x8288_0a8a,
        0x000c_0c0c,
        0xb3b0_3383,
        0x727c_3e4e,
        0xd0d0_10c0,
        0x7278_3a4a,
        0x4344_0747,
        0x9294_1686,
        0xe1e4_25c5,
        0x2224_2606,
        0x8080_0080,
        0xa1ac_2d8d,
        0xd3dc_1fcf,
        0xa1a0_2181,
        0x3030_3000,
        0x3334_3707,
        0xa2ac_2e8e,
        0x3234_3606,
        0x1114_1505,
        0x2220_2202,
        0x3038_3808,
        0xf0f4_34c4,
        0xa3a4_2787,
        0x4144_0545,
        0x404c_0c4c,
        0x8180_0181,
        0xe1e8_29c9,
        0x8084_0484,
        0x9394_1787,
        0x3134_3505,
        0xc3c8_0bcb,
        0xc2cc_0ece,
        0x303c_3c0c,
        0x7170_3141,
        0x1110_1101,
        0xc3c4_07c7,
        0x8188_0989,
        0x7174_3545,
        0xf3f8_3bcb,
        0xd2d8_1aca,
        0xf0f8_38c8,
        0x9094_1484,
        0x5158_1949,
        0x8280_0282,
        0xc0c4_04c4,
        0xf3fc_3fcf,
        0x4148_0949,
        0x3138_3909,
        0x6364_2747,
        0xc0c0_00c0,
        0xc3cc_0fcf,
        0xd3d4_17c7,
        0xb0b8_3888,
        0x030c_0f0f,
        0x828c_0e8e,
        0x4240_0242,
        0x2320_2303,
        0x9190_1181,
        0x606c_2c4c,
        0xd3d8_1bcb,
        0xa0a4_2484,
        0x3034_3404,
        0xf1f0_31c1,
        0x4048_0848,
        0xc2c0_02c2,
        0x636c_2f4f,
        0x313c_3d0d,
        0x212c_2d0d,
        0x4040_0040,
        0xb2bc_3e8e,
        0x323c_3e0e,
        0xb0bc_3c8c,
        0xc1c0_01c1,
        0xa2a8_2a8a,
        0xb2b8_3a8a,
        0x424c_0e4e,
        0x5154_1545,
        0x3338_3b0b,
        0xd0dc_1ccc,
        0x6068_2848,
        0x737c_3f4f,
        0x909c_1c8c,
        0xd0d8_18c8,
        0x4248_0a4a,
        0x5254_1646,
        0x7374_3747,
        0xa0a0_2080,
        0xe1ec_2dcd,
        0x4244_0646,
        0xb1b4_3585,
        0x2328_2b0b,
        0x6164_2545,
        0xf2f8_3aca,
        0xe3e0_23c3,
        0xb1b8_3989,
        0xb1b0_3181,
        0x939c_1f8f,
        0x525c_1e4e,
        0xf1f8_39c9,
        0xe2e4_26c6,
        0xb2b0_3282,
        0x3130_3101,
        0xe2e8_2aca,
        0x616c_2d4d,
        0x535c_1f4f,
        0xe0e4_24c4,
        0xf0f0_30c0,
        0xc1cc_0dcd,
        0x8088_0888,
        0x1214_1606,
        0x3238_3a0a,
        0x5058_1848,
        0xd0d4_14c4,
        0x6260_2242,
        0x2128_2909,
        0x0304_0707,
        0x3330_3303,
        0xe0e8_28c8,
        0x1318_1b0b,
        0x0104_0505,
        0x7178_3949,
        0x9090_1080,
        0x6268_2a4a,
        0x2228_2a0a,
        0x9298_1a8a,
    ],
    [
        0x0830_3838,
        0xc8e0_e828,
        0x0d21_2c2d,
        0x86a2_a426,
        0xcfc3_cc0f,
        0xced2_dc1e,
        0x83b3_b033,
        0x88b0_b838,
        0x8fa3_ac2f,
        0x4060_6020,
        0x4551_5415,
        0xc7c3_c407,
        0x4440_4404,
        0x4f63_6c2f,
        0x4b63_682b,
        0x4b53_581b,
        0xc3c3_c003,
        0x4262_6022,
        0x0333_3033,
        0x85b1_b435,
        0x0921_2829,
        0x80a0_a020,
        0xc2e2_e022,
        0x87a3_a427,
        0xc3d3_d013,
        0x8191_9011,
        0x0111_1011,
        0x0602_0406,
        0x0c10_1c1c,
        0x8cb0_bc3c,
        0x0632_3436,
        0x4b43_480b,
        0xcfe3_ec2f,
        0x8880_8808,
        0x4c60_6c2c,
        0x88a0_a828,
        0x0713_1417,
        0xc4c0_c404,
        0x0612_1416,
        0xc4f0_f434,
        0xc2c2_c002,
        0x4541_4405,
        0xc1e1_e021,
        0xc6d2_d416,
        0x0f33_3c3f,
        0x0d31_3c3d,
        0x8e82_8c0e,
        0x8890_9818,
        0x0820_2828,
        0x4e42_4c0e,
        0xc6f2_f436,
        0x0e32_3c3e,
        0x85a1_a425,
        0xc9f1_f839,
        0x0d01_0c0d,
        0xcfd3_dc1f,
        0xc8d0_d818,
        0x0b23_282b,
        0x4662_6426,
        0x4a72_783a,
        0x0723_2427,
        0x0f23_2c2f,
        0xc1f1_f031,
        0x4272_7032,
        0x4242_4002,
        0xc4d0_d414,
        0x4141_4001,
        0xc0c0_c000,
        0x4373_7033,
        0x4763_6427,
        0x8ca0_ac2c,
        0x8b83_880b,
        0xc7f3_f437,
        0x8da1_ac2d,
        0x8080_8000,
        0x0f13_1c1f,
        0xcac2_c80a,
        0x0c20_2c2c,
        0x8aa2_a82a,
        0x0430_3434,
        0xc2d2_d012,
        0x0b03_080b,
        0xcee2_ec2e,
        0xc9e1_e829,
        0x4d51_5c1d,
        0x8490_9414,
        0x0810_1818,
        0xc8f0_f838,
        0x4753_5417,
        0x8ea2_ac2e,
        0x0800_0808,
        0xc5c1_c405,
        0x0313_1013,
        0xcdc1_cc0d,
        0x8682_8406,
        0x89b1_b839,
        0xcff3_fc3f,
        0x4d71_7c3d,
        0xc1c1_c001,
        0x0131_3031,
        0xc5f1_f435,
        0x8a82_880a,
        0x4a62_682a,
        0x81b1_b031,
        0xc1d1_d011,
        0x0020_2020,
        0xc7d3_d417,
        0x0202_0002,
        0x0222_2022,
        0x0400_0404,
        0x4860_6828,
        0x4171_7031,
        0x0703_0407,
        0xcbd3_d81b,
        0x8d91_9c1d,
        0x8991_9819,
        0x4161_6021,
        0x8eb2_bc3e,
        0xc6e2_e426,
        0x4951_5819,
        0xcdd1_dc1d,
        0x4151_5011,
        0x8090_9010,
        0xccd0_dc1c,
        0x8a92_981a,
        0x83a3_a023,
        0x8ba3_a82b,
        0xc0d0_d010,
        0x8181_8001,
        0x0f03_0c0f,
        0x4743_4407,
        0x0a12_181a,
        0xc3e3_e023,
        0xcce0_ec2c,
        0x8d81_8c0d,
        0x8fb3_bc3f,
        0x8692_9416,
        0x4b73_783b,
        0x4c50_5c1c,
        0x82a2_a022,
        0x81a1_a021,
        0x4363_6023,
        0x0323_2023,
        0x4d41_4c0d,
        0xc8c0_c808,
        0x8e92_9c1e,
        0x8c90_9c1c,
        0x0a32_383a,
        0x0c00_0c0c,
        0x0e22_2c2e,
        0x8ab2_b83a,
        0x4e62_6c2e,
        0x8f93_9c1f,
        0x4a52_581a,
        0xc2f2_f032,
        0x8292_9012,
        0xc3f3_f033,
        0x4941_4809,
        0x4870_7838,
        0xccc0_cc0c,
        0x0511_1415,
        0xcbf3_f83b,
        0x4070_7030,
        0x4571_7435,
        0x4f73_7c3f,
        0x0531_3435,
        0x0010_1010,
        0x0303_0003,
        0x4460_6424,
        0x4d61_6c2d,
        0xc6c2_c406,
        0x4470_7434,
        0xc5d1_d415,
        0x84b0_b434,
        0xcae2_e82a,
        0x0901_0809,
        0x4672_7436,
        0x0911_1819,
        0xcef2_fc3e,
        0x4040_4000,
        0x0212_1012,
        0xc0e0_e020,
        0x8db1_bc3d,
        0x0501_0405,
        0xcaf2_f83a,
        0x0101_0001,
        0xc0f0_f030,
        0x0a22_282a,
        0x4e52_5c1e,
        0x89a1_a829,
        0x4652_5416,
        0x4343_4003,
        0x8581_8405,
        0x0410_1414,
        0x8981_8809,
        0x8b93_981b,
        0x80b0_b030,
        0xc5e1_e425,
        0x4840_4808,
        0x4971_7839,
        0x8793_9417,
        0xccf0_fc3c,
        0x0e12_1c1e,
        0x8282_8002,
        0x0121_2021,
        0x8c80_8c0c,
        0x0b13_181b,
        0x4f53_5c1f,
        0x4773_7437,
        0x4450_5414,
        0x82b2_b032,
        0x0d11_1c1d,
        0x0521_2425,
        0x4f43_4c0f,
        0x0000_0000,
        0x4642_4406,
        0xcde1_ec2d,
        0x4850_5818,
        0x4252_5012,
        0xcbe3_e82b,
        0x4e72_7c3e,
        0xcad2_d81a,
        0xc9c1_c809,
        0xcdf1_fc3d,
        0x0030_3030,
        0x8591_9415,
        0x4561_6425,
        0x0c30_3c3c,
        0x86b2_b436,
        0xc4e0_e424,
        0x8bb3_b83b,
        0x4c70_7c3c,
        0x0e02_0c0e,
        0x4050_5010,
        0x0931_3839,
        0x0622_2426,
        0x0232_3032,
        0x8480_8404,
        0x4961_6829,
        0x8393_9013,
        0x0733_3437,
        0xc7e3_e427,
        0x0420_2424,
        0x84a0_a424,
        0xcbc3_c80b,
        0x4353_5013,
        0x0a02_080a,
        0x8783_8407,
        0xc9d1_d819,
        0x4c40_4c0c,
        0x8383_8003,
        0x8f83_8c0f,
        0xcec2_cc0e,
        0x0b33_383b,
        0x4a42_480a,
        0x87b3_b437,
    ],
];

/// SEED cipher (128-bit block, 128-bit key).
///
/// Translates `SEED_KEY_SCHEDULE` and its associated routines from
/// `crypto/seed/seed.c`. The schedule holds 32 round-key words
/// (16 rounds × 2 subkeys). Block and key schedule operations use the
/// table-driven `SS` variant of the G-function for performance.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed {
    /// 32 round keys derived from the 128-bit user key.
    data: [u32; SEED_SCHEDULE_LEN],
}

impl Seed {
    /// SEED G-function: combines four byte-indexed S-box lookups via XOR.
    ///
    /// Direct port of the `G_FUNC` macro from `seed.c`.
    ///
    /// # Security (cache-timing)
    ///
    /// This is the **principal cache-timing-vulnerable site** of SEED
    /// encryption and decryption. The four byte-indexed lookups into
    /// `SEED_SS[0..=3]` use **secret-derived indices** (`(v & 0xff)`,
    /// `((v >> 8) & 0xff)`, etc., where `v = L XOR round_key` is a Feistel
    /// intermediate). Each sub-table is 256 × 32-bit = 1024 bytes —
    /// multiple cache lines on any modern CPU, so cache-line residency
    /// leaks bits of each byte index.
    ///
    /// Per block: **4 lookups × 16 rounds (each with 2 G-function calls) =
    /// 128 secret-indexed SEED_SS reads** (caller `F_func` invokes
    /// `g_func` three times per round via the SEED round structure;
    /// overall leakage scales with round count). Both encryption and
    /// decryption pass through this path.
    ///
    /// The SEED **key schedule** (`Seed::new`) also invokes `g_func` on
    /// intermediate key-derived values during KEYSCHEDULE_UPDATE0/UPDATE1,
    /// leaking during key setup.
    ///
    /// SEED is a 128-bit-block cipher and therefore is NOT Sweet32
    /// vulnerable, but no constant-time software path is provided and no
    /// hardware acceleration exists for SEED. Only mitigation: **migrate
    /// off SEED** to AES-GCM or ChaCha20-Poly1305. SEED remains in this
    /// crate for Korean government standard (TTA KS X 1213:2004)
    /// interoperability only.
    ///
    /// See the module-level *Security Notice — Cache-Timing Side Channel*
    /// for the full threat model.
    #[inline]
    fn g_func(v: u32) -> u32 {
        SEED_SS[0][(v & 0xff) as usize]
            ^ SEED_SS[1][((v >> 8) & 0xff) as usize]
            ^ SEED_SS[2][((v >> 16) & 0xff) as usize]
            ^ SEED_SS[3][((v >> 24) & 0xff) as usize]
    }

    /// Apply the `KEYSCHEDULE_UPDATE0` transformation (rotate x3/x4 pair left 8).
    #[inline]
    fn key_update0(x1: u32, x2: u32, x3: &mut u32, x4: &mut u32, kc: u32) -> (u32, u32) {
        let t0_save = *x3;
        *x3 = (*x3 << 8) ^ (*x4 >> 24);
        *x4 = (*x4 << 8) ^ (t0_save >> 24);
        let t0 = x1.wrapping_add(*x3).wrapping_sub(kc);
        let t1 = x2.wrapping_add(kc).wrapping_sub(*x4);
        (t0, t1)
    }

    /// Apply the `KEYSCHEDULE_UPDATE1` transformation (rotate x1/x2 pair right 8).
    #[inline]
    fn key_update1(x1: &mut u32, x2: &mut u32, x3: u32, x4: u32, kc: u32) -> (u32, u32) {
        let t0_save = *x1;
        *x1 = (*x1 >> 8) ^ (*x2 << 24);
        *x2 = (*x2 >> 8) ^ (t0_save << 24);
        let t0 = x1.wrapping_add(x3).wrapping_sub(kc);
        let t1 = x2.wrapping_add(kc).wrapping_sub(x4);
        (t0, t1)
    }

    /// `E_SEED` Feistel round: consumes two subkeys from `data[rbase..rbase+2]`
    /// and updates the left half `(x1, x2)`.
    #[inline]
    fn e_seed(
        data: &[u32; SEED_SCHEDULE_LEN],
        rbase: usize,
        x1: &mut u32,
        x2: &mut u32,
        x3: u32,
        x4: u32,
    ) {
        let mut t0 = x3 ^ data[rbase];
        let mut t1 = x4 ^ data[rbase + 1];
        t1 ^= t0;
        t1 = Self::g_func(t1);
        t0 = t0.wrapping_add(t1);
        t0 = Self::g_func(t0);
        t1 = t1.wrapping_add(t0);
        t1 = Self::g_func(t1);
        t0 = t0.wrapping_add(t1);
        *x1 ^= t0;
        *x2 ^= t1;
    }

    /// Build a new SEED cipher from a 128-bit (16-byte) key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is not exactly 16 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != SEED_KEY_LEN {
            return Err(CryptoError::Key(format!(
                "SEED key must be {SEED_KEY_LEN} bytes, got {}",
                key.len()
            )));
        }
        let mut data = [0u32; SEED_SCHEDULE_LEN];
        let mut x1 = load_u32_be(key, 0);
        let mut x2 = load_u32_be(key, 4);
        let mut x3 = load_u32_be(key, 8);
        let mut x4 = load_u32_be(key, 12);

        // Round 0: direct formula (no rotate).
        let mut t0 = x1.wrapping_add(x3).wrapping_sub(SEED_KC[0]);
        let mut t1 = x2.wrapping_sub(x4).wrapping_add(SEED_KC[0]);
        data[0] = Self::g_func(t0);
        data[1] = Self::g_func(t1);

        // Round 1: UPDATE1 with KC[1].
        let (rt0, rt1) = Self::key_update1(&mut x1, &mut x2, x3, x4, SEED_KC[1]);
        t0 = rt0;
        t1 = rt1;
        data[2] = Self::g_func(t0);
        data[3] = Self::g_func(t1);

        // Rounds 2..15: UPDATE0 for even, UPDATE1 for odd.
        for i in 2..16 {
            let (rt0, rt1) = if i & 1 == 0 {
                Self::key_update0(x1, x2, &mut x3, &mut x4, SEED_KC[i])
            } else {
                Self::key_update1(&mut x1, &mut x2, x3, x4, SEED_KC[i])
            };
            t0 = rt0;
            t1 = rt1;
            data[i * 2] = Self::g_func(t0);
            data[i * 2 + 1] = Self::g_func(t1);
        }

        // Scrub locals holding key-derived material.
        x1.zeroize();
        x2.zeroize();
        x3.zeroize();
        x4.zeroize();
        t0.zeroize();
        t1.zeroize();

        Ok(Seed { data })
    }
}

impl SymmetricCipher for Seed {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block128
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, SEED_BLOCK_LEN, "SEED")?;
        let mut x1 = load_u32_be(block, 0);
        let mut x2 = load_u32_be(block, 4);
        let mut x3 = load_u32_be(block, 8);
        let mut x4 = load_u32_be(block, 12);

        // 16 rounds: alternate (left, right) halves every 2 subkey slots.
        let mut rbase = 0usize;
        while rbase < SEED_SCHEDULE_LEN {
            Self::e_seed(&self.data, rbase, &mut x1, &mut x2, x3, x4);
            Self::e_seed(&self.data, rbase + 2, &mut x3, &mut x4, x1, x2);
            rbase += 4;
        }

        // Final output: halves swapped (x3, x4, x1, x2).
        store_u32_be(block, 0, x3);
        store_u32_be(block, 4, x4);
        store_u32_be(block, 8, x1);
        store_u32_be(block, 12, x2);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, SEED_BLOCK_LEN, "SEED")?;
        let mut x1 = load_u32_be(block, 0);
        let mut x2 = load_u32_be(block, 4);
        let mut x3 = load_u32_be(block, 8);
        let mut x4 = load_u32_be(block, 12);

        // Reverse round order: subkeys consumed from tail to head.
        let mut rbase = SEED_SCHEDULE_LEN;
        while rbase >= 4 {
            Self::e_seed(&self.data, rbase - 2, &mut x1, &mut x2, x3, x4);
            Self::e_seed(&self.data, rbase - 4, &mut x3, &mut x4, x1, x2);
            rbase -= 4;
        }

        store_u32_be(block, 0, x3);
        store_u32_be(block, 4, x4);
        store_u32_be(block, 8, x1);
        store_u32_be(block, 12, x2);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Seed
    }
}

// -----------------------------------------------------------------------------
// RC2 (RSA Data Security, RFC 2268)
// -----------------------------------------------------------------------------

/// RC2 block size: 8 bytes (64 bits).
const RC2_BLOCK_LEN: usize = 8;
/// RC2 minimum key length: 1 byte.
const RC2_MIN_KEY_LEN: usize = 1;
/// RC2 maximum key length: 128 bytes (1024 bits).
const RC2_MAX_KEY_LEN: usize = 128;
/// RC2 schedule length: 64 u16 words (128 bytes).
const RC2_SCHEDULE_LEN: usize = 64;
/// RC2 maximum effective key bits.
const RC2_MAX_BITS: usize = 1024;

const RC2_KEY_TABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

/// RC2 block cipher (64-bit block, variable-length key 1–128 bytes).
///
/// Translates C `RC2_KEY` from `crypto/rc2/rc2_local.h`. Little-endian
/// byte order throughout. The key schedule is 64 × u16 (128 bytes).
///
/// # Cryptographic Notice
///
/// RC2 is a legacy cipher retained only for backward compatibility with
/// older data formats (e.g., PKCS#12 password-encrypted bags). It is not
/// recommended for new deployments.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rc2 {
    /// 64-word (128-byte) expanded key schedule.
    data: [u16; RC2_SCHEDULE_LEN],
}

impl Rc2 {
    /// Construct an RC2 cipher with the given key.
    ///
    /// The effective key-bits parameter defaults to `key.len() * 8`
    /// (BSAFE/RFC 2268 convention used by most modern callers).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is outside the
    /// valid range 1–128 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        // Default effective-bits = len * 8 (BSAFE convention matching RFC 2268).
        let bits = key.len().saturating_mul(8);
        Self::new_with_effective_bits(key, bits)
    }

    /// Construct an RC2 cipher with the given key and explicit effective-bits
    /// parameter (RFC 2268 T1 parameter). `bits` is clamped to the range
    /// 1..=1024; zero selects the 1024-bit default.
    ///
    /// The working-buffer and counter variable names (`k`, `d`, `i`, `j`,
    /// `c`) mirror the key-expansion pseudocode in RFC 2268 §2 and the
    /// OpenSSL reference in `crypto/rc2/rc2_skey.c`; keeping them short
    /// preserves the direct correspondence with the specification.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is outside the
    /// valid range 1–128 bytes.
    ///
    /// # Security (cache-timing)
    ///
    /// ⚠️ **RC2 is cache-timing-vulnerable on BOTH the key-schedule path
    /// AND the encrypt/decrypt hot path. Additionally, RC2's 64-bit block
    /// size makes it vulnerable to Sweet32-style birthday attacks
    /// (CVE-2016-2183 class) — a property NOT shared with the 128-bit
    /// legacy ciphers (SEED, Camellia, ARIA, SM4) documented elsewhere in
    /// this module.**
    ///
    /// **Leakage Profile for RC2:**
    ///
    /// 1. **Key schedule (this function)** — three byte-indexed read sites
    ///    into [`RC2_KEY_TABLE`] (256 bytes ≈ 4 cache lines on a typical
    ///    64 B-line x86-64 CPU):
    ///    - **Forward expansion (~128 reads)**:
    ///      `RC2_KEY_TABLE[(k[j] + d) & 0xff]` iterated for `i` in
    ///      `len..128`. The index depends on the user key `k[..len]`
    ///      mixed with the propagating feedback byte `d`. Each access
    ///      leaks `log2(256/64) = 2` bits of the index via L1 cache-line
    ///      residency.
    ///    - **Effective-bits reduction (1 read)**:
    ///      `RC2_KEY_TABLE[k[i_red] & c]` where `c = 0xff >> ((8 - bits%8) % 8)`
    ///      is a public mask; the remaining `(bits % 8)` bits of
    ///      `k[i_red]` are still cache-observable.
    ///    - **Reverse pass (~i_red reads)**:
    ///      `RC2_KEY_TABLE[k[i+j_red] ^ d]` iterated downward; same
    ///      access pattern as forward expansion.
    ///
    /// 2. **Encrypt/decrypt MASH rounds** (see
    ///    [`Rc2::encrypt_block`](#method.encrypt_block) and
    ///    [`Rc2::decrypt_block`](#method.decrypt_block)) — four 6-bit-indexed
    ///    reads per block from `self.data[..64]` (64 × u16 = 128 bytes ≈
    ///    2 cache lines). Each MASH operation
    ///    `xi += self.data[xj & 0x3f]` indexes into the expanded key
    ///    schedule using 6 plaintext-state-derived bits. With 16 MIX
    ///    rounds + 2 MASH rounds per direction, the encrypt and decrypt
    ///    paths each perform **4 secret-indexed reads per 8-byte block**
    ///    (a total of 8 reads/block round-trip). The MASH indexing leaks
    ///    both the plaintext state (`x_j`) and the subkey pattern.
    ///
    /// **Threat Model:** A co-tenant adversary running on the same physical
    /// CPU (cloud VM, hypervisor neighbor, malicious browser tab) can mount
    /// Bernstein–Tromer–Osvik–Shamir-style cache-timing attacks against
    /// both key derivation and bulk encryption. Even an adversary
    /// observing only aggregate encryption latency can statistically
    /// recover key information given enough samples; the Sweet32 birthday
    /// bound (≈ 2³² blocks ≈ 32 GB at 64-bit blocks) compounds this risk
    /// for long-lived sessions.
    ///
    /// **Block-Size Vulnerability (Sweet32, CVE-2016-2183):** RC2's 64-bit
    /// block size means a single key approaches collision probability
    /// after ≈ 2³² blocks. Adler–Bhargavan–Leurent (2016) demonstrated
    /// practical session-cookie recovery against 3DES/Blowfish under
    /// HTTPS — both 64-bit-block ciphers. The same birthday-bound attack
    /// class applies directly to RC2.
    ///
    /// **Software Mitigations:** None implemented. RC2 has no hardware
    /// acceleration on any mainstream CPU. Bitslicing is theoretically
    /// possible but never deployed given RC2's legacy status.
    ///
    /// **Standards / Interop:** RC2 is preserved exclusively for backward
    /// compatibility with PKCS#12 password-encrypted bags (RFC 7292 §B.1)
    /// and legacy CMS/PKCS#7 messages. RFC 2268 (1998) specified RC2 with
    /// the explicit caveat that it is not recommended for new
    /// applications.
    ///
    /// **Recommendation:** Migrate to AES-GCM (RFC 5116) or
    /// ChaCha20-Poly1305 (RFC 8439) for new deployments. RC2 should be
    /// confined to read-only legacy-format compatibility paths and never
    /// used for confidentiality of long-lived secrets.
    ///
    /// **AAP §0.7.5:** Software cache-timing remediation is out of scope
    /// for this milestone; the leakage is documented here pending future
    /// hardware-accelerated or bitsliced implementations. See the
    /// module-level `Security Notice — Cache-Timing Side Channel` block
    /// for the per-cipher leakage table.
    #[allow(clippy::many_single_char_names)]
    pub fn new_with_effective_bits(key: &[u8], bits: usize) -> CryptoResult<Self> {
        let len = key.len();
        if !(RC2_MIN_KEY_LEN..=RC2_MAX_KEY_LEN).contains(&len) {
            return Err(CryptoError::Key(format!(
                "RC2 key length must be 1-128 bytes, got {len}"
            )));
        }

        // Clamp effective bits to 1..=1024; 0 means default 1024.
        let bits = if bits == 0 {
            RC2_MAX_BITS
        } else {
            bits.min(RC2_MAX_BITS)
        };

        // 128-byte working buffer; k[0..len] is the user key, k[len..128]
        // is expanded via the PI-table feedback, then reduced via the
        // effective-bits scheme, finally packed into 64 u16 words.
        let mut k = [0u8; RC2_MAX_KEY_LEN];
        k[..len].copy_from_slice(key);

        // Expand: d = k[len-1]; for i in len..128: d = T[(k[j] + d) & 0xff]; k[i] = d; j++
        // The original C uses a parallel `j` counter incremented manually;
        // we express the same access pattern via `enumerate()` so `j` is the
        // iteration index and `i` the destination offset in `k`.
        let mut d: u8 = k[len - 1];
        for (j, i) in (len..RC2_MAX_KEY_LEN).enumerate() {
            let idx = u16::from(k[j]).wrapping_add(u16::from(d)) & 0x00ff;
            // idx is masked to 0..=255, so the index fits in u8 without truncation.
            d = RC2_KEY_TABLE[idx as usize];
            k[i] = d;
        }

        // Reduce according to effective-bits:
        //   j = ceil(bits / 8); i = 128 - j; c = 0xff >> ((8 - bits%8) % 8)
        let j_red = (bits + 7) >> 3;
        let i_red = RC2_MAX_KEY_LEN - j_red;
        // In C: c = 0xff >> (-bits & 0x07). Equivalent to (8 - bits%8) % 8 in
        // unsigned arithmetic, producing 0 when bits is a multiple of 8.
        let shift = (8usize.wrapping_sub(bits % 8)) & 0x07;
        let c: u8 = 0xff_u8 >> shift;

        d = RC2_KEY_TABLE[usize::from(k[i_red] & c)];
        k[i_red] = d;

        // C pattern: while (i--) { d = T[k[i+j] ^ d]; k[i] = d; }
        // The post-decrement means the body runs for i going from (i_red - 1)
        // down to 0 inclusive.
        let mut i = i_red;
        while i > 0 {
            i -= 1;
            d = RC2_KEY_TABLE[usize::from(k[i + j_red] ^ d)];
            k[i] = d;
        }

        // Pack 128 bytes into 64 little-endian u16 words.
        let mut data = [0u16; RC2_SCHEDULE_LEN];
        for (word_idx, word) in data.iter_mut().enumerate() {
            *word = u16::from_le_bytes([k[2 * word_idx], k[2 * word_idx + 1]]);
        }

        // Zeroize working buffer; `d` and `c` are trivially forgettable
        // (local stack, single-byte, no key-dependent secrecy beyond k).
        k.zeroize();

        Ok(Self { data })
    }
}

impl SymmetricCipher for Rc2 {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, RC2_BLOCK_LEN, "RC2")?;

        // Load 4 little-endian u16 values: block[0..2]=x0, [2..4]=x1, [4..6]=x2, [6..8]=x3.
        let mut x0 = u16::from_le_bytes([block[0], block[1]]);
        let mut x1 = u16::from_le_bytes([block[2], block[3]]);
        let mut x2 = u16::from_le_bytes([block[4], block[5]]);
        let mut x3 = u16::from_le_bytes([block[6], block[7]]);

        // p_idx walks through self.data[0..64]; p1 (for MASH) is always self.data[0..64].
        let mut p_idx = 0usize;
        let mut n: u32 = 3;
        let mut i: u32 = 5;

        loop {
            // MIX round: 4 operations consuming 4 consecutive subkeys, rotating
            // left by 1, 2, 3, 5 respectively.
            //
            // C: t = (x0 + (x1 & ~x3) + (x2 & x3) + *p0++) & 0xffff; x0 = rotl(t, 1);
            // The mask `& 0xffff` is enforced by the u16 type in Rust.
            let t = x0
                .wrapping_add(x1 & !x3)
                .wrapping_add(x2 & x3)
                .wrapping_add(self.data[p_idx]);
            p_idx += 1;
            x0 = t.rotate_left(1);

            let t = x1
                .wrapping_add(x2 & !x0)
                .wrapping_add(x3 & x0)
                .wrapping_add(self.data[p_idx]);
            p_idx += 1;
            x1 = t.rotate_left(2);

            let t = x2
                .wrapping_add(x3 & !x1)
                .wrapping_add(x0 & x1)
                .wrapping_add(self.data[p_idx]);
            p_idx += 1;
            x2 = t.rotate_left(3);

            let t = x3
                .wrapping_add(x0 & !x2)
                .wrapping_add(x1 & x2)
                .wrapping_add(self.data[p_idx]);
            p_idx += 1;
            x3 = t.rotate_left(5);

            i -= 1;
            if i == 0 {
                n -= 1;
                if n == 0 {
                    break;
                }
                i = if n == 2 { 6 } else { 5 };

                // MASH round: each xi += p1[xj & 0x3f] where j follows the cyclic
                // rotation (3 -> 0, 0 -> 1, 1 -> 2, 2 -> 3).
                x0 = x0.wrapping_add(self.data[usize::from(x3 & 0x003f)]);
                x1 = x1.wrapping_add(self.data[usize::from(x0 & 0x003f)]);
                x2 = x2.wrapping_add(self.data[usize::from(x1 & 0x003f)]);
                x3 = x3.wrapping_add(self.data[usize::from(x2 & 0x003f)]);
            }
        }

        // Store little-endian.
        block[0..2].copy_from_slice(&x0.to_le_bytes());
        block[2..4].copy_from_slice(&x1.to_le_bytes());
        block[4..6].copy_from_slice(&x2.to_le_bytes());
        block[6..8].copy_from_slice(&x3.to_le_bytes());
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, RC2_BLOCK_LEN, "RC2")?;

        let mut x0 = u16::from_le_bytes([block[0], block[1]]);
        let mut x1 = u16::from_le_bytes([block[2], block[3]]);
        let mut x2 = u16::from_le_bytes([block[4], block[5]]);
        let mut x3 = u16::from_le_bytes([block[6], block[7]]);

        // Decryption walks subkeys backwards from self.data[63] downward.
        let mut p_idx: usize = RC2_SCHEDULE_LEN - 1;
        let mut n: u32 = 3;
        let mut i: u32 = 5;

        loop {
            // REV-MIX: reverse-rotate (rotate_left(16-s) == rotate_right(s)) then subtract.
            // C: t = rotl(x3, 11); x3 = (t - (x0 & ~x2) - (x1 & x2) - *p0--) & 0xffff;
            let t = x3.rotate_left(11);
            x3 = t
                .wrapping_sub(x0 & !x2)
                .wrapping_sub(x1 & x2)
                .wrapping_sub(self.data[p_idx]);
            p_idx = p_idx.wrapping_sub(1);

            let t = x2.rotate_left(13);
            x2 = t
                .wrapping_sub(x3 & !x1)
                .wrapping_sub(x0 & x1)
                .wrapping_sub(self.data[p_idx]);
            p_idx = p_idx.wrapping_sub(1);

            let t = x1.rotate_left(14);
            x1 = t
                .wrapping_sub(x2 & !x0)
                .wrapping_sub(x3 & x0)
                .wrapping_sub(self.data[p_idx]);
            p_idx = p_idx.wrapping_sub(1);

            let t = x0.rotate_left(15);
            x0 = t
                .wrapping_sub(x1 & !x3)
                .wrapping_sub(x2 & x3)
                .wrapping_sub(self.data[p_idx]);
            // After the final MIX of the final iteration, p_idx underflows
            // via wrapping_sub; that is harmless because we exit the loop
            // before using p_idx again.
            p_idx = p_idx.wrapping_sub(1);

            i -= 1;
            if i == 0 {
                n -= 1;
                if n == 0 {
                    break;
                }
                i = if n == 2 { 6 } else { 5 };

                // REV-MASH: undo the encryption MASH (order reversed).
                x3 = x3.wrapping_sub(self.data[usize::from(x2 & 0x003f)]);
                x2 = x2.wrapping_sub(self.data[usize::from(x1 & 0x003f)]);
                x1 = x1.wrapping_sub(self.data[usize::from(x0 & 0x003f)]);
                x0 = x0.wrapping_sub(self.data[usize::from(x3 & 0x003f)]);
            }
        }

        block[0..2].copy_from_slice(&x0.to_le_bytes());
        block[2..4].copy_from_slice(&x1.to_le_bytes());
        block[4..6].copy_from_slice(&x2.to_le_bytes());
        block[6..8].copy_from_slice(&x3.to_le_bytes());
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Rc2
    }
}

// -----------------------------------------------------------------------------
// RC5 (RSA Data Security, RFC 2040)
// -----------------------------------------------------------------------------

/// RC5 block size: 8 bytes (64 bits, two 32-bit halves).
const RC5_BLOCK_LEN: usize = 8;
/// RC5 minimum key length: 1 byte.
const RC5_MIN_KEY_LEN: usize = 1;
/// RC5 maximum key length: 255 bytes.
const RC5_MAX_KEY_LEN: usize = 255;
/// RC5 subkey schedule length: 2*(16+1) = 34 u32 words (for max 16 rounds).
const RC5_SCHEDULE_LEN: usize = 34;
/// RC5 key loader maximum length: ceil(255/4) = 64 u32 words.
const RC5_L_BUF_LEN: usize = 64;
/// RC5 default rounds (also maximum): 16 rounds (matches OpenSSL `RC5_16_ROUNDS`).
const RC5_DEFAULT_ROUNDS: u32 = 16;
/// RC5 magic constant P = Odd((e - 2) * 2^32) where e is Euler's number.
const RC5_P: u32 = 0xb7e1_5163;
/// RC5 magic constant Q = Odd((phi - 1) * 2^32) where phi is the golden ratio.
const RC5_Q: u32 = 0x9e37_79b9;

/// RC5-32 block cipher (64-bit block, 8/12/16 rounds, 1–255 byte key).
///
/// Implements the RC5-32/r/b variant (word size 32 bits, r rounds, b key bytes).
/// Data-dependent rotations are the distinguishing cryptographic feature.
/// Translates C `RC5_32_KEY` and `RC5_32_encrypt` / `RC5_32_decrypt` from
/// `crypto/rc5/rc5_skey.c` and `crypto/rc5/rc5_enc.c`.
///
/// # Cryptographic Notice
///
/// RC5 is retained for backward compatibility. Newer deployments should prefer
/// AES-GCM or ChaCha20-Poly1305. RC5-32/12/16 with short keys is vulnerable
/// to differential cryptanalysis; prefer 16 rounds for security-sensitive use.
///
/// # Example
///
/// ```ignore
/// use openssl_crypto::symmetric::legacy::Rc5;
/// use openssl_crypto::symmetric::SymmetricCipher;
///
/// let key = b"sixteen-byte-key";
/// let cipher = Rc5::new(key).expect("RC5 key");
/// let mut block = [0u8; 8];
/// cipher.encrypt_block(&mut block).unwrap();
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rc5 {
    /// Expanded subkey schedule: 2*(rounds+1) u32 words (max 34 for 16 rounds).
    data: [u32; RC5_SCHEDULE_LEN],
    /// Number of rounds: 8, 12, or 16.
    rounds: u32,
}

impl Rc5 {
    /// Creates a new RC5 cipher context with the default 16 rounds.
    ///
    /// The key may be 1 to 255 bytes. Key scheduling is as specified in
    /// `RC5_32_set_key()` from `crypto/rc5/rc5_skey.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key.len()` is not in `1..=255`.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        Self::new_with_rounds(key, RC5_DEFAULT_ROUNDS)
    }

    /// Creates a new RC5 cipher context with an explicit round count.
    ///
    /// # Parameters
    ///
    /// - `key`: 1 to 255 bytes of key material.
    /// - `rounds`: must be 8, 12, or 16 (matching `RC5_8_ROUNDS`,
    ///   `RC5_12_ROUNDS`, `RC5_16_ROUNDS` from `include/openssl/rc5.h`).
    ///
    /// The local-variable names (`t`, `c`, `a`, `b`, `m`) mirror the RC5
    /// key-schedule pseudocode in RFC 2040 §4.3 and RFC 2040 §4.4 and the
    /// OpenSSL reference in `crypto/rc5/rc5_skey.c`; keeping them short
    /// preserves the direct correspondence with the specification.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key.len()` is not in `1..=255` or
    /// if `rounds` is not one of 8, 12, 16.
    #[allow(clippy::many_single_char_names)]
    pub fn new_with_rounds(key: &[u8], rounds: u32) -> CryptoResult<Self> {
        if key.len() < RC5_MIN_KEY_LEN || key.len() > RC5_MAX_KEY_LEN {
            return Err(CryptoError::Key(format!(
                "RC5 key length must be {RC5_MIN_KEY_LEN}..={RC5_MAX_KEY_LEN}, got {}",
                key.len()
            )));
        }
        if rounds != 8 && rounds != 12 && rounds != 16 {
            return Err(CryptoError::Key(format!(
                "RC5 rounds must be 8, 12, or 16, got {rounds}"
            )));
        }

        // `t` = number of active subkey words = 2*(rounds+1)
        // For rounds=8: 18; rounds=12: 26; rounds=16: 34.
        let t: usize = ((rounds as usize) + 1) * 2;
        let len = key.len();
        // `c` = number of u32 words needed to hold the user key = ceil(len/4).
        let c: usize = (len + 3) / 4;

        // Load key bytes into L[] as little-endian u32 words. Matches the
        // c2l / c2ln macros from rc5_local.h. Unused bytes are zero.
        let mut l_buf = [0u32; RC5_L_BUF_LEN];
        let n_full = len / 4;
        for i in 0..n_full {
            l_buf[i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let partial = len - n_full * 4;
        if partial > 0 {
            let mut last = [0u8; 4];
            last[..partial].copy_from_slice(&key[n_full * 4..n_full * 4 + partial]);
            l_buf[n_full] = u32::from_le_bytes(last);
        }

        // Initialize the subkey schedule S[0..t] with the magic constants.
        // S[0] = P; S[i] = S[i-1] + Q (mod 2^32) for 0 < i < t.
        let mut data = [0u32; RC5_SCHEDULE_LEN];
        data[0] = RC5_P;
        for i in 1..t {
            data[i] = data[i - 1].wrapping_add(RC5_Q);
        }

        // Mixing loop: 3 * max(t, c) iterations.
        let mix = t.max(c) * 3;
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        let mut ii: usize = 0;
        let mut jj: usize = 0;
        for _ in 0..mix {
            // A = S[ii] = ROTL((S[ii] + A + B), 3)
            let k1 = data[ii].wrapping_add(a).wrapping_add(b);
            let s_ii = k1.rotate_left(3);
            data[ii] = s_ii;
            a = s_ii;

            // B = L[jj] = ROTL((L[jj] + A + B), (A + B))
            // The C code uses `m = (int)(A + B)` and the x86 `rol` instruction
            // consumes only the low 5 bits of cl, which exactly matches Rust's
            // rotate_left semantics (implicitly masks `n % 32`).
            let m = a.wrapping_add(b);
            let k2 = l_buf[jj].wrapping_add(a).wrapping_add(b);
            let l_jj = k2.rotate_left(m);
            l_buf[jj] = l_jj;
            b = l_jj;

            ii = if ii + 1 >= t { 0 } else { ii + 1 };
            jj = if jj + 1 >= c { 0 } else { jj + 1 };
        }

        // Zeroize the temporary key-buffer.
        l_buf.zeroize();

        Ok(Self { data, rounds })
    }
}

impl SymmetricCipher for Rc5 {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    /// Encrypts one 8-byte block in place.
    ///
    /// Implements the loop-unrolled encryption from `RC5_32_encrypt()` in
    /// `crypto/rc5/rc5_enc.c`:
    ///
    /// ```text
    /// A = d[0] + S[0];
    /// B = d[1] + S[1];
    /// for i in 1..=rounds:
    ///     A = ((A ^ B) <<< B) + S[2*i]
    ///     B = ((B ^ A) <<< A) + S[2*i + 1]
    /// ```
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, RC5_BLOCK_LEN, "RC5")?;

        let s = &self.data;
        let mut a = u32::from_le_bytes([block[0], block[1], block[2], block[3]]).wrapping_add(s[0]);
        let mut b = u32::from_le_bytes([block[4], block[5], block[6], block[7]]).wrapping_add(s[1]);

        // E_RC5_32 macro expansion, r iterations.
        // Rust's rotate_left implicitly masks `n % 32`, matching the C code's
        // data-dependent rotation semantics exactly.
        let rounds_usize = self.rounds as usize;
        for r in 1..=rounds_usize {
            let n = 2 * r;
            a ^= b;
            a = a.rotate_left(b);
            a = a.wrapping_add(s[n]);
            b ^= a;
            b = b.rotate_left(a);
            b = b.wrapping_add(s[n + 1]);
        }

        block[0..4].copy_from_slice(&a.to_le_bytes());
        block[4..8].copy_from_slice(&b.to_le_bytes());
        Ok(())
    }

    /// Decrypts one 8-byte block in place.
    ///
    /// Inverse of [`Self::encrypt_block`], matching `RC5_32_decrypt()` from
    /// `crypto/rc5/rc5_enc.c`:
    ///
    /// ```text
    /// A = d[0]; B = d[1];
    /// for i in (1..=rounds).rev():
    ///     B = ((B - S[2*i+1]) >>> A) ^ A
    ///     A = ((A - S[2*i]) >>> B) ^ B
    /// d[0] = A - S[0]; d[1] = B - S[1];
    /// ```
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, RC5_BLOCK_LEN, "RC5")?;

        let s = &self.data;
        let mut a = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let mut b = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);

        let rounds_usize = self.rounds as usize;
        for r in (1..=rounds_usize).rev() {
            let n = 2 * r;
            b = b.wrapping_sub(s[n + 1]);
            b = b.rotate_right(a);
            b ^= a;
            a = a.wrapping_sub(s[n]);
            a = a.rotate_right(b);
            a ^= b;
        }

        a = a.wrapping_sub(s[0]);
        b = b.wrapping_sub(s[1]);

        block[0..4].copy_from_slice(&a.to_le_bytes());
        block[4..8].copy_from_slice(&b.to_le_bytes());
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Rc5
    }
}

// =============================================================================
// Camellia — 128-bit block cipher (128/192/256-bit keys)
// =============================================================================
//
// Translated from `crypto/camellia/camellia.c`, `crypto/camellia/cmll_misc.c`,
// and `crypto/camellia/cmll_local.h`.
//
// Camellia is a 128-bit block cipher supporting 128-, 192-, and 256-bit keys.
// Designed jointly by NTT and Mitsubishi Electric, specified in RFC 3713. The
// structure is an 18-round (for 128-bit keys, `grandRounds = 3`) or 24-round
// (for 192/256-bit keys, `grandRounds = 4`) Feistel network with FL/FL^-1
// diffusion layers inserted every 6 rounds.
//
// The byte order is big-endian throughout (matching the OpenSSL GETU32/PUTU32
// macros). The S-boxes below are identical u32 tables derived from the
// specification.
//
// Algorithm specification:
// http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html

/// Camellia block length (128 bits = 16 bytes).
const CAMELLIA_BLOCK_LEN: usize = 16;
/// Number of `u32` words in the Camellia key schedule (`CAMELLIA_TABLE_BYTE_LEN / 4`).
const CAMELLIA_SCHEDULE_LEN: usize = 68;

/// Camellia key-schedule Σ (SIGMA) constants derived from the fractional part of √2
/// (see RFC 3713 §2.4.1). 12 `u32` words arranged as six 64-bit constants.
static CAMELLIA_SIGMA: [u32; 12] = [
    0xa09e_667f,
    0x3bcc_908b,
    0xb67a_e858,
    0x4caa_73b2,
    0xc6ef_372f,
    0xe94f_82be,
    0x54ff_53a5,
    0xf1d3_6f1c,
    0x10e5_27fa,
    0xde68_2d1d,
    0xb056_88c2,
    0xb3e6_c1fd,
];

static SBOX1_1110: [u32; 256] = [
    0x7070_7000,
    0x8282_8200,
    0x2c2c_2c00,
    0xecec_ec00,
    0xb3b3_b300,
    0x2727_2700,
    0xc0c0_c000,
    0xe5e5_e500,
    0xe4e4_e400,
    0x8585_8500,
    0x5757_5700,
    0x3535_3500,
    0xeaea_ea00,
    0x0c0c_0c00,
    0xaeae_ae00,
    0x4141_4100,
    0x2323_2300,
    0xefef_ef00,
    0x6b6b_6b00,
    0x9393_9300,
    0x4545_4500,
    0x1919_1900,
    0xa5a5_a500,
    0x2121_2100,
    0xeded_ed00,
    0x0e0e_0e00,
    0x4f4f_4f00,
    0x4e4e_4e00,
    0x1d1d_1d00,
    0x6565_6500,
    0x9292_9200,
    0xbdbd_bd00,
    0x8686_8600,
    0xb8b8_b800,
    0xafaf_af00,
    0x8f8f_8f00,
    0x7c7c_7c00,
    0xebeb_eb00,
    0x1f1f_1f00,
    0xcece_ce00,
    0x3e3e_3e00,
    0x3030_3000,
    0xdcdc_dc00,
    0x5f5f_5f00,
    0x5e5e_5e00,
    0xc5c5_c500,
    0x0b0b_0b00,
    0x1a1a_1a00,
    0xa6a6_a600,
    0xe1e1_e100,
    0x3939_3900,
    0xcaca_ca00,
    0xd5d5_d500,
    0x4747_4700,
    0x5d5d_5d00,
    0x3d3d_3d00,
    0xd9d9_d900,
    0x0101_0100,
    0x5a5a_5a00,
    0xd6d6_d600,
    0x5151_5100,
    0x5656_5600,
    0x6c6c_6c00,
    0x4d4d_4d00,
    0x8b8b_8b00,
    0x0d0d_0d00,
    0x9a9a_9a00,
    0x6666_6600,
    0xfbfb_fb00,
    0xcccc_cc00,
    0xb0b0_b000,
    0x2d2d_2d00,
    0x7474_7400,
    0x1212_1200,
    0x2b2b_2b00,
    0x2020_2000,
    0xf0f0_f000,
    0xb1b1_b100,
    0x8484_8400,
    0x9999_9900,
    0xdfdf_df00,
    0x4c4c_4c00,
    0xcbcb_cb00,
    0xc2c2_c200,
    0x3434_3400,
    0x7e7e_7e00,
    0x7676_7600,
    0x0505_0500,
    0x6d6d_6d00,
    0xb7b7_b700,
    0xa9a9_a900,
    0x3131_3100,
    0xd1d1_d100,
    0x1717_1700,
    0x0404_0400,
    0xd7d7_d700,
    0x1414_1400,
    0x5858_5800,
    0x3a3a_3a00,
    0x6161_6100,
    0xdede_de00,
    0x1b1b_1b00,
    0x1111_1100,
    0x1c1c_1c00,
    0x3232_3200,
    0x0f0f_0f00,
    0x9c9c_9c00,
    0x1616_1600,
    0x5353_5300,
    0x1818_1800,
    0xf2f2_f200,
    0x2222_2200,
    0xfefe_fe00,
    0x4444_4400,
    0xcfcf_cf00,
    0xb2b2_b200,
    0xc3c3_c300,
    0xb5b5_b500,
    0x7a7a_7a00,
    0x9191_9100,
    0x2424_2400,
    0x0808_0800,
    0xe8e8_e800,
    0xa8a8_a800,
    0x6060_6000,
    0xfcfc_fc00,
    0x6969_6900,
    0x5050_5000,
    0xaaaa_aa00,
    0xd0d0_d000,
    0xa0a0_a000,
    0x7d7d_7d00,
    0xa1a1_a100,
    0x8989_8900,
    0x6262_6200,
    0x9797_9700,
    0x5454_5400,
    0x5b5b_5b00,
    0x1e1e_1e00,
    0x9595_9500,
    0xe0e0_e000,
    0xffff_ff00,
    0x6464_6400,
    0xd2d2_d200,
    0x1010_1000,
    0xc4c4_c400,
    0x0000_0000,
    0x4848_4800,
    0xa3a3_a300,
    0xf7f7_f700,
    0x7575_7500,
    0xdbdb_db00,
    0x8a8a_8a00,
    0x0303_0300,
    0xe6e6_e600,
    0xdada_da00,
    0x0909_0900,
    0x3f3f_3f00,
    0xdddd_dd00,
    0x9494_9400,
    0x8787_8700,
    0x5c5c_5c00,
    0x8383_8300,
    0x0202_0200,
    0xcdcd_cd00,
    0x4a4a_4a00,
    0x9090_9000,
    0x3333_3300,
    0x7373_7300,
    0x6767_6700,
    0xf6f6_f600,
    0xf3f3_f300,
    0x9d9d_9d00,
    0x7f7f_7f00,
    0xbfbf_bf00,
    0xe2e2_e200,
    0x5252_5200,
    0x9b9b_9b00,
    0xd8d8_d800,
    0x2626_2600,
    0xc8c8_c800,
    0x3737_3700,
    0xc6c6_c600,
    0x3b3b_3b00,
    0x8181_8100,
    0x9696_9600,
    0x6f6f_6f00,
    0x4b4b_4b00,
    0x1313_1300,
    0xbebe_be00,
    0x6363_6300,
    0x2e2e_2e00,
    0xe9e9_e900,
    0x7979_7900,
    0xa7a7_a700,
    0x8c8c_8c00,
    0x9f9f_9f00,
    0x6e6e_6e00,
    0xbcbc_bc00,
    0x8e8e_8e00,
    0x2929_2900,
    0xf5f5_f500,
    0xf9f9_f900,
    0xb6b6_b600,
    0x2f2f_2f00,
    0xfdfd_fd00,
    0xb4b4_b400,
    0x5959_5900,
    0x7878_7800,
    0x9898_9800,
    0x0606_0600,
    0x6a6a_6a00,
    0xe7e7_e700,
    0x4646_4600,
    0x7171_7100,
    0xbaba_ba00,
    0xd4d4_d400,
    0x2525_2500,
    0xabab_ab00,
    0x4242_4200,
    0x8888_8800,
    0xa2a2_a200,
    0x8d8d_8d00,
    0xfafa_fa00,
    0x7272_7200,
    0x0707_0700,
    0xb9b9_b900,
    0x5555_5500,
    0xf8f8_f800,
    0xeeee_ee00,
    0xacac_ac00,
    0x0a0a_0a00,
    0x3636_3600,
    0x4949_4900,
    0x2a2a_2a00,
    0x6868_6800,
    0x3c3c_3c00,
    0x3838_3800,
    0xf1f1_f100,
    0xa4a4_a400,
    0x4040_4000,
    0x2828_2800,
    0xd3d3_d300,
    0x7b7b_7b00,
    0xbbbb_bb00,
    0xc9c9_c900,
    0x4343_4300,
    0xc1c1_c100,
    0x1515_1500,
    0xe3e3_e300,
    0xadad_ad00,
    0xf4f4_f400,
    0x7777_7700,
    0xc7c7_c700,
    0x8080_8000,
    0x9e9e_9e00,
];

static SBOX4_4404: [u32; 256] = [
    0x7070_0070,
    0x2c2c_002c,
    0xb3b3_00b3,
    0xc0c0_00c0,
    0xe4e4_00e4,
    0x5757_0057,
    0xeaea_00ea,
    0xaeae_00ae,
    0x2323_0023,
    0x6b6b_006b,
    0x4545_0045,
    0xa5a5_00a5,
    0xeded_00ed,
    0x4f4f_004f,
    0x1d1d_001d,
    0x9292_0092,
    0x8686_0086,
    0xafaf_00af,
    0x7c7c_007c,
    0x1f1f_001f,
    0x3e3e_003e,
    0xdcdc_00dc,
    0x5e5e_005e,
    0x0b0b_000b,
    0xa6a6_00a6,
    0x3939_0039,
    0xd5d5_00d5,
    0x5d5d_005d,
    0xd9d9_00d9,
    0x5a5a_005a,
    0x5151_0051,
    0x6c6c_006c,
    0x8b8b_008b,
    0x9a9a_009a,
    0xfbfb_00fb,
    0xb0b0_00b0,
    0x7474_0074,
    0x2b2b_002b,
    0xf0f0_00f0,
    0x8484_0084,
    0xdfdf_00df,
    0xcbcb_00cb,
    0x3434_0034,
    0x7676_0076,
    0x6d6d_006d,
    0xa9a9_00a9,
    0xd1d1_00d1,
    0x0404_0004,
    0x1414_0014,
    0x3a3a_003a,
    0xdede_00de,
    0x1111_0011,
    0x3232_0032,
    0x9c9c_009c,
    0x5353_0053,
    0xf2f2_00f2,
    0xfefe_00fe,
    0xcfcf_00cf,
    0xc3c3_00c3,
    0x7a7a_007a,
    0x2424_0024,
    0xe8e8_00e8,
    0x6060_0060,
    0x6969_0069,
    0xaaaa_00aa,
    0xa0a0_00a0,
    0xa1a1_00a1,
    0x6262_0062,
    0x5454_0054,
    0x1e1e_001e,
    0xe0e0_00e0,
    0x6464_0064,
    0x1010_0010,
    0x0000_0000,
    0xa3a3_00a3,
    0x7575_0075,
    0x8a8a_008a,
    0xe6e6_00e6,
    0x0909_0009,
    0xdddd_00dd,
    0x8787_0087,
    0x8383_0083,
    0xcdcd_00cd,
    0x9090_0090,
    0x7373_0073,
    0xf6f6_00f6,
    0x9d9d_009d,
    0xbfbf_00bf,
    0x5252_0052,
    0xd8d8_00d8,
    0xc8c8_00c8,
    0xc6c6_00c6,
    0x8181_0081,
    0x6f6f_006f,
    0x1313_0013,
    0x6363_0063,
    0xe9e9_00e9,
    0xa7a7_00a7,
    0x9f9f_009f,
    0xbcbc_00bc,
    0x2929_0029,
    0xf9f9_00f9,
    0x2f2f_002f,
    0xb4b4_00b4,
    0x7878_0078,
    0x0606_0006,
    0xe7e7_00e7,
    0x7171_0071,
    0xd4d4_00d4,
    0xabab_00ab,
    0x8888_0088,
    0x8d8d_008d,
    0x7272_0072,
    0xb9b9_00b9,
    0xf8f8_00f8,
    0xacac_00ac,
    0x3636_0036,
    0x2a2a_002a,
    0x3c3c_003c,
    0xf1f1_00f1,
    0x4040_0040,
    0xd3d3_00d3,
    0xbbbb_00bb,
    0x4343_0043,
    0x1515_0015,
    0xadad_00ad,
    0x7777_0077,
    0x8080_0080,
    0x8282_0082,
    0xecec_00ec,
    0x2727_0027,
    0xe5e5_00e5,
    0x8585_0085,
    0x3535_0035,
    0x0c0c_000c,
    0x4141_0041,
    0xefef_00ef,
    0x9393_0093,
    0x1919_0019,
    0x2121_0021,
    0x0e0e_000e,
    0x4e4e_004e,
    0x6565_0065,
    0xbdbd_00bd,
    0xb8b8_00b8,
    0x8f8f_008f,
    0xebeb_00eb,
    0xcece_00ce,
    0x3030_0030,
    0x5f5f_005f,
    0xc5c5_00c5,
    0x1a1a_001a,
    0xe1e1_00e1,
    0xcaca_00ca,
    0x4747_0047,
    0x3d3d_003d,
    0x0101_0001,
    0xd6d6_00d6,
    0x5656_0056,
    0x4d4d_004d,
    0x0d0d_000d,
    0x6666_0066,
    0xcccc_00cc,
    0x2d2d_002d,
    0x1212_0012,
    0x2020_0020,
    0xb1b1_00b1,
    0x9999_0099,
    0x4c4c_004c,
    0xc2c2_00c2,
    0x7e7e_007e,
    0x0505_0005,
    0xb7b7_00b7,
    0x3131_0031,
    0x1717_0017,
    0xd7d7_00d7,
    0x5858_0058,
    0x6161_0061,
    0x1b1b_001b,
    0x1c1c_001c,
    0x0f0f_000f,
    0x1616_0016,
    0x1818_0018,
    0x2222_0022,
    0x4444_0044,
    0xb2b2_00b2,
    0xb5b5_00b5,
    0x9191_0091,
    0x0808_0008,
    0xa8a8_00a8,
    0xfcfc_00fc,
    0x5050_0050,
    0xd0d0_00d0,
    0x7d7d_007d,
    0x8989_0089,
    0x9797_0097,
    0x5b5b_005b,
    0x9595_0095,
    0xffff_00ff,
    0xd2d2_00d2,
    0xc4c4_00c4,
    0x4848_0048,
    0xf7f7_00f7,
    0xdbdb_00db,
    0x0303_0003,
    0xdada_00da,
    0x3f3f_003f,
    0x9494_0094,
    0x5c5c_005c,
    0x0202_0002,
    0x4a4a_004a,
    0x3333_0033,
    0x6767_0067,
    0xf3f3_00f3,
    0x7f7f_007f,
    0xe2e2_00e2,
    0x9b9b_009b,
    0x2626_0026,
    0x3737_0037,
    0x3b3b_003b,
    0x9696_0096,
    0x4b4b_004b,
    0xbebe_00be,
    0x2e2e_002e,
    0x7979_0079,
    0x8c8c_008c,
    0x6e6e_006e,
    0x8e8e_008e,
    0xf5f5_00f5,
    0xb6b6_00b6,
    0xfdfd_00fd,
    0x5959_0059,
    0x9898_0098,
    0x6a6a_006a,
    0x4646_0046,
    0xbaba_00ba,
    0x2525_0025,
    0x4242_0042,
    0xa2a2_00a2,
    0xfafa_00fa,
    0x0707_0007,
    0x5555_0055,
    0xeeee_00ee,
    0x0a0a_000a,
    0x4949_0049,
    0x6868_0068,
    0x3838_0038,
    0xa4a4_00a4,
    0x2828_0028,
    0x7b7b_007b,
    0xc9c9_00c9,
    0xc1c1_00c1,
    0xe3e3_00e3,
    0xf4f4_00f4,
    0xc7c7_00c7,
    0x9e9e_009e,
];

static SBOX2_0222: [u32; 256] = [
    0x00e0_e0e0,
    0x0005_0505,
    0x0058_5858,
    0x00d9_d9d9,
    0x0067_6767,
    0x004e_4e4e,
    0x0081_8181,
    0x00cb_cbcb,
    0x00c9_c9c9,
    0x000b_0b0b,
    0x00ae_aeae,
    0x006a_6a6a,
    0x00d5_d5d5,
    0x0018_1818,
    0x005d_5d5d,
    0x0082_8282,
    0x0046_4646,
    0x00df_dfdf,
    0x00d6_d6d6,
    0x0027_2727,
    0x008a_8a8a,
    0x0032_3232,
    0x004b_4b4b,
    0x0042_4242,
    0x00db_dbdb,
    0x001c_1c1c,
    0x009e_9e9e,
    0x009c_9c9c,
    0x003a_3a3a,
    0x00ca_caca,
    0x0025_2525,
    0x007b_7b7b,
    0x000d_0d0d,
    0x0071_7171,
    0x005f_5f5f,
    0x001f_1f1f,
    0x00f8_f8f8,
    0x00d7_d7d7,
    0x003e_3e3e,
    0x009d_9d9d,
    0x007c_7c7c,
    0x0060_6060,
    0x00b9_b9b9,
    0x00be_bebe,
    0x00bc_bcbc,
    0x008b_8b8b,
    0x0016_1616,
    0x0034_3434,
    0x004d_4d4d,
    0x00c3_c3c3,
    0x0072_7272,
    0x0095_9595,
    0x00ab_abab,
    0x008e_8e8e,
    0x00ba_baba,
    0x007a_7a7a,
    0x00b3_b3b3,
    0x0002_0202,
    0x00b4_b4b4,
    0x00ad_adad,
    0x00a2_a2a2,
    0x00ac_acac,
    0x00d8_d8d8,
    0x009a_9a9a,
    0x0017_1717,
    0x001a_1a1a,
    0x0035_3535,
    0x00cc_cccc,
    0x00f7_f7f7,
    0x0099_9999,
    0x0061_6161,
    0x005a_5a5a,
    0x00e8_e8e8,
    0x0024_2424,
    0x0056_5656,
    0x0040_4040,
    0x00e1_e1e1,
    0x0063_6363,
    0x0009_0909,
    0x0033_3333,
    0x00bf_bfbf,
    0x0098_9898,
    0x0097_9797,
    0x0085_8585,
    0x0068_6868,
    0x00fc_fcfc,
    0x00ec_ecec,
    0x000a_0a0a,
    0x00da_dada,
    0x006f_6f6f,
    0x0053_5353,
    0x0062_6262,
    0x00a3_a3a3,
    0x002e_2e2e,
    0x0008_0808,
    0x00af_afaf,
    0x0028_2828,
    0x00b0_b0b0,
    0x0074_7474,
    0x00c2_c2c2,
    0x00bd_bdbd,
    0x0036_3636,
    0x0022_2222,
    0x0038_3838,
    0x0064_6464,
    0x001e_1e1e,
    0x0039_3939,
    0x002c_2c2c,
    0x00a6_a6a6,
    0x0030_3030,
    0x00e5_e5e5,
    0x0044_4444,
    0x00fd_fdfd,
    0x0088_8888,
    0x009f_9f9f,
    0x0065_6565,
    0x0087_8787,
    0x006b_6b6b,
    0x00f4_f4f4,
    0x0023_2323,
    0x0048_4848,
    0x0010_1010,
    0x00d1_d1d1,
    0x0051_5151,
    0x00c0_c0c0,
    0x00f9_f9f9,
    0x00d2_d2d2,
    0x00a0_a0a0,
    0x0055_5555,
    0x00a1_a1a1,
    0x0041_4141,
    0x00fa_fafa,
    0x0043_4343,
    0x0013_1313,
    0x00c4_c4c4,
    0x002f_2f2f,
    0x00a8_a8a8,
    0x00b6_b6b6,
    0x003c_3c3c,
    0x002b_2b2b,
    0x00c1_c1c1,
    0x00ff_ffff,
    0x00c8_c8c8,
    0x00a5_a5a5,
    0x0020_2020,
    0x0089_8989,
    0x0000_0000,
    0x0090_9090,
    0x0047_4747,
    0x00ef_efef,
    0x00ea_eaea,
    0x00b7_b7b7,
    0x0015_1515,
    0x0006_0606,
    0x00cd_cdcd,
    0x00b5_b5b5,
    0x0012_1212,
    0x007e_7e7e,
    0x00bb_bbbb,
    0x0029_2929,
    0x000f_0f0f,
    0x00b8_b8b8,
    0x0007_0707,
    0x0004_0404,
    0x009b_9b9b,
    0x0094_9494,
    0x0021_2121,
    0x0066_6666,
    0x00e6_e6e6,
    0x00ce_cece,
    0x00ed_eded,
    0x00e7_e7e7,
    0x003b_3b3b,
    0x00fe_fefe,
    0x007f_7f7f,
    0x00c5_c5c5,
    0x00a4_a4a4,
    0x0037_3737,
    0x00b1_b1b1,
    0x004c_4c4c,
    0x0091_9191,
    0x006e_6e6e,
    0x008d_8d8d,
    0x0076_7676,
    0x0003_0303,
    0x002d_2d2d,
    0x00de_dede,
    0x0096_9696,
    0x0026_2626,
    0x007d_7d7d,
    0x00c6_c6c6,
    0x005c_5c5c,
    0x00d3_d3d3,
    0x00f2_f2f2,
    0x004f_4f4f,
    0x0019_1919,
    0x003f_3f3f,
    0x00dc_dcdc,
    0x0079_7979,
    0x001d_1d1d,
    0x0052_5252,
    0x00eb_ebeb,
    0x00f3_f3f3,
    0x006d_6d6d,
    0x005e_5e5e,
    0x00fb_fbfb,
    0x0069_6969,
    0x00b2_b2b2,
    0x00f0_f0f0,
    0x0031_3131,
    0x000c_0c0c,
    0x00d4_d4d4,
    0x00cf_cfcf,
    0x008c_8c8c,
    0x00e2_e2e2,
    0x0075_7575,
    0x00a9_a9a9,
    0x004a_4a4a,
    0x0057_5757,
    0x0084_8484,
    0x0011_1111,
    0x0045_4545,
    0x001b_1b1b,
    0x00f5_f5f5,
    0x00e4_e4e4,
    0x000e_0e0e,
    0x0073_7373,
    0x00aa_aaaa,
    0x00f1_f1f1,
    0x00dd_dddd,
    0x0059_5959,
    0x0014_1414,
    0x006c_6c6c,
    0x0092_9292,
    0x0054_5454,
    0x00d0_d0d0,
    0x0078_7878,
    0x0070_7070,
    0x00e3_e3e3,
    0x0049_4949,
    0x0080_8080,
    0x0050_5050,
    0x00a7_a7a7,
    0x00f6_f6f6,
    0x0077_7777,
    0x0093_9393,
    0x0086_8686,
    0x0083_8383,
    0x002a_2a2a,
    0x00c7_c7c7,
    0x005b_5b5b,
    0x00e9_e9e9,
    0x00ee_eeee,
    0x008f_8f8f,
    0x0001_0101,
    0x003d_3d3d,
];

static SBOX3_3033: [u32; 256] = [
    0x3800_3838,
    0x4100_4141,
    0x1600_1616,
    0x7600_7676,
    0xd900_d9d9,
    0x9300_9393,
    0x6000_6060,
    0xf200_f2f2,
    0x7200_7272,
    0xc200_c2c2,
    0xab00_abab,
    0x9a00_9a9a,
    0x7500_7575,
    0x0600_0606,
    0x5700_5757,
    0xa000_a0a0,
    0x9100_9191,
    0xf700_f7f7,
    0xb500_b5b5,
    0xc900_c9c9,
    0xa200_a2a2,
    0x8c00_8c8c,
    0xd200_d2d2,
    0x9000_9090,
    0xf600_f6f6,
    0x0700_0707,
    0xa700_a7a7,
    0x2700_2727,
    0x8e00_8e8e,
    0xb200_b2b2,
    0x4900_4949,
    0xde00_dede,
    0x4300_4343,
    0x5c00_5c5c,
    0xd700_d7d7,
    0xc700_c7c7,
    0x3e00_3e3e,
    0xf500_f5f5,
    0x8f00_8f8f,
    0x6700_6767,
    0x1f00_1f1f,
    0x1800_1818,
    0x6e00_6e6e,
    0xaf00_afaf,
    0x2f00_2f2f,
    0xe200_e2e2,
    0x8500_8585,
    0x0d00_0d0d,
    0x5300_5353,
    0xf000_f0f0,
    0x9c00_9c9c,
    0x6500_6565,
    0xea00_eaea,
    0xa300_a3a3,
    0xae00_aeae,
    0x9e00_9e9e,
    0xec00_ecec,
    0x8000_8080,
    0x2d00_2d2d,
    0x6b00_6b6b,
    0xa800_a8a8,
    0x2b00_2b2b,
    0x3600_3636,
    0xa600_a6a6,
    0xc500_c5c5,
    0x8600_8686,
    0x4d00_4d4d,
    0x3300_3333,
    0xfd00_fdfd,
    0x6600_6666,
    0x5800_5858,
    0x9600_9696,
    0x3a00_3a3a,
    0x0900_0909,
    0x9500_9595,
    0x1000_1010,
    0x7800_7878,
    0xd800_d8d8,
    0x4200_4242,
    0xcc00_cccc,
    0xef00_efef,
    0x2600_2626,
    0xe500_e5e5,
    0x6100_6161,
    0x1a00_1a1a,
    0x3f00_3f3f,
    0x3b00_3b3b,
    0x8200_8282,
    0xb600_b6b6,
    0xdb00_dbdb,
    0xd400_d4d4,
    0x9800_9898,
    0xe800_e8e8,
    0x8b00_8b8b,
    0x0200_0202,
    0xeb00_ebeb,
    0x0a00_0a0a,
    0x2c00_2c2c,
    0x1d00_1d1d,
    0xb000_b0b0,
    0x6f00_6f6f,
    0x8d00_8d8d,
    0x8800_8888,
    0x0e00_0e0e,
    0x1900_1919,
    0x8700_8787,
    0x4e00_4e4e,
    0x0b00_0b0b,
    0xa900_a9a9,
    0x0c00_0c0c,
    0x7900_7979,
    0x1100_1111,
    0x7f00_7f7f,
    0x2200_2222,
    0xe700_e7e7,
    0x5900_5959,
    0xe100_e1e1,
    0xda00_dada,
    0x3d00_3d3d,
    0xc800_c8c8,
    0x1200_1212,
    0x0400_0404,
    0x7400_7474,
    0x5400_5454,
    0x3000_3030,
    0x7e00_7e7e,
    0xb400_b4b4,
    0x2800_2828,
    0x5500_5555,
    0x6800_6868,
    0x5000_5050,
    0xbe00_bebe,
    0xd000_d0d0,
    0xc400_c4c4,
    0x3100_3131,
    0xcb00_cbcb,
    0x2a00_2a2a,
    0xad00_adad,
    0x0f00_0f0f,
    0xca00_caca,
    0x7000_7070,
    0xff00_ffff,
    0x3200_3232,
    0x6900_6969,
    0x0800_0808,
    0x6200_6262,
    0x0000_0000,
    0x2400_2424,
    0xd100_d1d1,
    0xfb00_fbfb,
    0xba00_baba,
    0xed00_eded,
    0x4500_4545,
    0x8100_8181,
    0x7300_7373,
    0x6d00_6d6d,
    0x8400_8484,
    0x9f00_9f9f,
    0xee00_eeee,
    0x4a00_4a4a,
    0xc300_c3c3,
    0x2e00_2e2e,
    0xc100_c1c1,
    0x0100_0101,
    0xe600_e6e6,
    0x2500_2525,
    0x4800_4848,
    0x9900_9999,
    0xb900_b9b9,
    0xb300_b3b3,
    0x7b00_7b7b,
    0xf900_f9f9,
    0xce00_cece,
    0xbf00_bfbf,
    0xdf00_dfdf,
    0x7100_7171,
    0x2900_2929,
    0xcd00_cdcd,
    0x6c00_6c6c,
    0x1300_1313,
    0x6400_6464,
    0x9b00_9b9b,
    0x6300_6363,
    0x9d00_9d9d,
    0xc000_c0c0,
    0x4b00_4b4b,
    0xb700_b7b7,
    0xa500_a5a5,
    0x8900_8989,
    0x5f00_5f5f,
    0xb100_b1b1,
    0x1700_1717,
    0xf400_f4f4,
    0xbc00_bcbc,
    0xd300_d3d3,
    0x4600_4646,
    0xcf00_cfcf,
    0x3700_3737,
    0x5e00_5e5e,
    0x4700_4747,
    0x9400_9494,
    0xfa00_fafa,
    0xfc00_fcfc,
    0x5b00_5b5b,
    0x9700_9797,
    0xfe00_fefe,
    0x5a00_5a5a,
    0xac00_acac,
    0x3c00_3c3c,
    0x4c00_4c4c,
    0x0300_0303,
    0x3500_3535,
    0xf300_f3f3,
    0x2300_2323,
    0xb800_b8b8,
    0x5d00_5d5d,
    0x6a00_6a6a,
    0x9200_9292,
    0xd500_d5d5,
    0x2100_2121,
    0x4400_4444,
    0x5100_5151,
    0xc600_c6c6,
    0x7d00_7d7d,
    0x3900_3939,
    0x8300_8383,
    0xdc00_dcdc,
    0xaa00_aaaa,
    0x7c00_7c7c,
    0x7700_7777,
    0x5600_5656,
    0x0500_0505,
    0x1b00_1b1b,
    0xa400_a4a4,
    0x1500_1515,
    0x3400_3434,
    0x1e00_1e1e,
    0x1c00_1c1c,
    0xf800_f8f8,
    0x5200_5252,
    0x2000_2020,
    0x1400_1414,
    0xe900_e9e9,
    0xbd00_bdbd,
    0xdd00_dddd,
    0xe400_e4e4,
    0xa100_a1a1,
    0xe000_e0e0,
    0x8a00_8a8a,
    0xf100_f1f1,
    0xd600_d6d6,
    0x7a00_7a7a,
    0xbb00_bbbb,
    0xe300_e3e3,
    0x4000_4040,
    0x4f00_4f4f,
];
/// Camellia round-function (Feistel) helper.
///
/// Translation of the `Camellia_Feistel(_s0, _s1, _s2, _s3, _key)` macro from
/// `crypto/camellia/camellia.c`. The round function takes the four state
/// words `(s0, s1, s2, s3)` and two round-key words, updating `s2` and `s3`.
///
/// # Security (cache-timing)
///
/// This is the **principal cache-timing-vulnerable site** of Camellia
/// encryption and decryption. The function performs **8 byte-indexed
/// lookups per call** into four S-box tables — `SBOX1_1110`, `SBOX2_0222`,
/// `SBOX3_3033`, `SBOX4_4404` — using **secret-derived indices** (bytes
/// of `t0 = s0 XOR k0` and `t1 = s1 XOR k1`, where `s0/s1` carry Feistel
/// state and `k0/k1` are round subkeys, both secret-derived).
///
/// Each S-box is 256 × 32-bit = 1024 bytes, occupying multiple cache
/// lines. Cache-line residency leaks bits of each byte index after a
/// single round.
///
/// Per block leakage (camellia_feistel calls × 8 lookups/call):
/// * **Camellia-128 (18 rounds):** 18 × 8 = **144 secret-indexed reads**
/// * **Camellia-192/256 (24 rounds):** 24 × 8 = **192 secret-indexed reads**
///
/// Both `Camellia::encrypt_block` and `Camellia::decrypt_block` traverse
/// this path. The Camellia **key schedule** (`Camellia::new`) also
/// invokes `camellia_feistel` to derive `KA` and `KB` from `KL` and `KR`,
/// so per-key leakage occurs during setup.
///
/// Camellia is a 128-bit-block cipher and therefore is NOT Sweet32
/// vulnerable. It is a NESSIE- and CRYPTREC-recommended cipher and
/// remains in cryptographic good standing on a *mathematical* basis.
/// However, no constant-time software path is implemented and no
/// hardware acceleration (analogous to AES-NI) is widely available.
/// Recommended remediation: prefer **AES-GCM or ChaCha20-Poly1305** for
/// new deployments. Camellia is preserved for Japanese government
/// (CRYPTREC) interoperability.
///
/// See the module-level *Security Notice — Cache-Timing Side Channel*
/// for the full threat model and references.
#[inline]
fn camellia_feistel(s0: u32, s1: u32, s2: &mut u32, s3: &mut u32, k0: u32, k1: u32) {
    let t0 = s0 ^ k0;
    let mut t3 = SBOX4_4404[(t0 & 0xff) as usize];
    let t1 = s1 ^ k1;
    t3 ^= SBOX3_3033[((t0 >> 8) & 0xff) as usize];
    let mut t2 = SBOX1_1110[(t1 & 0xff) as usize];
    t3 ^= SBOX2_0222[((t0 >> 16) & 0xff) as usize];
    t2 ^= SBOX4_4404[((t1 >> 8) & 0xff) as usize];
    t3 ^= SBOX1_1110[((t0 >> 24) & 0xff) as usize];
    t2 ^= t3;
    t3 = t3.rotate_right(8);
    t2 ^= SBOX3_3033[((t1 >> 16) & 0xff) as usize];
    *s3 ^= t3;
    t2 ^= SBOX2_0222[((t1 >> 24) & 0xff) as usize];
    *s2 ^= t2;
    *s3 ^= t2;
}

/// 128-bit left rotation of the 4-word state `[s0, s1, s2, s3]` by `n` bits
/// (1 ≤ n ≤ 31).
///
/// Translation of the `RotLeft128(_s0, _s1, _s2, _s3, _n)` macro from
/// `crypto/camellia/camellia.c`.
#[inline]
fn rot_left_128(s0: &mut u32, s1: &mut u32, s2: &mut u32, s3: &mut u32, n: u32) {
    debug_assert!(n > 0 && n < 32, "RotLeft128 requires 0 < n < 32");
    let t0 = *s0 >> (32 - n);
    *s0 = (*s0 << n) | (*s1 >> (32 - n));
    *s1 = (*s1 << n) | (*s2 >> (32 - n));
    *s2 = (*s2 << n) | (*s3 >> (32 - n));
    *s3 = (*s3 << n) | t0;
}

/// Camellia block cipher (128-bit block, 128/192/256-bit key).
///
/// This is a faithful Rust translation of OpenSSL's `CAMELLIA_KEY` structure
/// and associated routines from `crypto/camellia/camellia.c`.
///
/// Cryptographic notice: Camellia remains a NESSIE- and CRYPTREC-recommended
/// cipher and is fully supported by TLS 1.2 (RFC 4132). It is retained in the
/// legacy module because modern deployments generally prefer AES. Encryption
/// and decryption keys use the same schedule; direction is selected by the
/// traversal order of `rd_key`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Camellia {
    /// Expanded round-key schedule (`KEY_TABLE_TYPE` in the C reference).
    rd_key: [u32; CAMELLIA_SCHEDULE_LEN],
    /// Number of "grand rounds" — 3 for 128-bit keys, 4 for 192/256-bit keys.
    /// Each grand round consists of 6 Feistel rounds plus (for all but the
    /// last) an FL/FL⁻¹ diffusion layer.
    grand_rounds: u32,
    /// Effective key size in bits — 128, 192, or 256 — used only for
    /// `algorithm()` reporting. Not secret.
    key_bits: u16,
}

impl Camellia {
    /// Construct a new Camellia cipher from a 16-, 24-, or 32-byte key.
    ///
    /// Corresponds to `Camellia_set_key(userKey, bits, key)` from
    /// `crypto/camellia/cmll_misc.c`. Returns an error if the key length is
    /// not one of the three accepted sizes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let bits: u16 = match key.len() {
            16 => 128,
            24 => 192,
            32 => 256,
            _ => {
                return Err(CryptoError::Key(
                    "Camellia key length must be 16, 24, or 32 bytes".into(),
                ));
            }
        };

        let mut rd_key = [0u32; CAMELLIA_SCHEDULE_LEN];
        let grand_rounds = Self::ekeygen(u32::from(bits), key, &mut rd_key);

        Ok(Self {
            rd_key,
            grand_rounds,
            key_bits: bits,
        })
    }

    /// Camellia key-schedule expansion.
    ///
    /// Translation of `Camellia_Ekeygen(int keyBitLength, const u8 *rawKey,
    /// KEY_TABLE_TYPE k)` from `crypto/camellia/camellia.c`. Returns the
    /// `grandRounds` value (3 for 128-bit keys, 4 for 192/256-bit keys).
    fn ekeygen(key_bit_length: u32, raw_key: &[u8], k: &mut [u32; CAMELLIA_SCHEDULE_LEN]) -> u32 {
        #[inline]
        fn getu32(b: &[u8]) -> u32 {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }

        let mut s0 = getu32(&raw_key[0..4]);
        let mut s1 = getu32(&raw_key[4..8]);
        let mut s2 = getu32(&raw_key[8..12]);
        let mut s3 = getu32(&raw_key[12..16]);
        k[0] = s0;
        k[1] = s1;
        k[2] = s2;
        k[3] = s3;

        if key_bit_length != 128 {
            s0 = getu32(&raw_key[16..20]);
            s1 = getu32(&raw_key[20..24]);
            k[8] = s0;
            k[9] = s1;
            if key_bit_length == 192 {
                s2 = !s0;
                s3 = !s1;
            } else {
                s2 = getu32(&raw_key[24..28]);
                s3 = getu32(&raw_key[28..32]);
            }
            k[10] = s2;
            k[11] = s3;
            s0 ^= k[0];
            s1 ^= k[1];
            s2 ^= k[2];
            s3 ^= k[3];
        }

        // Use the Feistel routine to scramble the key material (4 applications).
        camellia_feistel(
            s0,
            s1,
            &mut s2,
            &mut s3,
            CAMELLIA_SIGMA[0],
            CAMELLIA_SIGMA[1],
        );
        camellia_feistel(
            s2,
            s3,
            &mut s0,
            &mut s1,
            CAMELLIA_SIGMA[2],
            CAMELLIA_SIGMA[3],
        );

        s0 ^= k[0];
        s1 ^= k[1];
        s2 ^= k[2];
        s3 ^= k[3];
        camellia_feistel(
            s0,
            s1,
            &mut s2,
            &mut s3,
            CAMELLIA_SIGMA[4],
            CAMELLIA_SIGMA[5],
        );
        camellia_feistel(
            s2,
            s3,
            &mut s0,
            &mut s1,
            CAMELLIA_SIGMA[6],
            CAMELLIA_SIGMA[7],
        );

        if key_bit_length == 128 {
            // Fill the keyTable with the many block rotations of KL and KA.
            k[4] = s0;
            k[5] = s1;
            k[6] = s2;
            k[7] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KA <<< 15
            k[12] = s0;
            k[13] = s1;
            k[14] = s2;
            k[15] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KA <<< 30
            k[16] = s0;
            k[17] = s1;
            k[18] = s2;
            k[19] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KA <<< 45
            k[24] = s0;
            k[25] = s1;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KA <<< 60
            k[28] = s0;
            k[29] = s1;
            k[30] = s2;
            k[31] = s3;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 2); // KA <<< 94
            k[40] = s1;
            k[41] = s2;
            k[42] = s3;
            k[43] = s0;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 17); // KA <<< 111
            k[48] = s1;
            k[49] = s2;
            k[50] = s3;
            k[51] = s0;

            s0 = k[0];
            s1 = k[1];
            s2 = k[2];
            s3 = k[3];
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KL <<< 15
            k[8] = s0;
            k[9] = s1;
            k[10] = s2;
            k[11] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 30); // KL <<< 45
            k[20] = s0;
            k[21] = s1;
            k[22] = s2;
            k[23] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KL <<< 60
            k[26] = s2;
            k[27] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 17); // KL <<< 77
            k[32] = s0;
            k[33] = s1;
            k[34] = s2;
            k[35] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 17); // KL <<< 94
            k[36] = s0;
            k[37] = s1;
            k[38] = s2;
            k[39] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 17); // KL <<< 111
            k[44] = s0;
            k[45] = s1;
            k[46] = s2;
            k[47] = s3;

            3
        } else {
            k[12] = s0;
            k[13] = s1;
            k[14] = s2;
            k[15] = s3;
            s0 ^= k[8];
            s1 ^= k[9];
            s2 ^= k[10];
            s3 ^= k[11];
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                CAMELLIA_SIGMA[8],
                CAMELLIA_SIGMA[9],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                CAMELLIA_SIGMA[10],
                CAMELLIA_SIGMA[11],
            );

            k[4] = s0;
            k[5] = s1;
            k[6] = s2;
            k[7] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 30); // KB <<< 30
            k[20] = s0;
            k[21] = s1;
            k[22] = s2;
            k[23] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 30); // KB <<< 60
            k[40] = s0;
            k[41] = s1;
            k[42] = s2;
            k[43] = s3;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 19); // KB <<< 111
            k[64] = s1;
            k[65] = s2;
            k[66] = s3;
            k[67] = s0;

            s0 = k[8];
            s1 = k[9];
            s2 = k[10];
            s3 = k[11];
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KR <<< 15
            k[8] = s0;
            k[9] = s1;
            k[10] = s2;
            k[11] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KR <<< 30
            k[16] = s0;
            k[17] = s1;
            k[18] = s2;
            k[19] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 30); // KR <<< 60
            k[36] = s0;
            k[37] = s1;
            k[38] = s2;
            k[39] = s3;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 2); // KR <<< 94
            k[52] = s1;
            k[53] = s2;
            k[54] = s3;
            k[55] = s0;

            s0 = k[12];
            s1 = k[13];
            s2 = k[14];
            s3 = k[15];
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 15); // KA <<< 15
            k[12] = s0;
            k[13] = s1;
            k[14] = s2;
            k[15] = s3;
            rot_left_128(&mut s0, &mut s1, &mut s2, &mut s3, 30); // KA <<< 45
            k[28] = s0;
            k[29] = s1;
            k[30] = s2;
            k[31] = s3;
            // KA <<< 77 (reuses the s1..s0 reordering from the previous rotation)
            k[48] = s1;
            k[49] = s2;
            k[50] = s3;
            k[51] = s0;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 17); // KA <<< 94
            k[56] = s1;
            k[57] = s2;
            k[58] = s3;
            k[59] = s0;

            s0 = k[0];
            s1 = k[1];
            s2 = k[2];
            s3 = k[3];
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 13); // KL <<< 45
            k[24] = s1;
            k[25] = s2;
            k[26] = s3;
            k[27] = s0;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 15); // KL <<< 60
            k[32] = s1;
            k[33] = s2;
            k[34] = s3;
            k[35] = s0;
            rot_left_128(&mut s1, &mut s2, &mut s3, &mut s0, 17); // KL <<< 77
            k[44] = s1;
            k[45] = s2;
            k[46] = s3;
            k[47] = s0;
            rot_left_128(&mut s2, &mut s3, &mut s0, &mut s1, 2); // KL <<< 111
            k[60] = s2;
            k[61] = s3;
            k[62] = s0;
            k[63] = s1;

            4
        }
    }
}

impl SymmetricCipher for Camellia {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block128
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, CAMELLIA_BLOCK_LEN, "Camellia")?;

        let key_table = &self.rd_key;
        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) ^ key_table[0];
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]) ^ key_table[1];
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]) ^ key_table[2];
        let mut s3 =
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]) ^ key_table[3];

        // Index advances by 12 per FL layer, then +4 at the final output whitening.
        let mut k_idx: usize = 4;
        let k_end: usize = (self.grand_rounds as usize) * 16;

        loop {
            // Camellia makes 6 Feistel rounds per "grand round".
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx],
                key_table[k_idx + 1],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx + 2],
                key_table[k_idx + 3],
            );
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx + 4],
                key_table[k_idx + 5],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx + 6],
                key_table[k_idx + 7],
            );
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx + 8],
                key_table[k_idx + 9],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx + 10],
                key_table[k_idx + 11],
            );
            k_idx += 12;

            if k_idx == k_end {
                break;
            }

            // FL/FL⁻¹ diffusion layer (D-function of the specification §3.2).
            s1 ^= (s0 & key_table[k_idx]).rotate_left(1);
            s2 ^= s3 | key_table[k_idx + 3];
            s0 ^= s1 | key_table[k_idx + 1];
            s3 ^= (s2 & key_table[k_idx + 2]).rotate_left(1);
            k_idx += 4;
        }

        // Post-whitening (note the output word order: s2, s3, s0, s1).
        s2 ^= key_table[k_idx];
        s3 ^= key_table[k_idx + 1];
        s0 ^= key_table[k_idx + 2];
        s1 ^= key_table[k_idx + 3];

        block[0..4].copy_from_slice(&s2.to_be_bytes());
        block[4..8].copy_from_slice(&s3.to_be_bytes());
        block[8..12].copy_from_slice(&s0.to_be_bytes());
        block[12..16].copy_from_slice(&s1.to_be_bytes());
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, CAMELLIA_BLOCK_LEN, "Camellia")?;

        let key_table = &self.rd_key;
        // Start at the end of the schedule; decryption walks backward.
        let mut k_idx: usize = (self.grand_rounds as usize) * 16;
        let k_end: usize = 4;

        let mut s0 =
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]) ^ key_table[k_idx];
        let mut s1 =
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]) ^ key_table[k_idx + 1];
        let mut s2 =
            u32::from_be_bytes([block[8], block[9], block[10], block[11]]) ^ key_table[k_idx + 2];
        let mut s3 =
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]) ^ key_table[k_idx + 3];

        loop {
            // 6 Feistel rounds per grand round (reverse order).
            k_idx -= 12;
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx + 10],
                key_table[k_idx + 11],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx + 8],
                key_table[k_idx + 9],
            );
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx + 6],
                key_table[k_idx + 7],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx + 4],
                key_table[k_idx + 5],
            );
            camellia_feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                key_table[k_idx + 2],
                key_table[k_idx + 3],
            );
            camellia_feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                key_table[k_idx],
                key_table[k_idx + 1],
            );

            if k_idx == k_end {
                break;
            }

            // Inverse FL/FL⁻¹ diffusion layer.
            k_idx -= 4;
            s1 ^= (s0 & key_table[k_idx + 2]).rotate_left(1);
            s2 ^= s3 | key_table[k_idx + 1];
            s0 ^= s1 | key_table[k_idx + 3];
            s3 ^= (s2 & key_table[k_idx]).rotate_left(1);
        }

        // Final whitening with keyTable + 0.
        k_idx -= 4;
        s2 ^= key_table[k_idx];
        s3 ^= key_table[k_idx + 1];
        s0 ^= key_table[k_idx + 2];
        s1 ^= key_table[k_idx + 3];

        block[0..4].copy_from_slice(&s2.to_be_bytes());
        block[4..8].copy_from_slice(&s3.to_be_bytes());
        block[8..12].copy_from_slice(&s0.to_be_bytes());
        block[12..16].copy_from_slice(&s1.to_be_bytes());
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        match self.key_bits {
            128 => CipherAlgorithm::Camellia128,
            192 => CipherAlgorithm::Camellia192,
            _ => CipherAlgorithm::Camellia256,
        }
    }
}

// =============================================================================
// ARIA
// =============================================================================
//
// Source: crypto/aria/aria.c (OpenSSL C reference, SMALL_FOOTPRINT variant).
//
// ARIA is a 128-bit block cipher with 128/192/256-bit keys, standardised by
// the Korean KATS (KS X 1213:2004) and published as RFC 5794. It was designed
// by the Korean National Security Research Institute in 2003–2004.
//
// The algorithm uses 12 (128-bit key), 14 (192-bit key), or 16 (256-bit key)
// rounds. Each round consists of:
//
//  * A **substitution layer** using four fixed S-boxes (SB1, SB2, SB3, SB4).
//    Odd rounds use the pattern (SB1, SB2, SB3, SB4); even rounds use the
//    pattern (SB3, SB4, SB1, SB2).
//  * A **diffusion layer** — a 16×16 linear map over GF(2) computed as 16
//    XORs of seven input bytes each.
//
// The key schedule derives four 128-bit words W0, W1, W2, W3 from the master
// key via three Feistel-like invocations with round constants C1, C2, C3,
// then generates 13/15/17 round keys by circular rotations of (W_i, W_{i+1}).
//
// This SMALL_FOOTPRINT implementation uses 4×256-byte S-box tables (1 KiB
// total) in contrast to the table-driven variant which would require 4×1 KiB
// expanded u32 tables (4 KiB total). The trade-off is additional per-round
// byte-level operations for reduced code and data footprint, matching the
// `#ifdef OPENSSL_SMALL_FOOTPRINT` branch of the C source (lines 685–1121).

/// ARIA block size in bytes (128 bits).
const ARIA_BLOCK_LEN: usize = 16;

/// Maximum number of 128-bit round keys (rounds + 1, with rounds=16 for
/// 256-bit keys).
const ARIA_MAX_KEYS: usize = 17;

/// Round constant C1 (from RFC 5794 §2.2). Used as the first constant for
/// 128-bit keys, third for 192-bit keys, and second for 256-bit keys.
static ARIA_C1: [u8; 16] = [
    0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0,
];

/// Round constant C2. Used as second for 128-bit keys, first for 192-bit,
/// third for 256-bit.
static ARIA_C2: [u8; 16] = [
    0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0,
];

/// Round constant C3. Used as third for 128-bit keys, second for 192-bit,
/// first for 256-bit.
static ARIA_C3: [u8; 16] = [
    0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e,
];

static ARIA_SB1: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

static ARIA_SB2: [u8; 256] = [
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
];

static ARIA_SB3: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

static ARIA_SB4: [u8; 256] = [
    0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
    0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
    0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
    0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
    0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
    0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
    0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
    0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
    0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
    0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
    0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
    0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
    0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
    0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
    0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
    0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60,
];

// -----------------------------------------------------------------------------
// ARIA helper functions
// -----------------------------------------------------------------------------

/// XOR two 128-bit buffers byte-wise into an output buffer.
///
/// Translates C `xor128()` from `crypto/aria/aria.c` line 840.
#[inline]
fn aria_xor128(out: &mut [u8; 16], x: &[u8; 16], y: &[u8; 16]) {
    for i in 0..16 {
        out[i] = x[i] ^ y[i];
    }
}

/// Generalised circular right rotate by `n` bits of `z`, then XOR with
/// `xor_val`, storing the result in `out`.
///
/// Translates C `rotnr()` from `crypto/aria/aria.c` line 852. The C source
/// first performs a byte-level rotation by `n / 8` positions, then a
/// cross-byte bit rotation by `n % 8` bits.
///
/// The rotation is a cyclic right rotation in the big-endian 128-bit view,
/// i.e. the MSB of `z` (byte 0, bit 7) becomes a lower bit after rotation.
#[inline]
fn aria_rotnr(n: u32, out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    let bytes = (n / 8) as usize;
    let bits = n % 8;
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[(i + bytes) % 16] = z[i];
    }
    for i in 0..16 {
        let prev = if i == 0 { 15 } else { i - 1 };
        // When `bits == 0` the `t[prev] << 8` term must contribute zero.
        let low = t[i] >> bits;
        let high = if bits == 0 {
            0u8
        } else {
            // Safe shift: 1 ≤ 8 - bits ≤ 7.
            t[prev] << (8 - bits)
        };
        out[i] = (low | high) ^ xor_val[i];
    }
}

/// Circular right rotate 19 bits and XOR — used for round keys 0..3.
///
/// Translates C `rot19r()` from `crypto/aria/aria.c` line 869.
#[inline]
fn aria_rot19r(out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    aria_rotnr(19, out, xor_val, z);
}

/// Circular right rotate 31 bits and XOR — used for round keys 4..7.
///
/// Translates C `rot31r()` from `crypto/aria/aria.c` line 878.
#[inline]
fn aria_rot31r(out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    aria_rotnr(31, out, xor_val, z);
}

/// Circular left rotate 61 bits and XOR — used for round keys 8..11.
///
/// Translates C `rot61l()` from `crypto/aria/aria.c` line 887. Implemented
/// as a right rotation by `128 - 61 = 67` bits.
#[inline]
fn aria_rot61l(out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    aria_rotnr(128 - 61, out, xor_val, z);
}

/// Circular left rotate 31 bits and XOR — used for round keys 12..15.
///
/// Translates C `rot31l()` from `crypto/aria/aria.c` line 896. Implemented
/// as a right rotation by `128 - 31 = 97` bits.
#[inline]
fn aria_rot31l(out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    aria_rotnr(128 - 31, out, xor_val, z);
}

/// Circular left rotate 19 bits and XOR — used for round key 16.
///
/// Translates C `rot19l()` from `crypto/aria/aria.c` line 905. Implemented
/// as a right rotation by `128 - 19 = 109` bits.
#[inline]
fn aria_rot19l(out: &mut [u8; 16], xor_val: &[u8; 16], z: &[u8; 16]) {
    aria_rotnr(128 - 19, out, xor_val, z);
}

/// First substitution layer — applied in odd steps.
///
/// Translates C `sl1()` from `crypto/aria/aria.c` line 914. For each group
/// of four bytes, applies SB1 → SB2 → SB3 → SB4 after XOR with the round
/// key byte.
///
/// # Security (cache-timing)
///
/// This is one of two **principal cache-timing-vulnerable sites** of ARIA
/// encryption (`aria_sl1`, applied in odd-numbered substitution steps).
/// The function performs **16 byte-indexed lookups per call** into four
/// S-box tables — `ARIA_SB1`, `ARIA_SB2`, `ARIA_SB3`, `ARIA_SB4` —
/// using **secret-derived indices** (`x[i] XOR y[i]`, where `x` is the
/// state byte and `y` is the corresponding round-key byte). Each S-box
/// is 256 bytes (so each byte-indexed lookup is one cache-line read of
/// secret data; cache-line residency leaks the high bits of each byte).
///
/// Per block leakage (sl1 + sl2 calls × 16 lookups/call):
/// * **ARIA-128 (12 rounds):** `aria_sl1` invoked in 6 odd steps → 96
///   reads, plus `aria_sl2` adds another 96 → **192 secret-indexed
///   reads/block** total.
/// * **ARIA-192 (14 rounds):** **224 reads/block**.
/// * **ARIA-256 (16 rounds):** **256 reads/block**.
///
/// The ARIA **key schedule** (`Aria::new`) also invokes `aria_sl1` and
/// `aria_sl2` to derive `W1, W2, W3` from `KL, KR`, leaking during key
/// setup.
///
/// ARIA is a 128-bit-block cipher (NOT Sweet32-vulnerable) and is the
/// Korean national standard (KS X 1213-1:2009 / RFC 5794). It remains
/// in cryptographic good standing on a *mathematical* basis. However,
/// no constant-time software path is implemented and no hardware
/// acceleration is widely available. Recommended remediation: prefer
/// **AES-GCM or ChaCha20-Poly1305** for new deployments. ARIA is
/// preserved for Korean government interoperability.
///
/// See the module-level *Security Notice — Cache-Timing Side Channel*
/// for the full threat model and references.
#[inline]
fn aria_sl1(out: &mut [u8; 16], x: &[u8; 16], y: &[u8; 16]) {
    let mut i = 0;
    while i < ARIA_BLOCK_LEN {
        out[i] = ARIA_SB1[(x[i] ^ y[i]) as usize];
        out[i + 1] = ARIA_SB2[(x[i + 1] ^ y[i + 1]) as usize];
        out[i + 2] = ARIA_SB3[(x[i + 2] ^ y[i + 2]) as usize];
        out[i + 3] = ARIA_SB4[(x[i + 3] ^ y[i + 3]) as usize];
        i += 4;
    }
}

/// Second substitution layer — applied in even steps.
///
/// Translates C `sl2()` from `crypto/aria/aria.c` line 929. For each group
/// of four bytes, applies SB3 → SB4 → SB1 → SB2 after XOR with the round
/// key byte.
///
/// # Security (cache-timing)
///
/// This is the second of two **principal cache-timing-vulnerable sites**
/// of ARIA encryption (`aria_sl2`, applied in even-numbered substitution
/// steps). The leakage profile is **identical** to `aria_sl1` —
/// **16 byte-indexed lookups per call** into the same four 256-byte
/// S-box tables (`ARIA_SB1..ARIA_SB4`) using secret-derived indices.
///
/// Refer to the `aria_sl1` SECURITY block for the full per-cipher
/// leakage profile, threat model, and remediation guidance.
#[inline]
fn aria_sl2(out: &mut [u8; 16], x: &[u8; 16], y: &[u8; 16]) {
    let mut i = 0;
    while i < ARIA_BLOCK_LEN {
        out[i] = ARIA_SB3[(x[i] ^ y[i]) as usize];
        out[i + 1] = ARIA_SB4[(x[i + 1] ^ y[i + 1]) as usize];
        out[i + 2] = ARIA_SB1[(x[i + 2] ^ y[i + 2]) as usize];
        out[i + 3] = ARIA_SB2[(x[i + 3] ^ y[i + 3]) as usize];
        i += 4;
    }
}

/// Diffusion layer A — a 16×16 GF(2) linear map.
///
/// Translates C `a()` from `crypto/aria/aria.c` line 944. Each output byte
/// is the XOR of seven specific input bytes, derived from the ARIA
/// specification (RFC 5794 §2.4.3).
///
/// Caller must not alias `y` with `x` (mirrors C precondition comment).
#[inline]
fn aria_diffusion(y: &mut [u8; 16], x: &[u8; 16]) {
    y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
    y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
    y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
    y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
    y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
    y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
    y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
    y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
    y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
    y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
    y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
    y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
    y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
    y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
    y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
    y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
}

/// Odd round function FO: substitution layer 1, then diffusion.
///
/// Translates C `FO()` from `crypto/aria/aria.c` line 969.
#[inline]
fn aria_fo(out: &mut [u8; 16], d: &[u8; 16], rk: &[u8; 16]) {
    let mut y = [0u8; 16];
    aria_sl1(&mut y, d, rk);
    aria_diffusion(out, &y);
}

/// Even round function FE: substitution layer 2, then diffusion.
///
/// Translates C `FE()` from `crypto/aria/aria.c` line 983.
#[inline]
fn aria_fe(out: &mut [u8; 16], d: &[u8; 16], rk: &[u8; 16]) {
    let mut y = [0u8; 16];
    aria_sl2(&mut y, d, rk);
    aria_diffusion(out, &y);
}

// -----------------------------------------------------------------------------
// ARIA cipher struct
// -----------------------------------------------------------------------------

/// ARIA block cipher (128-bit block, 128/192/256-bit key).
///
/// Translates the C `ARIA_KEY` structure from `include/crypto/aria.h`:
///
/// ```c
/// struct aria_key_st {
///     ARIA_u128 rd_key[ARIA_MAX_KEYS];
///     unsigned int rounds;
/// };
/// ```
///
/// Key material is zeroed on drop via [`ZeroizeOnDrop`].
///
/// # Example
///
/// ```ignore
/// use openssl_crypto::symmetric::{Aria, SymmetricCipher};
///
/// let key = [0u8; 16];
/// let cipher = Aria::new(&key).expect("128-bit key accepted");
/// assert_eq!(cipher.block_size() as usize, 16);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Aria {
    rd_key: [[u8; 16]; ARIA_MAX_KEYS],
    rounds: u32,
    key_bits: u16,
}

impl Aria {
    /// Construct an ARIA cipher with a 16/24/32-byte key.
    ///
    /// Replaces C `ossl_aria_set_encrypt_key()` from `crypto/aria/aria.c`
    /// line 1028. Returns [`CryptoError::Key`] if `key.len()` is not 16, 24,
    /// or 32 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        // Declare `key_bits` as `u16` directly: all valid values (128, 192,
        // 256) fit trivially, and downstream consumers in `set_encrypt_key`
        // receive a widened `u32` via lossless `u32::from`.
        let key_bits: u16 = match key.len() {
            16 => 128,
            24 => 192,
            32 => 256,
            n => {
                return Err(CryptoError::Key(format!(
                    "ARIA key length must be 16, 24, or 32 bytes, got {n}"
                )));
            }
        };

        let mut rd_key = [[0u8; 16]; ARIA_MAX_KEYS];
        let rounds = Self::set_encrypt_key(key, u32::from(key_bits), &mut rd_key);

        Ok(Self {
            rd_key,
            rounds,
            key_bits,
        })
    }

    /// Expand a raw key into an encryption schedule, returning the round
    /// count. Mirrors the C `ossl_aria_set_encrypt_key()` logic.
    fn set_encrypt_key(user_key: &[u8], bits: u32, rd_key: &mut [[u8; 16]; ARIA_MAX_KEYS]) -> u32 {
        let (rounds, ck1, ck2, ck3) = match bits {
            128 => (12u32, &ARIA_C1, &ARIA_C2, &ARIA_C3),
            192 => (14u32, &ARIA_C2, &ARIA_C3, &ARIA_C1),
            256 => (16u32, &ARIA_C3, &ARIA_C1, &ARIA_C2),
            _ => unreachable!("caller validated bits"),
        };

        let mut w0 = [0u8; 16];
        w0.copy_from_slice(&user_key[..16]);

        let mut kr = [0u8; 16];
        if bits == 192 {
            // Lower half = user_key[16..24], upper half = 0.
            kr[..8].copy_from_slice(&user_key[16..24]);
        } else if bits == 256 {
            kr.copy_from_slice(&user_key[16..32]);
        }
        // For bits == 128, kr remains all zeroes (initialised above).

        // Feistel-like key derivation producing W0..W3 (RFC 5794 §2.3.1).
        let mut w1 = [0u8; 16];
        let mut w2 = [0u8; 16];
        let mut w3 = [0u8; 16];

        // FO(w3, w0, ck1); xor128(w1, w3, &kr);
        aria_fo(&mut w3, &w0, ck1);
        aria_xor128(&mut w1, &w3, &kr);

        // FE(w3, w1, ck2); xor128(w2, w3, &w0);
        aria_fe(&mut w3, &w1, ck2);
        aria_xor128(&mut w2, &w3, &w0);

        // FO(kr, w2, ck3); xor128(w3, kr, &w1);
        aria_fo(&mut kr, &w2, ck3);
        aria_xor128(&mut w3, &kr, &w1);

        // Round-key generation via rotations of (Wi, W_{i+1}).
        aria_rot19r(&mut rd_key[0], &w0, &w1);
        aria_rot19r(&mut rd_key[1], &w1, &w2);
        aria_rot19r(&mut rd_key[2], &w2, &w3);
        aria_rot19r(&mut rd_key[3], &w3, &w0);

        aria_rot31r(&mut rd_key[4], &w0, &w1);
        aria_rot31r(&mut rd_key[5], &w1, &w2);
        aria_rot31r(&mut rd_key[6], &w2, &w3);
        aria_rot31r(&mut rd_key[7], &w3, &w0);

        aria_rot61l(&mut rd_key[8], &w0, &w1);
        aria_rot61l(&mut rd_key[9], &w1, &w2);
        aria_rot61l(&mut rd_key[10], &w2, &w3);
        aria_rot61l(&mut rd_key[11], &w3, &w0);

        aria_rot31l(&mut rd_key[12], &w0, &w1);
        if rounds > 12 {
            aria_rot31l(&mut rd_key[13], &w1, &w2);
            aria_rot31l(&mut rd_key[14], &w2, &w3);

            if rounds > 14 {
                aria_rot31l(&mut rd_key[15], &w3, &w0);
                aria_rot19l(&mut rd_key[16], &w0, &w1);
            }
        }
        rounds
    }

    /// Core block transformation, shared by encrypt and decrypt.
    ///
    /// Mirrors C `do_encrypt()` from `crypto/aria/aria.c` line 996. Both
    /// directions invoke the same structure because decryption uses a
    /// transformed round-key schedule (see `decrypt_block` comment).
    fn do_encrypt(
        rd_key: &[[u8; 16]; ARIA_MAX_KEYS],
        rounds: u32,
        output: &mut [u8; 16],
        input: &[u8; 16],
    ) {
        let mut p = *input;
        let rounds_usize = rounds as usize;

        // (rounds - 2) / 2 pairs of (FO, FE) rounds.
        let mut i = 0usize;
        while i < rounds_usize.saturating_sub(2) {
            let mut tmp = [0u8; 16];
            aria_fo(&mut tmp, &p, &rd_key[i]);
            p = tmp;
            aria_fe(&mut tmp, &p, &rd_key[i + 1]);
            p = tmp;
            i += 2;
        }

        // Second-to-last round is an FO; last round is plain sl2 + XOR.
        let mut tmp = [0u8; 16];
        aria_fo(&mut tmp, &p, &rd_key[rounds_usize - 2]);
        p = tmp;

        let mut out_tmp = [0u8; 16];
        aria_sl2(&mut out_tmp, &p, &rd_key[rounds_usize - 1]);
        aria_xor128(output, &out_tmp, &rd_key[rounds_usize]);
    }
}

impl SymmetricCipher for Aria {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block128
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, ARIA_BLOCK_LEN, "ARIA")?;
        let mut input = [0u8; 16];
        input.copy_from_slice(&block[..16]);
        let mut output = [0u8; 16];
        Self::do_encrypt(&self.rd_key, self.rounds, &mut output, &input);
        block[..16].copy_from_slice(&output);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, ARIA_BLOCK_LEN, "ARIA")?;

        // Derive a decryption schedule from this instance's encryption
        // schedule, matching C `ossl_aria_set_decrypt_key()` at line 1104:
        //
        //   dk.rd_key[0] = ek.rd_key[rounds];
        //   for i in 1..rounds: dk.rd_key[i] = a(ek.rd_key[rounds - i]);
        //   dk.rd_key[rounds] = ek.rd_key[0];
        //
        // We build this lazily on each call (ARIA's decryption throughput
        // is modest and this keeps the struct small). Higher-throughput
        // callers can cache a separate `Aria` instance constructed against
        // the same key if needed.
        let rounds_usize = self.rounds as usize;
        let mut dec_key = [[0u8; 16]; ARIA_MAX_KEYS];
        dec_key[0] = self.rd_key[rounds_usize];
        for (i, dst) in dec_key.iter_mut().enumerate().take(rounds_usize).skip(1) {
            aria_diffusion(dst, &self.rd_key[rounds_usize - i]);
        }
        dec_key[rounds_usize] = self.rd_key[0];

        let mut input = [0u8; 16];
        input.copy_from_slice(&block[..16]);
        let mut output = [0u8; 16];
        Self::do_encrypt(&dec_key, self.rounds, &mut output, &input);
        block[..16].copy_from_slice(&output);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        match self.key_bits {
            128 => CipherAlgorithm::Aria128,
            192 => CipherAlgorithm::Aria192,
            _ => CipherAlgorithm::Aria256,
        }
    }
}

// =============================================================================
// SM4
// =============================================================================
// Translated from `crypto/sm4/sm4.c` (Ribose Inc., 2017; ported from Botan).
// SM4 is the Chinese national block cipher standard (GB/T 32907-2016, also
// published as an international standard ISO/IEC 18033-3:2010/AMD1:2021).
//
// Parameters: 128-bit block, 128-bit key, 32 rounds, big-endian byte order.
// The round function uses a non-linear S-box `τ` followed by two different
// linear transforms:
//   - `L (x) = x ⊕ (x <<< 2) ⊕ (x <<< 10) ⊕ (x <<< 18) ⊕ (x <<< 24)` for encryption.
//   - `L'(x) = x ⊕ (x <<< 13) ⊕ (x <<< 23)` for the key schedule.
//
// The implementation follows OpenSSL's split between a side-channel-resistant
// byte-wise path (`SM4_T_slow`) used for the outermost four rounds and a
// table-driven fast path (`SM4_T`) used for the inner 24 rounds. The output
// word order is reversed (B3, B2, B1, B0) which mirrors the reflection step
// in the SM4 specification.
// =============================================================================

/// Number of 32-bit round keys produced by the SM4 key schedule.
const SM4_KEY_SCHEDULE: usize = 32;

/// Block size (16 bytes / 128 bits) of SM4.
const SM4_BLOCK_LEN: usize = 16;

/// Key size (16 bytes / 128 bits) of SM4 — the only supported key length.
const SM4_KEY_LEN: usize = 16;

/// SM4 S-box (non-linear substitution τ). From `crypto/sm4/sm4.c` line 15.
static SM4_S: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

/// Precomputed SM4 T-table (S-box composed with linear L). Corresponds
/// to C `SM4_SBOX_T0` in `crypto/sm4/sm4.c`.
static SM4_SBOX_T0: [u32; 256] = [
    0x8ed5_5b5b,
    0xd092_4242,
    0x4dea_a7a7,
    0x06fd_fbfb,
    0xfccf_3333,
    0x65e2_8787,
    0xc93d_f4f4,
    0x6bb5_dede,
    0x4e16_5858,
    0x6eb4_dada,
    0x4414_5050,
    0xcac1_0b0b,
    0x8828_a0a0,
    0x17f8_efef,
    0x9c2c_b0b0,
    0x1105_1414,
    0x872b_acac,
    0xfb66_9d9d,
    0xf298_6a6a,
    0xae77_d9d9,
    0x822a_a8a8,
    0x46bc_fafa,
    0x1404_1010,
    0xcfc0_0f0f,
    0x02a8_aaaa,
    0x5445_1111,
    0x5f13_4c4c,
    0xbe26_9898,
    0x6d48_2525,
    0x9e84_1a1a,
    0x1e06_1818,
    0xfd9b_6666,
    0xec9e_7272,
    0x4a43_0909,
    0x1051_4141,
    0x24f7_d3d3,
    0xd593_4646,
    0x53ec_bfbf,
    0xf89a_6262,
    0x927b_e9e9,
    0xff33_cccc,
    0x0455_5151,
    0x270b_2c2c,
    0x4f42_0d0d,
    0x59ee_b7b7,
    0xf3cc_3f3f,
    0x1cae_b2b2,
    0xea63_8989,
    0x74e7_9393,
    0x7fb1_cece,
    0x6c1c_7070,
    0x0dab_a6a6,
    0xedca_2727,
    0x2808_2020,
    0x48eb_a3a3,
    0xc197_5656,
    0x8082_0202,
    0xa3dc_7f7f,
    0xc496_5252,
    0x12f9_ebeb,
    0xa174_d5d5,
    0xb38d_3e3e,
    0xc33f_fcfc,
    0x3ea4_9a9a,
    0x5b46_1d1d,
    0x1b07_1c1c,
    0x3ba5_9e9e,
    0x0cff_f3f3,
    0x3ff0_cfcf,
    0xbf72_cdcd,
    0x4b17_5c5c,
    0x52b8_eaea,
    0x8f81_0e0e,
    0x3d58_6565,
    0xcc3c_f0f0,
    0x7d19_6464,
    0x7ee5_9b9b,
    0x9187_1616,
    0x734e_3d3d,
    0x08aa_a2a2,
    0xc869_a1a1,
    0xc76a_adad,
    0x8583_0606,
    0x7ab0_caca,
    0xb570_c5c5,
    0xf465_9191,
    0xb2d9_6b6b,
    0xa789_2e2e,
    0x18fb_e3e3,
    0x47e8_afaf,
    0x330f_3c3c,
    0x674a_2d2d,
    0xb071_c1c1,
    0x0e57_5959,
    0xe99f_7676,
    0xe135_d4d4,
    0x661e_7878,
    0xb424_9090,
    0x360e_3838,
    0x265f_7979,
    0xef62_8d8d,
    0x3859_6161,
    0x95d2_4747,
    0x2aa0_8a8a,
    0xb125_9494,
    0xaa22_8888,
    0x8c7d_f1f1,
    0xd73b_ecec,
    0x0501_0404,
    0xa521_8484,
    0x9879_e1e1,
    0x9b85_1e1e,
    0x84d7_5353,
    0x0000_0000,
    0x5e47_1919,
    0x0b56_5d5d,
    0xe39d_7e7e,
    0x9fd0_4f4f,
    0xbb27_9c9c,
    0x1a53_4949,
    0x7c4d_3131,
    0xee36_d8d8,
    0x0a02_0808,
    0x7be4_9f9f,
    0x20a2_8282,
    0xd4c7_1313,
    0xe8cb_2323,
    0xe69c_7a7a,
    0x42e9_abab,
    0x43bd_fefe,
    0xa288_2a2a,
    0x9ad1_4b4b,
    0x4041_0101,
    0xdbc4_1f1f,
    0xd838_e0e0,
    0x61b7_d6d6,
    0x2fa1_8e8e,
    0x2bf4_dfdf,
    0x3af1_cbcb,
    0xf6cd_3b3b,
    0x1dfa_e7e7,
    0xe560_8585,
    0x4115_5454,
    0x25a3_8686,
    0x60e3_8383,
    0x16ac_baba,
    0x295c_7575,
    0x34a6_9292,
    0xf799_6e6e,
    0xe434_d0d0,
    0x721a_6868,
    0x0154_5555,
    0x19af_b6b6,
    0xdf91_4e4e,
    0xfa32_c8c8,
    0xf030_c0c0,
    0x21f6_d7d7,
    0xbc8e_3232,
    0x75b3_c6c6,
    0x6fe0_8f8f,
    0x691d_7474,
    0x2ef5_dbdb,
    0x6ae1_8b8b,
    0x962e_b8b8,
    0x8a80_0a0a,
    0xfe67_9999,
    0xe2c9_2b2b,
    0xe061_8181,
    0xc0c3_0303,
    0x8d29_a4a4,
    0xaf23_8c8c,
    0x07a9_aeae,
    0x390d_3434,
    0x1f52_4d4d,
    0x764f_3939,
    0xd36e_bdbd,
    0x81d6_5757,
    0xb7d8_6f6f,
    0xeb37_dcdc,
    0x5144_1515,
    0xa6dd_7b7b,
    0x09fe_f7f7,
    0xb68c_3a3a,
    0x932f_bcbc,
    0x0f03_0c0c,
    0x03fc_ffff,
    0xc26b_a9a9,
    0xba73_c9c9,
    0xd96c_b5b5,
    0xdc6d_b1b1,
    0x375a_6d6d,
    0x1550_4545,
    0xb98f_3636,
    0x771b_6c6c,
    0x13ad_bebe,
    0xda90_4a4a,
    0x57b9_eeee,
    0xa9de_7777,
    0x4cbe_f2f2,
    0x837e_fdfd,
    0x5511_4444,
    0xbdda_6767,
    0x2c5d_7171,
    0x4540_0505,
    0x631f_7c7c,
    0x5010_4040,
    0x325b_6969,
    0xb8db_6363,
    0x220a_2828,
    0xc5c2_0707,
    0xf531_c4c4,
    0xa88a_2222,
    0x31a7_9696,
    0xf9ce_3737,
    0x977a_eded,
    0x49bf_f6f6,
    0x992d_b4b4,
    0xa475_d1d1,
    0x90d3_4343,
    0x5a12_4848,
    0x58ba_e2e2,
    0x71e6_9797,
    0x64b6_d2d2,
    0x70b2_c2c2,
    0xad8b_2626,
    0xcd68_a5a5,
    0xcb95_5e5e,
    0x624b_2929,
    0x3c0c_3030,
    0xce94_5a5a,
    0xab76_dddd,
    0x867f_f9f9,
    0xf164_9595,
    0x5dbb_e6e6,
    0x35f2_c7c7,
    0x2d09_2424,
    0xd1c6_1717,
    0xd66f_b9b9,
    0xdec5_1b1b,
    0x9486_1212,
    0x7818_6060,
    0x30f3_c3c3,
    0x897c_f5f5,
    0x5cef_b3b3,
    0xd23a_e8e8,
    0xacdf_7373,
    0x794c_3535,
    0xa020_8080,
    0x9d78_e5e5,
    0x56ed_bbbb,
    0x235e_7d7d,
    0xc63e_f8f8,
    0x8bd4_5f5f,
    0xe7c8_2f2f,
    0xdd39_e4e4,
    0x6849_2121,
];

/// Precomputed SM4 T-table (S-box composed with linear L). Corresponds
/// to C `SM4_SBOX_T1` in `crypto/sm4/sm4.c`.
static SM4_SBOX_T1: [u32; 256] = [
    0x5b8e_d55b,
    0x42d0_9242,
    0xa74d_eaa7,
    0xfb06_fdfb,
    0x33fc_cf33,
    0x8765_e287,
    0xf4c9_3df4,
    0xde6b_b5de,
    0x584e_1658,
    0xda6e_b4da,
    0x5044_1450,
    0x0bca_c10b,
    0xa088_28a0,
    0xef17_f8ef,
    0xb09c_2cb0,
    0x1411_0514,
    0xac87_2bac,
    0x9dfb_669d,
    0x6af2_986a,
    0xd9ae_77d9,
    0xa882_2aa8,
    0xfa46_bcfa,
    0x1014_0410,
    0x0fcf_c00f,
    0xaa02_a8aa,
    0x1154_4511,
    0x4c5f_134c,
    0x98be_2698,
    0x256d_4825,
    0x1a9e_841a,
    0x181e_0618,
    0x66fd_9b66,
    0x72ec_9e72,
    0x094a_4309,
    0x4110_5141,
    0xd324_f7d3,
    0x46d5_9346,
    0xbf53_ecbf,
    0x62f8_9a62,
    0xe992_7be9,
    0xccff_33cc,
    0x5104_5551,
    0x2c27_0b2c,
    0x0d4f_420d,
    0xb759_eeb7,
    0x3ff3_cc3f,
    0xb21c_aeb2,
    0x89ea_6389,
    0x9374_e793,
    0xce7f_b1ce,
    0x706c_1c70,
    0xa60d_aba6,
    0x27ed_ca27,
    0x2028_0820,
    0xa348_eba3,
    0x56c1_9756,
    0x0280_8202,
    0x7fa3_dc7f,
    0x52c4_9652,
    0xeb12_f9eb,
    0xd5a1_74d5,
    0x3eb3_8d3e,
    0xfcc3_3ffc,
    0x9a3e_a49a,
    0x1d5b_461d,
    0x1c1b_071c,
    0x9e3b_a59e,
    0xf30c_fff3,
    0xcf3f_f0cf,
    0xcdbf_72cd,
    0x5c4b_175c,
    0xea52_b8ea,
    0x0e8f_810e,
    0x653d_5865,
    0xf0cc_3cf0,
    0x647d_1964,
    0x9b7e_e59b,
    0x1691_8716,
    0x3d73_4e3d,
    0xa208_aaa2,
    0xa1c8_69a1,
    0xadc7_6aad,
    0x0685_8306,
    0xca7a_b0ca,
    0xc5b5_70c5,
    0x91f4_6591,
    0x6bb2_d96b,
    0x2ea7_892e,
    0xe318_fbe3,
    0xaf47_e8af,
    0x3c33_0f3c,
    0x2d67_4a2d,
    0xc1b0_71c1,
    0x590e_5759,
    0x76e9_9f76,
    0xd4e1_35d4,
    0x7866_1e78,
    0x90b4_2490,
    0x3836_0e38,
    0x7926_5f79,
    0x8def_628d,
    0x6138_5961,
    0x4795_d247,
    0x8a2a_a08a,
    0x94b1_2594,
    0x88aa_2288,
    0xf18c_7df1,
    0xecd7_3bec,
    0x0405_0104,
    0x84a5_2184,
    0xe198_79e1,
    0x1e9b_851e,
    0x5384_d753,
    0x0000_0000,
    0x195e_4719,
    0x5d0b_565d,
    0x7ee3_9d7e,
    0x4f9f_d04f,
    0x9cbb_279c,
    0x491a_5349,
    0x317c_4d31,
    0xd8ee_36d8,
    0x080a_0208,
    0x9f7b_e49f,
    0x8220_a282,
    0x13d4_c713,
    0x23e8_cb23,
    0x7ae6_9c7a,
    0xab42_e9ab,
    0xfe43_bdfe,
    0x2aa2_882a,
    0x4b9a_d14b,
    0x0140_4101,
    0x1fdb_c41f,
    0xe0d8_38e0,
    0xd661_b7d6,
    0x8e2f_a18e,
    0xdf2b_f4df,
    0xcb3a_f1cb,
    0x3bf6_cd3b,
    0xe71d_fae7,
    0x85e5_6085,
    0x5441_1554,
    0x8625_a386,
    0x8360_e383,
    0xba16_acba,
    0x7529_5c75,
    0x9234_a692,
    0x6ef7_996e,
    0xd0e4_34d0,
    0x6872_1a68,
    0x5501_5455,
    0xb619_afb6,
    0x4edf_914e,
    0xc8fa_32c8,
    0xc0f0_30c0,
    0xd721_f6d7,
    0x32bc_8e32,
    0xc675_b3c6,
    0x8f6f_e08f,
    0x7469_1d74,
    0xdb2e_f5db,
    0x8b6a_e18b,
    0xb896_2eb8,
    0x0a8a_800a,
    0x99fe_6799,
    0x2be2_c92b,
    0x81e0_6181,
    0x03c0_c303,
    0xa48d_29a4,
    0x8caf_238c,
    0xae07_a9ae,
    0x3439_0d34,
    0x4d1f_524d,
    0x3976_4f39,
    0xbdd3_6ebd,
    0x5781_d657,
    0x6fb7_d86f,
    0xdceb_37dc,
    0x1551_4415,
    0x7ba6_dd7b,
    0xf709_fef7,
    0x3ab6_8c3a,
    0xbc93_2fbc,
    0x0c0f_030c,
    0xff03_fcff,
    0xa9c2_6ba9,
    0xc9ba_73c9,
    0xb5d9_6cb5,
    0xb1dc_6db1,
    0x6d37_5a6d,
    0x4515_5045,
    0x36b9_8f36,
    0x6c77_1b6c,
    0xbe13_adbe,
    0x4ada_904a,
    0xee57_b9ee,
    0x77a9_de77,
    0xf24c_bef2,
    0xfd83_7efd,
    0x4455_1144,
    0x67bd_da67,
    0x712c_5d71,
    0x0545_4005,
    0x7c63_1f7c,
    0x4050_1040,
    0x6932_5b69,
    0x63b8_db63,
    0x2822_0a28,
    0x07c5_c207,
    0xc4f5_31c4,
    0x22a8_8a22,
    0x9631_a796,
    0x37f9_ce37,
    0xed97_7aed,
    0xf649_bff6,
    0xb499_2db4,
    0xd1a4_75d1,
    0x4390_d343,
    0x485a_1248,
    0xe258_bae2,
    0x9771_e697,
    0xd264_b6d2,
    0xc270_b2c2,
    0x26ad_8b26,
    0xa5cd_68a5,
    0x5ecb_955e,
    0x2962_4b29,
    0x303c_0c30,
    0x5ace_945a,
    0xddab_76dd,
    0xf986_7ff9,
    0x95f1_6495,
    0xe65d_bbe6,
    0xc735_f2c7,
    0x242d_0924,
    0x17d1_c617,
    0xb9d6_6fb9,
    0x1bde_c51b,
    0x1294_8612,
    0x6078_1860,
    0xc330_f3c3,
    0xf589_7cf5,
    0xb35c_efb3,
    0xe8d2_3ae8,
    0x73ac_df73,
    0x3579_4c35,
    0x80a0_2080,
    0xe59d_78e5,
    0xbb56_edbb,
    0x7d23_5e7d,
    0xf8c6_3ef8,
    0x5f8b_d45f,
    0x2fe7_c82f,
    0xe4dd_39e4,
    0x2168_4921,
];

/// Precomputed SM4 T-table (S-box composed with linear L). Corresponds
/// to C `SM4_SBOX_T2` in `crypto/sm4/sm4.c`.
static SM4_SBOX_T2: [u32; 256] = [
    0x5b5b_8ed5,
    0x4242_d092,
    0xa7a7_4dea,
    0xfbfb_06fd,
    0x3333_fccf,
    0x8787_65e2,
    0xf4f4_c93d,
    0xdede_6bb5,
    0x5858_4e16,
    0xdada_6eb4,
    0x5050_4414,
    0x0b0b_cac1,
    0xa0a0_8828,
    0xefef_17f8,
    0xb0b0_9c2c,
    0x1414_1105,
    0xacac_872b,
    0x9d9d_fb66,
    0x6a6a_f298,
    0xd9d9_ae77,
    0xa8a8_822a,
    0xfafa_46bc,
    0x1010_1404,
    0x0f0f_cfc0,
    0xaaaa_02a8,
    0x1111_5445,
    0x4c4c_5f13,
    0x9898_be26,
    0x2525_6d48,
    0x1a1a_9e84,
    0x1818_1e06,
    0x6666_fd9b,
    0x7272_ec9e,
    0x0909_4a43,
    0x4141_1051,
    0xd3d3_24f7,
    0x4646_d593,
    0xbfbf_53ec,
    0x6262_f89a,
    0xe9e9_927b,
    0xcccc_ff33,
    0x5151_0455,
    0x2c2c_270b,
    0x0d0d_4f42,
    0xb7b7_59ee,
    0x3f3f_f3cc,
    0xb2b2_1cae,
    0x8989_ea63,
    0x9393_74e7,
    0xcece_7fb1,
    0x7070_6c1c,
    0xa6a6_0dab,
    0x2727_edca,
    0x2020_2808,
    0xa3a3_48eb,
    0x5656_c197,
    0x0202_8082,
    0x7f7f_a3dc,
    0x5252_c496,
    0xebeb_12f9,
    0xd5d5_a174,
    0x3e3e_b38d,
    0xfcfc_c33f,
    0x9a9a_3ea4,
    0x1d1d_5b46,
    0x1c1c_1b07,
    0x9e9e_3ba5,
    0xf3f3_0cff,
    0xcfcf_3ff0,
    0xcdcd_bf72,
    0x5c5c_4b17,
    0xeaea_52b8,
    0x0e0e_8f81,
    0x6565_3d58,
    0xf0f0_cc3c,
    0x6464_7d19,
    0x9b9b_7ee5,
    0x1616_9187,
    0x3d3d_734e,
    0xa2a2_08aa,
    0xa1a1_c869,
    0xadad_c76a,
    0x0606_8583,
    0xcaca_7ab0,
    0xc5c5_b570,
    0x9191_f465,
    0x6b6b_b2d9,
    0x2e2e_a789,
    0xe3e3_18fb,
    0xafaf_47e8,
    0x3c3c_330f,
    0x2d2d_674a,
    0xc1c1_b071,
    0x5959_0e57,
    0x7676_e99f,
    0xd4d4_e135,
    0x7878_661e,
    0x9090_b424,
    0x3838_360e,
    0x7979_265f,
    0x8d8d_ef62,
    0x6161_3859,
    0x4747_95d2,
    0x8a8a_2aa0,
    0x9494_b125,
    0x8888_aa22,
    0xf1f1_8c7d,
    0xecec_d73b,
    0x0404_0501,
    0x8484_a521,
    0xe1e1_9879,
    0x1e1e_9b85,
    0x5353_84d7,
    0x0000_0000,
    0x1919_5e47,
    0x5d5d_0b56,
    0x7e7e_e39d,
    0x4f4f_9fd0,
    0x9c9c_bb27,
    0x4949_1a53,
    0x3131_7c4d,
    0xd8d8_ee36,
    0x0808_0a02,
    0x9f9f_7be4,
    0x8282_20a2,
    0x1313_d4c7,
    0x2323_e8cb,
    0x7a7a_e69c,
    0xabab_42e9,
    0xfefe_43bd,
    0x2a2a_a288,
    0x4b4b_9ad1,
    0x0101_4041,
    0x1f1f_dbc4,
    0xe0e0_d838,
    0xd6d6_61b7,
    0x8e8e_2fa1,
    0xdfdf_2bf4,
    0xcbcb_3af1,
    0x3b3b_f6cd,
    0xe7e7_1dfa,
    0x8585_e560,
    0x5454_4115,
    0x8686_25a3,
    0x8383_60e3,
    0xbaba_16ac,
    0x7575_295c,
    0x9292_34a6,
    0x6e6e_f799,
    0xd0d0_e434,
    0x6868_721a,
    0x5555_0154,
    0xb6b6_19af,
    0x4e4e_df91,
    0xc8c8_fa32,
    0xc0c0_f030,
    0xd7d7_21f6,
    0x3232_bc8e,
    0xc6c6_75b3,
    0x8f8f_6fe0,
    0x7474_691d,
    0xdbdb_2ef5,
    0x8b8b_6ae1,
    0xb8b8_962e,
    0x0a0a_8a80,
    0x9999_fe67,
    0x2b2b_e2c9,
    0x8181_e061,
    0x0303_c0c3,
    0xa4a4_8d29,
    0x8c8c_af23,
    0xaeae_07a9,
    0x3434_390d,
    0x4d4d_1f52,
    0x3939_764f,
    0xbdbd_d36e,
    0x5757_81d6,
    0x6f6f_b7d8,
    0xdcdc_eb37,
    0x1515_5144,
    0x7b7b_a6dd,
    0xf7f7_09fe,
    0x3a3a_b68c,
    0xbcbc_932f,
    0x0c0c_0f03,
    0xffff_03fc,
    0xa9a9_c26b,
    0xc9c9_ba73,
    0xb5b5_d96c,
    0xb1b1_dc6d,
    0x6d6d_375a,
    0x4545_1550,
    0x3636_b98f,
    0x6c6c_771b,
    0xbebe_13ad,
    0x4a4a_da90,
    0xeeee_57b9,
    0x7777_a9de,
    0xf2f2_4cbe,
    0xfdfd_837e,
    0x4444_5511,
    0x6767_bdda,
    0x7171_2c5d,
    0x0505_4540,
    0x7c7c_631f,
    0x4040_5010,
    0x6969_325b,
    0x6363_b8db,
    0x2828_220a,
    0x0707_c5c2,
    0xc4c4_f531,
    0x2222_a88a,
    0x9696_31a7,
    0x3737_f9ce,
    0xeded_977a,
    0xf6f6_49bf,
    0xb4b4_992d,
    0xd1d1_a475,
    0x4343_90d3,
    0x4848_5a12,
    0xe2e2_58ba,
    0x9797_71e6,
    0xd2d2_64b6,
    0xc2c2_70b2,
    0x2626_ad8b,
    0xa5a5_cd68,
    0x5e5e_cb95,
    0x2929_624b,
    0x3030_3c0c,
    0x5a5a_ce94,
    0xdddd_ab76,
    0xf9f9_867f,
    0x9595_f164,
    0xe6e6_5dbb,
    0xc7c7_35f2,
    0x2424_2d09,
    0x1717_d1c6,
    0xb9b9_d66f,
    0x1b1b_dec5,
    0x1212_9486,
    0x6060_7818,
    0xc3c3_30f3,
    0xf5f5_897c,
    0xb3b3_5cef,
    0xe8e8_d23a,
    0x7373_acdf,
    0x3535_794c,
    0x8080_a020,
    0xe5e5_9d78,
    0xbbbb_56ed,
    0x7d7d_235e,
    0xf8f8_c63e,
    0x5f5f_8bd4,
    0x2f2f_e7c8,
    0xe4e4_dd39,
    0x2121_6849,
];

/// Precomputed SM4 T-table (S-box composed with linear L). Corresponds
/// to C `SM4_SBOX_T3` in `crypto/sm4/sm4.c`.
static SM4_SBOX_T3: [u32; 256] = [
    0xd55b_5b8e,
    0x9242_42d0,
    0xeaa7_a74d,
    0xfdfb_fb06,
    0xcf33_33fc,
    0xe287_8765,
    0x3df4_f4c9,
    0xb5de_de6b,
    0x1658_584e,
    0xb4da_da6e,
    0x1450_5044,
    0xc10b_0bca,
    0x28a0_a088,
    0xf8ef_ef17,
    0x2cb0_b09c,
    0x0514_1411,
    0x2bac_ac87,
    0x669d_9dfb,
    0x986a_6af2,
    0x77d9_d9ae,
    0x2aa8_a882,
    0xbcfa_fa46,
    0x0410_1014,
    0xc00f_0fcf,
    0xa8aa_aa02,
    0x4511_1154,
    0x134c_4c5f,
    0x2698_98be,
    0x4825_256d,
    0x841a_1a9e,
    0x0618_181e,
    0x9b66_66fd,
    0x9e72_72ec,
    0x4309_094a,
    0x5141_4110,
    0xf7d3_d324,
    0x9346_46d5,
    0xecbf_bf53,
    0x9a62_62f8,
    0x7be9_e992,
    0x33cc_ccff,
    0x5551_5104,
    0x0b2c_2c27,
    0x420d_0d4f,
    0xeeb7_b759,
    0xcc3f_3ff3,
    0xaeb2_b21c,
    0x6389_89ea,
    0xe793_9374,
    0xb1ce_ce7f,
    0x1c70_706c,
    0xaba6_a60d,
    0xca27_27ed,
    0x0820_2028,
    0xeba3_a348,
    0x9756_56c1,
    0x8202_0280,
    0xdc7f_7fa3,
    0x9652_52c4,
    0xf9eb_eb12,
    0x74d5_d5a1,
    0x8d3e_3eb3,
    0x3ffc_fcc3,
    0xa49a_9a3e,
    0x461d_1d5b,
    0x071c_1c1b,
    0xa59e_9e3b,
    0xfff3_f30c,
    0xf0cf_cf3f,
    0x72cd_cdbf,
    0x175c_5c4b,
    0xb8ea_ea52,
    0x810e_0e8f,
    0x5865_653d,
    0x3cf0_f0cc,
    0x1964_647d,
    0xe59b_9b7e,
    0x8716_1691,
    0x4e3d_3d73,
    0xaaa2_a208,
    0x69a1_a1c8,
    0x6aad_adc7,
    0x8306_0685,
    0xb0ca_ca7a,
    0x70c5_c5b5,
    0x6591_91f4,
    0xd96b_6bb2,
    0x892e_2ea7,
    0xfbe3_e318,
    0xe8af_af47,
    0x0f3c_3c33,
    0x4a2d_2d67,
    0x71c1_c1b0,
    0x5759_590e,
    0x9f76_76e9,
    0x35d4_d4e1,
    0x1e78_7866,
    0x2490_90b4,
    0x0e38_3836,
    0x5f79_7926,
    0x628d_8def,
    0x5961_6138,
    0xd247_4795,
    0xa08a_8a2a,
    0x2594_94b1,
    0x2288_88aa,
    0x7df1_f18c,
    0x3bec_ecd7,
    0x0104_0405,
    0x2184_84a5,
    0x79e1_e198,
    0x851e_1e9b,
    0xd753_5384,
    0x0000_0000,
    0x4719_195e,
    0x565d_5d0b,
    0x9d7e_7ee3,
    0xd04f_4f9f,
    0x279c_9cbb,
    0x5349_491a,
    0x4d31_317c,
    0x36d8_d8ee,
    0x0208_080a,
    0xe49f_9f7b,
    0xa282_8220,
    0xc713_13d4,
    0xcb23_23e8,
    0x9c7a_7ae6,
    0xe9ab_ab42,
    0xbdfe_fe43,
    0x882a_2aa2,
    0xd14b_4b9a,
    0x4101_0140,
    0xc41f_1fdb,
    0x38e0_e0d8,
    0xb7d6_d661,
    0xa18e_8e2f,
    0xf4df_df2b,
    0xf1cb_cb3a,
    0xcd3b_3bf6,
    0xfae7_e71d,
    0x6085_85e5,
    0x1554_5441,
    0xa386_8625,
    0xe383_8360,
    0xacba_ba16,
    0x5c75_7529,
    0xa692_9234,
    0x996e_6ef7,
    0x34d0_d0e4,
    0x1a68_6872,
    0x5455_5501,
    0xafb6_b619,
    0x914e_4edf,
    0x32c8_c8fa,
    0x30c0_c0f0,
    0xf6d7_d721,
    0x8e32_32bc,
    0xb3c6_c675,
    0xe08f_8f6f,
    0x1d74_7469,
    0xf5db_db2e,
    0xe18b_8b6a,
    0x2eb8_b896,
    0x800a_0a8a,
    0x6799_99fe,
    0xc92b_2be2,
    0x6181_81e0,
    0xc303_03c0,
    0x29a4_a48d,
    0x238c_8caf,
    0xa9ae_ae07,
    0x0d34_3439,
    0x524d_4d1f,
    0x4f39_3976,
    0x6ebd_bdd3,
    0xd657_5781,
    0xd86f_6fb7,
    0x37dc_dceb,
    0x4415_1551,
    0xdd7b_7ba6,
    0xfef7_f709,
    0x8c3a_3ab6,
    0x2fbc_bc93,
    0x030c_0c0f,
    0xfcff_ff03,
    0x6ba9_a9c2,
    0x73c9_c9ba,
    0x6cb5_b5d9,
    0x6db1_b1dc,
    0x5a6d_6d37,
    0x5045_4515,
    0x8f36_36b9,
    0x1b6c_6c77,
    0xadbe_be13,
    0x904a_4ada,
    0xb9ee_ee57,
    0xde77_77a9,
    0xbef2_f24c,
    0x7efd_fd83,
    0x1144_4455,
    0xda67_67bd,
    0x5d71_712c,
    0x4005_0545,
    0x1f7c_7c63,
    0x1040_4050,
    0x5b69_6932,
    0xdb63_63b8,
    0x0a28_2822,
    0xc207_07c5,
    0x31c4_c4f5,
    0x8a22_22a8,
    0xa796_9631,
    0xce37_37f9,
    0x7aed_ed97,
    0xbff6_f649,
    0x2db4_b499,
    0x75d1_d1a4,
    0xd343_4390,
    0x1248_485a,
    0xbae2_e258,
    0xe697_9771,
    0xb6d2_d264,
    0xb2c2_c270,
    0x8b26_26ad,
    0x68a5_a5cd,
    0x955e_5ecb,
    0x4b29_2962,
    0x0c30_303c,
    0x945a_5ace,
    0x76dd_ddab,
    0x7ff9_f986,
    0x6495_95f1,
    0xbbe6_e65d,
    0xf2c7_c735,
    0x0924_242d,
    0xc617_17d1,
    0x6fb9_b9d6,
    0xc51b_1bde,
    0x8612_1294,
    0x1860_6078,
    0xf3c3_c330,
    0x7cf5_f589,
    0xefb3_b35c,
    0x3ae8_e8d2,
    0xdf73_73ac,
    0x4c35_3579,
    0x2080_80a0,
    0x78e5_e59d,
    0xedbb_bb56,
    0x5e7d_7d23,
    0x3ef8_f8c6,
    0xd45f_5f8b,
    0xc82f_2fe7,
    0x39e4_e4dd,
    0x4921_2168,
];

/// Family Key constants used in the key schedule initialisation step.
/// From `crypto/sm4/sm4.c` lines 284–286.
static SM4_FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

/// Constant Key values used in the SM4 key schedule iteration.
/// From `crypto/sm4/sm4.c` lines 291–300.
static SM4_CK: [u32; 32] = [
    0x0007_0e15,
    0x1c23_2a31,
    0x383f_464d,
    0x545b_6269,
    0x7077_7e85,
    0x8c93_9aa1,
    0xa8af_b6bd,
    0xc4cb_d2d9,
    0xe0e7_eef5,
    0xfc03_0a11,
    0x181f_262d,
    0x343b_4249,
    0x5057_5e65,
    0x6c73_7a81,
    0x888f_969d,
    0xa4ab_b2b9,
    0xc0c7_ced5,
    0xdce3_eaf1,
    0xf8ff_060d,
    0x141b_2229,
    0x3037_3e45,
    0x4c53_5a61,
    0x686f_767d,
    0x848b_9299,
    0xa0a7_aeb5,
    0xbcc3_cad1,
    0xd8df_e6ed,
    0xf4fb_0209,
    0x1017_1e25,
    0x2c33_3a41,
    0x484f_565d,
    0x646b_7279,
];
// -----------------------------------------------------------------------------
// SM4 round helpers
// -----------------------------------------------------------------------------

/// Apply the SM4 S-box `τ` to each byte of a 32-bit word.
///
/// Mirrors `SM4_T_non_lin_sub` from `crypto/sm4/sm4.c` lines 253–262.
///
/// # Security (cache-timing)
///
/// This helper performs **4 byte-indexed lookups per call** into
/// `SM4_S` (the 256-byte SM4 substitution box) using **secret-derived
/// indices** (each byte of `x = state XOR round_key`). Although `SM4_S`
/// is one cache line of 256 bytes (4 typical 64-byte cache lines on
/// x86-64), cache-line residency still leaks the high 2 bits of each
/// byte index per access.
///
/// `sm4_tau` is invoked by both `sm4_t_slow` (for the outermost rounds)
/// and `sm4_key_sub` (during key schedule). Per-block leakage attribution
/// is detailed in the `sm4_t_slow` and `sm4_t_fast` SECURITY blocks
/// below.
#[inline]
fn sm4_tau(x: u32) -> u32 {
    let b3 = SM4_S[((x >> 24) & 0xff) as usize];
    let b2 = SM4_S[((x >> 16) & 0xff) as usize];
    let b1 = SM4_S[((x >> 8) & 0xff) as usize];
    let b0 = SM4_S[(x & 0xff) as usize];
    (u32::from(b3) << 24) | (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0)
}

/// Byte-wise evaluation of the SM4 round function `T(x) = L(τ(x))`.
///
/// Used for the outermost four rounds (0..=3 and 28..=31) — the
/// upstream OpenSSL `SM4_T_slow` from `crypto/sm4/sm4.c` lines 264–267
/// uses this byte-wise path (rather than the table-driven `SM4_T`)
/// **specifically to reduce — but NOT eliminate — cache-timing leakage
/// at the boundary between attacker-controlled plaintext/ciphertext
/// and round-key-mixed state**. The smaller 256-byte `SM4_S` table
/// (one cache-line set on most x86-64 CPUs) leaks fewer bits per
/// access than the four 1024-byte `SM4_SBOX_T*` tables used by
/// `sm4_t_fast`, but the leakage is **NOT zero** and `sm4_t_slow` is
/// **NOT a constant-time substitute** for the round function.
///
/// # Security (cache-timing)
///
/// `sm4_t_slow` invokes `sm4_tau` once, which performs **4 SM4_S
/// byte-indexed lookups per call**. The subsequent rotation+XOR
/// linear layer `L(t) = t ^ rotl(t,2) ^ rotl(t,10) ^ rotl(t,18) ^
/// rotl(t,24)` uses constant-amount rotations and is constant-time on
/// supported targets.
///
/// Per block leakage when `sm4_t_slow` is selected (only for rounds
/// 0..=3 and 28..=31 in the upstream design):
/// * 8 rounds × 4 SM4_S reads/round = **32 secret-indexed reads/block**
///   from the 256-byte `SM4_S` table (smaller leakage surface than
///   `sm4_t_fast`'s 1024-byte tables).
///
/// The full SM4 cipher uses `sm4_t_slow` for 8 of 32 rounds and
/// `sm4_t_fast` for the remaining 24 rounds. Combined per-block
/// leakage is documented in `sm4_t_fast`.
///
/// `sm4_t_slow` is **NOT a remediation path on its own** — it merely
/// reduces (does not eliminate) the leakage surface for boundary
/// rounds. The SM4 **key schedule** (`Sm4::new`) calls `sm4_key_sub`
/// (which also calls `sm4_tau`) once per round-key derivation,
/// leaking SM4_S accesses on key-derived intermediate values during
/// setup.
///
/// SM4 is a 128-bit-block cipher (NOT Sweet32-vulnerable) and is the
/// Chinese national standard (GB/T 32907-2016, GM/T 0002-2012). It
/// remains in cryptographic good standing on a *mathematical* basis.
/// However, no constant-time software path is implemented here and no
/// hardware acceleration (analogous to the SM4-NI extensions present
/// on some ARM platforms) is leveraged in this pure-Rust translation.
/// Recommended remediation: prefer **AES-GCM or ChaCha20-Poly1305**
/// for new deployments. SM4 is preserved for Chinese government and
/// commercial cryptography (OSCCA) interoperability.
///
/// See the module-level *Security Notice — Cache-Timing Side Channel*
/// for the full threat model and references.
#[inline]
fn sm4_t_slow(x: u32) -> u32 {
    let t = sm4_tau(x);
    t ^ t.rotate_left(2) ^ t.rotate_left(10) ^ t.rotate_left(18) ^ t.rotate_left(24)
}

/// Table-driven evaluation of the SM4 round function `T(x) = L(τ(x))`.
///
/// Combines the four precomputed `SM4_SBOX_T*` tables using one lookup per
/// input byte. Mirrors `SM4_T` from `crypto/sm4/sm4.c` lines 269–272.
///
/// # Security (cache-timing)
///
/// This is the **principal cache-timing-vulnerable site** of SM4
/// encryption and decryption for the inner 24 rounds. The function
/// performs **4 byte-indexed lookups per call** into the four
/// precomputed tables `SM4_SBOX_T0`, `SM4_SBOX_T1`, `SM4_SBOX_T2`,
/// `SM4_SBOX_T3` — each 256 × 32-bit = **1024 bytes** spanning
/// multiple cache lines. Indices are bytes of `x = state XOR round_key`
/// (secret-derived), so cache-line residency leaks the high bits of
/// each byte index after a single round.
///
/// Per block leakage with the standard SM4 (32 rounds):
/// * Inner 24 rounds × 4 `SM4_SBOX_T*` reads/round = **96
///   secret-indexed reads/block** from the four 1024-byte tables.
/// * Outer 8 rounds × 4 `SM4_S` reads/round (via `sm4_t_slow` →
///   `sm4_tau`) = **32 secret-indexed reads/block** from the 256-byte
///   table.
/// * **Total: 128 secret-indexed reads/block.**
///
/// Both `Sm4::encrypt_block` and `Sm4::decrypt_block` traverse this
/// path; SM4 decryption uses the same round function with the
/// round-key schedule reversed.
///
/// SM4 has hardware acceleration on some ARMv8 platforms (the SM4-NI
/// crypto extension, similar in spirit to AES-NI). This pure-Rust
/// implementation does **not** leverage such instructions; that
/// remediation pathway is out of scope for this milestone (per AAP
/// §0.7.5 the perlasm assembly generators are explicitly preserved
/// only as the validation reference).
///
/// Refer to the `sm4_t_slow` and `sm4_tau` SECURITY blocks for
/// per-helper leakage detail and to the module-level *Security
/// Notice — Cache-Timing Side Channel* for the full threat model.
#[inline]
fn sm4_t_fast(x: u32) -> u32 {
    SM4_SBOX_T0[((x >> 24) & 0xff) as usize]
        ^ SM4_SBOX_T1[((x >> 16) & 0xff) as usize]
        ^ SM4_SBOX_T2[((x >> 8) & 0xff) as usize]
        ^ SM4_SBOX_T3[(x & 0xff) as usize]
}

/// SM4 key schedule transform `T'(x) = L'(τ(x))`.
///
/// Differs from the encryption `T` in that `L'` only combines rotations by
/// 13 and 23. Mirrors `SM4_key_sub` from `crypto/sm4/sm4.c` lines 274–277.
#[inline]
fn sm4_key_sub(x: u32) -> u32 {
    let t = sm4_tau(x);
    t ^ t.rotate_left(13) ^ t.rotate_left(23)
}

/// Execute four consecutive SM4 rounds using the supplied round function.
///
/// This is a functional translation of the `SM4_RNDS` macro defined at
/// `crypto/sm4/sm4.c` lines 324–330. The four working words are updated
/// in-place; `rk_base` is the index of the first of four consecutive
/// round keys to consume.
#[inline]
fn sm4_rnds(
    state: &mut [u32; 4],
    rk: &[u32; SM4_KEY_SCHEDULE],
    rk_base: usize,
    round: fn(u32) -> u32,
) {
    let (b0, b1, b2, b3) = (state[0], state[1], state[2], state[3]);
    let n0 = b0 ^ round(b1 ^ b2 ^ b3 ^ rk[rk_base]);
    let n1 = b1 ^ round(n0 ^ b2 ^ b3 ^ rk[rk_base + 1]);
    let n2 = b2 ^ round(n0 ^ n1 ^ b3 ^ rk[rk_base + 2]);
    let n3 = b3 ^ round(n0 ^ n1 ^ n2 ^ rk[rk_base + 3]);
    state[0] = n0;
    state[1] = n1;
    state[2] = n2;
    state[3] = n3;
}

// -----------------------------------------------------------------------------
// Sm4 cipher
// -----------------------------------------------------------------------------

/// SM4 cipher (Chinese national standard, 128-bit block, 128-bit key).
///
/// Translates the C `SM4_KEY` structure from `include/crypto/sm4.h` and the
/// implementation in `crypto/sm4/sm4.c`. The round keys are expanded lazily
/// via [`Sm4::new`] and then used in-place for both encryption and
/// decryption by reversing the key-index walk.
///
/// The key material is automatically zeroed when the instance is dropped
/// (see [`zeroize::ZeroizeOnDrop`]).
///
/// # Examples
///
/// ```
/// # use openssl_crypto::symmetric::{Sm4, SymmetricCipher, BlockSize};
/// let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
///            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
/// let cipher = Sm4::new(&key).expect("16-byte key");
/// assert_eq!(cipher.block_size(), BlockSize::Block128);
/// let mut block = [0u8; 16];
/// block.copy_from_slice(&key);
/// cipher.encrypt_block(&mut block).unwrap();
/// cipher.decrypt_block(&mut block).unwrap();
/// assert_eq!(&block[..], &key[..]);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm4 {
    /// 32 expanded round keys, produced by [`Sm4::expand_key`].
    rk: [u32; SM4_KEY_SCHEDULE],
}

impl Sm4 {
    /// Construct a new SM4 cipher from a 16-byte key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key.len() != 16`.
    ///
    /// Mirrors `ossl_sm4_set_key` from `crypto/sm4/sm4.c` lines 279–322.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != SM4_KEY_LEN {
            return Err(CryptoError::Key(format!(
                "SM4 requires a {SM4_KEY_LEN}-byte key, got {} bytes",
                key.len()
            )));
        }
        let rk = Self::expand_key(key);
        Ok(Self { rk })
    }

    /// Expand a 16-byte user key into 32 round keys.
    ///
    /// The expansion XORs the input with the fixed `FK` family constants,
    /// then applies 32 iterations of the `T'` transform with the
    /// `CK` round constants, directly mirroring the C reference.
    fn expand_key(key: &[u8]) -> [u32; SM4_KEY_SCHEDULE] {
        let mut k = [
            load_u32_be(key, 0) ^ SM4_FK[0],
            load_u32_be(key, 4) ^ SM4_FK[1],
            load_u32_be(key, 8) ^ SM4_FK[2],
            load_u32_be(key, 12) ^ SM4_FK[3],
        ];
        let mut rk = [0u32; SM4_KEY_SCHEDULE];
        let mut i = 0;
        while i < SM4_KEY_SCHEDULE {
            k[0] ^= sm4_key_sub(k[1] ^ k[2] ^ k[3] ^ SM4_CK[i]);
            k[1] ^= sm4_key_sub(k[2] ^ k[3] ^ k[0] ^ SM4_CK[i + 1]);
            k[2] ^= sm4_key_sub(k[3] ^ k[0] ^ k[1] ^ SM4_CK[i + 2]);
            k[3] ^= sm4_key_sub(k[0] ^ k[1] ^ k[2] ^ SM4_CK[i + 3]);
            rk[i] = k[0];
            rk[i + 1] = k[1];
            rk[i + 2] = k[2];
            rk[i + 3] = k[3];
            i += 4;
        }
        // Zero working key material before it leaves the stack frame.
        k.zeroize();
        rk
    }

    /// Core 32-round transform shared by encryption and decryption.
    ///
    /// `rk_order` is an array of 32 indices specifying the order in which
    /// round keys are consumed — `[0, 1, …, 31]` for encryption, or
    /// `[31, 30, …, 0]` for decryption. The first and last four rounds use
    /// `sm4_t_slow` (side-channel protected), the inner 24 rounds use
    /// `sm4_t_fast`. The output is written with the SM4-specified
    /// word reflection: `(B3, B2, B1, B0)`.
    fn crypt_block(&self, block: &mut [u8], rk_order: &[usize; SM4_KEY_SCHEDULE]) {
        // Rearrange round keys into the order requested by the caller.
        // This keeps the macro-style rnds helper independent of direction.
        let mut rk = [0u32; SM4_KEY_SCHEDULE];
        for (dst, src_idx) in rk.iter_mut().zip(rk_order.iter()) {
            *dst = self.rk[*src_idx];
        }
        let mut state = [
            load_u32_be(block, 0),
            load_u32_be(block, 4),
            load_u32_be(block, 8),
            load_u32_be(block, 12),
        ];
        // First four rounds: byte-wise S-box (side-channel resistant).
        sm4_rnds(&mut state, &rk, 0, sm4_t_slow);
        // Middle 24 rounds: table-driven (fast).
        sm4_rnds(&mut state, &rk, 4, sm4_t_fast);
        sm4_rnds(&mut state, &rk, 8, sm4_t_fast);
        sm4_rnds(&mut state, &rk, 12, sm4_t_fast);
        sm4_rnds(&mut state, &rk, 16, sm4_t_fast);
        sm4_rnds(&mut state, &rk, 20, sm4_t_fast);
        sm4_rnds(&mut state, &rk, 24, sm4_t_fast);
        // Final four rounds: byte-wise S-box again.
        sm4_rnds(&mut state, &rk, 28, sm4_t_slow);
        // Output word order is reversed per the SM4 specification: B3..B0.
        store_u32_be(block, 0, state[3]);
        store_u32_be(block, 4, state[2]);
        store_u32_be(block, 8, state[1]);
        store_u32_be(block, 12, state[0]);
        // Zero the temporary schedule so no round-key material lingers.
        rk.zeroize();
        state.zeroize();
    }
}

impl SymmetricCipher for Sm4 {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block128
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, SM4_BLOCK_LEN, "SM4")?;
        // Round-key order 0, 1, 2, …, 31.
        let mut order = [0usize; SM4_KEY_SCHEDULE];
        for (i, slot) in order.iter_mut().enumerate() {
            *slot = i;
        }
        self.crypt_block(block, &order);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, SM4_BLOCK_LEN, "SM4")?;
        // Round-key order 31, 30, 29, …, 0 (mirror of encryption order).
        let mut order = [0usize; SM4_KEY_SCHEDULE];
        for (i, slot) in order.iter_mut().enumerate() {
            *slot = SM4_KEY_SCHEDULE - 1 - i;
        }
        self.crypt_block(block, &order);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Sm4
    }
}

// =============================================================================
// RC4 (stream cipher)
// =============================================================================
// Translated from `crypto/rc4/rc4_skey.c` (KSA) and `crypto/rc4/rc4_enc.c`
// (PRGA). RC4 is a byte-oriented stream cipher that produces a keystream by
// indexing a 256-element permutation with two internal counters `x` and `y`.
// Each output byte is produced by swapping two entries of the permutation
// and XOR-ing the input with `S[(S[x] + S[y]) & 0xff]`.
//
// RC4 is cryptographically **broken** (see RFC 7465 — prohibition of RC4 in
// TLS). It is retained here for interoperability with legacy peers only.
//
// The struct mirrors C `RC4_KEY` from `include/openssl/rc4.h`:
// ```c
// typedef struct rc4_key_st {
//     RC4_INT x, y;
//     RC4_INT data[256];
// } RC4_KEY;
// ```
// `RC4_INT` defaults to `unsigned int` (i.e. `u32`) for performance, matching
// the layout used in OpenSSL's standard C build; the semantic values remain
// bytes masked by `& 0xff`.
// =============================================================================

/// Minimum RC4 key size, in bytes. A single byte is sufficient for the
/// KSA but produces a trivially weak keystream; the CLI layer enforces
/// higher limits for user-facing subcommands.
const RC4_KEY_MIN: usize = 1;

/// Maximum RC4 key size, in bytes. Historically RC4 accepted up to 256
/// bytes of keying material (2048-bit effective key).
const RC4_KEY_MAX: usize = 256;

/// RC4 stream cipher state.
///
/// Holds the 256-byte permutation plus the two 8-bit counters that
/// advance once per output byte. The state evolves monotonically; calling
/// [`Rc4::process`] twice is equivalent to processing the concatenation of
/// the two inputs once.
///
/// The key-dependent permutation is automatically zeroed on drop via
/// [`zeroize::ZeroizeOnDrop`].
///
/// # Examples
///
/// ```
/// # use openssl_crypto::symmetric::{Rc4, StreamCipher, CipherAlgorithm};
/// let mut cipher = Rc4::new(b"Key").expect("non-empty key");
/// let ct = cipher.process(b"Plaintext").unwrap();
/// assert_eq!(ct.len(), 9);
/// // Decryption is the same operation; construct a fresh instance.
/// let mut inv = Rc4::new(b"Key").unwrap();
/// let pt = inv.process(&ct).unwrap();
/// assert_eq!(pt, b"Plaintext");
/// assert_eq!(cipher.algorithm(), CipherAlgorithm::Rc4);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rc4 {
    /// The `x` counter, advanced before each keystream byte.
    x: u32,
    /// The `y` counter, computed from the permutation each step.
    y: u32,
    /// Current 256-entry permutation (S-box).
    data: [u32; 256],
}

impl Rc4 {
    /// Initialise an RC4 cipher from a key of 1..=256 bytes.
    ///
    /// Mirrors `RC4_set_key` from `crypto/rc4/rc4_skey.c`. The resulting
    /// instance is ready to call [`Rc4::process`] immediately.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key.len()` is outside the
    /// supported range 1..=256.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.is_empty() || key.len() > RC4_KEY_MAX {
            return Err(CryptoError::Key(format!(
                "RC4 requires a key of {RC4_KEY_MIN}..={RC4_KEY_MAX} bytes, got {}",
                key.len()
            )));
        }
        // Initialise the identity permutation d[i] = i.
        let mut data = [0u32; 256];
        for (i, slot) in data.iter_mut().enumerate() {
            // `i` is bounded by `data.len() == 256`, which fits comfortably
            // in a `u32`; the `unwrap_or(0)` fallback is unreachable and
            // purely defensive.
            *slot = u32::try_from(i).unwrap_or(0);
        }
        // KSA: scramble the permutation using the key. The two indices
        // `id1` and `id2` mirror the identically-named C locals, with
        // `id1` walking the key (wrapping at `key.len()`) and `id2`
        // absorbing entropy from successive permutation entries.
        let len = key.len();
        let mut id1: usize = 0;
        let mut id2: u32 = 0;
        let mut i = 0usize;
        while i < 256 {
            // Four-way unrolled loop mirroring the C `SK_LOOP(d, i+k)`.
            for k in 0..4 {
                let pos = i + k;
                let tmp = data[pos];
                id2 = (u32::from(key[id1]).wrapping_add(tmp).wrapping_add(id2)) & 0xff;
                id1 += 1;
                if id1 == len {
                    id1 = 0;
                }
                data[pos] = data[id2 as usize];
                data[id2 as usize] = tmp;
            }
            i += 4;
        }
        Ok(Self { x: 0, y: 0, data })
    }
}

impl StreamCipher for Rc4 {
    fn process(&mut self, input: &[u8]) -> CryptoResult<Vec<u8>> {
        // The PRGA is symmetric: encrypt and decrypt use identical code.
        // We loop byte-by-byte rather than replicate the C 8-way unroll
        // because Rust auto-vectorisation is sufficient and the simpler
        // loop is easier to audit against the RC4 specification.
        let mut out = Vec::with_capacity(input.len());
        let mut x = self.x;
        let mut y = self.y;
        for &b in input {
            x = (x + 1) & 0xff;
            let tx = self.data[x as usize];
            y = (tx.wrapping_add(y)) & 0xff;
            let ty = self.data[y as usize];
            self.data[x as usize] = ty;
            self.data[y as usize] = tx;
            let k_index = (tx.wrapping_add(ty)) & 0xff;
            let keystream = self.data[k_index as usize];
            // `keystream` only holds a byte value by construction, so the
            // `& 0xff` above already guarantees the high bits are zero.
            // `try_from` provides a defence-in-depth check per rule R6.
            let ks_byte = u8::try_from(keystream).map_err(|_| {
                CryptoError::Common(CommonError::InvalidArgument(
                    "RC4 keystream exceeded byte range".to_string(),
                ))
            })?;
            out.push(b ^ ks_byte);
        }
        self.x = x;
        self.y = y;
        Ok(out)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Rc4
    }
}
